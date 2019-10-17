#include "includes.h"

#ifndef ns_t_rrsig // ns_t_rrsig was not defined in my arpa/nameser.h
#define ns_t_rrsig 46
#endif

struct dns_rr_type {
  uint16_t rrtype;
  char *rrdesc;
};

// All the names must not be longer than RRTYPE_MAX_LEN-1
// The ns_t_xxx constants are defined in arpa/nameser.h
static struct dns_rr_type DNS_RR_TYPES[] = {
  { ns_t_a,      "A" },
  { ns_t_aaaa,   "AAAA" },
  { ns_t_cname,  "CNAME" },
  { ns_t_mx,     "MX" },
  { ns_t_ns,     "NS" },
  { ns_t_ptr,    "PTR" },
  { ns_t_soa,    "SOA" },
  { ns_t_srv,    "SRV" },
  { ns_t_txt,    "TXT" },
  { ns_t_rrsig,  "RRSIG" },
  { 0,           "<unknown>" },  // Special last entry to denote unidentified RR type value
};

static const char* get_rrtype_name(uint16_t rrtype);
static void resolve_callback(void* mydata, int rcode, void* packet, int packet_len, int sec, char* why_bogus, int a);
static int copy_reply_without_rrsig(resolver_request_t *request, const uint8_t *reply, int reply_len);

int resolver_init(app_t *app, const char *dns_csv) {
  int ret = 0;
  char *dns_s = NULL;

  app->ub_ctx = ub_ctx_create_event(app->ev_base);
  if (NULL == app->ub_ctx) {
    zlog_error(app->resolver_log_cat, "(DS-30101) Failed init application: unable to initialize unbound context");
    ret = 31001;
    goto end;
  }

  dns_s = strdup(dns_csv);
  if (NULL == dns_s) {
    zlog_error(app->resolver_log_cat, "(DS-30102) Failed init application: unable to allocate memory");
    ret = 31002;
    goto end;
  }

  char *dns_p = NULL;
  char *dns = strtok_r(dns_s, ",", &dns_p);
  while (NULL != dns) {
    int err = ub_ctx_set_fwd(app->ub_ctx, dns);
    if (0 != err) {
      zlog_error(app->resolver_log_cat, "(DS-30103) Failed to init application: unable to set add upstream DNS '%s': %s", dns, ub_strerror(err));
      ret = 31003;
      goto end;
    } else {
      zlog_notice(app->resolver_log_cat, "Upstream DNS server added: %s", dns);
    }
    dns = strtok_r(NULL, ",", &dns_p);
  }

  zlog_info(app->resolver_log_cat, "Unbound context initialized.");

  end:
  free(dns_s);
  return ret;
}

int resolver_cleanup(app_t *app) {
  if (NULL != app->ub_ctx) {
    ub_ctx_delete(app->ub_ctx);
    app->ub_ctx = NULL;
  }
  return 0;
}

void resolver_cancel(app_t *app, resolver_request_t *request) {
  if (INVALID_REQUEST_ID != request->request_id) {
    ub_cancel(app->ub_ctx, request->request_id);
    request->request_id = INVALID_REQUEST_ID;
  }
}

int resolver_resolve(app_t *app, resolver_request_t *request) {
  assert(NULL != request);
  assert(NULL != request->request_buf);

  int ret = 0;
  uint8_t *p = request->request_buf;
  size_t p_offset = 0, p_length = request->request_buf_len;

  if (p_length < 12) {
    zlog_error(app->resolver_log_cat, "(DS-30200) (%s) DNS query packet from client is malformed: invalid header", request->client_addr);
    ret = 30200;
    goto end;
  }

  uint16_t qdcount = (p[4]<<8 | p[5]);
  if (0 == qdcount) {
    zlog_error(app->resolver_log_cat, "(DS-30201) (%s) DNS query packet from client is malformed: no question", request->client_addr);
    ret = 30201;
    goto end;
  } else if (qdcount > 1) {
    zlog_warn(app->resolver_log_cat, "(DS-30202) (%s) DNS query packet from client contains multiple queries. Only first query will be answered.", request->client_addr);
  }

  uint16_t ancount = (p[6]<<8 | p[7]);
  uint16_t nscount = (p[8]<<8 | p[9]);
  uint16_t arcount = (p[10]<<8 | p[11]);
  p_offset += 12; // ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT

  if (ancount > 0 || nscount > 0) {
    zlog_error(app->resolver_log_cat, "(DS-30203) (%s) DNS query packet from client contains answer records", request->client_addr);
    ret = 30203;
    goto end;
  }

  uint16_t rrtype = 0, rrclass = 0;
  for (int i=0; i<qdcount; i++) {
    if (i == 0) {
      int enc_len = ns_name_uncompress(p, p+p_length, p+p_offset, request->request_name, sizeof(request->request_name));
      if (enc_len < 0) {
        zlog_error(app->resolver_log_cat, "(DS-30204) (%s) DNS query packet from client is malformed: unable to parse query name", request->client_addr);
        ret = 30204;
        goto end;
      }
      p_offset += enc_len;

      if (p_offset+4 > p_length) {
        zlog_error(app->resolver_log_cat, "(DS-30205) (%s) DNS query packet from client is malformed: incomplete query record for '%s'", request->client_addr, request->request_name);
        ret = 30205;
        goto end;
      }

      rrtype = p[p_offset]<<8 | p[p_offset+1];
      rrclass = p[p_offset+2]<<8 | p[p_offset+3];
      p_offset += 4;
    } else {
      // Ignore other query records
      const uint8_t *ptr = p+p_offset;
      if (0 != ns_name_skip(&ptr, p+p_length)) {
        zlog_error(app->resolver_log_cat, "(DS-30206) (%s) DNS query packet from client is malformed: unable to parse query name", request->client_addr);
        ret = 30206;
        goto end;
      }
      p_offset = ptr - p;
      p_offset += 4; // skip rrtype and rrclass fields

      if (p_offset+4 > p_length) {
        zlog_error(app->resolver_log_cat, "(DS-30207) (%s) DNS query packet from client is malformed: incomplete query record", request->client_addr);
        ret = 30207;
        goto end;
      }
    }
  }

  for (int i=0; i<arcount; i++) {
    // EDNS0 OPT parsing
    if (p_offset + 11 <= p_length && p[p_offset] == 0 && p[p_offset+1] == 0 && p[p_offset+2] == 0x29) {
      if (p[p_offset+6] == 0) {  // EDNS version
        request->use_dnssec = (p[p_offset+7] & 0x80);
      }
    }

    const uint8_t *ptr = p+p_offset;
    if (0 != ns_name_skip(&ptr, p+p_length)) {
      zlog_error(app->resolver_log_cat, "(DS-30208) (%s) DNS query packet from client is malformed: unable to parse query name", request->client_addr);
      ret = 30208;
      goto end;
    }
    p_offset = ptr - p;
    if (p_offset + 8 > p_length) {
      zlog_error(app->resolver_log_cat, "(DS-30209) (%s) DNS query packet from client is malformed: incomplete AR", request->client_addr);
      ret = 30209;
      goto end;
    }

    p_offset += 8; // type, class, ttl
    uint16_t rdlength = p[p_offset]<<8 | p[p_offset+1];
    p_offset += rdlength;

    if (p_offset > p_length) {
      zlog_error(app->resolver_log_cat, "(DS-30210) (%s) DNS query packet from client is malformed: incomplete AR", request->client_addr);
      ret = 30210;
      goto end;
    }
  }

  strncpy(request->request_type, get_rrtype_name(rrtype), RRTYPE_MAX_LEN-1);
  zlog_info(app->resolver_log_cat, "(%s) Resolving %s %s (EDNS-do=%s)...", request->client_addr, request->request_type, request->request_name, request->use_dnssec?"Y":"N");

  ub_resolve_event(app->ub_ctx, request->request_name, rrtype, rrclass, request, resolve_callback, &(request->request_id));

  end:
  return ret;
}

static void resolve_callback(void* mydata, int rcode, void* packet, int packet_len, int sec, char* why_bogus, int a) {
  resolver_request_t *request = (resolver_request_t *)mydata;
  request->request_id = INVALID_REQUEST_ID;

  if (0 == rcode) {
    if (1 == sec) { // bogus (should not receive this since we do not set anchor file to activate DNSSEC verification)
      zlog_warn(request->app->resolver_log_cat, "(%s) %s %s reply fails DNSSEC verification", request->client_addr, request->request_type, request->request_name);
    } else { // 0==sec (unsecure) or 2==sec (dnssec)
      request->reply_buf = malloc(packet_len);
      if (NULL != request->reply_buf) {
        if (request->use_dnssec) {
          memcpy(request->reply_buf, packet, packet_len);
          request->reply_buf_len = packet_len;
        } else { // request does not support DNSSEC
          if (0 != copy_reply_without_rrsig(request, packet, packet_len)) {
            // error parsing reply, so drop this reply silently
            return;
          }
        }

        // copy txID from request to response
        request->reply_buf[0] = request->request_buf[0];
        request->reply_buf[1] = request->request_buf[1];

        uint16_t answers_count = (request->reply_buf[6]<<8 | request->reply_buf[7]);
        zlog_info(request->app->resolver_log_cat, "(%s) %s %s resolved with %u answers", request->client_addr, request->request_type, request->request_name, answers_count);

        https_send_reply(request->app, request);
      } else {
        zlog_warn(request->app->resolver_log_cat, "(%s) (DS-30301) Failed to send back DNS reply: unable to allocate memory", request->client_addr);
      }
    }
  } else {
    // Squelch the warning if rcode is SERVFAIL (2) or NXDOMAIN (3)
    if (rcode!=2 && rcode!=3) {
      zlog_warn(request->app->resolver_log_cat, "(%s) (DS-30302) Failed to resolve %s %s: rcode=%d", request->client_addr, request->request_type, request->request_name, rcode);
     }
  }
}

static const char* get_rrtype_name(uint16_t rrtype) {
  const char *ret = NULL;
  int index = 0;
  while (true) {
    struct dns_rr_type *t = &(DNS_RR_TYPES[index++]);
    ret = t->rrdesc;
    if (rrtype == t->rrtype || 0 == t->rrtype) {
      break;
    }
  }
  return ret;
}

static int copy_reply_without_rrsig(resolver_request_t *request, const uint8_t *reply, int reply_len) {
  assert(NULL != request->reply_buf);

  int ret = 0;
  app_t *app = request->app;
  const uint8_t *p = reply;
  uint8_t *out = request->reply_buf;
  size_t p_offset = 0, p_length = reply_len;
  size_t out_offset = 0;

  if (p_length < 12) {
    zlog_error(app->resolver_log_cat, "(DS-30400) (%s) DNS reply for %s '%s' is malformed: invalid header", request->client_addr, request->request_type, request->request_name);
    ret = 30400;
    goto end;
  }

  uint16_t qdcount = (p[4]<<8 | p[5]);
  if (0 == qdcount) {
    zlog_error(app->resolver_log_cat, "(DS-30401) (%s) DNS reply for %s '%s' is malformed: no question", request->client_addr, request->request_type, request->request_name);
    ret = 30401;
    goto end;
  } else if (qdcount > 1) {
    zlog_error(app->resolver_log_cat, "(DS-30402) (%s) DNS reply for %s '%s' contains multiple queries", request->client_addr, request->request_type, request->request_name);
    ret = 30402;
    goto end;
  }

  uint16_t ancount = (p[6]<<8 | p[7]);
  uint16_t nscount = (p[8]<<8 | p[9]);
  uint16_t arcount = (p[10]<<8 | p[11]);
  p_offset += 12; // ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
  memcpy(out, p, 12);
  out_offset = 12;

  for (int i=0; i<qdcount; i++) {
    const uint8_t *ptr = p + p_offset;
    if (ns_name_skip(&ptr, p+p_length) != 0) {
      zlog_error(app->resolver_log_cat, "(DS-30403) (%s) Failed to parse DNS reply for %s '%s': incomplete query record", request->client_addr, request->request_type, request->request_name);
      ret = 30403;
      goto end;
    }
    size_t enc_len = ptr - p - p_offset;
    if (p_offset+enc_len+4 > p_length) {
      zlog_error(app->resolver_log_cat, "(DS-30404) (%s) Failed to parse DNS reply for %s '%s': incomplete query record", request->client_addr, request->request_type, request->request_name);
      ret = 30404;
      goto end;
    }
    memcpy(out+out_offset, p+p_offset, enc_len+4);
    p_offset += enc_len + 4;
    out_offset += enc_len + 4;
  }

  uint16_t adjusted_ancount = 0;
  for (int i=0; i<ancount; i++) {
    const uint8_t *ptr = p + p_offset;
    if (ns_name_skip(&ptr, p+p_length) != 0) {
      zlog_error(app->resolver_log_cat, "(DS-30405) (%s) Failed to parse DNS reply for %s '%s': incomplete answer record", request->client_addr, request->request_type, request->request_name);
      ret = 30405;
      goto end;
    }

    size_t enc_len = ptr - p - p_offset;
    if (p_offset+enc_len+10 > p_length) {
      zlog_error(app->resolver_log_cat, "(DS-30406) (%s) Failed to parse DNS reply for %s '%s': incomplete answer record", request->client_addr, request->request_type, request->request_name);
      ret = 30406;
      goto end;
    }

    uint16_t rrtype = (p[p_offset+enc_len]<<8 | p[p_offset+enc_len+1]);
    uint16_t rdlength = (p[p_offset+enc_len+8]<<8 | p[p_offset+enc_len+9]);
    if (p_offset+enc_len+10+rdlength > p_length) {
      zlog_error(app->resolver_log_cat, "(DS-30407) (%s) Failed to parse DNS reply for %s '%s': incomplete answer record", request->client_addr, request->request_type, request->request_name);
      ret = 30407;
      goto end;
    }

    if (rrtype != ns_t_rrsig) {
      zlog_debug(app->resolver_log_cat, "(%s) Copying record at index %d for %s '%s'", request->client_addr, i, request->request_type, request->request_name);
      memcpy(out+out_offset, p+p_offset, enc_len+10+rdlength);
      out_offset += enc_len+10+rdlength;
      adjusted_ancount++;
    } else {
      zlog_debug(app->resolver_log_cat, "(%s) Skipping RRSIG record at index %d for %s '%s'", request->client_addr, i, request->request_type, request->request_name);
    }
    p_offset += enc_len+10+rdlength;
  }
  // Adjust the ANCOUNT field of the reply header in out buffer
  out[6] = adjusted_ancount >> 8;
  out[7] = adjusted_ancount & 0xff;

  // Copy the remaining authority and additional records over to out buffer
  size_t n = p_length - p_offset;
  memcpy(out+out_offset, p+p_offset, n);
  out_offset += n;

  zlog_debug(app->resolver_log_cat, "(%s) Reply for %s '%s' contains ANCOUNT=%d NSCOUNT=%d ARCOUNT=%d", request->client_addr, request->request_type, request->request_name, adjusted_ancount, nscount, arcount);

  end:
  if (0 == ret) {
    request->reply_buf_len = out_offset;
  }
  return ret;
}
