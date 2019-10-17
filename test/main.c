#include "includes.h"

static uint16_t get_rrtype(const char *s);
static int perform_query(CURL *curl, uint16_t rrtype, const char *rrtype_label, const char *name);
static size_t query_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);

int main(int argc, char **argv) {
  CURL *curl = NULL;
  const char *rrtype_label = NULL;
  const char *doh_url = "https://127.0.0.1:10443/dns-query";
  int ret = EXIT_SUCCESS;

  ares_library_init(ARES_LIB_INIT_ALL);

  curl = curl_easy_init();
  if (NULL == curl) {
    ret = EXIT_FAILURE;
    printf("Failed to initialize application: unable to initialize curl handle\n");
    goto end;
  }

  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  bool has_started_query = false;
  uint16_t rrtype = ns_t_invalid;
  for (int arg_index = 1; arg_index < argc; arg_index++) {
    if (!has_started_query) {
      if (0 == strncmp(argv[arg_index], "https://", 8 /* strlen("https://") */)) {
        doh_url = argv[arg_index];
        continue;
      } else {
        uint16_t r = get_rrtype(argv[arg_index]);
        if (ns_t_invalid != r) {
          rrtype = r;
          rrtype_label = argv[arg_index];
          continue;
        }
      }
    }

    if (!has_started_query) {
      if (ns_t_invalid == rrtype) {
        rrtype = ns_t_a;
      }
      curl_easy_setopt(curl, CURLOPT_URL, doh_url);

      printf("Using DOH service at %s\n", doh_url);
      has_started_query = true;
    }

    perform_query(curl, rrtype, rrtype_label, argv[arg_index]);
  }

  end:
  if (NULL == curl) {
    curl_easy_cleanup(curl);
  }
  return ret;
}

static uint16_t get_rrtype(const char *s) {
  // ns_t_ enumeration constants are defined in arpa/nameser.h
  if (0 == strcmp(s, "A")) {
    return ns_t_a;
  } else if (0 == strcmp(s, "AAAA")) {
    return ns_t_aaaa;
  } else if (0 == strcmp(s, "NS")) {
    return ns_t_ns;
  } else if (0 == strcmp(s, "MX")) {
    return ns_t_mx;
  } else if (0 == strcmp(s, "SOA")) {
    return ns_t_soa;
  } else if (0 == strcmp(s, "TXT")) {
    return ns_t_txt;
  }
  return ns_t_invalid;
}

static int perform_query(CURL *curl, uint16_t rrtype, const char *rrtype_label, const char *name) {
  struct curl_slist *headers = NULL;
  struct evbuffer *reply_buf = NULL;
  uint8_t *packet = NULL;
  int packet_len = 0;

  int rv = ares_create_query(name, ns_c_in, rrtype, 0, 0, &packet, &packet_len, 0);
  if (ARES_SUCCESS != rv) {
    printf("Failed to perform query for '%s': %s", name, ares_strerror(rv));
    return -1;
  }

  reply_buf = evbuffer_new();
  headers = curl_slist_append(headers, "accept: application/dns-message");
  headers = curl_slist_append(headers, "content-type: application/dns-message");

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, packet);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, packet_len);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, query_write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, reply_buf);

  printf("Querying %s %s...", rrtype_label, name);
  CURLcode res = curl_easy_perform(curl);
  if (CURLE_OK == res) {
    printf("\n");

    size_t b_len = evbuffer_get_length(reply_buf);
    uint8_t *b = evbuffer_pullup(reply_buf, -1);
    if (ns_t_a == rrtype) {
      struct hostent *hosts = NULL;
      if (ARES_SUCCESS == (rv = ares_parse_a_reply(b, b_len, &hosts, NULL, NULL))) {
        char ip[INET_ADDRSTRLEN];
        int addr_index = 0;
        while (NULL != hosts->h_addr_list[addr_index]) {
          inet_ntop(hosts->h_addrtype, hosts->h_addr_list[addr_index], ip, INET_ADDRSTRLEN);
          printf("\t%s\n", ip);
          addr_index++;
        }
        ares_free_hostent(hosts);
      } else {
        printf("\tError in A record: %s\n", ares_strerror(rv));
      }
    } else if (ns_t_aaaa == rrtype) {
      struct hostent *hosts = NULL;
      if (ARES_SUCCESS == (rv = ares_parse_aaaa_reply(b, b_len, &hosts, NULL, NULL))) {
        char ip[INET6_ADDRSTRLEN];
        int addr_index = 0;
        while (NULL != hosts->h_addr_list[addr_index]) {
          inet_ntop(hosts->h_addrtype, hosts->h_addr_list[addr_index], ip, INET6_ADDRSTRLEN);
          printf("\t%s\n", ip);
          addr_index++;
        }
        ares_free_hostent(hosts);
      } else {
        printf("\tError in AAAA record: %s\n", ares_strerror(rv));
      }
    } else if (ns_t_ns == rrtype) {
      struct hostent *hosts = NULL;
      if (ARES_SUCCESS == (rv = ares_parse_ns_reply(b, b_len, &hosts))) {
        int addr_index = 0;
        while (NULL != hosts->h_aliases[addr_index]) {
          printf("\t%s\n", hosts->h_aliases[addr_index]);
          addr_index++;
        }
        ares_free_hostent(hosts);
      } else {
        printf("\tError in NS record: %s\n", ares_strerror(rv));
      }
    } else if (ns_t_mx == rrtype) {
      struct ares_mx_reply* mx_out = NULL;
      if (ARES_SUCCESS == (rv = ares_parse_mx_reply(b, b_len, &mx_out))) {
        for (struct ares_mx_reply *mx = mx_out ; NULL != mx ; mx = mx->next) {
          printf("\t%d\t%s\n", mx->priority, mx->host);
        }
        ares_free_data(mx_out);
      } else {
        printf("\tError in MX record: %s\n", ares_strerror(rv));
      }
    } else if (ns_t_soa == rrtype) {
      struct ares_soa_reply* soa_out = NULL;
      if (ARES_SUCCESS == (rv = ares_parse_soa_reply(b, b_len, &soa_out))) {
        printf("\t%s %s %u %u %u %u %u\n", soa_out->nsname, soa_out->hostmaster, soa_out->serial, soa_out->refresh, soa_out->retry, soa_out->expire, soa_out->minttl);
        ares_free_data(soa_out);
      } else {
        printf("\tError in SOA record: %s\n", ares_strerror(rv));
      }
    } else if (ns_t_txt == rrtype) {
      struct ares_txt_ext *txt_out = NULL;
      if (ARES_SUCCESS == (rv = ares_parse_txt_reply_ext(b, b_len, &txt_out))) {
        for (struct ares_txt_ext *txt = txt_out ; NULL != txt ; txt = txt->next) {
          if (txt != txt_out && txt->record_start) {
            printf("\n");
          }
          printf("\t%.*s", (int)txt->length, txt->txt);
        }
        printf("\n");
        ares_free_data(txt_out);
      } else {
        printf("\tError in TXT record: %s\n", ares_strerror(rv));
      }
    }
  } else {
    printf("failed: %s\n", curl_easy_strerror(res));
  }

  if (NULL != headers) {
    curl_slist_free_all(headers);
  }
  if (NULL != reply_buf) {
    evbuffer_free(reply_buf);
  }
  free(packet);
  return 0;
}

static size_t query_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
  struct evbuffer *reply_buf = (struct evbuffer *)userdata;
  return (0 == evbuffer_add(reply_buf, ptr, size*nmemb)) ? size*nmemb : 0;
}
