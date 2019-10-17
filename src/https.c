#include "includes.h"

// A significant portion of the code in this file was adapted from
// https://github.com/nghttp2/nghttp2/blob/master/examples/libevent-server.c
// Its copyright notice is as follows:
/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)
#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

typedef enum http2_method { HTTP_UNKNOWN, HTTP_GET, HTTP_POST } http2_method_t;

typedef struct http2_stream_data {
  resolver_request_t request;

  nghttp2_session *session;
  struct http2_stream_data *prev, *next;
  struct evbuffer *body;
  char *path;
  http2_method_t method;
  int32_t stream_id;
} http2_stream_data_t;

typedef struct http2_session_data {
  app_t *app;
  nghttp2_session *session;
  char client_addr[NI_MAXHOST];

  struct bufferevent *bev;
  struct http2_stream_data root;
} http2_session_data_t;

static int setup_ssl(app_t *app, const char *key_file, const char *cert_file);
static int setup_socket(app_t *app, int port);

// libevent callbacks for transferring data between socket+evbuffer and nghttp2
static void evconnlistener_accept_cb(struct evconnlistener *listener, int fd, struct sockaddr *addr, int addrlen, void *arg);
static void bufev_read_cb(struct bufferevent *bev, void *ptr);
static void bufev_write_cb(struct bufferevent *bev, void *ptr);
static void bufev_event_cb(struct bufferevent *bev, short events, void *ptr);

// nghttp2 engine callbacks and supporting calls for http2
static ssize_t h2session_send_cb(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data);
static int h2session_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);
static int h2session_data_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t data_len, void *user_data);
static int h2session_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data);
static int h2session_begin_headers_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);
static int h2session_header_cb(nghttp2_session *session,
                               const nghttp2_frame *frame, const uint8_t *name,
                               size_t namelen, const uint8_t *value,
                               size_t valuelen, uint8_t flags, void *user_data);
static int next_proto_cb(SSL *ssl, const unsigned char **data, unsigned int *len, void *arg);
static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg);
static ssize_t reply_read_callback(nghttp2_session *session, int32_t stream_id,
                                   uint8_t *buf, size_t length,
                                   uint32_t *data_flags,
                                   nghttp2_data_source *source,
                                   void *user_data);
static void delete_http2_session_data(http2_session_data_t *session_data);
static void delete_http2_stream_data(http2_stream_data_t *stream_data);
static int send_404(nghttp2_session *session, http2_stream_data_t *stream_data);
static int process_request(nghttp2_session *session,
                           http2_session_data_t *session_data,
                           http2_stream_data_t *stream_data);

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;


int https_init(app_t *app, int port, const char *key_file, const char *cert_file) {
  int ret = 0;

  if (0 != (ret = setup_ssl(app, key_file, cert_file))) {
    return ret;
  }
  if (0 != (ret = setup_socket(app, port))) {
    return ret;
  }
  return ret;
}

int https_cleanup(app_t *app) {
  if (NULL != app->https_listener) {
    evconnlistener_free(app->https_listener);
    app->https_listener = NULL;
  }
  if (NULL != app->ssl_ctx) {
    SSL_CTX_free(app->ssl_ctx);
  }

  return 0;
}

int https_send_reply(app_t *app, resolver_request_t *request) {
  http2_stream_data_t *stream_data = (http2_stream_data_t *)request;

  nghttp2_nv hdrs[] = {
    MAKE_NV(":status", "200"),
    MAKE_NV("content-type", "application/dns-message"),
    MAKE_NV("cache-control", "max-age=60,private")
  };

  nghttp2_data_provider data_prd;
  memset(&data_prd, 0, sizeof(nghttp2_data_provider));
  data_prd.read_callback = reply_read_callback;

  int rv = nghttp2_submit_response(stream_data->session, stream_data->stream_id, hdrs, ARRLEN(hdrs), &data_prd);
  if (0 != rv) {
    zlog_warn(app->https_log_cat, "(DS-22001) (%s) Failed to send back DNS reply: %s", stream_data->request.client_addr, nghttp2_strerror(rv));
    return 22001;
  }
  zlog_debug(app->https_log_cat, "(%s) DNS reply for %s %s sent", stream_data->request.client_addr, stream_data->request.request_type, stream_data->request.request_name);

  if (0 != (rv = nghttp2_session_send(stream_data->session))) {
    zlog_warn(app->https_log_cat, "(DS-22002) (%s) Failed to send back DNS reply: %s", stream_data->request.client_addr, nghttp2_strerror(rv));
    return 22002;
  }
  return 0;
}

static int setup_socket(app_t *app, int port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  app->https_listener = evconnlistener_new_bind(
        app->ev_base, evconnlistener_accept_cb, app,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, /* flags */
        -1 /* backlog (ask libevent to choose value) */,
        (const struct sockaddr *)&addr,
        sizeof(addr));
  if (NULL == app->https_listener) {
    zlog_fatal(app->https_log_cat, "Failed to initialize application: unable to listen to port %d", port);
    return 20001;
  }

  zlog_notice(app->https_log_cat, "Now listening on port %d for incoming DNS queries over HTTPS", port);
  return 0;
}

static int setup_ssl(app_t *app, const char *key_file, const char *cert_file) {
  int ret = 0;
  EC_KEY *ecdh = NULL;

  app->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if (NULL == app->ssl_ctx) {
    zlog_error(app->https_log_cat, "(DS-20101) Failed to initialize application: unable to create SSL/TLS context: %s", ERR_error_string(ERR_get_error(), NULL));
    ret = 20101;
    goto end;
  }
  SSL_CTX_set_options(app->ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                          SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (NULL == ecdh) {
    zlog_error(app->https_log_cat, "(DS-20102) Failed to initialize application: unable to get EC: %s", ERR_error_string(ERR_get_error(), NULL));
    ret = 20102;
    goto end;
  }
  SSL_CTX_set_tmp_ecdh(app->ssl_ctx, ecdh);

  if (SSL_CTX_use_PrivateKey_file(app->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
    zlog_error(app->https_log_cat, "(DS-20103) Failed to initialize application: unable to read private key '%s'", key_file);
    ret = 20103;
    goto end;
  } else {
    zlog_notice(app->https_log_cat, "Initializing SSL context using private key file at %s", key_file);
  }
  if (SSL_CTX_use_certificate_chain_file(app->ssl_ctx, cert_file) != 1) {
    zlog_error(app->https_log_cat, "(DS-20104) Failed to initialize application: unable to read cert file '%s'", cert_file);
    ret = 20104;
    goto end;
  } else {
    zlog_notice(app->https_log_cat, "Initializing SSL context using certificate chain file at %s", cert_file);
  }

  next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
  memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID, NGHTTP2_PROTO_VERSION_ID_LEN);
  next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

  SSL_CTX_set_next_protos_advertised_cb(app->ssl_ctx, next_proto_cb, NULL);
  SSL_CTX_set_alpn_select_cb(app->ssl_ctx, alpn_select_proto_cb, NULL);

  end:
  if (NULL != ecdh) {
    EC_KEY_free(ecdh);
  }
  return ret;
}

static int next_proto_cb(SSL *ssl, const unsigned char **data, unsigned int *len, void *arg) {
  *data = next_proto_list;
  *len = (unsigned int)next_proto_list_len;
  return SSL_TLSEXT_ERR_OK;
}

static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg) {
  int rv = nghttp2_select_next_protocol((unsigned char **)out, outlen, in, inlen);
  return (rv != 1) ? SSL_TLSEXT_ERR_NOACK : SSL_TLSEXT_ERR_OK;
}

static void evconnlistener_accept_cb(struct evconnlistener *listener, int fd, struct sockaddr *addr, int addrlen, void *arg) {
  app_t *app = (app_t *)arg;
  assert(NULL != app);

  int ret = 0;
  http2_session_data_t *session_data = NULL;
  SSL *ssl = NULL;

  ssl = SSL_new(app->ssl_ctx);
  if (NULL == ssl) {
    zlog_error(app->https_log_cat, "(DS-20201) Failed to accept new HTTPS connection: unable to create SSL session");
    ret = 20201;
    goto end;
  }

  session_data = calloc(1, sizeof(http2_session_data_t));
  if (NULL == session_data) {
    zlog_error(app->https_log_cat, "(DS-20202) Failed to accept new HTTPS connection: unable to allocate memory");
    ret = 20202;
    goto end;
  }
  session_data->app = app;

  int val = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));

  session_data->bev = bufferevent_openssl_socket_new(
      app->ev_base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
      BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
  bufferevent_setcb(session_data->bev, bufev_read_cb, bufev_write_cb, bufev_event_cb, session_data);

  int rv = getnameinfo(addr, (socklen_t)addrlen, session_data->client_addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
  if (0 != rv) {
    strcpy(session_data->client_addr, "unknown");
  }

  zlog_debug(app->https_log_cat, "(%s) Incoming client connection", session_data->client_addr);

  end:
  if (0 != ret) {
    if (NULL != ssl) {
      SSL_shutdown(ssl);
    }
    if (NULL != session_data) {
      free(session_data);
    }
  }
}

static void bufev_read_cb(struct bufferevent *bev, void *ptr) {
  http2_session_data_t *session_data = (http2_session_data_t *)ptr;

  // Read the data in the bufferevent and feed them into nghttp2 library
  // function. Invocation of nghttp2_session_mem_recv() may make
  // additional pending frames, so call nghttp2_session_send() at the end of the
  // function.
  int ret = 0;
  struct evbuffer *input = bufferevent_get_input(session_data->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  ssize_t readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  if (readlen < 0) {
    zlog_warn(session_data->app->https_log_cat, "(DS-20401) (%s) Read failed: %s", session_data->client_addr, nghttp2_strerror((int)readlen));
    ret = 20401;
    goto end;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    zlog_warn(session_data->app->https_log_cat, "(DS-20402) (%s) Read failed", session_data->client_addr);
    ret = 20402;
    goto end;
  }

  int rv = nghttp2_session_send(session_data->session);
  if (0 != rv) {
    zlog_warn(session_data->app->https_log_cat, "(DS-20403) (%s) Read failed: %s", session_data->client_addr, nghttp2_strerror(rv));
    ret = 20403;
    goto end;
  }

  end:
  if (0 != ret) {
    delete_http2_session_data(session_data);
  }
}

static void bufev_write_cb(struct bufferevent *bev, void *ptr) {
  http2_session_data_t *session_data = (http2_session_data_t *)ptr;
  if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    return;
  }
  if (nghttp2_session_want_read(session_data->session) == 0 && nghttp2_session_want_write(session_data->session) == 0) {
    delete_http2_session_data(session_data);
    return;
  }
  if (0 != nghttp2_session_send(session_data->session)) {
    delete_http2_session_data(session_data);
    return;
  }
}

static void bufev_event_cb(struct bufferevent *bev, short events, void *ptr) {
  http2_session_data_t *session_data = (http2_session_data_t *)ptr;
  app_t *app = session_data->app;

  if (events & BEV_EVENT_CONNECTED) {
    int ret = 0;
    unsigned int alpnlen = 0;
    const unsigned char *alpn = NULL;
    nghttp2_session_callbacks *callbacks = NULL;
    SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);

    SSL_get0_next_proto_negotiated(ssl, &alpn, &alpnlen);
    if (NULL == alpn) {
      SSL_get0_alpn_selected(ssl, &alpn, &alpnlen);
    }

    if (NULL == alpn || 2 != alpnlen || memcmp("h2", alpn, 2) != 0) {
      zlog_warn(app->https_log_cat, "(DS-20301) (%s) Client does not accept h2 protocol", session_data->client_addr);
      ret = 20301;
      goto end;
    }

    if (0 != nghttp2_session_callbacks_new(&callbacks)) {
      zlog_warn(app->https_log_cat, "(DS-20302) (%s) Failed to setup connection: unable to allocate memory", session_data->client_addr);
      ret = 20302;
      goto end;
    }
    nghttp2_session_callbacks_set_send_callback(callbacks, h2session_send_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2session_frame_recv_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2session_data_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2session_stream_close_cb);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2session_header_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2session_begin_headers_cb);

    if (0 != nghttp2_session_server_new(&session_data->session, callbacks, session_data)) {
      zlog_warn(app->https_log_cat, "(DS-20303) (%s) Failed to setup connection: unable to allocate memory", session_data->client_addr);
      ret = 20303;
      goto end;
    }

    // Send HTTP/2 client connection header, which includes 24 bytes magic octets and SETTINGS frame
    nghttp2_settings_entry iv[1] = { { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 } };
    int rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
    if (0 != rv) {
      zlog_warn(app->https_log_cat, "(DS-20304) (%s) Failed to setup connection: %s", session_data->client_addr, nghttp2_strerror(rv));
      ret = 20304;
      goto end;
    }

    rv = nghttp2_session_send(session_data->session);
    if (0 != rv) {
      zlog_warn(app->https_log_cat, "(DS-20305) (%s) Failed to setup connection: %s", session_data->client_addr, nghttp2_strerror(rv));
      ret = 20305;
      goto end;
    }

    zlog_debug(app->https_log_cat, "(%s) Client connection upgraded to http2", session_data->client_addr);

    end:
    if (NULL != callbacks) {
      nghttp2_session_callbacks_del(callbacks);
    }
    if (0 != ret) {
      delete_http2_session_data(session_data);
    }
    return;
  }
  if (events & BEV_EVENT_EOF) {
    // fprintf(stderr, "%s EOF\n", session_data->client_addr);
  } else if (events & BEV_EVENT_ERROR) {
    zlog_warn(app->https_log_cat, "(%s) Network error", session_data->client_addr);
  } else if (events & BEV_EVENT_TIMEOUT) {
    zlog_warn(app->https_log_cat, "(%s) Timeout", session_data->client_addr);
  }
  delete_http2_session_data(session_data);
}

static void delete_http2_session_data(http2_session_data_t *session_data) {
  SSL *ssl = bufferevent_openssl_get_ssl(session_data->bev);
  if (ssl) {
    SSL_shutdown(ssl);
  }
  bufferevent_free(session_data->bev);
  nghttp2_session_del(session_data->session);

  for (http2_stream_data_t *stream_data = session_data->root.next; stream_data;) {
    http2_stream_data_t *next = stream_data->next;
    delete_http2_stream_data(stream_data);
    stream_data = next;
  }
  free(session_data);
}

static void delete_http2_stream_data(http2_stream_data_t *stream_data) {
  resolver_cancel(stream_data->request.app, &(stream_data->request));
  if (NULL != stream_data->body) {
    evbuffer_free(stream_data->body);
  }
  free(stream_data->request.request_buf);
  free(stream_data->request.reply_buf);
  free(stream_data->path);
  free(stream_data);
}

static ssize_t h2session_send_cb(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
  http2_session_data_t *session_data = (http2_session_data_t *)user_data;
  struct bufferevent *bev = session_data->bev;

  // Avoid excessive buffering in server side.
  if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >= OUTPUT_WOULDBLOCK_THRESHOLD) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }
  bufferevent_write(bev, data, length);
  return (ssize_t)length;
}

static int h2session_data_recv_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t data_len, void *user_data) {
  http2_session_data_t *session_data = (http2_session_data_t *)user_data;
  zlog_debug(session_data->app->https_log_cat, "(%s) Received %lu bytes of DATA", session_data->client_addr, data_len);

  http2_stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (NULL != stream_data) {
    if (HTTP_POST == stream_data->method) {
      if (NULL == stream_data->body) {
        stream_data->body = evbuffer_new();
        if (NULL == stream_data->body) {
          zlog_warn(session_data->app->https_log_cat, "(%s) (DS-20501) Failed to process DATA: unable to allocate memory", session_data->client_addr);
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        evbuffer_add(stream_data->body, data, data_len);
      }
    } else {
      zlog_warn(session_data->app->https_log_cat, "(%s) (DS-20502) Received DATA when http method is not POST", session_data->client_addr);
    }
  }

  return 0;
}

static int h2session_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
  http2_session_data_t *session_data = (http2_session_data_t *)user_data;
  http2_stream_data_t *stream_data = NULL;

  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    // Check that the client request has finished
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      // For DATA and HEADERS frame, this callback may be called after
      // h2session_stream_close_cb. Check that stream still alive.
      if (NULL == stream_data) {
        return 0;
      } else {
        if (0 != process_request(session, session_data, stream_data)) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
    }
    break;
  default:
    break;
  }
  return 0;
}

static int h2session_stream_close_cb(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
  http2_stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (NULL == stream_data) {
    return 0;
  }

  // Remove stream
  stream_data->prev->next = stream_data->next;
  if (NULL != stream_data->next) {
    stream_data->next->prev = stream_data->prev;
  }

  delete_http2_stream_data(stream_data);
  return 0;
}

static int h2session_begin_headers_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
  http2_session_data_t *session_data = (http2_session_data_t *)user_data;

  if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  // Create a new stream and add it to the session_data's stream linked list
  http2_stream_data_t *stream_data = calloc(1, sizeof(http2_stream_data_t));
  stream_data->session = session;
  stream_data->stream_id = frame->hd.stream_id;
  stream_data->next = session_data->root.next;
  session_data->root.next = stream_data;
  stream_data->prev = &session_data->root;
  if (stream_data->next) {
    stream_data->next->prev = stream_data;
  }
  stream_data->method = HTTP_UNKNOWN;
  stream_data->request.app = session_data->app;
  stream_data->request.request_id = INVALID_REQUEST_ID;
  strcpy(stream_data->request.client_addr, session_data->client_addr);

  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream_data);
  return 0;
}

static int h2session_header_cb(nghttp2_session *session,
                               const nghttp2_frame *frame, const uint8_t *name,
                               size_t namelen, const uint8_t *value,
                               size_t valuelen, uint8_t flags, void *user_data) {
  http2_session_data_t *session_data = (http2_session_data_t *)user_data;
  http2_stream_data_t *stream_data = NULL;
  const char PATH[] = ":path", METHOD[] = ":method";

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }
    zlog_debug(session_data->app->https_log_cat, "(%s) Received header: %s=%s", session_data->client_addr, name, value);

    stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (NULL == stream_data || NULL != stream_data->path) {
      break;
    }
    if (0 == strcmp(METHOD, (char *)name)) {  /* according to nghttp2, name is NULL-terminated */
      if (0 == strcmp((char *)value, "POST")) {
        stream_data->method = HTTP_POST;
      } else if (0 == strcmp((char *)value, "GET")) {
        stream_data->method = HTTP_GET;
      } else {
        zlog_warn(session_data->app->https_log_cat, "(%s) (DS-20601) Unhandled :method header: %s", session_data->client_addr, value);
      }
    } else if (0 == strcmp(PATH, (char *)name)) {
      stream_data->path = strdup((char *)value); /* according to nghttp2, value is NULL-terminated */
    }
    break;
  }
  return 0;
}

static int process_request(nghttp2_session *session,
                           http2_session_data_t *session_data,
                           http2_stream_data_t *stream_data) {
  app_t *app = session_data->app;

  int ret = 0;
  const char *URI_PATH = "/dns-query";

  if (INVALID_REQUEST_ID != stream_data->request.request_id) { // should never happen
    zlog_error(app->https_log_cat, "(%s) (DS-21001) Failed to perform DNS query: another request is in progress", session_data->client_addr);
    ret = 21001;
    goto end;
  }

  if (NULL == stream_data->path) {
    zlog_warn(app->https_log_cat, "(%s) (DS-21002) Client did not send :path header", session_data->client_addr);
    ret = 21002;
    goto end;
  }

  if (HTTP_UNKNOWN == stream_data->method) {
    zlog_warn(app->https_log_cat, "(%s) (DS-21002) Failed to perform DNS query: client did not use HTTP GET or POST method", session_data->client_addr);
    ret = 21002;
    goto end;
  } else if (HTTP_POST == stream_data->method) {
    if (0 != strcmp(URI_PATH, stream_data->path)) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21010) Failed to perform DNS query: client did not use /dns-query for :path header", session_data->client_addr);
      ret = 21010;
      goto end;
    }

    stream_data->request.request_buf_len = evbuffer_get_length(stream_data->body);
    stream_data->request.request_buf = malloc(stream_data->request.request_buf_len);
    if (NULL == stream_data->request.request_buf) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21011) Failed to perform DNS query: unable to allocate memory", session_data->client_addr);
      ret = 21011;
      goto end;
    }
    if (stream_data->request.request_buf_len != evbuffer_copyout(stream_data->body, stream_data->request.request_buf, stream_data->request.request_buf_len)) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21012) Failed to perform DNS query: unable to copy data between memory buffers", session_data->client_addr);
      ret = 21012;
      goto end;
    }

    resolver_resolve(app, &(stream_data->request));
  } else { // if HTTP_GET == stream_data->method
    char path[4010];
    if (strlen(stream_data->path) >= 4000) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21020) Failed to perform DNS query: path is suspiciously too long (%lu chars)", session_data->client_addr, strlen(stream_data->path));
      ret = 21020;
      goto end;
    }
    strcpy(path, "http://a"); // yuarel parsing requires the scheme and host to be present
    strncat(path, stream_data->path, 4000);

    struct yuarel url;
    memset(&url, 0, sizeof(struct yuarel));
    if (0 != yuarel_parse(&url, path)) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21021) Failed to perform DNS query: unable to parse path", session_data->client_addr);
      ret = 21021;
      goto end;
    }

    if (NULL == url.query) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21022) Failed to perform DNS query: missing query for GET request", session_data->client_addr);
      ret = 21022;
      goto end;
    }

    struct yuarel_param params[10];
    int params_count = yuarel_parse_query(url.query, '&', params, 10);
    if (params_count < 0) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21023) Failed to perform DNS query: unable to parse query", session_data->client_addr);
      ret = 21023;
      goto end;
    }

    bool has_dns_param = false;
    for (int param_index=0; param_index<params_count; param_index++) {
      if (0 == strcmp(params[param_index].key, "dns")) {
        has_dns_param = true;

        stream_data->request.request_buf = base64_decode((uint8_t *)params[param_index].val, strlen(params[param_index].val), &(stream_data->request.request_buf_len));
        if (NULL == stream_data->request.request_buf) {
          zlog_warn(app->https_log_cat, "(%s) (DS-21024) Failed to perform DNS query: unable to decode dns query", session_data->client_addr);
          ret = 21024;
          goto end;
        }

        resolver_resolve(app, &(stream_data->request));
      }
    }
    if (!has_dns_param) {
      zlog_warn(app->https_log_cat, "(%s) (DS-21024) Failed to perform DNS query: missing dns param in query", session_data->client_addr);
      ret = 21024;
      goto end;
    }
  }

  end:
  if (0 != ret) {
    send_404(session, stream_data);
  }
  return ret;
}

static int send_404(nghttp2_session *session, http2_stream_data_t *stream_data) {
  app_t *app = stream_data->request.app;
  nghttp2_nv hdrs[] = {
    MAKE_NV(":status", "404"),
  };

  nghttp2_data_provider data_prd;
  memset(&data_prd, 0, sizeof(nghttp2_data_provider));
  data_prd.read_callback = reply_read_callback;

  const char ERROR_HTML[] = "<html><head><title>404</title></head><body><h1>404 Not Found</h1></body></html>";
  stream_data->request.reply_buf = (uint8_t *)strdup(ERROR_HTML);
  if (NULL != stream_data->request.reply_buf) {
    stream_data->request.reply_buf_len = strlen(ERROR_HTML);
  }

  int rv = nghttp2_submit_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), &data_prd);
  if (0 != rv) {
    zlog_warn(app->https_log_cat, "(DS-22101) (%s) Failed to send back 404 response: %s", stream_data->request.client_addr, nghttp2_strerror(rv));
    return 22001;
  }

  if (0 != (rv = nghttp2_session_send(stream_data->session))) {
    zlog_warn(app->https_log_cat, "(DS-22102) (%s) Failed to send back 404 response: %s", stream_data->request.client_addr, nghttp2_strerror(rv));
    return 22002;
  }

  return 0;
}

static ssize_t reply_read_callback(nghttp2_session *session, int32_t stream_id,
                                   uint8_t *buf, size_t length,
                                   uint32_t *data_flags,
                                   nghttp2_data_source *source,
                                   void *user_data) {
  http2_stream_data_t *stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (NULL == stream_data) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  size_t n = stream_data->request.reply_buf_len - stream_data->request.reply_buf_offset;
  if (length >= n) {
    length = n;
  }

  memcpy(buf+stream_data->request.reply_buf_offset, stream_data->request.reply_buf, length);
  n -= length;
  stream_data->request.reply_buf_offset += length;

  if (0 == n) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return length;
}
