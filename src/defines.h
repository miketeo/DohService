/*
 * Copyright (c) 2019 Michael Teo <miketeo@mikteo.net>
 *
 * DohService is provided 'as-is', without any express or implied warranty. In no event will the author be held liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 */
 
#ifndef DEFINES_H
#define DEFINES_H

#define APP_NAME "DohService"
#define APP_VERSION "1.0.0"
#define APP_LOG_CONFIG_FILENAME "log.conf"

#define RRTYPE_MAX_LEN 20
#define INVALID_REQUEST_ID 0

/**
 * Application context
 */
struct app {
  SSL_CTX *ssl_ctx;
  struct event_base *ev_base;
  struct evconnlistener *https_listener;
  struct ub_ctx *ub_ctx;

  zlog_category_t *main_log_cat;
  zlog_category_t *https_log_cat;
  zlog_category_t *resolver_log_cat;
};
typedef struct app app_t;

/**
 * Represents the state of a DNS request/response transaction
 */
struct resolver_request {
  app_t *app;
  uint8_t *request_buf;   //!< malloc-buffer containing the DNS query
  size_t request_buf_len; //!< number of bytes in request_buf
  bool use_dnssec;        //!< true if client supports DNSSEC
  char client_addr[NI_MAXHOST];  //!< Should contain the IP address of the client making the DNS request

  // Following reply_xxx fields will be filled in when unbound has resolved the query
  uint8_t *reply_buf;     //!< malloc-buffer containing the DNS reply
  size_t reply_buf_len;   //!< number of bytes in reply_buf
  size_t reply_buf_offset;//!< read offset in reply_buf

  // Following request_xxx fields will be filled after resolver_resolve()
  int request_id;                     //!< The async_id return value from unbound that can be used to cancel an ongoing unbound request
  char request_type[RRTYPE_MAX_LEN];  //!< String reflecting the type of request: "A", "AAAA", "NS", "SOA", etc
  char request_name[NS_MAXDNAME];     //!< Hostname being queried
};
typedef struct resolver_request resolver_request_t;

/**
 * Start listening on HTTPS port.
 *
 * Implemented in https.c
 */
int https_init(app_t *app, int port, const char *key_file, const char *cert_file);

/**
 * Stop listening on HTTPS port
 */
int https_cleanup(app_t *app);

/**
 * Send the DNS resolution response back to the client
 */
int https_send_reply(app_t *app, resolver_request_t *request);

/**
 * Initialize the unbound context in app
 *
 * Implemented in resolver.c
 * @param dns_csv comma-separated list of IP addresses defining the list of upstream DNS servers to use for DNS resolution
 */
int resolver_init(app_t *app, const char *dns_csv);

/**
 * Cleanup the unbound context that has been initialized in resolver_init()
 *
 * Implemented in resolver.c
 */
int resolver_cleanup(app_t *app);

/**
 * Perform dns resolution on the raw DNS packet
 *
 * Implemented in resolver.c
 */
int resolver_resolve(app_t *app, resolver_request_t *request);

/**
 * Cancel the outgoing dns resolution in request (if any)
 *
 * Implemented in resolver.c
 */
void resolver_cancel(app_t *app, resolver_request_t *request);

/**
 * Decode data with input_length and returns a pointer to the buffer containing the decoded data
 * The caller must free the returned pointer after use.
 *
 * Implemented in base64.c
 */
uint8_t* base64_decode(const uint8_t *data, size_t input_length, size_t *output_length);

#endif // DEFINES_H
