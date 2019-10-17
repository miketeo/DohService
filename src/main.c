#include <signal.h>
#include "includes.h"
#include "argtable3.h"

/**
 * \brief SIGINT handler
 * Will signal thelibevent main event loop to break out of the loop
 */
static void sigint_eventcb(evutil_socket_t fd, short event, void *arg){
  app_t *app = (app_t*)arg;
  zlog_warn(app->main_log_cat, "Received SIGINT. Will exit application now...");
  event_base_loopbreak(app->ev_base);
}

/**
 * \brief SIGTERM handler
 * Will signal thelibevent main event loop to break out of the loop
 */
static void sigterm_eventcb(evutil_socket_t fd, short event, void *arg){
  app_t *app = (app_t*)arg;
  zlog_warn(app->main_log_cat, "Received SIGTERM. Will exit application now...");
  event_base_loopbreak(app->ev_base);
}

int main(int argc, char *argv[]) {
  int ret = EXIT_SUCCESS; // macro defined in stdlib.h

  //
  // Command-line arguments parsing
  //

  struct arg_str *key_file = arg_str0(NULL, NULL, "KEYFILE", "Full path to the SSL key file");
  struct arg_str *cert_file = arg_str0(NULL, NULL, "CERTFILE", "Full path to the SSL cert file");
  struct arg_str *dns_csv = arg_str0(NULL, "dns", "DNS-SERVERS", "Comma-separated list of upstream DNS servers. Default: 8.8.8.8,8.8.4.4");
  struct arg_int *port = arg_int0(NULL, "port", "PORT", "HTTPS port");
  struct arg_lit *help = arg_lit0("-h", "help", "display this help and exit");
  struct arg_lit *version = arg_lit0(NULL, "version", "display version information and exit");
  struct arg_end *end = arg_end(20);
  void* argtable[] = { port, dns_csv, help, version, key_file, cert_file, end };
  if (arg_nullcheck(argtable) != 0) {
    // NULL entries were detected, some allocations must have failed
    printf("(DS-19901) Failed to initialize application.\n");
    return EXIT_FAILURE;
  }

  port->ival[0] = 443;
  dns_csv->sval[0] = "8.8.8.8,8.8.4.4";  // By default, we use google DNS
  int arg_errors = arg_parse(argc, argv, argtable);

  if (help->count > 0) {
    printf("Usage: " APP_NAME);
    arg_print_syntax(stdout, argtable, "\n");
    goto end;
  }

  if (version->count > 0) {
    printf("%s version %s-%s built on %s\n", APP_NAME, APP_VERSION, GW_GIT_COMMIT, GW_BUILD_DATE);
    goto end;
  }

  if (arg_errors > 0) {
    arg_print_errors(stdout, end, APP_NAME);
    printf("Try '" APP_NAME " --help' for more information.\n");
    ret = EXIT_FAILURE;
    goto end;
  }

  // Initialize the zlog context
  if (0 != zlog_init(APP_LOG_CONFIG_FILENAME)) {
    printf("(DS-19904) Failed to initialize application: unable to init log from '%s'.\n", APP_LOG_CONFIG_FILENAME);
    ret = EXIT_FAILURE;
    goto end;
  }

  // Initialize global app variable
  struct event *sigint_ev = NULL, *sigterm_ev = NULL;
  app_t app;
  memset(&app, 0, sizeof(app_t));

  app.main_log_cat = zlog_get_category("ds_main");
  app.https_log_cat = zlog_get_category("ds_https");
  app.resolver_log_cat = zlog_get_category("ds_resolver");
  zlog_notice(app.main_log_cat, "Initializing %s version %s-%s...", APP_NAME, APP_VERSION, GW_GIT_COMMIT);

  app.ev_base = event_base_new();
  if (NULL == app.ev_base) {
    zlog_fatal(app.main_log_cat, "(DS-19909) Failed to initialize service");
    ret = EXIT_FAILURE;
    goto end3;
  }

  sigint_ev = evsignal_new(app.ev_base, SIGINT, sigint_eventcb, &app);
  sigterm_ev = evsignal_new(app.ev_base, SIGTERM, sigterm_eventcb, &app);
  if (NULL != sigint_ev && NULL != sigterm_ev) {
    evsignal_add(sigint_ev, NULL);
    evsignal_add(sigterm_ev, NULL);
    zlog_debug(app.main_log_cat, "Signal handlers registered");
  } else {
    zlog_fatal(app.main_log_cat, "(DS-19911) Failed to initialize application. Please contact vendor for support.");
    ret = EXIT_FAILURE;
    goto end3;
  }

  if (0 == resolver_init(&app, dns_csv->sval[0]) && 0 == https_init(&app, port->ival[0], key_file->sval[0], cert_file->sval[0])) {
    //
    // Loop forever until we terminate
    //
    zlog_notice(app.main_log_cat, "Entering event loop. Send SIGINT or SIGTERM if you want to exit this application.");
    event_base_dispatch(app.ev_base);  // This will not return until the registered above signal handlers break the event loop
  }

  https_cleanup(&app);
  resolver_cleanup(&app);

  end3:
  // Cleanup libevent stuff
  if (NULL != sigterm_ev) {
    evsignal_del(sigterm_ev);
    event_free(sigterm_ev);
  }
  if (NULL != sigint_ev) {
    evsignal_del(sigint_ev);
    event_free(sigint_ev);
  }

  // Free whatever we have initialized on the global app variable
  if (NULL != app.ev_base) {
    event_base_free(app.ev_base);
  }

  // Bye-bye
  end2:
  zlog_notice(app.main_log_cat, "Service will now quit. This is the last log message.");
  zlog_fini();

end:
  arg_freetable(argtable,sizeof(argtable)/sizeof(argtable[0]));

  return ret;
}
