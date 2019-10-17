This file contains the error code classes that have been defined for the application.

+ DS-1xxxx : main.c
  - DS-199xx: main

+ DS-2xxxx : https.c
  - DS-200xx: setup_socket
  - DS-201xx: setup_ssl
  - DS-202xx: evconnlistener_accept_cb
  - DS-203xx: bufev_event_cb
  - DS-204xx: bufev_read_cb
  - DS-205xx: h2session_data_recv_cb
  - DS-206xx: h2session_header_cb
  - DS-210xx: process_request
  - DS-220xx: https_send_reply
  - DS-221xx: send_404

+ DS-3xxxx : resolver.c
  - DS-301xx: resolver_init
  - DS-302xx: resolver_resolve
  - DS-303xx: resolve_callback
  - DS-304xx: strip_rrsig_from_reply
