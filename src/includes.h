#ifndef INCLUDES_H
#define INCLUDES_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <arpa/nameser.h>

#include <jemalloc/jemalloc.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <zlog.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent_ssl.h>
#include <event2/listener.h>
#include <event2/http.h>
#include <nghttp2/nghttp2.h>
#include <unbound.h>
#include <unbound-event.h>

#include "yuarel.h"
#include "defines.h"

#endif // INCLUDES_H
