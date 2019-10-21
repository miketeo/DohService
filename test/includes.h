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
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <ares.h>
#include <curl/curl.h>
#include <event2/buffer.h>

#include "defines.h"

#endif // INCLUDES_H
