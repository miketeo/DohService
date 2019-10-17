GIT_COMMIT=$(shell git rev-parse --short=7 HEAD)
BUILD_DATE:=$(shell date --iso=seconds)

SOURCES=$(wildcard *.c)
OBJECTS=$(addprefix .objs/,$(SOURCES:%.c=%.o))
EXT_LIBS=$(addprefix $(CURDIR)/../deps/lib/,libunbound.a libevent.a libevent_pthreads.a libevent_extra.a libcurl.a libcares.a libnghttp2.a libssl.a libcrypto.a)
CFLAGS=-g -pedantic -fexceptions -Wall -DGW_GIT_COMMIT=\"$(GIT_COMMIT)\" -DGW_BUILD_DATE=\"$(BUILD_DATE)\" -D_GNU_SOURCE -D_POSIX_C_SOURCE -D_REENTRANT -D_THREAD_SAFE -I$(CURDIR)/../deps/include -I$(CURDIR)/../deps/include/libnl3
LDFLAGS=-g

all: $(OBJECTS)
	$(MAKE) DohTest

clean:
	@rm -fr .objs docs DohTest

doc:
	@doxygen

DohTest: $(OBJECTS) $(MODULES)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(EXT_LIBS) -L$(CURDIR)/../deps/lib -ldl -lpthread -lm -lz -lrt -lc

.PHONY: $(MODULES)
$(MODULES):
	$(MAKE) -C $@ all GIT_COMMIT=\"$(GIT_COMMIT)\" BUILD_DATE=\"$(BUILD_DATE)\"

-include $(OBJECTS:.o=.P)

.objs/%.o : %.c
	@mkdir -p .objs
	$(CC) -std=c99 $(CFLAGS) $(CPPFLAGS) -c $< -o $@
	@$(CC) -std=c99 $(CFLAGS) $(CPPFLAGS) -c $< -MM -MF .objs/$*.d
	@sed -e '1s/^/.objs\//' < .objs/$*.d > .objs/$*.P
