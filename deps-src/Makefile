all: ../deps/lib/libjemalloc.a ../deps/lib/libssl.a ../deps/lib/libzlog.a ../deps/lib/libcares.a ../deps/lib/libevent.a ../deps/lib/libunbound.a ../deps/lib/libnghttp2.a ../deps/lib/libcurl.a

clean:

distclean:
	- rm -fr ../deps/*

../deps/lib/libjemalloc.a:
	wget -q -O - https://github.com/jemalloc/jemalloc/releases/download/5.2.1/jemalloc-5.2.1.tar.bz2 | tar -xvj
	cd jemalloc-5.2.1 && ./configure --prefix=$(CURDIR)/../deps --disable-cxx && make all install
	@rm -fr jemalloc-5.2.1

../deps/lib/libssl.a:
	wget -q -O - https://www.openssl.org/source/openssl-1.1.1t.tar.gz | tar -xvz
	cd openssl-1.1.1t && ./config --prefix=$(CURDIR)/../deps --openssldir=$(CURDIR)/../deps && make all install
	@rm -fr openssl-1.1.1t

../deps/lib/libzlog.a:
	wget -q -O - https://github.com/HardySimpson/zlog/archive/1.2.15.tar.gz | tar -xvz
	cd zlog-1.2.15 && make PREFIX=$(CURDIR)/../deps all install
	@rm -fr zlog-1.2.15

../deps/lib/libcares.a:
	wget -q -O - https://github.com/c-ares/c-ares/releases/download/cares-1_17_1/c-ares-1.17.1.tar.gz | tar -xvz
	cd c-ares-1.17.1 && ./configure --prefix=$(CURDIR)/../deps --disable-nonblocking && make all install
	@rm -fr c-ares-1.17.1

../deps/lib/libevent.a:
	wget -q -O - https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz | tar -xvz
	cd libevent-2.1.12-stable && ./configure --prefix=$(CURDIR)/../deps CPPFLAGS="-I$(CURDIR)/../deps/include" LDFLAGS="-L$(CURDIR)/../deps/lib" && make all install
	@rm -fr libevent-2.1.12-stable

../deps/lib/libunbound.a:
	wget -q -O - https://www.nlnetlabs.nl/downloads/unbound/unbound-1.17.1.tar.gz | tar -xvz
	cd unbound-1.17.1 && ./configure --prefix=$(CURDIR)/../deps --disable-flto --enable-pthreads --enable-event-api --with-libevent=$(CURDIR)/../deps --with-ssl=$(CURDIR)/../deps --with-libunbound-only && make all install
	@rm -fr unbound-1.17.1

../deps/lib/libnghttp2.a:
	wget -q -O - https://github.com/nghttp2/nghttp2/releases/download/v1.43.0/nghttp2-1.43.0.tar.bz2 | tar -xvj
	cd nghttp2-1.43.0 && ./configure --prefix=$(CURDIR)/../deps --enable-lib-only && make all install
	@rm -fr nghttp2-1.43.0

../deps/lib/libcurl.a:
	wget -q -O - https://curl.haxx.se/download/curl-7.75.0.tar.gz | tar -xvz
	cd curl-7.75.0 && ./configure --prefix=$(CURDIR)/../deps --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt --with-nghttp2=$(CURDIR)/../deps --with-ssl=$(CURDIR)/../deps && make all install
	@rm -fr curl-7.75.0
