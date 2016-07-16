RC = cargo
RFLAGS = build --release
RCLEAN = clean
PREFIX = /usr
UNAME := $(shell uname)

all: encryptsave

encryptsave:
	test -e include || mkdir include
	cd tox$@; $(RC) $(RFLAGS)
	cp tox$@/include/tox$@.h include/tox$@.h

ifeq ($(UNAME), Linux)
	cp tox$@/target/release/libtox$@.so libtox$@.so
	strip libtox$@.so
endif
ifeq ($(UNAME), Darwin)
	cp tox$@/target/release/libtox$@.dylib libtox$@.dylib
endif

install: encryptsave
	install -m644 include/toxencryptsave.h $(PREFIX)/include/toxencryptsave.h
	install -D -m755 libtoxencryptsave.so $(PREFIX)/lib/libtoxencryptsave.so

uninstall:
	rm $(PREFIX)/include/toxencryptsave.h
	rm $(PREFIX)/lib/libtoxencryptsave.so

clean:
	rm include -r
	rm *.so
	cd toxencryptsave; $(RC) $(RCLEAN)
