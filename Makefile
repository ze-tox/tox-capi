RC = cargo
RFLAGS = build --release
RCLEAN = clean
PREFIX = /usr

all: encryptsave

encryptsave:
	test -e include || mkdir include
	cd tox$@; $(RC) $(RFLAGS)
	cp tox$@/include/tox$@.h include/tox$@.h
	cp tox$@/target/release/libtox$@.so libtox$@.so

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
