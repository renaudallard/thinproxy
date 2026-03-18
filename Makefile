CC ?=		cc
CFLAGS ?=	-O2 -pipe
CFLAGS +=	-Wall -Wextra -Werror -pedantic -std=c99

PREFIX ?=	/usr/local
BINDIR ?=	$(PREFIX)/bin
MANDIR ?=	$(PREFIX)/share/man

all: thinproxy

thinproxy: thinproxy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ thinproxy.c

install: thinproxy
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 thinproxy $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 thinproxy.8 $(DESTDIR)$(MANDIR)/man8/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/thinproxy
	rm -f $(DESTDIR)$(MANDIR)/man8/thinproxy.8

clean:
	rm -f thinproxy

.PHONY: all install uninstall clean
