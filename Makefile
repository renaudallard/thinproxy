CC ?=		cc
CFLAGS ?=	-O2 -pipe
CFLAGS +=	-Wall -Wextra -Werror -pedantic -std=c99

PREFIX ?=	/usr/local
BINDIR ?=	$(PREFIX)/bin
MANDIR ?=	$(PREFIX)/share/man

all: nanoproxy

nanoproxy: nanoproxy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ nanoproxy.c

install: nanoproxy
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 nanoproxy $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 nanoproxy.8 $(DESTDIR)$(MANDIR)/man8/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/nanoproxy
	rm -f $(DESTDIR)$(MANDIR)/man8/nanoproxy.8

clean:
	rm -f nanoproxy

.PHONY: all install uninstall clean
