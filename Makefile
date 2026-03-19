CC ?=		cc
CFLAGS ?=	-O2 -pipe
WARNINGS =	-Wall -Wextra -Werror -pedantic -std=c99 \
		-Wformat -Wformat-security -Wconversion -Wsign-conversion \
		-Wshadow -Wstrict-prototypes -Wmissing-prototypes \
		-Wold-style-definition -Wimplicit-fallthrough
HARDENING =	-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LINKER_HARDENING !=	if [ "$$(uname -s)" != "Darwin" ]; then \
				echo "-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack"; \
			else echo "-pie"; fi

PREFIX ?=	/usr/local
BINDIR ?=	$(PREFIX)/bin
MANDIR ?=	$(PREFIX)/share/man
UNITDIR ?=	/lib/systemd/system

all: thinproxy

thinproxy: thinproxy.c
	$(CC) $(CFLAGS) $(WARNINGS) $(HARDENING) $(LINKER_HARDENING) $(LDFLAGS) -o $@ thinproxy.c

install: thinproxy
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 thinproxy $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 thinproxy.8 $(DESTDIR)$(MANDIR)/man8/
	@if [ -d /etc/rc.d ]; then \
		install -d $(DESTDIR)/etc/rc.d; \
		install -m 755 openbsd/rc.d/thinproxy $(DESTDIR)/etc/rc.d/; \
	elif [ -d /lib/systemd ] || [ -n "$(DESTDIR)" ]; then \
		install -d $(DESTDIR)$(UNITDIR); \
		install -m 644 thinproxy.service $(DESTDIR)$(UNITDIR)/; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/thinproxy
	rm -f $(DESTDIR)$(MANDIR)/man8/thinproxy.8
	rm -f $(DESTDIR)/etc/rc.d/thinproxy
	rm -f $(DESTDIR)$(UNITDIR)/thinproxy.service

clean:
	rm -f thinproxy

.PHONY: all install uninstall clean
