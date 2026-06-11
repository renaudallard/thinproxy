CC ?=		cc
CFLAGS ?=	-O2 -pipe
CFLAGS +=	-Wall -Wextra -Werror -pedantic -std=c99

PREFIX ?=	/usr/local
BINDIR ?=	$(PREFIX)/bin
# MANDIR is computed per-OS at install time when left empty (OpenBSD uses
# $(PREFIX)/man, others $(PREFIX)/share/man); set it to override.
MANDIR ?=
UNITDIR ?=	/lib/systemd/system

all: thinproxy

thinproxy: thinproxy.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ thinproxy.c

install: thinproxy
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 thinproxy $(DESTDIR)$(BINDIR)/
	@mandir="$(MANDIR)"; \
	if [ -z "$$mandir" ]; then \
		case "`uname -s`" in \
		OpenBSD) mandir="$(PREFIX)/man";; \
		*) mandir="$(PREFIX)/share/man";; \
		esac; \
	fi; \
	install -d "$(DESTDIR)$$mandir/man8"; \
	install -m 644 thinproxy.8 "$(DESTDIR)$$mandir/man8/"
	@case "`uname -s`" in \
	OpenBSD) \
		install -d $(DESTDIR)/etc/rc.d; \
		install -m 755 openbsd/rc.d/thinproxy $(DESTDIR)/etc/rc.d/; \
		;; \
	Linux) \
		install -d $(DESTDIR)$(UNITDIR); \
		install -m 644 thinproxy.service $(DESTDIR)$(UNITDIR)/; \
		;; \
	*) \
		echo "no service file for `uname -s`; install manually"; \
		;; \
	esac

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/thinproxy
	@mandir="$(MANDIR)"; \
	if [ -z "$$mandir" ]; then \
		case "`uname -s`" in \
		OpenBSD) mandir="$(PREFIX)/man";; \
		*) mandir="$(PREFIX)/share/man";; \
		esac; \
	fi; \
	rm -f "$(DESTDIR)$$mandir/man8/thinproxy.8"
	rm -f $(DESTDIR)/etc/rc.d/thinproxy
	rm -f $(DESTDIR)$(UNITDIR)/thinproxy.service

clean:
	rm -f thinproxy

.PHONY: all install uninstall clean
