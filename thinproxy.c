/*
 * Copyright (c) 2026 Renaud Allard <renaud@allard.it>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#ifdef __OpenBSD__
#include <unistd.h>	/* pledge, unveil */
#endif

#ifdef __linux__
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#endif

#define THINPROXY_VERSION	"0.1.1"
#define DEFAULT_ADDR		"127.0.0.1"
#define DEFAULT_PORT		"8080"
#define DEFAULT_CONFIG		"/etc/thinproxy.conf"
#define BUF_SIZE		8192
#define MAX_CONNS		512
#define MAX_FDS			((MAX_CONNS) * 2 + 16)
#define MAX_ACL			256
#define POLL_TIMEOUT		30000	/* milliseconds */

/* ---- portability ---- */

#ifdef __OpenBSD__
/* __dead provided by <sys/cdefs.h> */
#elif !defined(__dead)
#define __dead	/* empty */
#endif

/*
 * On non-OpenBSD, provide inline wrappers that use POSIX
 * equivalents instead of BSD functions, avoiding compat
 * function conflicts with varying system headers.
 */
#ifndef __OpenBSD__
#undef strlcpy
#define strlcpy(d, s, n)	(size_t)snprintf((d), (n), "%s", (s))
static void
closefrom_compat(int lowfd)
{
	int fd;
	for (fd = lowfd; fd < MAX_FDS; fd++)
		(void)close(fd);
}
#define closefrom	closefrom_compat
static long long
strtonum_compat(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
	long long ll;
	char *ep;

	errno = 0;
	ll = strtoll(numstr, &ep, 10);
	if (numstr == ep || *ep != '\0')
		*errstrp = "invalid";
	else if (ll < minval)
		*errstrp = "too small";
	else if (ll > maxval)
		*errstrp = "too large";
	else {
		*errstrp = NULL;
		return ll;
	}
	return 0;
}
#define strtonum	strtonum_compat
#endif

#define ERR_400	"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
#define ERR_403	"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
#define ERR_502	"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
#define ERR_503	"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"

enum conn_state {
	S_REQUEST,	/* reading request from client */
	S_RESOLVING,	/* async DNS resolution */
	S_CONNECTING,	/* async connect to upstream */
	S_RESPONSE,	/* sending CONNECT 200 to client */
	S_RELAY,	/* bidirectional data relay */
	S_SPLICED	/* kernel-level relay via SO_SPLICE */
};

enum fd_type {
	FD_LISTEN,
	FD_CLIENT,
	FD_SERVER,
	FD_RESOLVE
};

enum acl_mode {
	ACL_NONE,	/* no rules, allow all */
	ACL_ALLOW,	/* whitelist: allow listed, deny rest */
	ACL_DENY	/* blacklist: deny listed, allow rest */
};

struct acl_entry {
	int		family;
	union {
		struct in_addr	v4;
		struct in6_addr	v6;
	}		addr;
	int		prefixlen;
};

struct dns_result {
	int		err;
	int		family;
	int		socktype;
	int		protocol;
	socklen_t	addrlen;
	struct sockaddr_storage addr;
};

struct conn {
	int		cfd;		/* client file descriptor */
	int		sfd;		/* server file descriptor */
	int		rfd;		/* DNS resolve pipe fd */
	struct sockaddr_storage	peer;	/* client address */
	enum conn_state	state;
	int		is_connect;
	int		ceof;		/* client EOF received */
	int		seof;		/* server EOF received */

	uint8_t		c2s[BUF_SIZE];	/* client-to-server buffer */
	size_t		c2s_off;
	size_t		c2s_len;

	uint8_t		s2c[BUF_SIZE];	/* server-to-client buffer */
	size_t		s2c_off;
	size_t		s2c_len;

	char		req[BUF_SIZE];	/* request accumulator */
	size_t		req_len;

	time_t		atime;		/* last activity */
};

/* globals */
static volatile sig_atomic_t	running = 1;
static struct pollfd		pfds[MAX_FDS];
static nfds_t			npfds;
static struct conn		*fdmap[MAX_FDS];
static int			fdtype_arr[MAX_FDS];
static int			fd_pidx[MAX_FDS];
static int			nconns;
static int			accept_paused;
static time_t			now;
static int			vflag;
static int			dflag;
static int			use_syslog;

/* configuration */
static char			cfg_addr[256] = DEFAULT_ADDR;
static char			cfg_port[8] = DEFAULT_PORT;
static char			cfg_user[64];
static int			cfg_maxconns = MAX_CONNS;
static int			cfg_timeout = 300;
static int			cfg_deny_private = 1;
static int			cfg_maxconns_per_ip = 32;

/* ACL */
static enum acl_mode		acl_mode;
static struct acl_entry		acl_list[MAX_ACL];
static int			nacl;

/* CONNECT port whitelist */
#define MAX_CONNECT_PORTS	64
static int			connect_ports[MAX_CONNECT_PORTS] = { 443 };
static int			nconnect_ports = 1;

/* forward declarations */
static void	conn_close(struct conn *);
static void	conn_update_poll(struct conn *);

/* best-effort write; return value intentionally discarded */
static void
ign_write(int fd, const void *buf, size_t len)
{
	ssize_t r;

	r = write(fd, buf, len);
	(void)r;
}

static void
logmsg(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (use_syslog)
		vsyslog(pri, fmt, ap);
	else {
		vfprintf(stderr, fmt, ap);
		fputc('\n', stderr);
	}
	va_end(ap);
}

static void
sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

static int
set_nonblock(int fd)
{
	int fl;

	fl = fcntl(fd, F_GETFL, 0);
	if (fl == -1)
		return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void
set_nodelay(int fd)
{
	int on = 1;

	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

/* ---- poll management ---- */

static int
poll_add(int fd, short events, struct conn *c, int type)
{
	nfds_t idx;

	if (fd < 0 || fd >= MAX_FDS || npfds >= (nfds_t)MAX_FDS)
		return -1;

	idx = npfds++;
	pfds[idx].fd = fd;
	pfds[idx].events = events;
	pfds[idx].revents = 0;
	fdmap[fd] = c;
	fdtype_arr[fd] = type;
	fd_pidx[fd] = (int)idx;
	return 0;
}

static void
poll_del(int fd)
{
	int idx;
	nfds_t last;

	if (fd < 0 || fd >= MAX_FDS || fd_pidx[fd] < 0)
		return;

	idx = fd_pidx[fd];
	fdmap[fd] = NULL;
	fd_pidx[fd] = -1;

	last = --npfds;
	if ((nfds_t)idx != last) {
		pfds[idx] = pfds[last];
		fd_pidx[pfds[idx].fd] = idx;
	}
}

static void
poll_mod(int fd, short events)
{
	if (fd >= 0 && fd < MAX_FDS && fd_pidx[fd] >= 0)
		pfds[fd_pidx[fd]].events = events;
}

/* ---- connection management ---- */

static void
conn_close(struct conn *c)
{
	if (c == NULL)
		return;
	if (c->rfd >= 0) {
		poll_del(c->rfd);
		close(c->rfd);
	}
	if (c->cfd >= 0) {
		poll_del(c->cfd);
		close(c->cfd);
	}
	if (c->sfd >= 0) {
		poll_del(c->sfd);
		close(c->sfd);
	}
	free(c);
	nconns--;
	accept_paused = 0;
}

static struct conn *
conn_alloc(int cfd)
{
	struct conn *c;

	if (nconns >= cfg_maxconns) {
		logmsg(LOG_WARNING, "connection limit reached");
		return NULL;
	}

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return NULL;

	c->cfd = cfd;
	c->sfd = -1;
	c->rfd = -1;
	c->state = S_REQUEST;
	c->atime = now;
	nconns++;
	return c;
}

/* ---- buffer helpers ---- */

static void
buf_compact(uint8_t *buf, size_t *off, size_t *len)
{
	if (*off > 0 && *len > 0) {
		memmove(buf, buf + *off, *len);
		*off = 0;
	} else if (*len == 0) {
		*off = 0;
	}
}

/* ---- ACL ---- */

static int
acl_add(const char *cidr)
{
	char buf[INET6_ADDRSTRLEN + 4];
	char *slash;
	struct acl_entry *e;

	if (nacl >= MAX_ACL) {
		logmsg(LOG_ERR, "ACL table full");
		return -1;
	}

	e = &acl_list[nacl];
	strlcpy(buf, cidr, sizeof(buf));

	slash = strchr(buf, '/');
	if (slash != NULL) {
		const char *errstr;

		*slash++ = '\0';
		e->prefixlen = (int)strtonum(slash, 0, 128, &errstr);
		if (errstr != NULL) {
			logmsg(LOG_ERR, "invalid prefix length: %s", cidr);
			return -1;
		}
	} else {
		e->prefixlen = -1;
	}

	if (inet_pton(AF_INET, buf, &e->addr.v4) == 1) {
		e->family = AF_INET;
		if (e->prefixlen == -1)
			e->prefixlen = 32;
		if (e->prefixlen < 0 || e->prefixlen > 32) {
			logmsg(LOG_ERR, "invalid prefix length: %s", cidr);
			return -1;
		}
	} else if (inet_pton(AF_INET6, buf, &e->addr.v6) == 1) {
		e->family = AF_INET6;
		if (e->prefixlen == -1)
			e->prefixlen = 128;
		if (e->prefixlen < 0 || e->prefixlen > 128) {
			logmsg(LOG_ERR, "invalid prefix length: %s", cidr);
			return -1;
		}
	} else {
		logmsg(LOG_ERR, "invalid address: %s", cidr);
		return -1;
	}

	nacl++;
	return 0;
}

static int
acl_match_entry(struct acl_entry *e, struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET && e->family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		uint32_t mask;

		if (e->prefixlen == 0)
			return 1;
		mask = htonl(~(uint32_t)0 << (32 - e->prefixlen));
		return (sin->sin_addr.s_addr & mask) ==
		    (e->addr.v4.s_addr & mask);
	}

	if (sa->sa_family == AF_INET6 && e->family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		uint8_t *a = sin6->sin6_addr.s6_addr;
		uint8_t *b = e->addr.v6.s6_addr;
		int bits = e->prefixlen;
		int i;

		for (i = 0; i < 16 && bits > 0; i++, bits -= 8) {
			uint8_t m = bits >= 8 ? 0xff :
			    (uint8_t)(0xff << (8 - bits));
			if ((a[i] & m) != (b[i] & m))
				return 0;
		}
		return 1;
	}

	return 0;
}

/*
 * Check if a client address is permitted by the ACL.
 * Returns 1 if allowed, 0 if denied.
 */
static int
acl_check(struct sockaddr *sa)
{
	struct sockaddr_in sin4;
	struct sockaddr_in6 *sin6;
	int i;

	if (acl_mode == ACL_NONE)
		return 1;

	/* extract IPv4 from IPv4-mapped IPv6 for correct matching */
	if (sa->sa_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			memset(&sin4, 0, sizeof(sin4));
			sin4.sin_family = AF_INET;
			memcpy(&sin4.sin_addr,
			    sin6->sin6_addr.s6_addr + 12, 4);
			sa = (struct sockaddr *)&sin4;
		}
	}

	for (i = 0; i < nacl; i++) {
		if (acl_match_entry(&acl_list[i], sa))
			return (acl_mode == ACL_ALLOW) ? 1 : 0;
	}

	return (acl_mode == ACL_ALLOW) ? 0 : 1;
}

/*
 * Check if a CONNECT port is allowed.
 * Returns 1 if allowed, 0 if denied.
 */
static int
connect_port_allowed(const char *port)
{
	int p, i;

	if (nconnect_ports == 0)
		return 1;

	p = (int)strtoll(port, NULL, 10);
	for (i = 0; i < nconnect_ports; i++) {
		if (connect_ports[i] == p)
			return 1;
	}
	return 0;
}

/*
 * Extract IPv4 address from sockaddr, handling IPv4-mapped IPv6.
 * Returns 1 and fills *out if IPv4 (native or mapped), 0 otherwise.
 */
static int
extract_v4(struct sockaddr *sa, struct in_addr *out)
{
	if (sa->sa_family == AF_INET) {
		*out = ((struct sockaddr_in *)sa)->sin_addr;
		return 1;
	}
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			memcpy(out, sin6->sin6_addr.s6_addr + 12, 4);
			return 1;
		}
	}
	return 0;
}

static int
per_ip_check(struct sockaddr *sa)
{
	int fd, count;
	struct in_addr new_v4;
	int new_is_v4;

	if (cfg_maxconns_per_ip <= 0)
		return 1;

	new_is_v4 = extract_v4(sa, &new_v4);

	count = 0;
	for (fd = 0; fd < MAX_FDS; fd++) {
		struct conn *c = fdmap[fd];
		struct in_addr peer_v4;
		if (c == NULL || fdtype_arr[fd] != FD_CLIENT)
			continue;
		if (c->cfd != fd)
			continue;
		if (new_is_v4) {
			if (extract_v4((struct sockaddr *)&c->peer,
			    &peer_v4) &&
			    new_v4.s_addr == peer_v4.s_addr)
				count++;
		} else if (sa->sa_family == AF_INET6 &&
		    c->peer.ss_family == AF_INET6) {
			struct sockaddr_in6 *a = (struct sockaddr_in6 *)sa;
			struct sockaddr_in6 *b =
			    (struct sockaddr_in6 *)&c->peer;
			if (memcmp(&a->sin6_addr, &b->sin6_addr, 16) == 0)
				count++;
		}
		if (count >= cfg_maxconns_per_ip)
			return 0;
	}
	return 1;
}

static int
is_private_v4(uint32_t a)
{
	/* 0.0.0.0/8 */
	if ((a >> 24) == 0)
		return 1;
	/* 10.0.0.0/8 */
	if ((a >> 24) == 10)
		return 1;
	/* 100.64.0.0/10 shared/CGN */
	if ((a & 0xffc00000) == 0x64400000)
		return 1;
	/* 127.0.0.0/8 loopback */
	if ((a >> 24) == 127)
		return 1;
	/* 169.254.0.0/16 link-local */
	if ((a >> 16) == 0xa9fe)
		return 1;
	/* 172.16.0.0/12 */
	if ((a & 0xfff00000) == 0xac100000)
		return 1;
	/* 192.168.0.0/16 */
	if ((a >> 16) == 0xc0a8)
		return 1;
	/* 224.0.0.0/3 multicast + reserved */
	if (a >= 0xe0000000)
		return 1;
	return 0;
}

static int
is_private_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		return is_private_v4(ntohl(sin->sin_addr.s_addr));
	}

	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
		uint8_t *b = sin6->sin6_addr.s6_addr;

		if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
			return 1;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			return 1;
		/* fc00::/7 unique local */
		if ((b[0] & 0xfe) == 0xfc)
			return 1;
		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
			return 1;
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			return 1;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			uint32_t v4;
			memcpy(&v4, b + 12, 4);
			return is_private_v4(ntohl(v4));
		}
		return 0;
	}

	return 0;
}

/* ---- configuration ---- */

static int
parse_bool(const char *val, const char *path, int lineno)
{
	if (strcasecmp(val, "yes") == 0 || strcmp(val, "1") == 0)
		return 1;
	if (strcasecmp(val, "no") == 0 || strcmp(val, "0") == 0)
		return 0;
	logmsg(LOG_ERR, "%s:%d: invalid boolean: %s", path, lineno, val);
	return -1;
}

static int
parse_config(const char *path, int must_exist)
{
	FILE *fp;
	char line[1024];
	char *p, *key, *val;
	int lineno = 0;

	fp = fopen(path, "r");
	if (fp == NULL) {
		if (errno == ENOENT && !must_exist)
			return 0;
		logmsg(LOG_ERR, "%s: %s", path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		lineno++;

		p = strchr(line, '\n');
		if (p != NULL)
			*p = '\0';
		else if (strlen(line) >= sizeof(line) - 1) {
			logmsg(LOG_ERR, "%s:%d: line too long",
			    path, lineno);
			fclose(fp);
			return -1;
		}

		p = strchr(line, '#');
		if (p != NULL)
			*p = '\0';

		p = line;
		while (*p != '\0' && isspace((unsigned char)*p))
			p++;
		if (*p == '\0')
			continue;

		key = p;
		while (*p != '\0' && !isspace((unsigned char)*p))
			p++;
		if (*p != '\0')
			*p++ = '\0';
		while (*p != '\0' && isspace((unsigned char)*p))
			p++;
		val = p;

		p = val + strlen(val);
		while (p > val && isspace((unsigned char)*(p - 1)))
			p--;
		*p = '\0';

		if (val[0] == '\0') {
			logmsg(LOG_ERR, "%s:%d: missing value for %s",
			    path, lineno, key);
			fclose(fp);
			return -1;
		}

		if (strcasecmp(key, "listen") == 0) {
			strlcpy(cfg_addr, val, sizeof(cfg_addr));
		} else if (strcasecmp(key, "port") == 0) {
			strlcpy(cfg_port, val, sizeof(cfg_port));
		} else if (strcasecmp(key, "user") == 0) {
			strlcpy(cfg_user, val, sizeof(cfg_user));
		} else if (strcasecmp(key, "daemon") == 0) {
			int b = parse_bool(val, path, lineno);
			if (b == -1) {
				fclose(fp);
				return -1;
			}
			dflag = b;
		} else if (strcasecmp(key, "verbose") == 0) {
			int b = parse_bool(val, path, lineno);
			if (b == -1) {
				fclose(fp);
				return -1;
			}
			vflag = b;
		} else if (strcasecmp(key, "max_connections") == 0) {
			const char *errstr;
			int n = (int)strtonum(val, 1, MAX_CONNS, &errstr);
			if (errstr != NULL) {
				logmsg(LOG_ERR,
				    "%s:%d: max_connections: %s",
				    path, lineno, errstr);
				fclose(fp);
				return -1;
			}
			cfg_maxconns = n;
		} else if (strcasecmp(key, "idle_timeout") == 0) {
			const char *errstr;
			int n = (int)strtonum(val, 1, 86400, &errstr);
			if (errstr != NULL) {
				logmsg(LOG_ERR,
				    "%s:%d: idle_timeout: %s",
				    path, lineno, errstr);
				fclose(fp);
				return -1;
			}
			cfg_timeout = n;
		} else if (strcasecmp(key, "allow") == 0) {
			if (acl_mode == ACL_DENY) {
				logmsg(LOG_ERR,
				    "%s:%d: cannot mix allow and deny",
				    path, lineno);
				fclose(fp);
				return -1;
			}
			acl_mode = ACL_ALLOW;
			if (acl_add(val) == -1) {
				fclose(fp);
				return -1;
			}
		} else if (strcasecmp(key, "deny") == 0) {
			if (acl_mode == ACL_ALLOW) {
				logmsg(LOG_ERR,
				    "%s:%d: cannot mix allow and deny",
				    path, lineno);
				fclose(fp);
				return -1;
			}
			acl_mode = ACL_DENY;
			if (acl_add(val) == -1) {
				fclose(fp);
				return -1;
			}
		} else if (strcasecmp(key, "max_connections_per_ip") == 0) {
			const char *errstr;
			int n = (int)strtonum(val, 1, MAX_CONNS, &errstr);
			if (errstr != NULL) {
				logmsg(LOG_ERR,
				    "%s:%d: max_connections_per_ip: %s",
				    path, lineno, errstr);
				fclose(fp);
				return -1;
			}
			cfg_maxconns_per_ip = n;
		} else if (strcasecmp(key, "deny_private") == 0) {
			int b = parse_bool(val, path, lineno);
			if (b == -1) {
				fclose(fp);
				return -1;
			}
			cfg_deny_private = b;
		} else if (strcasecmp(key, "connect_port") == 0) {
			static int connect_port_seen;
			const char *errstr;
			int n = (int)strtonum(val, 1, 65535, &errstr);
			if (errstr != NULL) {
				logmsg(LOG_ERR,
				    "%s:%d: connect_port: %s",
				    path, lineno, errstr);
				fclose(fp);
				return -1;
			}
			if (!connect_port_seen) {
				nconnect_ports = 0;
				connect_port_seen = 1;
			}
			if (nconnect_ports >= MAX_CONNECT_PORTS) {
				logmsg(LOG_ERR,
				    "%s:%d: too many connect_port entries",
				    path, lineno);
				fclose(fp);
				return -1;
			}
			connect_ports[nconnect_ports++] = n;
		} else {
			logmsg(LOG_ERR, "%s:%d: unknown directive: %s",
			    path, lineno, key);
			fclose(fp);
			return -1;
		}
	}

	fclose(fp);
	return 0;
}

/* ---- HTTP parsing ---- */

static const char *
find_eoh(const char *buf, size_t len)
{
	size_t i;

	if (len < 4)
		return NULL;
	for (i = 0; i <= len - 4; i++) {
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		    buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return buf + i;
	}
	return NULL;
}

static int
prefix_ci(const char *s, size_t slen, const char *pfx)
{
	size_t plen = strlen(pfx);

	return slen >= plen && strncasecmp(s, pfx, plen) == 0;
}

/*
 * Parse host[:port] from a string segment.
 * Handles both IPv4 and IPv6 bracket notation.
 */
static int
parse_hostport(const char *s, const char *end,
    char *host, size_t hsz, char *port, size_t psz,
    const char *defport)
{
	const char *col;
	size_t n;

	if (*s == '[') {
		col = memchr(s, ']', (size_t)(end - s));
		if (col == NULL)
			return -1;
		n = (size_t)(col - s - 1);
		if (n == 0 || n >= hsz)
			return -1;
		memcpy(host, s + 1, n);
		host[n] = '\0';
		if (col + 1 < end && col[1] == ':') {
			n = (size_t)(end - col - 2);
			if (n == 0 || n >= psz)
				return -1;
			memcpy(port, col + 2, n);
			port[n] = '\0';
		} else {
			strlcpy(port, defport, psz);
		}
	} else {
		col = memchr(s, ':', (size_t)(end - s));
		if (col != NULL) {
			n = (size_t)(col - s);
			if (n == 0 || n >= hsz)
				return -1;
			memcpy(host, s, n);
			host[n] = '\0';
			n = (size_t)(end - col - 1);
			if (n == 0 || n >= psz)
				return -1;
			memcpy(port, col + 1, n);
			port[n] = '\0';
		} else {
			n = (size_t)(end - s);
			if (n == 0 || n >= hsz)
				return -1;
			memcpy(host, s, n);
			host[n] = '\0';
			strlcpy(port, defport, psz);
		}
	}
	return 0;
}

/*
 * Parse an HTTP request line.
 * Fills method, host, port, path. Sets *is_connect.
 * Returns 0 on success, -1 on malformed input.
 */
static int
parse_request(const char *req, size_t len,
    char *method, size_t msz,
    char *host, size_t hsz,
    char *port, size_t psz,
    char *path, size_t pathsz,
    int *is_connect)
{
	const char *p, *lend, *ustart, *uend;
	const char *h, *hend, *slash;
	size_t n;

	lend = memchr(req, '\r', len);
	if (lend == NULL || lend + 1 >= req + len || lend[1] != '\n')
		return -1;

	p = memchr(req, ' ', (size_t)(lend - req));
	if (p == NULL)
		return -1;
	n = (size_t)(p - req);
	if (n == 0 || n >= msz)
		return -1;
	memcpy(method, req, n);
	method[n] = '\0';

	while (p < lend && *p == ' ')
		p++;
	ustart = p;

	uend = NULL;
	for (p = lend - 1; p > ustart; p--) {
		if (*p == ' ') {
			uend = p;
			break;
		}
	}
	if (uend == NULL || uend == ustart)
		return -1;

	*is_connect = (strcasecmp(method, "CONNECT") == 0);

	if (*is_connect) {
		if (parse_hostport(ustart, uend, host, hsz,
		    port, psz, "443") == -1)
			return -1;
		path[0] = '\0';
	} else {
		if (!prefix_ci(ustart, (size_t)(uend - ustart), "http://"))
			return -1;
		h = ustart + 7;
		slash = memchr(h, '/', (size_t)(uend - h));
		hend = slash ? slash : uend;
		if (parse_hostport(h, hend, host, hsz,
		    port, psz, "80") == -1)
			return -1;
		if (slash != NULL) {
			n = (size_t)(uend - slash);
			if (n >= pathsz)
				return -1;
			memcpy(path, slash, n);
			path[n] = '\0';
		} else {
			strlcpy(path, "/", pathsz);
		}
	}

	for (p = port; *p; p++) {
		if (!isdigit((unsigned char)*p))
			return -1;
	}
	if (host[0] == '\0')
		return -1;
	return 0;
}

/*
 * Build a modified HTTP request for upstream forwarding.
 * Replaces absolute URI with path, adds Connection: close,
 * strips hop-by-hop proxy headers.
 * Returns bytes written to buf, or -1 on error.
 */
static ssize_t
build_request(const char *req, size_t reqlen,
    uint8_t *buf, size_t bufsz,
    const char *method, const char *path)
{
	const char *p, *end, *lend, *ver;
	size_t n = 0;
	int have_conn = 0;

	end = req + reqlen;

	lend = memchr(req, '\r', reqlen);
	if (lend == NULL)
		return -1;

	ver = lend;
	while (ver > req && *(ver - 1) != ' ')
		ver--;
	if (ver <= req)
		return -1;

	n = (size_t)snprintf((char *)buf, bufsz, "%s %s %.*s\r\n",
	    method, path, (int)(lend - ver), ver);
	if (n >= bufsz)
		return -1;

	p = lend + 2;
	while (p < end) {
		lend = memchr(p, '\r', (size_t)(end - p));
		if (lend == NULL || lend + 1 >= end || lend[1] != '\n')
			break;

		if (lend == p) {
			if (!have_conn) {
				size_t w = (size_t)snprintf((char *)buf + n,
				    bufsz - n, "Connection: close\r\n");
				n += w;
				if (n >= bufsz)
					return -1;
			}
			n += (size_t)snprintf((char *)buf + n,
			    bufsz - n, "\r\n");
			if (n >= bufsz)
				return -1;

			p = lend + 2;
			if (p < end) {
				size_t rem = (size_t)(end - p);
				if (n + rem > bufsz)
					return -1;
				memcpy(buf + n, p, rem);
				n += rem;
			}
			return (ssize_t)n;
		}

		if (prefix_ci(p, (size_t)(lend - p), "Proxy-Connection:") ||
		    prefix_ci(p, (size_t)(lend - p), "Proxy-Authorization:")) {
			p = lend + 2;
			continue;
		}

		if (prefix_ci(p, (size_t)(lend - p), "Connection:")) {
			size_t w = (size_t)snprintf((char *)buf + n,
			    bufsz - n, "Connection: close\r\n");
			n += w;
			if (n >= bufsz)
				return -1;
			have_conn = 1;
			p = lend + 2;
			continue;
		}

		{
			size_t hlen = (size_t)(lend - p + 2);
			if (n + hlen > bufsz)
				return -1;
			memcpy(buf + n, p, hlen);
			n += hlen;
		}
		p = lend + 2;
	}
	return -1;
}

/* ---- async DNS resolution ---- */

static void __dead
dns_child(const char *host, const char *port, int wfd)
{
	struct addrinfo hints, *res;
	struct dns_result dr;
	int err;

	if (wfd != 3) {
		(void)dup2(wfd, 3);
		wfd = 3;
	}
	closefrom(4);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	memset(&dr, 0, sizeof(dr));
	err = getaddrinfo(host, port, &hints, &res);
	if (err != 0 || res == NULL) {
		dr.err = -1;
		ign_write(wfd, &dr, sizeof(dr));
		_exit(0);
	}

	dr.err = 0;
	dr.family = res->ai_family;
	dr.socktype = res->ai_socktype;
	dr.protocol = res->ai_protocol;
	dr.addrlen = res->ai_addrlen;
	memcpy(&dr.addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	ign_write(wfd, &dr, sizeof(dr));
	_exit(0);
}

static int
dns_resolve_start(struct conn *c, const char *host, const char *port)
{
	int pfd[2];
	pid_t pid;

	if (pipe(pfd) == -1) {
		logmsg(LOG_ERR, "pipe: %s", strerror(errno));
		return -1;
	}

	if (pfd[0] >= MAX_FDS) {
		close(pfd[0]);
		close(pfd[1]);
		logmsg(LOG_ERR, "pipe fd too high");
		return -1;
	}

	pid = fork();
	if (pid == -1) {
		logmsg(LOG_ERR, "fork: %s", strerror(errno));
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	if (pid == 0) {
		close(pfd[0]);
		dns_child(host, port, pfd[1]);
		/* NOTREACHED */
	}

	close(pfd[1]);
	if (set_nonblock(pfd[0]) == -1) {
		close(pfd[0]);
		return -1;
	}

	c->rfd = pfd[0];
	return 0;
}

/* ---- state handlers ---- */

static void
handle_request(struct conn *c)
{
	ssize_t nr;
	const char *eoh;
	char method[16], host[256], port[8], path[BUF_SIZE];
	int is_connect;

	nr = read(c->cfd, c->req + c->req_len,
	    sizeof(c->req) - c->req_len - 1);
	if (nr <= 0) {
		if (nr == 0 || (errno != EAGAIN && errno != EINTR))
			conn_close(c);
		return;
	}
	c->req_len += (size_t)nr;
	c->req[c->req_len] = '\0';
	c->atime = now;

	eoh = find_eoh(c->req, c->req_len);
	if (eoh == NULL) {
		if (c->req_len >= sizeof(c->req) - 1) {
			logmsg(LOG_WARNING, "request too large");
			ign_write(c->cfd, ERR_400, sizeof(ERR_400) - 1);
			conn_close(c);
		}
		return;
	}

	if (parse_request(c->req, c->req_len, method, sizeof(method),
	    host, sizeof(host), port, sizeof(port),
	    path, sizeof(path), &is_connect) == -1) {
		logmsg(LOG_WARNING, "malformed request");
		ign_write(c->cfd, ERR_400, sizeof(ERR_400) - 1);
		conn_close(c);
		return;
	}

	c->is_connect = is_connect;
	if (vflag) {
		char logbuf[2048];
		char peer[INET6_ADDRSTRLEN];
		size_t li, ln;

		peer[0] = '\0';
		if (c->peer.ss_family == AF_INET)
			inet_ntop(AF_INET,
			    &((struct sockaddr_in *)&c->peer)->sin_addr,
			    peer, sizeof(peer));
		else if (c->peer.ss_family == AF_INET6)
			inet_ntop(AF_INET6,
			    &((struct sockaddr_in6 *)&c->peer)->sin6_addr,
			    peer, sizeof(peer));

		ln = (size_t)snprintf(logbuf, sizeof(logbuf),
		    "%s %s %s:%s%s", peer, method, host, port,
		    is_connect ? "" : path);
		if (ln >= sizeof(logbuf))
			ln = sizeof(logbuf) - 1;
		for (li = 0; li < ln; li++) {
			if (logbuf[li] < 0x20 || logbuf[li] >= 0x7f)
				logbuf[li] = '?';
		}
		logmsg(LOG_INFO, "%s", logbuf);
	}

	if (is_connect && !connect_port_allowed(port)) {
		logmsg(LOG_WARNING, "CONNECT port %s denied", port);
		ign_write(c->cfd, ERR_403, sizeof(ERR_403) - 1);
		conn_close(c);
		return;
	}

	if (!is_connect) {
		ssize_t built = build_request(c->req, c->req_len,
		    c->c2s, sizeof(c->c2s), method, path);
		if (built == -1) {
			logmsg(LOG_WARNING, "request build failed");
			ign_write(c->cfd, ERR_400, sizeof(ERR_400) - 1);
			conn_close(c);
			return;
		}
		c->c2s_off = 0;
		c->c2s_len = (size_t)built;
	}

	if (dns_resolve_start(c, host, port) == -1) {
		logmsg(LOG_WARNING, "resolve %s:%s failed", host, port);
		ign_write(c->cfd, ERR_502, sizeof(ERR_502) - 1);
		conn_close(c);
		return;
	}

	c->state = S_RESOLVING;
	poll_mod(c->cfd, 0);
	if (poll_add(c->rfd, POLLIN, c, FD_RESOLVE) == -1) {
		close(c->rfd);
		c->rfd = -1;
		conn_close(c);
	}
}

static void
handle_resolving(struct conn *c)
{
	struct dns_result dr;
	ssize_t nr;
	int fd, on;

	nr = read(c->rfd, &dr, sizeof(dr));
	if (nr == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		conn_close(c);
		return;
	}

	poll_del(c->rfd);
	close(c->rfd);
	c->rfd = -1;

	if (nr != (ssize_t)sizeof(dr) || dr.err != 0) {
		logmsg(LOG_WARNING, "DNS resolution failed");
		ign_write(c->cfd, ERR_502, sizeof(ERR_502) - 1);
		conn_close(c);
		return;
	}

	if (cfg_deny_private &&
	    is_private_addr((struct sockaddr *)&dr.addr)) {
		logmsg(LOG_WARNING, "private address denied");
		ign_write(c->cfd, ERR_403, sizeof(ERR_403) - 1);
		conn_close(c);
		return;
	}

	fd = socket(dr.family, dr.socktype, dr.protocol);
	if (fd == -1 || fd >= MAX_FDS) {
		if (fd != -1)
			close(fd);
		ign_write(c->cfd, ERR_502, sizeof(ERR_502) - 1);
		conn_close(c);
		return;
	}

	if (set_nonblock(fd) == -1) {
		close(fd);
		ign_write(c->cfd, ERR_502, sizeof(ERR_502) - 1);
		conn_close(c);
		return;
	}

	on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	set_nodelay(fd);

	if (connect(fd, (struct sockaddr *)&dr.addr, dr.addrlen) == -1) {
		if (errno != EINPROGRESS) {
			logmsg(LOG_WARNING, "connect: %s", strerror(errno));
			close(fd);
			ign_write(c->cfd, ERR_502, sizeof(ERR_502) - 1);
			conn_close(c);
			return;
		}
	}

	c->sfd = fd;
	c->state = S_CONNECTING;
	if (poll_add(c->sfd, POLLOUT, c, FD_SERVER) == -1) {
		close(c->sfd);
		c->sfd = -1;
		conn_close(c);
	}
}

static void
handle_connecting(struct conn *c)
{
	int err;
	socklen_t sl;

	sl = sizeof(err);
	if (getsockopt(c->sfd, SOL_SOCKET, SO_ERROR, &err, &sl) == -1 ||
	    err != 0) {
		logmsg(LOG_WARNING, "upstream: %s",
		    strerror(err ? err : errno));
		ign_write(c->cfd, ERR_502, sizeof(ERR_502) - 1);
		conn_close(c);
		return;
	}
	c->atime = now;

	if (c->is_connect) {
		static const char ok[] =
		    "HTTP/1.1 200 Connection Established\r\n\r\n";
		memcpy(c->s2c, ok, sizeof(ok) - 1);
		c->s2c_off = 0;
		c->s2c_len = sizeof(ok) - 1;
		c->state = S_RESPONSE;
		poll_mod(c->cfd, POLLOUT);
		poll_mod(c->sfd, 0);
	} else {
		c->state = S_RELAY;
		poll_mod(c->cfd, POLLIN);
		poll_mod(c->sfd, POLLOUT);
	}
}

static void
handle_response(struct conn *c)
{
	ssize_t nw;

	nw = write(c->cfd, c->s2c + c->s2c_off, c->s2c_len);
	if (nw <= 0) {
		if (nw == 0 || (errno != EAGAIN && errno != EINTR))
			conn_close(c);
		return;
	}

	c->s2c_off += (size_t)nw;
	c->s2c_len -= (size_t)nw;
	c->atime = now;

	if (c->s2c_len == 0) {
		c->s2c_off = 0;
#ifdef SO_SPLICE
		/*
		 * Let the kernel relay the CONNECT tunnel.
		 * Falls back to userspace relay if splice fails.
		 */
		{
			struct splice sp;
			memset(&sp, 0, sizeof(sp));
			sp.sp_idle.tv_sec = (time_t)cfg_timeout;

			sp.sp_fd = c->sfd;
			if (setsockopt(c->cfd, SOL_SOCKET, SO_SPLICE,
			    &sp, sizeof(sp)) == 0) {
				sp.sp_fd = c->cfd;
				if (setsockopt(c->sfd, SOL_SOCKET,
				    SO_SPLICE, &sp, sizeof(sp)) == 0) {
					c->state = S_SPLICED;
					poll_mod(c->cfd, POLLIN);
					poll_mod(c->sfd, POLLIN);
					return;
				}
				/* undo first splice */
				sp.sp_fd = -1;
				(void)setsockopt(c->cfd, SOL_SOCKET,
				    SO_SPLICE, &sp, sizeof(sp));
			}
		}
#endif
		c->state = S_RELAY;
		poll_mod(c->cfd, POLLIN);
		poll_mod(c->sfd, POLLIN);
	}
}

static void
conn_update_poll(struct conn *c)
{
	short cev = 0, sev = 0;

	if (c->state != S_RELAY)
		return;

	if (c->ceof && c->c2s_len == 0 &&
	    c->seof && c->s2c_len == 0) {
		conn_close(c);
		return;
	}

	if (!c->ceof && c->c2s_off + c->c2s_len < BUF_SIZE)
		cev |= POLLIN;
	if (c->s2c_len > 0)
		cev |= POLLOUT;

	if (!c->seof && c->s2c_off + c->s2c_len < BUF_SIZE)
		sev |= POLLIN;
	if (c->c2s_len > 0)
		sev |= POLLOUT;

	if (c->cfd >= 0)
		poll_mod(c->cfd, cev);
	if (c->sfd >= 0)
		poll_mod(c->sfd, sev);
}

static void
handle_relay_read(struct conn *c, int fd)
{
	ssize_t nr;
	uint8_t *buf;
	size_t *off, *len, space;
	int *eof;

	if (fd == c->cfd) {
		buf = c->c2s; off = &c->c2s_off;
		len = &c->c2s_len; eof = &c->ceof;
	} else {
		buf = c->s2c; off = &c->s2c_off;
		len = &c->s2c_len; eof = &c->seof;
	}

	buf_compact(buf, off, len);

	space = BUF_SIZE - *off - *len;
	if (space == 0) {
		conn_update_poll(c);
		return;
	}

	nr = read(fd, buf + *off + *len, space);
	if (nr <= 0) {
		if (nr == 0)
			*eof = 1;
		else if (errno != EAGAIN && errno != EINTR) {
			conn_close(c);
			return;
		}
		conn_update_poll(c);
		return;
	}

	*len += (size_t)nr;
	c->atime = now;
	conn_update_poll(c);
}

static void
handle_relay_write(struct conn *c, int fd)
{
	ssize_t nw;
	uint8_t *buf;
	size_t *off, *len;

	if (fd == c->cfd) {
		buf = c->s2c; off = &c->s2c_off; len = &c->s2c_len;
	} else {
		buf = c->c2s; off = &c->c2s_off; len = &c->c2s_len;
	}

	if (*len == 0)
		return;

	nw = write(fd, buf + *off, *len);
	if (nw == -1) {
		if (errno != EAGAIN && errno != EINTR)
			conn_close(c);
		return;
	}

	*off += (size_t)nw;
	*len -= (size_t)nw;
	if (*len == 0)
		*off = 0;
	c->atime = now;
	conn_update_poll(c);
}

/* ---- accept ---- */

static void
accept_conn(int lfd)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	int fd, on;
	struct conn *c;

	sl = sizeof(ss);
#ifdef __OpenBSD__
	fd = accept4(lfd, (struct sockaddr *)&ss, &sl, SOCK_NONBLOCK);
#else
	fd = accept(lfd, (struct sockaddr *)&ss, &sl);
#endif
	if (fd == -1) {
		if (errno == EMFILE || errno == ENFILE) {
			logmsg(LOG_ERR, "accept: %s", strerror(errno));
			accept_paused = 1;
		} else if (errno != EAGAIN && errno != ECONNABORTED &&
		    errno != EINTR)
			logmsg(LOG_ERR, "accept: %s", strerror(errno));
		return;
	}

	if (!acl_check((struct sockaddr *)&ss)) {
		if (vflag)
			logmsg(LOG_INFO, "denied by ACL");
		ign_write(fd, ERR_403, sizeof(ERR_403) - 1);
		close(fd);
		return;
	}

	if (!per_ip_check((struct sockaddr *)&ss)) {
		if (vflag)
			logmsg(LOG_INFO, "per-IP connection limit reached");
		ign_write(fd, ERR_503, sizeof(ERR_503) - 1);
		close(fd);
		return;
	}

	if (fd >= MAX_FDS) {
		close(fd);
		return;
	}

#ifndef __OpenBSD__
	if (set_nonblock(fd) == -1) {
		close(fd);
		return;
	}
#endif

	on = 1;
	(void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	set_nodelay(fd);

	c = conn_alloc(fd);
	if (c == NULL) {
		ign_write(fd, ERR_503, sizeof(ERR_503) - 1);
		close(fd);
		return;
	}
	memcpy(&c->peer, &ss, sizeof(ss));

	if (poll_add(fd, POLLIN, c, FD_CLIENT) == -1) {
		c->cfd = -1;
		conn_close(c);
		close(fd);
	}
}

/* ---- timeouts ---- */

static void
reap_timeouts(void)
{
	int fd;

	for (fd = 0; fd < MAX_FDS; fd++) {
		struct conn *c = fdmap[fd];
		if (c == NULL || fdtype_arr[fd] == FD_LISTEN)
			continue;
		if (c->cfd != fd)
			continue;
		if (c->state == S_SPLICED)
			continue;
		if (now - c->atime > cfg_timeout) {
			if (vflag)
				logmsg(LOG_INFO, "idle timeout");
			conn_close(c);
		}
	}
}

/* ---- event loop ---- */

static void
event_loop(int lfd)
{
	struct {
		int	fd;
		short	rev;
	} evbuf[MAX_FDS];
	int nev, ret;
	nfds_t i;
	time_t last_reap;

	now = time(NULL);
	last_reap = now;

	while (running) {
		poll_mod(lfd, (nconns < cfg_maxconns && !accept_paused)
		    ? POLLIN : 0);

		ret = poll(pfds, npfds, POLL_TIMEOUT);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			logmsg(LOG_ERR, "poll: %s", strerror(errno));
			break;
		}

		now = time(NULL);

		nev = 0;
		for (i = 0; i < npfds; i++) {
			if (pfds[i].revents) {
				evbuf[nev].fd = pfds[i].fd;
				evbuf[nev].rev = pfds[i].revents;
				nev++;
			}
		}

		for (i = 0; i < (nfds_t)nev; i++) {
			int fd = evbuf[i].fd;
			short rev = evbuf[i].rev;
			struct conn *c;

			if (fd < 0 || fd >= MAX_FDS)
				continue;

			if (fdtype_arr[fd] == FD_LISTEN) {
				if (rev & POLLIN)
					accept_conn(fd);
				continue;
			}

			c = fdmap[fd];
			if (c == NULL)
				continue;

			if (rev & POLLNVAL) {
				conn_close(c);
				continue;
			}

			switch (c->state) {
			case S_REQUEST:
				if (rev & (POLLIN | POLLHUP))
					handle_request(c);
				break;
			case S_RESOLVING:
				if (fd == c->rfd &&
				    (rev & (POLLIN | POLLHUP)))
					handle_resolving(c);
				else if (fd == c->cfd)
					conn_close(c);
				break;
			case S_CONNECTING:
				if (fd == c->sfd &&
				    (rev & (POLLOUT | POLLHUP | POLLERR)))
					handle_connecting(c);
				else if (fd == c->cfd)
					conn_close(c);
				break;
			case S_RESPONSE:
				if (rev & POLLOUT)
					handle_response(c);
				else if (rev & POLLHUP)
					conn_close(c);
				break;
			case S_RELAY:
				if (rev & POLLIN)
					handle_relay_read(c, fd);
				if (fdmap[fd] != NULL && (rev & POLLOUT))
					handle_relay_write(c, fd);
				if (fdmap[fd] != NULL &&
				    (rev & POLLHUP) && !(rev & POLLIN)) {
					if (fd == c->cfd)
						c->ceof = 1;
					else
						c->seof = 1;
					conn_update_poll(c);
				}
				break;
			case S_SPLICED:
				conn_close(c);
				break;
			}

			if (fdmap[fd] != NULL && (rev & POLLERR))
				conn_close(fdmap[fd]);
		}

		if (now - last_reap >= POLL_TIMEOUT / 1000) {
			reap_timeouts();
			last_reap = now;
		}
	}
}

/* ---- listener setup ---- */

static int
setup_listener(const char *addr, const char *port)
{
	struct addrinfo hints, *res, *r;
	int fd = -1, err, on, attempt;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(addr, port, &hints, &res);
	if (err) {
		logmsg(LOG_ERR, "getaddrinfo: %s", gai_strerror(err));
		return -1;
	}

	/*
	 * Retry bind when the address is temporarily held by
	 * orphaned TCP connections (FIN_WAIT_2, TIME_WAIT).
	 * SO_REUSEADDR/SO_REUSEPORT do not cover all cases
	 * on OpenBSD.
	 */
	for (attempt = 0; attempt < 5; attempt++) {
		for (r = res; r != NULL; r = r->ai_next) {
			fd = socket(r->ai_family, r->ai_socktype,
			    r->ai_protocol);
			if (fd == -1) {
				err = errno;
				continue;
			}
			on = 1;
			(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
			    &on, sizeof(on));
#ifdef SO_REUSEPORT
			(void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
			    &on, sizeof(on));
#endif
			if (bind(fd, r->ai_addr, r->ai_addrlen) == -1) {
				err = errno;
				close(fd);
				fd = -1;
				continue;
			}
			break;
		}
		if (fd != -1 || err != EADDRINUSE)
			break;
		logmsg(LOG_INFO, "bind %s:%s: retrying (%d/5)",
		    addr, port, attempt + 1);
		sleep(1);
	}
	freeaddrinfo(res);

	if (fd == -1) {
		logmsg(LOG_ERR, "bind %s:%s: %s", addr, port,
		    strerror(err));
		return -1;
	}

	if (listen(fd, 128) == -1) {
		logmsg(LOG_ERR, "listen: %s", strerror(errno));
		close(fd);
		return -1;
	}

	if (set_nonblock(fd) == -1) {
		close(fd);
		return -1;
	}
	return fd;
}

/* ---- privilege dropping ---- */

static int
drop_privs(const char *user)
{
	struct passwd *pw;

	pw = getpwnam(user);
	if (pw == NULL) {
		logmsg(LOG_ERR, "unknown user: %s", user);
		return -1;
	}
	if (getuid() == pw->pw_uid) {
		if (setgid(pw->pw_gid) == -1)
			logmsg(LOG_WARNING, "setgid: %s", strerror(errno));
		return 0;
	}
	if (setgroups(1, &pw->pw_gid) == -1 ||
	    setgid(pw->pw_gid) == -1 ||
	    setuid(pw->pw_uid) == -1) {
		logmsg(LOG_ERR, "setuid: %s", strerror(errno));
		return -1;
	}
	return 0;
}

/* ---- seccomp-bpf (Linux) ---- */

#ifdef __linux__

#if defined(__x86_64__)
#define THINPROXY_AUDIT_ARCH	AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define THINPROXY_AUDIT_ARCH	AUDIT_ARCH_AARCH64
#else
#define THINPROXY_AUDIT_ARCH	0
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS	0x80000000U
#endif

#define SC_ALLOW(nr) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int
setup_seccomp(void)
{
#if THINPROXY_AUDIT_ARCH == 0
	logmsg(LOG_WARNING, "seccomp: unsupported architecture, skipping");
	return 0;
#else
	struct sock_filter filter[] = {
		/* validate architecture */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		    offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
		    THINPROXY_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

		/* load syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
		    offsetof(struct seccomp_data, nr)),

		/* I/O */
		SC_ALLOW(__NR_read),
		SC_ALLOW(__NR_write),
		SC_ALLOW(__NR_writev),
		SC_ALLOW(__NR_close),

		/* network */
		SC_ALLOW(__NR_socket),
		SC_ALLOW(__NR_connect),
#ifdef __NR_accept
		SC_ALLOW(__NR_accept),
#endif
		SC_ALLOW(__NR_accept4),
		SC_ALLOW(__NR_setsockopt),
		SC_ALLOW(__NR_getsockopt),
		SC_ALLOW(__NR_sendto),
		SC_ALLOW(__NR_recvfrom),
		SC_ALLOW(__NR_recvmsg),
#ifdef __NR_sendmmsg
		SC_ALLOW(__NR_sendmmsg),
#endif
		SC_ALLOW(__NR_bind),
		SC_ALLOW(__NR_getsockname),

		/* event loop */
#ifdef __NR_poll
		SC_ALLOW(__NR_poll),
#endif
		SC_ALLOW(__NR_ppoll),

		/* process */
#ifdef __NR_fork
		SC_ALLOW(__NR_fork),
#endif
		SC_ALLOW(__NR_clone),
#ifdef __NR_clone3
		SC_ALLOW(__NR_clone3),
#endif
#ifdef __NR_pipe
		SC_ALLOW(__NR_pipe),
#endif
		SC_ALLOW(__NR_pipe2),
		SC_ALLOW(__NR_exit_group),
		SC_ALLOW(__NR_wait4),

		/* fd management */
		SC_ALLOW(__NR_fcntl),
#ifdef __NR_dup2
		SC_ALLOW(__NR_dup2),
#endif
		SC_ALLOW(__NR_dup3),

		/* fd management (DNS child) */
		SC_ALLOW(__NR_ioctl),
		SC_ALLOW(__NR_lseek),

		/* file access (DNS child: /etc/resolv.conf, /etc/hosts) */
		SC_ALLOW(__NR_openat),
#ifdef __NR_fstat
		SC_ALLOW(__NR_fstat),
#endif
		SC_ALLOW(__NR_newfstatat),
#ifdef __NR_faccessat
		SC_ALLOW(__NR_faccessat),
#endif

		/* memory */
		SC_ALLOW(__NR_brk),
		SC_ALLOW(__NR_mmap),
		SC_ALLOW(__NR_munmap),
		SC_ALLOW(__NR_mremap),
		SC_ALLOW(__NR_mprotect),

		/* signals */
		SC_ALLOW(__NR_rt_sigaction),
		SC_ALLOW(__NR_rt_sigreturn),
		SC_ALLOW(__NR_rt_sigprocmask),

		/* time */
		SC_ALLOW(__NR_clock_gettime),

		/* glibc/musl internals */
		SC_ALLOW(__NR_getpid),
		SC_ALLOW(__NR_futex),
		SC_ALLOW(__NR_getrandom),
#ifdef __NR_prlimit64
		SC_ALLOW(__NR_prlimit64),
#endif
#ifdef __NR_set_robust_list
		SC_ALLOW(__NR_set_robust_list),
#endif
#ifdef __NR_rseq
		SC_ALLOW(__NR_rseq),
#endif

		/* default deny */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
		logmsg(LOG_ERR, "prctl(NO_NEW_PRIVS): %s",
		    strerror(errno));
		return -1;
	}
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
		logmsg(LOG_ERR, "prctl(SECCOMP): %s", strerror(errno));
		return -1;
	}
	return 0;
#endif /* THINPROXY_AUDIT_ARCH */
}
#endif /* __linux__ */

/* ---- main ---- */

static void __dead
usage(void)
{
	fprintf(stderr,
	    "usage: thinproxy [-dVv] [-b address] [-f config] "
	    "[-p port] [-u user]\n");
	exit(1);
}

#ifndef THINPROXY_NO_MAIN
int
main(int argc, char *argv[])
{
	const char *cfgpath = DEFAULT_CONFIG;
	int cfgpath_explicit = 0;
	int ch, lfd, i;
	struct sigaction sa;

	/* pre-scan for -f before config parsing */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
			cfgpath = argv[i + 1];
			cfgpath_explicit = 1;
			break;
		}
	}

	if (parse_config(cfgpath, cfgpath_explicit) == -1)
		return 1;

	/* CLI overrides config */
	optind = 1;
	while ((ch = getopt(argc, argv, "b:df:p:u:Vv")) != -1) {
		switch (ch) {
		case 'b':
			strlcpy(cfg_addr, optarg, sizeof(cfg_addr));
			break;
		case 'd':
			dflag = 1;
			break;
		case 'f':
			break;
		case 'p':
			strlcpy(cfg_port, optarg, sizeof(cfg_port));
			break;
		case 'u':
			strlcpy(cfg_user, optarg, sizeof(cfg_user));
			break;
		case 'V':
			fprintf(stderr, "thinproxy %s\n", THINPROXY_VERSION);
			return 0;
		case 'v':
			vflag = 1;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	for (i = 0; i < MAX_FDS; i++)
		fd_pidx[i] = -1;

	lfd = setup_listener(cfg_addr, cfg_port);
	if (lfd == -1)
		return 1;

	if (cfg_user[0] != '\0' && drop_privs(cfg_user) == -1) {
		close(lfd);
		return 1;
	}

	if (dflag) {
#ifdef __APPLE__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
		if (daemon(0, 0) == -1) {
			logmsg(LOG_ERR, "daemon: %s", strerror(errno));
			close(lfd);
			return 1;
		}
		use_syslog = 1;
		openlog("thinproxy", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#ifdef __APPLE__
#pragma GCC diagnostic pop
#endif
	}

#ifdef __OpenBSD__
	if (unveil("/etc/resolv.conf", "r") == -1 ||
	    unveil("/etc/hosts", "r") == -1 ||
	    unveil(NULL, NULL) == -1) {
		logmsg(LOG_ERR, "unveil: %s", strerror(errno));
		close(lfd);
		return 1;
	}
	if (pledge("stdio inet dns proc", NULL) == -1) {
		logmsg(LOG_ERR, "pledge: %s", strerror(errno));
		close(lfd);
		return 1;
	}
#endif

#ifdef __linux__
	if (setup_seccomp() == -1) {
		close(lfd);
		return 1;
	}
#endif

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTERM, &sa, NULL) == -1 ||
	    sigaction(SIGINT, &sa, NULL) == -1) {
		logmsg(LOG_ERR, "sigaction: %s", strerror(errno));
		close(lfd);
		return 1;
	}
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);
	(void)sigaction(SIGCHLD, &sa, NULL);

	if (poll_add(lfd, POLLIN, NULL, FD_LISTEN) == -1) {
		logmsg(LOG_ERR, "poll_add failed");
		close(lfd);
		return 1;
	}

	logmsg(LOG_INFO, "thinproxy %s listening on %s:%s",
	    THINPROXY_VERSION, cfg_addr, cfg_port);

	event_loop(lfd);

	logmsg(LOG_INFO, "shutting down");
	for (i = 0; i < MAX_FDS; i++) {
		if (fdmap[i] != NULL && fdtype_arr[i] == FD_CLIENT)
			conn_close(fdmap[i]);
	}
	close(lfd);

	if (use_syslog)
		closelog();
	return 0;
}
#endif /* THINPROXY_NO_MAIN */
