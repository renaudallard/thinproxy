# thinproxy

Lightweight, asynchronous HTTP/HTTPS proxy written in C.
Zero dependencies, single file, minimal attack surface.

## Features

- HTTP request forwarding with header rewriting
- HTTPS tunneling via CONNECT method
- IPv4 and IPv6 support
- Single-threaded, non-blocking I/O with poll(2)
- Asynchronous DNS resolution via forked child processes
- Zero-copy kernel relay for CONNECT tunnels on OpenBSD (SO_SPLICE)
- Source IP access control lists (allow/deny with CIDR)
- CONNECT port whitelist (default: 443 only)
- Private/reserved address blocking (SSRF protection)
- Per-IP connection limits
- Privilege dropping after bind
- OpenBSD pledge(2)/unveil(2) and Linux seccomp-BPF sandboxing
- Automatic bind retry on restart
- ~26 KB memory per connection

## Build

```
make
```

Builds on OpenBSD, Linux (glibc and musl), macOS, FreeBSD, NetBSD, and DragonFlyBSD.

On minimal Linux images such as Alpine, install the toolchain and kernel headers
first. The `linux-headers` package provides `<linux/seccomp.h>` for the seccomp
sandbox:

```sh
apk add gcc musl-dev make linux-headers
```

## Install

```
make install
```

The default prefix is `/usr/local`. Override with:

```
make install PREFIX=/usr DESTDIR=/tmp/pkg
```

### OpenBSD

```sh
rcctl enable thinproxy
rcctl start thinproxy
```

### Linux (systemd)

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now thinproxy
```

The shipped unit runs thinproxy as an unprivileged, transient user
(`DynamicUser=yes`), so the configuration does not need a `user` directive;
`/etc/thinproxy.conf` must be readable by the service. The unit also passes
`-F` to keep thinproxy in the foreground, so leave `daemon` set to `no`
(the default); a `daemon yes` config would otherwise make the service exit.

## Usage

```
thinproxy [-dFVv] [-b address] [-f config] [-p port] [-u user]
```

| Flag | Description |
|------|-------------|
| `-b address` | Bind address (default: `127.0.0.1`) |
| `-d` | Daemonize and log to syslog |
| `-F` | Force foreground, overriding a `daemon yes` config (for systemd etc.) |
| `-f config` | Configuration file (default: `/etc/thinproxy.conf`) |
| `-p port` | Listen port (default: `8080`) |
| `-u user` | Drop privileges to user after bind |
| `-V` | Print version and exit |
| `-v` | Enable all log categories |

Command-line flags override configuration file values.

### Examples

```sh
thinproxy                                    # default settings
thinproxy -v -b 0.0.0.0 -p 3128             # all interfaces, verbose
thinproxy -d -u _thinproxy                   # daemon with privilege drop
thinproxy -f /etc/thinproxy/thinproxy.conf   # custom config

curl -x http://127.0.0.1:8080 http://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

## Configuration

Default path: `/etc/thinproxy.conf` (silently ignored if missing).
See `thinproxy.conf.example` for a full example.

### General

| Directive | Description | Default |
|-----------|-------------|---------|
| `listen` | Bind address | `127.0.0.1` |
| `port` | Listen port | `8080` |
| `user` | Drop privileges to user | none |
| `daemon` | Run as daemon (`yes`/`no`) | `no` |
| `verbose` | Enable all log categories (`yes`/`no`) | `no` |
| `log` | Log category (repeatable: `requests`, `denied`, `wildcard`) | `denied` |

### Limits

| Directive | Description | Default |
|-----------|-------------|---------|
| `max_connections` | Max concurrent connections (1-512) | `512` |
| `max_connections_per_ip` | Max connections per source IP (1-512); IPv6 peers are aggregated by /64 | `32` |
| `idle_timeout` | Idle timeout in seconds (1-86400) | `300` |

### Security

| Directive | Description | Default |
|-----------|-------------|---------|
| `deny_private` | Block private/reserved destinations (`yes`/`no`) | `yes` |
| `nat64_prefix` | Additional NAT64 /96 prefix to unwrap (e.g. `2001:db8:64::/96`) | (well-known `64:ff9b::/96` only) |
| `connect_port` | Allowed CONNECT port (repeatable, `0` = wildcard) | `443` |
| `allow` | Allow source address/CIDR (whitelist mode) | |
| `deny` | Deny source address/CIDR (blacklist mode) | |

### Access Control

Use `allow` or `deny` directives, but not both.
When `allow` is used, unlisted addresses are denied.
When `deny` is used, unlisted addresses are allowed.
Both IPv4 and IPv6 with optional CIDR prefix are supported.

### Logging

thinproxy logs to stderr, or to syslog when run as a daemon with `-d`. A request is logged once for its disposition (never both an accepted and a denied line):

- Accepted (`requests` category): `<client> <method> <host>:<port>[<path>]` (path shown for plain HTTP)
- Denied (`denied` category): `<client> DENIED [<dest>] <reason>`, where `<dest>` is shown when known (omitted for `ACL` and `PER_IP_LIMIT`, which are decided before the request is read); reasons are `ACL`, `PER_IP_LIMIT`, `CONNECT_PORT`, `PRIVATE_ADDRESS`
- Resolve failure (always logged): `<client> RESOLVE_FAILED <dest> <reason>` with reason `LOOKUP`, `CHILD_KILLED`, `SHORT_READ`, or `SETUP`
- Timeout (`requests` category): `<client> TIMEOUT [<dest>]` when a connection exceeds `idle_timeout`

For plain HTTP, `<dest>` includes the path. When the `wildcard` category is enabled, a CONNECT whose port matched the wildcard rule is tagged with a trailing `WILDCARD_PORT` on whichever line it produces.

### Example Configuration

```
listen 0.0.0.0
port 3128
user _thinproxy
daemon yes
deny_private yes
connect_port 443
connect_port 8443
max_connections_per_ip 16
allow 192.168.1.0/24
allow 127.0.0.1
```

## Signals

`SIGTERM`, `SIGINT`, and `SIGHUP` all trigger a clean shutdown.
The daemon does not reload its configuration on `SIGHUP`; restart it to
pick up changes. `SIGPIPE` and `SIGCHLD` are ignored.

## Request Smuggling Defenses

Requests are rejected with `400 Bad Request` if they contain:

- Control bytes (other than SP) anywhere in the request line
- Whitespace inside the request-target
- Control bytes other than HTAB inside any header line
- Whitespace between a header name and its colon
- Obsolete header line folding (obs-fold)
- Duplicate `Host`, `Content-Length`, or `Transfer-Encoding` headers
- A missing `Host` header on a forwarded (non-CONNECT) request
- A `Transfer-Encoding` value other than `chunked`
- Both `Transfer-Encoding` and `Content-Length` together

## Platform Notes

### OpenBSD

- pledge(2) restricts syscalls to `stdio inet dns proc`
- unveil(2) restricts filesystem to `/etc/resolv.conf` and `/etc/hosts`
- SO_SPLICE provides zero-copy kernel relay for CONNECT tunnels
- accept4(2) with SOCK_NONBLOCK avoids extra fcntl(2) per connection
- Native strlcpy(3), closefrom(2), and strtonum(3)

### Linux

- seccomp-BPF restricts syscalls to an allowlist (I/O, networking, DNS, process forking); violations are logged with the blocked syscall number
- Supports x86_64 and aarch64
- POSIX-compatible fallbacks for BSD-specific functions
- Packages available as `.deb`, `.rpm`, `.apk`, and static binaries

### macOS, FreeBSD, NetBSD, DragonFlyBSD

- POSIX-compatible fallbacks for BSD-specific functions
- Static binaries available for FreeBSD, NetBSD, and DragonFlyBSD

## License

BSD 2-Clause. See [LICENSE](LICENSE).
