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
- ~25 KB memory per connection

## Build

```
make
```

Builds on OpenBSD, Linux (glibc and musl), macOS, and FreeBSD.

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

## Usage

```
thinproxy [-dVv] [-b address] [-f config] [-p port] [-u user]
```

| Flag | Description |
|------|-------------|
| `-b address` | Bind address (default: `127.0.0.1`) |
| `-d` | Daemonize and log to syslog |
| `-f config` | Configuration file (default: `/etc/thinproxy.conf`) |
| `-p port` | Listen port (default: `8080`) |
| `-u user` | Drop privileges to user after bind |
| `-V` | Print version and exit |
| `-v` | Verbose logging |

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
| `verbose` | Verbose logging (`yes`/`no`) | `no` |

### Limits

| Directive | Description | Default |
|-----------|-------------|---------|
| `max_connections` | Max concurrent connections (1-512) | `512` |
| `max_connections_per_ip` | Max connections per source IP (1-512) | `32` |
| `idle_timeout` | Idle timeout in seconds (1-86400) | `300` |

### Security

| Directive | Description | Default |
|-----------|-------------|---------|
| `deny_private` | Block private/reserved destinations (`yes`/`no`) | `yes` |
| `connect_port` | Allowed CONNECT port (repeatable) | `443` |
| `allow` | Allow source address/CIDR (whitelist mode) | |
| `deny` | Deny source address/CIDR (blacklist mode) | |

### Access Control

Use `allow` or `deny` directives, but not both.
When `allow` is used, unlisted addresses are denied.
When `deny` is used, unlisted addresses are allowed.
Both IPv4 and IPv6 with optional CIDR prefix are supported.

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

## Platform Notes

### OpenBSD

- pledge(2) restricts syscalls to `stdio inet dns proc`
- unveil(2) restricts filesystem to `/etc/resolv.conf` and `/etc/hosts`
- SO_SPLICE provides zero-copy kernel relay for CONNECT tunnels
- accept4(2) with SOCK_NONBLOCK avoids extra fcntl(2) per connection
- Native strlcpy(3), closefrom(2), and strtonum(3)

### Linux

- seccomp-BPF restricts syscalls to an allowlist (I/O, networking, DNS, process forking)
- Supports x86_64 and aarch64
- POSIX-compatible fallbacks for BSD-specific functions
- Packages available as `.deb`, `.rpm`, `.apk`, and static binaries

### macOS

- POSIX-compatible fallbacks for BSD-specific functions

## License

BSD 2-Clause. See [LICENSE](LICENSE).
