# thinproxy

Lightweight, asynchronous HTTP/HTTPS proxy written in C. Zero dependencies, single file, minimal attack surface.

## Features

**Proxy**
- HTTP request forwarding with header rewriting
- HTTPS tunneling via CONNECT method
- IPv4 and IPv6 support

**Performance**
- Single-threaded, non-blocking I/O using poll(2)
- Asynchronous DNS resolution via forked processes
- Small memory footprint (~25 KB per connection)

**Security**
- Source IP access control lists (allow/deny with CIDR)
- CONNECT port whitelist
- Private/reserved address blocking (SSRF protection)
- Per-IP connection limits
- Privilege dropping after bind
- OpenBSD pledge(2) and unveil(2) support
- Syslog logging in daemon mode

## Build

```
make
```

## Install

```
make install
```

The default prefix is `/usr/local`. Override with:

```
make install PREFIX=/usr DESTDIR=/tmp/pkg
```

A systemd unit file is installed to `/lib/systemd/system/`. To enable:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now thinproxy
```

## Usage

```
thinproxy [-dVv] [-b address] [-f config] [-p port] [-u user]
```

### Options

| Flag | Description |
|------|-------------|
| `-b address` | Bind address (default: `127.0.0.1`) |
| `-d` | Daemonize and log to syslog |
| `-f config` | Configuration file (default: `/etc/thinproxy.conf`) |
| `-p port` | Listen port (default: `8080`) |
| `-u user` | Drop privileges to user after bind |
| `-V` | Print version and exit |
| `-v` | Verbose logging |

CLI flags override configuration file values.

### Examples

```sh
# Start with default settings
thinproxy

# Custom configuration file
thinproxy -f /path/to/thinproxy.conf

# Listen on all interfaces with verbose logging
thinproxy -v -b 0.0.0.0 -p 3128

# Run as a daemon with privilege dropping
thinproxy -d -u _thinproxy -p 8080

# Use with curl
curl -x http://127.0.0.1:8080 http://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

## Configuration

Default path: `/etc/thinproxy.conf` (silently ignored if missing).
See `thinproxy.conf.example` for a full example.

### General

| Directive | Description | Default |
|-----------|-------------|---------|
| `listen <address>` | Bind address | `127.0.0.1` |
| `port <number>` | Listen port | `8080` |
| `user <name>` | Drop privileges to user | none |
| `daemon <yes\|no>` | Run as daemon | `no` |
| `verbose <yes\|no>` | Verbose logging | `no` |

### Limits

| Directive | Description | Default |
|-----------|-------------|---------|
| `max_connections <n>` | Max concurrent connections (1-512) | `512` |
| `max_connections_per_ip <n>` | Max concurrent connections per source IP | unlimited |
| `idle_timeout <n>` | Idle timeout in seconds | `300` |

### Security

| Directive | Description | Default |
|-----------|-------------|---------|
| `deny_private <yes\|no>` | Block connections to private/reserved addresses | `no` |
| `connect_port <port>` | Allowed CONNECT port (whitelist, repeatable) | all |
| `allow <ip[/prefix]>` | Allow source address (whitelist mode) | |
| `deny <ip[/prefix]>` | Deny source address (blacklist mode) | |

### Access Control

Use `allow` or `deny` directives, but not both:

- **Whitelist mode**: when `allow` is used, all other addresses are denied
- **Blacklist mode**: when `deny` is used, all other addresses are allowed

Both IPv4 and IPv6 addresses are supported, with optional CIDR prefix.

Example whitelist:

```
allow 127.0.0.1
allow 192.168.1.0/24
allow ::1
```

### Hardened Example

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
```

## Limits

- Maximum 512 concurrent connections (compile-time)
- 8 KB buffer per direction per connection

## License

BSD 2-Clause. See [LICENSE](LICENSE).
