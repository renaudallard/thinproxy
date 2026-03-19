# thinproxy

Lightweight, asynchronous HTTP/HTTPS proxy written in C.

## Features

- HTTP request forwarding with header rewriting
- HTTPS tunneling via CONNECT method
- Single-threaded, non-blocking I/O using poll(2)
- Asynchronous DNS resolution via forked processes
- Small memory footprint (~25 KB per connection)
- CONNECT port whitelist and private address blocking (SSRF protection)
- Per-IP connection limits
- Configuration file with ACL support
- Privilege dropping after bind
- OpenBSD pledge(2) and unveil(2) support
- Syslog logging in daemon mode
- IPv4 and IPv6 support

## Build

    make

## Install

    make install

The default prefix is `/usr/local`. Override with:

    make install PREFIX=/usr DESTDIR=/tmp/pkg

## Usage

    thinproxy [-dVv] [-b address] [-f config] [-p port] [-u user]

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

Start with default settings:

    thinproxy

Use a custom configuration file:

    thinproxy -f /path/to/thinproxy.conf

Listen on all interfaces with verbose logging:

    thinproxy -v -b 0.0.0.0 -p 3128

Run as a daemon with privilege dropping:

    thinproxy -d -u nobody -p 8080

Use with curl:

    curl -x http://127.0.0.1:8080 http://example.com
    curl -x http://127.0.0.1:8080 https://example.com

## Configuration

Default path: `/etc/thinproxy.conf` (silently ignored if missing).

See `thinproxy.conf.example` for a full example.

### Directives

| Directive | Description |
|-----------|-------------|
| `listen <address>` | Bind address |
| `port <number>` | Listen port |
| `user <name>` | Drop privileges to user |
| `daemon <yes\|no>` | Run as daemon |
| `verbose <yes\|no>` | Verbose logging |
| `max_connections <n>` | Max concurrent connections (1-512) |
| `idle_timeout <n>` | Idle timeout in seconds |
| `max_connections_per_ip <n>` | Max concurrent connections per source IP |
| `deny_private <yes\|no>` | Block connections to private/reserved addresses |
| `connect_port <port>` | Allowed CONNECT port (whitelist, repeatable) |
| `allow <ip[/prefix]>` | Allow source address (whitelist mode) |
| `deny <ip[/prefix]>` | Deny source address (blacklist mode) |

### Access Control

Use `allow` or `deny` directives, but not both:

- **Whitelist mode**: when `allow` is used, all other addresses are denied
- **Blacklist mode**: when `deny` is used, all other addresses are allowed

Both IPv4 and IPv6 addresses are supported, with optional CIDR prefix.

Example whitelist:

    allow 127.0.0.1
    allow 192.168.1.0/24
    allow ::1

## Limits

- Maximum 512 concurrent connections (configurable)
- 8 KB buffer per direction per connection

## License

BSD 2-Clause. See [LICENSE](LICENSE).
