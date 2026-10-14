# Configuration

Quark reads `quark.toml` (default `/etc/quark/quark.toml`, or `--config` / `QUARK_CONFIG`). Every
key is optional. On first start without a file, Quark writes a starter one from the environment.

Day-to-day chat settings (who can sign up, history, group chats, files, push, federation, web,
calls, welcome message, admin contact) are **not** in this file: they live in the database, apply
live, and are changed with `quark ctl` (`settings.set`) or Gluon. A `[host.settings]` table only
seeds them for a domain Quark hasn't seen before.

## Environment

| Variable | Effect |
|---|---|
| `QUARK_CONFIG` | Path of the config file. |
| `QUARK_DOMAIN` | Comma-separated domains to serve, added to those in the file. |
| `QUARK_ADMINS` | Comma-separated admin JIDs (each added to its domain). |
| `QUARK_DATA_DIR` | Overrides `server.data_dir`. |
| `QUARK_LOG` | Overrides `server.log` (a `tracing` filter, e.g. `quark=debug`). |

## Reference

```toml
[server]
data_dir = "/var/lib/quark"   # database, uploads, admin socket, self-signed certificates
log = "info"

[[host]]
domain = "chat.example.com"
admins = ["you@chat.example.com"]   # outrank roles set through the admin API
[host.settings]                     # optional seed, Gluon's ChatSettings shape (snake or camel case)
sign_up = "invite"                  # closed | invite | open
history = "3m"                      # off | 1w | 1m | 3m | 1y | never

[listen]
c2s = ["[::]:5222"]        # clients, STARTTLS
c2s_tls = ["[::]:5223"]    # clients, TLS from the first byte (XEP-0368)
s2s = ["[::]:5269"]        # other servers
s2s_tls = ["[::]:5270"]
http = ["[::]:5280"]       # WebSocket, BOSH, uploads, invite pages, metrics (plain HTTP; put a TLS proxy in front)

[limits]
c2s_stanza_bytes = 262144
s2s_stanza_bytes = 524288
c2s_bytes_per_sec = 65536       # sustained, with a 4x burst
auth_timeout_secs = 60
resume_secs = 600               # how long a dropped phone can resume its session
max_queue = 10000               # stanzas queued for a slow client before it's cut off
max_sessions_per_account = 64
auth_failures_per_minute = 10   # per address
registrations_per_hour = 5      # per address (IPv6: per /64) for open sign-up; 4x for members' invites, 4x that in attempts

[tls]
cert_dir = "/etc/quark/certs"   # <domain>.crt + <domain>.key, or <domain>/fullchain.pem + privkey.pem; reloaded on change
require_c2s = true
self_signed_fallback = true

[http]
public_url = "https://chat.example.com"   # default https://<domain>
admin_api = false                         # POST /admin/api with the token in <data_dir>/admin.token
metrics = true                            # /metrics for loopback and private addresses

[s2s]
require_tls = true
idle_secs = 900
blocked = ["spam.example"]

[turn]
enabled = true
listen = "0.0.0.0:3478"
public_host = "turn.example.com"   # optional, defaults to the calls host
external_ip = "203.0.113.7"        # optional, when behind NAT
relay_min = 49160
relay_max = 49200

[turn.quota]
allocations = 1000            # relayed addresses open at once, in total
allocations_per_user = 16     # per account, but at most an eighth of the port range (min 2)
kbps = 10000                  # per relayed address, both directions; 0 for no limit
max_lifetime_secs = 3600

[turn.peers]
allow_private = false         # relay to 10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7
allow_loopback = false        # tests only
allow = []                    # networks always allowed, e.g. ["10.1.0.0/16"]
deny = []                     # networks never relayed to
```

The relay only sends where `turn.peers` allows. Loopback, link-local, cloud metadata endpoints,
multicast and reserved ranges are always refused. So are all of the machine's own addresses
(every interface, docker bridges included, re-listed every 30 seconds), except the relay's own
relayed ports, which is how two callers on the same server reach each other.

Private networks are off by default. Turning `allow_private` on lets any account send UDP to
every device on the server's networks (the router, a NAS, containers). Calls don't need it: two
phones on the same home Wi-Fi either connect directly or, when that fails, meet through their
relayed addresses on this server. Turn it on, or better list the networks in `allow`, only if
peers really live on a private network the server can route to, such as a VPN.

Relayed addresses that never get a permission end after 3 minutes, so the ones phones open while
setting up a call and don't use give their ports back quickly. The listener on `[::]` also takes
IPv4 (UDP and TCP). TCP connections must authenticate within 30 seconds and one address (or IPv6
/64) may have at most 16 open.

Check a file without starting: `quark check-config /path/to/quark.toml` (errors carry the line).
