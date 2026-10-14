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
c2s_stanza_bytes = 262144         # also caps PEP items replies, with s2s_stanza_bytes
s2s_stanza_bytes = 524288
c2s_bytes_per_sec = 65536       # sustained, with a 4x burst
auth_timeout_secs = 60
resume_secs = 600               # how long a dropped phone can resume its session
max_queue = 10000               # stanzas queued for a slow client before it's cut off
max_sessions_per_account = 64
auth_failures_per_minute = 10   # per address
registrations_per_hour = 5      # per address, open sign-up

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
```

Check a file without starting: `quark check-config /path/to/quark.toml` (errors carry the line).
