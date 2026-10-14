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
| `QUARK_TURN_EXTERNAL_IP` | Overrides `turn.external_ip`: the public IP the call relay advertises. Needed in Docker and behind NAT. |

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
registrations_per_hour = 5      # per address (IPv6: per /64) for open sign-up; 4x for members' invites, 4x that in attempts

[tls]
cert_dir = "/etc/quark/certs"   # <domain>.crt + <domain>.key, or <domain>/fullchain.pem + privkey.pem; reloaded on change
require_c2s = true
self_signed_fallback = true

[http]
public_url = "https://chat.example.com"   # default https://<domain>
admin_api = false                         # POST /admin/api with the token in <data_dir>/admin.token
trusted_proxies = ["127.0.0.0/8", "::1"]  # reverse proxies whose X-Forwarded-For/-Proto count (see below)
metrics = true                            # /metrics for loopback, or private clients through a trusted proxy (see below)
metrics_token = "long-random-string"      # optional: /metrics then needs "Authorization: Bearer <token>", from anywhere
strip_photo_metadata = false              # strip EXIF/GPS from JPEG uploads (breaks shared file hashes; see below)

[s2s]
require_tls = true
require_valid_certs = false   # true: only servers whose certificate verifies (no self-signed)
idle_secs = 900
blocked = ["spam.example"]
allow_networks = []           # private networks other servers may be found at through DNS, e.g. ["10.0.0.0/8"]

[s2s.routes]                  # fixed addresses instead of DNS (always followed, private ones too)
"chat.internal" = "10.0.0.5:5269"   # or "tls://10.0.0.5:5270" for direct TLS

[turn]
enabled = true
listen = "0.0.0.0:3478"
public_host = "turn.example.com"   # optional, defaults to the calls host
external_ip = "203.0.113.7"        # when behind NAT or in Docker (or QUARK_TURN_EXTERNAL_IP)
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

Without `external_ip`, relayed addresses are advertised at the address the machine uses to reach
the client. Inside a container or behind NAT that is a private address phones on the internet
can't reach, so calls that need the relay fail; the server logs a warning the first time it
hands one out. Set `external_ip` (or `QUARK_TURN_EXTERNAL_IP`) to the public address. The relay
treats it as one of its own: peers there only reach its relayed ports.

Relayed addresses that never get a permission end after 3 minutes, so the ones phones open while
setting up a call and don't use give their ports back quickly. The listener on `[::]` also takes
IPv4 (UDP and TCP). TCP connections must authenticate within 30 seconds and one address (or IPv6
/64) may have at most 16 open.

### Federation and private addresses

Whoever runs a domain's DNS decides where this server connects when it delivers to that domain
or checks a dialback key for it. So without a route, federation only connects to public
addresses: loopback, private, link-local, cloud metadata and reserved ones are skipped, and a
domain that points only there fails as if it had no server. Otherwise a stranger could make the
server probe its own machine and network on any port. Servers on a private network federate
through `[s2s.routes]` or by listing their networks in `allow_networks`.

### Reverse proxies

`X-Forwarded-For` and `X-Forwarded-Proto` are only believed from addresses in
`trusted_proxies`, by default loopback alone; from anyone else they are ignored, since any client
could send them. A proxy on another machine or container must be listed, e.g.
`trusted_proxies = ["172.17.0.0/16"]` for nginx or Caddy in Docker. Being on a private network
doesn't make an address a proxy: under Docker every client reaches the server from the bridge
address. The client address decides sign-in and sign-up limits, so list only your proxies.

Each address (or IPv6 /64) may have at most 512 web connections open; trusted proxies, which
carry everyone's connections, aren't counted.

### Metrics behind a proxy

Without `metrics_token`, `/metrics` answers direct requests from loopback, and requests from a
trusted proxy whose `X-Forwarded-For` names a private client. Other private addresses (a
Prometheus container, the Docker bridge) need the token. A request with other proxy headers
(`X-Forwarded-Proto`, `X-Real-IP`, `Forwarded`, `Via`) but no `X-Forwarded-For` is refused, since
the proxy's own address says nothing about the client. A proxy that adds no headers at all
(nginx's default `proxy_pass`) on loopback looks exactly like a local scraper, so if yours
forwards `/metrics` that way, set `metrics_token` (or don't route `/metrics` through it). With a
token set, only the token counts: local requests need it as well.

### Photo metadata

With `strip_photo_metadata = true`, JPEG uploads lose EXIF (camera, time, GPS), XMP, IPTC and
comments as they stream in (the orientation is kept). It's off by default because the stored file
then differs from what was sent: clients that share a file's hash and size with its link
(XEP-0446/0447 stateless file sharing, used by Dino and Gajim) check the download against them and
reject it as corrupt. Most phone apps (Conversations, Monal, Siskin) strip location data before
uploading anyway. Turn it on when you'd rather protect people whose apps don't, and accept that
those hash checks fail for JPEGs.

Check a file without starting: `quark check-config /path/to/quark.toml` (errors carry the line).
