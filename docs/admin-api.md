# Quark admin API

Quark is managed through one JSON protocol, reachable two ways:

- **`quark ctl`** inside the container (or on the host). It reads one JSON request from standard
  input, sends it over the admin Unix socket (`<data_dir>/admin.sock`, mode 0600), prints one JSON
  response line and exits 0 (also on a refused request; non-zero only when the server can't be
  reached). This is what Gluon uses: `docker exec -i <container> quark ctl`, so no port is opened
  and secrets never show up in a process list.
- **HTTP** `POST /admin/api` on the web listener, with `Authorization: Bearer <admin token>`. The
  token lives in `<data_dir>/admin.token` (created on first start). Off unless `admin_http = true`.

## Envelope

Request:

```json
{ "cmd": "account.create", "args": { "host": "chat.example.com", "user": "sam", "password": "…", "role": "member" } }
```

Response:

```json
{ "ok": true, "value": { … } }
{ "ok": false, "code": "exists", "error": "There's already an account called sam@chat.example.com." }
```

`error` is a plain sentence meant to be shown to a person as is. `code` is stable and machine
readable: `invalid`, `not_found`, `exists`, `not_enabled`, `config`, `internal`.

All times are **milliseconds since the Unix epoch**. All JIDs are normalized (lowercase local and
domain parts).

## Shared shapes

`Settings` is exactly Gluon's `ChatSettings` (`src/lib/chat-types.ts`):

```ts
{
  signUp: "closed" | "invite" | "open",
  history: "off" | "1w" | "1m" | "3m" | "1y" | "never",
  groups: { on: boolean, host: string, whoCreates: "everyone" | "admins" },
  files: { on: boolean, host: string, maxMb: number, keepDays: number },
  push: boolean,
  federation: boolean,
  web: boolean,
  calls: { on: boolean, host: string },
  welcome: string | null,
  contact: string | null,
}
```

Quark applies every setting live. Nothing needs a restart.

`Invite`:

```ts
{ token: string, username: string | null, role: "member" | "admin", created: number, expires: number,
  uri: string /* xmpp:chat.example.com?register;preauth=TOKEN or xmpp:user@host?register;preauth=… */,
  page: string | null /* https://<host>/invite/<token> when web is on */, reusable: boolean, reset: boolean }
```

## Commands

### `status`
`{}` → `{ server: "quark", version: string, startedAt: number, configFile: string, dataDir: string }`.
Cheap; use it as a liveness check.

### `snapshot`
`{}` →

```ts
{
  server: "quark",
  version: string,            // e.g. "0.1.0"
  startedAt: number,
  configFile: string,         // path inside the container, e.g. /etc/quark/quark.toml
  certDir: string,            // where <host>.crt / <host>.key are picked up (hot reloaded)
  hosts: [{
    host: string,
    settings: Settings,
    admins: string[],         // JIDs listed in the config file (outrank roles set here)
    accounts: [{
      user: string,
      role: "member" | "admin",
      enabled: boolean,
      created: number | null,
      passwordChanged: number | null,
      lastActive: number | null,
      devices: [{ resource: string, client: string | null, ip: string | null, secure: boolean,
                  since: number | null, resumable: boolean, inactive: boolean }],
    }],
    invites: Invite[],
    rooms: [{ jid: string, name: string | null, description: string | null, public: boolean,
              membersOnly: boolean, persistent: boolean, occupants: number }],
    groupsHost: string | null,  // null when groups are off
    filesHost: string | null,   // null when files are off
    // Prosody-compatible module names for what is on, so Gluon's capability list works unchanged:
    // tls saslauth carbons pep bookmarks smacks csi_simple mam muc muc_mam http_file_share
    // cloud_notify s2s bosh websocket invites invites_register server_contact_info
    // turn_external external_services blocklist vcard4 vcard_legacy register ping time version
    // uptime lastactivity offline roster disco private account_activity welcome
    modules: string[],
    requireEncryption: boolean,
    tls: { selfSigned: boolean, notAfter: number | null, issuer: string | null } | null,
  }],
  turn: { builtIn: boolean, port: number, relayMin: number, relayMax: number, running: boolean },
  stats: { c2s: number, s2sIn: number, s2sOut: number, stanzasIn: number, stanzasOut: number },
}
```

### Accounts
- `account.create` `{ host, user, password, role: "member"|"admin" }` → `true`.
  `exists` when taken. Usernames match `^[a-z0-9][a-z0-9._-]{0,63}$`.
- `account.update` `{ host, user, password?, role?, enabled?, signOut?: true | "<resource>" }` →
  `{ closed: number }` (sessions closed). Turning an account off or changing its password also
  closes its sessions.
- `account.delete` `{ host, user }` → `true` (also when it didn't exist). Removes roster, archive,
  PEP data and closes sessions.

### Moving accounts (XEP-0227)
Accounts move between servers in the Portable Import/Export Format, which Prosody
(`mod_storage_xep0227`) and ejabberd (`export_piefxis` / `import_piefxis`) also read and write.

- `account.export` `{ host?: string, users?: string[] }` → `{ xml: string, accounts: number }`.
  Every account on every domain, or on `host`, or just `users` there (`not_found` when one doesn't
  exist). Each `<user/>` carries its SCRAM keys (Quark never has passwords), contacts, vCard,
  private XML storage, waiting offline messages, a `<account xmlns='urn:quark:pie:0' role
  enabled created/>` element, and whatever modules add (PEP, archives). **The keys let someone
  test passwords offline: treat an export like a password database.**
- `account.import` `{ xml: string, host?: string }` →
  `{ created: string[], skipped: [{ jid, reason }], notes: string[] }`. Only `host`'s accounts
  when given. Accounts that already exist, invalid usernames and domains this server doesn't
  serve are skipped (nothing is overwritten); `invalid` when the text isn't an export or holds no
  accounts. Up to 32 MB per request.
  - Keys come from `<scram-credentials/>` (SHA-1, SHA-256, SHA-512 sharing one salt), else from a
    plain `password` attribute (kept as is, even when shorter than Quark's minimum), else the
    account gets a random password and a note suggests a reset invite.
  - Prosody keeps SCRAM-SHA-1 keys only. Those accounts sign in with SCRAM-SHA-1 or PLAIN; apps
    that insist on SCRAM-SHA-256 fail until the first PLAIN sign-in, which fills in the other
    keys, or a new password. `notes` lists them.
  - Imports don't send welcome messages.

### Invites (XEP-0401 / XEP-0379)
- `invite.create` `{ host, username: string|null, role, days: number, reusable: boolean, reset?: boolean }`
  → `Invite`. `exists` when `username` is taken. With `reset: true` (and the `username` of an
  existing account) the link sets a new password instead of making an account, and signs the
  account's devices out. Returned invites also carry `inviter` (a JID, for invites members made
  for friends, or null) and `uses`.
- `invite.revoke` `{ host, token }` → `true`.
- `invite.peek` `{ host, token }` → `{ expires, username, uri } | null`.

### Group chats
- `room.create` `{ service, room, name, description, public, membersOnly, owner: string|null }` → `{ jid }`.
- `room.destroy` `{ jid, reason: string|null }` → `true`.

### Settings
- `settings.get` `{ host }` → `Settings`.
- `settings.set` `{ host, settings: Settings }` → `{ applied: true, notes: string[] }`.

### Config file
- `config.get` `{}` → `{ file: string, text: string }`.
- `config.check` `{ text }` → `{ ok: boolean, line: number | null, message: string }`.
- `config.set` `{ text }` → `{ ok: true }` after checking, writing atomically and reloading.
  Refused with `config` when the text doesn't check.
- `reload` `{}` → `{ reloaded: true, certs: number }`. Re-reads the config file and certificates.

### Calls (XEP-0215)
- `turn.set` `{ secret: string | null, host: string | null, port: number | null }` → `true`.
  With a secret, Quark hands out time-limited TURN credentials (coturn's `use-auth-secret`
  scheme) for an external relay. Without one, it uses its built-in relay when that's enabled.

### Messages
- `message.send` `{ from: string /* bare or full JID on this server, or the domain */, to: string,
  body: string, subject?: string }` → `true`. For server notifications (Gluon alerts) without
  signing in as a client.
