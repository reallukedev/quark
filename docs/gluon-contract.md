# What Gluon relies on

Gluon (`src/server/chat/quark.ts`, `quark-map.ts`, `backend.ts`) drives Quark through
[the admin API](admin-api.md). Beyond the API itself, it assumes:

1. **First start in an empty `/etc/quark`** creates `quark.toml` (with the domains from
   `QUARK_DOMAIN` and admins from `QUARK_ADMINS`) and the `/etc/quark/certs` folder.
2. **The container user is named `quark`** in `/etc/passwd`; Gluon chowns copied keys to it.
   `quark ctl` works as the container's default user.
3. **The snapshot always lists `invites` and `invites_register`** in `modules`, even when sign-up
   is `closed` (admins can still invite).
4. **Notifications**: Gluon creates `gluon@<domain>` (member; `exists` is fine), then calls
   `message.send` from `gluon@<domain>/notify`, one message per recipient. A local recipient
   without an account answers `not_found`. For a group chat it sends
   `from: "<room>@<service>/<nick>"`, `to: "<room>@<service>"`, which Quark posts into the room as a
   groupchat message under that nick.
5. **`turn.builtIn: false`** means the built-in relay is turned off in the config; `turn.running`
   means it is listening.
6. **`settings.set` notes** are plain sentences shown to people. **`config.check` `line`** is
   1-based or null. **`config.get` returns the exact file text** (Gluon compares it to catch
   stale saves).
7. **`invite.page` is null when the web side is off**; Gluon then uses its own page and
   `invite.peek`.
8. Image `ghcr.io/reallukedev/quark:0.1`; project URL `https://github.com/reallukedev/quark`.
