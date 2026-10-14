# Architecture

Quark is a Cargo workspace:

- `crates/core` (`quark-core`): the XML tree (`Element`), a streaming XML parser with hard size
  limits, JIDs (RFC 7622), stanza errors and helpers (`stanza::error_reply`, `iq_result`, `iq`),
  namespaces (`ns`), XEP-0082 times (`time`).
- `crates/server` (`quark`, lib + bin): the server.
- `crates/testkit` (`quark-testkit`): a real server on random ports plus a raw client, for
  integration tests in `crates/testkit/tests/`.

## The server crate

| Path | What |
|---|---|
| `config.rs` | `quark.toml` (listeners, TLS, limits, s2s, turn). Changes need `reload`. |
| `settings.rs` | Per-domain chat settings (Gluon's `ChatSettings` shape), live, in the DB. |
| `db.rs` | SQLite: one writer, readers in WAL, `db.read(|c| …)` / `db.write(|tx| …)` on blocking threads, per-module `Migration`s. |
| `accounts.rs` | Accounts, SCRAM keys (no passwords stored), roles. |
| `sasl.rs` | PLAIN, SCRAM-SHA-1/256/512(-PLUS), FAST. |
| `tls.rs` | Cert store: SNI, wildcards, hot reload, self-signed fallback, channel binding data. |
| `transport.rs` | `Transport` (negotiation) and `StanzaReader`/`StanzaWriter` (sessions). TCP here; WebSocket implements the same traits. |
| `c2s/` | Listeners, negotiation (STARTTLS, SASL, SASL2 + Bind2, FAST, resume), and the session actor (`session.rs`: XEP-0198, CSI buffering, write batching, backpressure). |
| `sessions.rs` | Registry of sessions by bare JID; `SessionHandle::send(el)` queues a stanza. |
| `router.rs` | `from_client` (client stanzas), `route` (anything with trusted from/to), message delivery, carbons. |
| `server.rs` | `Server`: hosts, components, modules, `request()` for server-originated IQs, kv store. |
| `modules/` | Features (see below). |
| `s2s/`, `http/`, `admin/`, `turn/` | Federation, web listener, admin API + `quark ctl`, TURN relay. |

## Modules

A feature implements `modules::Module` and is listed in `modules::all()` (order = hook order).
A module can:

- own tables (`migrations()`; rows tied to an account reference
  `accounts(host, user) ON DELETE CASCADE`),
- answer IQs (`iq_namespaces()` + `handle_iq(&IqCtx)`), for the server domain
  (`IqTarget::Server`) or an account's bare JID (`IqTarget::Account`). Return
  `ok(payload)`, `ok_empty()`, `Err(StanzaError)`, or `Ok(IqReply::Handled)` when it replied
  itself (send everything through `srv.route(..)` or the session so order is kept),
- add disco features/identities/forms/items and stream features,
- provide components on subdomains (`components()`, rebuilt whenever settings change),
- hook the pipeline: `stanza_out`, `stanza_in`, `message_out`, `message_in`,
  `message_undelivered` (return `Flow::Continue | Stop | Reject(err)`),
- react to `Event`s (session started/ended, available presence, subscription changes,
  account created/deleted, settings changed),
- run background tasks in `start()`.
- carry their per-account data in account exports and imports (XEP-0227,
  `export_account()` / `import_account()`; see `admin/pie.rs`).

Rules of thumb:

- Never hold a `parking_lot` lock across `.await` (use helpers like `SessionHandle::last_presence()`).
- Never block the runtime: database calls go through `db.read`/`db.write`, CPU-heavy work
  through `spawn_blocking`.
- Errors shown to people are plain sentences (`StanzaError::with_text`).
- Unknown or malformed input gets a protocol error, never a panic. No `unwrap()` outside tests.
- `cargo fmt`, `cargo clippy --all-targets` clean, tests for every behaviour.
