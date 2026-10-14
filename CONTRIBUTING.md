# Contributing to Quark

Thanks for helping. Bug reports, client-compatibility reports and pull requests are all welcome.

## Reporting a bug

Open an issue with: the Quark version (`quark --version`), the chat app and version you used,
what you did, what you expected and what happened. Logs help (`QUARK_LOG=quark=debug`); remove
passwords, tokens and personal addresses first. Security problems go to [SECURITY.md](SECURITY.md)
instead, never to a public issue.

## Working on the code

```sh
cargo test --workspace          # unit tests and the protocol suite (a real server per test)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Read [docs/architecture.md](docs/architecture.md) first: features are `Module`s, and most changes
touch one module plus its tests. Some ground rules:

- Follow the RFC or XEP you're implementing exactly where clients depend on it, and say which in
  a comment. Behaviour beyond the spec must not break standard clients.
- No `unwrap()`/`expect()` on anything that came from the network, no locks held across `.await`,
  no blocking on the async runtime, and a limit on everything a remote party can grow.
- Every behaviour change comes with a test, usually an integration test in
  `crates/testkit/tests/` that drives the server through the protocol
  ([docs/testing.md](docs/testing.md)).
- Errors shown to people are plain sentences.
- New dependencies should be popular, well maintained crates.

Keep pull requests focused, and describe what changed and how you tested it.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
