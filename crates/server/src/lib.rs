//! Quark, an XMPP server in one binary. See `docs/` for the protocol coverage and the admin API.

pub mod accounts;
pub mod admin;
pub mod c2s;
pub mod config;
pub mod db;
pub mod http;
pub mod modules;
pub mod router;
pub mod run;
pub mod s2s;
pub mod sasl;
pub mod server;
pub mod sessions;
pub mod settings;
pub mod tls;
pub mod transport;
pub mod turn;
