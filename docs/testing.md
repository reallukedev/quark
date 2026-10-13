# Writing protocol tests

Integration tests live in `crates/testkit/tests/*.rs` and drive a real Quark server through the
XMPP protocol, as a client would. Run them with `cargo test -p quark-testkit`.

## The test kit (`quark_testkit`)

```rust
use quark_testkit::{message, presence, Client, Options, TestServer, DOMAIN};
use quark_testkit::quark_core::{ns, Element};

let s = TestServer::start().await?;                 // domain "quark.test", random ports, temp dir
let s = TestServer::start_with(Options { allow_plain: true, ..Default::default() }).await?;
s.add_user("alice", "password1").await?;           // passwords: 8+ characters
s.add_admin("root", "password1").await?;
s.set_settings(|st| st.sign_up = quark::settings::SignUp::Open).await?;   // live settings (Gluon's ChatSettings shape)

let mut a = s.login("alice", "password1").await?;  // STARTTLS + SCRAM-SHA-256 + bind "test"
let mut a = s.login_as("alice", "password1", "phone").await?;
let mut a = s.online("alice", "password1", "phone").await?; // + roster get + initial presence

// Lower level:
let mut c = Client::connect(s.c2s(), DOMAIN).await?;   // opens the stream, reads features
c.features;            // Option<Element>: <stream:features/>
c.mechanisms();        // SASL mechanisms offered
c.starttls().await?;   // then a new stream (features refreshed)
c.auth_plain(user, pw).await?;
c.auth_scram("SCRAM-SHA-1" | "SCRAM-SHA-256" | "SCRAM-SHA-512" | "…-PLUS", user, pw).await?;
c.bind(Some("res")).await?;     // -> full JID; c.jid / c.bare()
let c = Client::connect_tls(s.c2s_tls(), DOMAIN).await?; // direct TLS (XEP-0368)
c.exporter;            // tls-exporter channel binding bytes (TLS 1.3)

c.send(&el).await?;  c.send_raw("<presence/>").await?;
c.recv().await?;                         // next top-level element (5 s timeout, errors if closed)
c.recv_within(Duration).await?;          // Option<Element>
c.expect(|e| e.name() == "message").await?;   // skips (and keeps) non-matching elements
c.expect_silence(Duration).await?;
c.iq("get" | "set", Some(to) | None, payload).await?;   // waits for the reply with that id
c.iq_get(..)  c.iq_set(..)  c.answer(&iq)              // answer an IQ the server sent
c.close().await?;            // </stream:stream>
c.drop_connection();         // vanish without closing (e.g. to test stream resumption)

message(to, "chat", "body")  presence(Some(to), Some("subscribe"))
```

## Elements (`quark_core::Element`)

```rust
Element::new("query", ns::ROSTER)                      // name, namespace
    .attr_set("ver", "1").attr_opt("node", maybe)      // builder
    .child(Element::new("item", ns::ROSTER))
    .text_child("body", ns::CLIENT, "hi")
    .text("…");
el.name(); el.ns(); el.is("iq", ns::CLIENT); el.attr("type");
el.get_child("bind", ns::BIND); el.has_child(..); el.children(); el.first_child();
el.text_content(); el.child_text("body", ns::CLIENT);
el.set_attr(k, v); el.append(child); el.to_xml(); Element::parse(xml)?;
quark_core::stanza::{iq, iq_result, error_reply, StanzaError::from_stanza(&el)}
```

Stanzas the client receives are in `ns::CLIENT` (`jabber:client`); stream-level elements in
`ns::STREAM`; SASL in `ns::SASL`, SASL2 in `ns::SASL2`, and so on (`quark_core::ns` has the
common namespaces as constants).
