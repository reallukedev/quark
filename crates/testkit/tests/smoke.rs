//! A first end-to-end check: sign in, ping, roster, a message between two accounts.

use quark_testkit::quark_core::{ns, Element};
use quark_testkit::{message, TestServer};

#[tokio::test]
async fn two_accounts_can_talk() -> anyhow::Result<()> {
    let s = TestServer::start().await?;
    s.add_user("alice", "password-a").await?;
    s.add_user("bob", "password-b").await?;
    let mut alice = s.online("alice", "password-a", "phone").await?;
    let mut bob = s.online("bob", "password-b", "laptop").await?;

    let pong = alice.iq_get(Some(s.domain()), Element::new("ping", ns::PING)).await?;
    assert_eq!(pong.attr("type"), Some("result"));

    alice.send(&message("bob@quark.test", "chat", "hello bob")).await?;
    let got = bob.expect(|e| e.name() == "message").await?;
    assert_eq!(got.child_text("body", ns::CLIENT).as_deref(), Some("hello bob"));
    assert_eq!(got.attr("from"), Some("alice@quark.test/phone"));
    Ok(())
}
