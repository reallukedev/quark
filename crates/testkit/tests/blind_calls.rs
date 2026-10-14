//! XEP-0215 External Service Discovery with the built-in TURN relay (RFC 8656) and STUN
//! (RFC 8489). Black-box: written from the specifications only.

mod blind_feat;

use std::net::SocketAddr;

use anyhow::{ensure, Context as _};
use blind_feat::*;
use quark::turn::stun::{attr, method, Class};
use quark_testkit::quark_core::{ns, Element};
use quark_testkit::turn::TurnClient;
use quark_testkit::{Client, TestServer};

#[derive(Debug, Clone)]
struct Service {
    kind: String,
    host: String,
    port: Option<u16>,
    transport: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

fn parse_services(el: &Element) -> Vec<Service> {
    let holder = el.get_child("services", ns::EXTDISCO).or_else(|| el.get_child("credentials", ns::EXTDISCO));
    holder
        .into_iter()
        .flat_map(|s| s.children().filter(|c| c.is("service", ns::EXTDISCO)))
        .map(|s| Service {
            kind: s.attr("type").unwrap_or("").to_string(),
            host: s.attr("host").unwrap_or("").to_string(),
            port: s.attr("port").and_then(|p| p.parse().ok()),
            transport: s.attr("transport").map(str::to_string),
            username: s.attr("username").map(str::to_string),
            password: s.attr("password").map(str::to_string),
        })
        .collect()
}

async fn server() -> anyhow::Result<(TestServer, Client)> {
    let s = TestServer::start().await?;
    s.set_settings(|st| st.calls.on = true).await?;
    s.add_user("alice", PW).await?;
    let c = s.login("alice", PW).await?;
    Ok((s, c))
}

async fn services(c: &mut Client, domain: &str, kind: Option<&str>) -> anyhow::Result<Vec<Service>> {
    let r = c.iq_get(Some(domain), Element::new("services", ns::EXTDISCO).attr_opt("type", kind)).await?;
    ensure!(is_result(&r), "services request failed: {r}");
    Ok(parse_services(&r))
}

/// A TURN service with credentials: from the list, or asked for with `<credentials/>`
/// (XEP-0215 §3.3).
async fn turn_with_credentials(c: &mut Client, domain: &str) -> anyhow::Result<(Service, String, String)> {
    let list = services(c, domain, None).await?;
    let turn =
        list.iter().find(|s| s.kind == "turn" || s.kind == "turns").cloned().with_context(|| format!("no turn service in {list:?}"))?;
    if let (Some(u), Some(p)) = (&turn.username, &turn.password) {
        return Ok((turn.clone(), u.clone(), p.clone()));
    }
    let mut svc = Element::new("service", ns::EXTDISCO).attr_set("host", turn.host.clone()).attr_set("type", turn.kind.clone());
    if let Some(p) = turn.port {
        svc.set_attr("port", p.to_string());
    }
    let r = c.iq_get(Some(domain), Element::new("credentials", ns::EXTDISCO).child(svc)).await?;
    ensure!(is_result(&r), "credentials request failed: {r}");
    let creds = parse_services(&r).into_iter().next().context("no service in credentials")?;
    Ok((turn, creds.username.context("no username")?, creds.password.context("no password")?))
}

/// The relay's local address on the port the service advertises (hosts in tests don't resolve).
fn relay_addr(s: &TestServer, svc: &Service) -> anyhow::Result<SocketAddr> {
    let listening = *s.listening.turn.first().context("the built-in relay isn't listening")?;
    if let Some(p) = svc.port {
        assert_eq!(p, listening.port(), "the advertised port is the relay's: {svc:?}");
    }
    Ok(listening)
}

/// XEP-0215 §4: the server advertises `urn:xmpp:extdisco:2`.
#[tokio::test]
async fn server_advertises_extdisco() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let info = disco_info(&mut c, Some(s.domain())).await?;
    ensure!(disco_features(&info).iter().any(|f| f == ns::EXTDISCO), "{info}");
    Ok(())
}

/// XEP-0215 §3.1: `services` lists STUN and TURN with host, port and transport; the TURN
/// entries carry (or can get) credentials. §3.2: filtering by type.
#[tokio::test]
async fn services_list_stun_and_turn() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let all = services(&mut c, s.domain(), None).await?;
    ensure!(all.iter().any(|v| v.kind == "stun"), "no stun: {all:?}");
    ensure!(all.iter().any(|v| v.kind == "turn"), "no turn: {all:?}");
    for v in &all {
        ensure!(!v.host.is_empty(), "every service has a host: {v:?}");
        if let Some(t) = &v.transport {
            ensure!(t == "udp" || t == "tcp", "transport {t}");
        }
    }
    let (_, u, p) = turn_with_credentials(&mut c, s.domain()).await?;
    ensure!(!u.is_empty() && !p.is_empty());

    let turn_only = services(&mut c, s.domain(), Some("turn")).await?;
    ensure!(!turn_only.is_empty() && turn_only.iter().all(|v| v.kind == "turn"), "type='turn' returns only turn: {turn_only:?}");
    Ok(())
}

/// RFC 8656 §7.2 with the XEP-0215 credentials: Allocate over UDP succeeds and returns a
/// relayed address (and a lifetime).
#[tokio::test]
async fn turn_allocate_with_credentials_udp() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (svc, u, p) = turn_with_credentials(&mut c, s.domain()).await?;
    let addr = relay_addr(&s, &svc)?;
    let mut t = TurnClient::udp(addr).await?.with_credentials(&u, &p);
    let relayed = t.allocate().await?;
    ensure!(relayed.port() != 0, "{relayed}");
    let r = t.refresh(600).await?;
    assert_eq!(r.class(), Class::Success, "refresh with the same credentials: {:?}", r.code());
    Ok(())
}

/// The same over TCP (RFC 8656 §3.1 allows TCP between client and server).
#[tokio::test]
async fn turn_allocate_with_credentials_tcp() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let list = services(&mut c, s.domain(), Some("turn")).await?;
    if !list.iter().any(|v| v.transport.as_deref() == Some("tcp")) {
        return Ok(()); // no TCP TURN advertised
    }
    let (svc, u, p) = turn_with_credentials(&mut c, s.domain()).await?;
    let addr = relay_addr(&s, &svc)?;
    let mut t = TurnClient::tcp(addr).await?.with_credentials(&u, &p);
    t.allocate().await?;
    Ok(())
}

/// RFC 8656 §7.2 / RFC 8489 §9.2: an unauthenticated Allocate gets a 401 challenge with REALM
/// and NONCE; wrong credentials get 401 again.
#[tokio::test]
async fn turn_rejects_missing_and_wrong_credentials() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let (svc, u, _) = turn_with_credentials(&mut c, s.domain()).await?;
    let addr = relay_addr(&s, &svc)?;

    let mut anon = TurnClient::udp(addr).await?;
    let r = anon
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        })
        .await?;
    assert_eq!(r.class(), Class::Error);
    assert_eq!(r.code(), Some(401));
    ensure!(r.text(attr::REALM).is_some(), "the challenge carries a REALM");
    ensure!(r.msg().get(attr::NONCE).is_some(), "the challenge carries a NONCE");

    let mut wrong = TurnClient::udp(addr).await?.with_credentials(&u, "definitely-not-the-password");
    let r = wrong
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        })
        .await?;
    assert_eq!(r.class(), Class::Error);
    assert_eq!(r.code(), Some(401), "wrong password");

    let mut stranger = TurnClient::udp(addr).await?.with_credentials("1999999999:nobody", "x");
    let r = stranger
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        })
        .await?;
    assert_eq!(r.code(), Some(401), "made-up username");
    Ok(())
}

/// RFC 8489 §6 / §14.2: a Binding request gets a success response whose XOR-MAPPED-ADDRESS
/// is the client's own address.
#[tokio::test]
async fn stun_binding() -> anyhow::Result<()> {
    let (s, mut c) = server().await?;
    let list = services(&mut c, s.domain(), Some("stun")).await?;
    let stun = list.first().context("no stun service")?;
    let addr = *s.listening.turn.first().context("no relay listening")?;
    if let Some(p) = stun.port {
        assert_eq!(p, addr.port(), "the advertised STUN port is the built-in server's: {stun:?}");
    }
    let mut t = TurnClient::udp(addr).await?;
    let r = t.request(method::BINDING, |_| {}).await?;
    assert_eq!(r.class(), Class::Success, "{:?}", r.code());
    assert_eq!(r.xor_addr(attr::XOR_MAPPED_ADDRESS), Some(t.local_addr()?));
    Ok(())
}

/// RFC 8656 §9–§12: two allocations relay data to each other once permissions exist, by
/// Send/Data indications and over a bound channel.
#[tokio::test]
async fn turn_relays_between_allocations() -> anyhow::Result<()> {
    use quark_testkit::turn::Relayed;
    let (s, mut c) = server().await?;
    let (svc, u, p) = turn_with_credentials(&mut c, s.domain()).await?;
    let addr = relay_addr(&s, &svc)?;
    let mut a = TurnClient::udp(addr).await?.with_credentials(&u, &p);
    let mut b = TurnClient::udp(addr).await?.with_credentials(&u, &p);
    let ra = a.allocate().await?;
    let rb = b.allocate().await?;
    assert_eq!(a.create_permission(rb).await?.class(), Class::Success);
    assert_eq!(b.create_permission(ra).await?.class(), Class::Success);

    a.send_indication(rb, b"hello through the relay").await?;
    let got = b.recv_data(std::time::Duration::from_secs(3)).await?.context("nothing relayed")?;
    assert_eq!(got, Relayed::Indication(ra, b"hello through the relay".to_vec()));

    assert_eq!(b.channel_bind(0x4000, ra).await?.class(), Class::Success);
    b.send_channel(0x4000, b"back on a channel").await?;
    let got = a.recv_data(std::time::Duration::from_secs(3)).await?.context("nothing relayed back")?;
    assert_eq!(got, Relayed::Indication(rb, b"back on a channel".to_vec()));
    Ok(())
}
