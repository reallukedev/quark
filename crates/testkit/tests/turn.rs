//! The built-in STUN/TURN relay (RFC 8489, RFC 8656), driven over real sockets.

use std::net::SocketAddr;
use std::time::Duration;

use quark::turn::stun::{attr, method, Class, Writer};
use quark_testkit::turn::{Relayed, TurnClient};
use quark_testkit::{Options, TestServer};
use tokio::net::UdpSocket;

const QUIET: Duration = Duration::from_millis(300);

/// Tests relay to sockets on 127.0.0.1, which a real server refuses.
const LOOPBACK_PEERS: &str = "\n[turn.peers]\nallow_loopback = true\n";

async fn server(extra: &str) -> anyhow::Result<TestServer> {
    TestServer::start_with(Options { extra_config: extra.into(), ..Default::default() }).await
}

fn udp(s: &TestServer) -> SocketAddr {
    s.listening.turn[0]
}

fn tcp(s: &TestServer) -> SocketAddr {
    s.listening.turn[1]
}

fn secret(s: &TestServer) -> String {
    s.srv.turn.relay().expect("the relay is running").secret().to_string()
}

fn creds(s: &TestServer, user: &str) -> (String, String) {
    let c = quark::turn::rest_credentials(&secret(s), user, 3600, quark_testkit::quark_core::time::now_ms());
    (c.username, c.password)
}

async fn client(s: &TestServer, user: &str) -> anyhow::Result<TurnClient> {
    let (u, p) = creds(s, user);
    Ok(TurnClient::udp(udp(s)).await?.with_credentials(&u, &p))
}

async fn peer() -> anyhow::Result<UdpSocket> {
    Ok(UdpSocket::bind("127.0.0.1:0").await?)
}

async fn peer_recv(p: &UdpSocket) -> anyhow::Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut buf = [0u8; 2048];
    match tokio::time::timeout(QUIET * 5, p.recv_from(&mut buf)).await {
        Err(_) => Ok(None),
        Ok(r) => {
            let (n, from) = r?;
            Ok(Some((buf[..n].to_vec(), from)))
        }
    }
}

#[tokio::test]
async fn binding_requests_get_the_senders_address_over_udp_and_tcp() -> anyhow::Result<()> {
    let s = server("").await?;
    for mut c in [TurnClient::udp(udp(&s)).await?, TurnClient::tcp(tcp(&s)).await?] {
        let r = c.request(method::BINDING, |_| {}).await?;
        assert_eq!(r.class(), Class::Success);
        assert_eq!(r.xor_addr(attr::XOR_MAPPED_ADDRESS), Some(c.local_addr()?));
        assert!(!r.msg().has_integrity());
    }
    Ok(())
}

#[tokio::test]
async fn a_bare_binding_request_gets_a_small_answer() -> anyhow::Result<()> {
    let s = server("").await?;
    let mut c = TurnClient::udp(udp(&s)).await?;
    let mut req = Vec::new();
    Writer::new(&mut req, method::BINDING, Class::Request, [3; 12]);
    let r = c.exchange(&req, [3; 12]).await?;
    // Header plus XOR-MAPPED-ADDRESS for IPv4, nothing more.
    assert_eq!(r.raw.len(), 20 + 12);
    Ok(())
}

#[tokio::test]
async fn allocating_without_credentials_is_challenged_with_realm_and_nonce() -> anyhow::Result<()> {
    let s = server("").await?;
    let mut c = TurnClient::udp(udp(&s)).await?;
    let r = c
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        })
        .await?;
    assert_eq!(r.class(), Class::Error);
    assert_eq!(r.code(), Some(401));
    assert_eq!(r.text(attr::REALM).as_deref(), Some("quark.test"));
    assert!(r.msg().get(attr::NONCE).is_some_and(|n| !n.is_empty()));
    assert!(!r.msg().has_integrity());
    Ok(())
}

#[tokio::test]
async fn wrong_passwords_are_refused_with_a_fresh_challenge() -> anyhow::Result<()> {
    let s = server("").await?;
    let (u, _) = creds(&s, "alice@quark.test");
    let mut c = TurnClient::udp(udp(&s)).await?.with_credentials(&u, "not-the-password");
    let r = c
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        })
        .await?;
    assert_eq!(r.code(), Some(401));
    assert!(r.text(attr::REALM).is_some());
    assert!(r.msg().get(attr::NONCE).is_some());
    Ok(())
}

#[tokio::test]
async fn expired_credentials_are_refused() -> anyhow::Result<()> {
    let s = server("").await?;
    let past = quark_testkit::quark_core::time::now_ms() - 7_200_000;
    let c = quark::turn::rest_credentials(&secret(&s), "alice@quark.test", 3600, past);
    let mut t = TurnClient::udp(udp(&s)).await?.with_credentials(&c.username, &c.password);
    assert!(t.allocate().await.is_err());
    Ok(())
}

#[tokio::test]
async fn credentials_for_another_secret_are_refused() -> anyhow::Result<()> {
    let s = server("").await?;
    let c = quark::turn::rest_credentials("someone-elses-secret", "alice@quark.test", 3600, quark_testkit::quark_core::time::now_ms());
    let mut t = TurnClient::udp(udp(&s)).await?.with_credentials(&c.username, &c.password);
    assert!(t.allocate().await.is_err());
    Ok(())
}

#[tokio::test]
async fn relays_between_a_client_and_a_peer_with_send_and_data_indications() -> anyhow::Result<()> {
    let s = server(LOOPBACK_PEERS).await?;
    let mut c = client(&s, "alice@quark.test").await?;
    let relayed = c.allocate().await?;
    assert_eq!(relayed.ip(), udp(&s).ip());
    assert!((49160..=49200).contains(&relayed.port()));

    let r = c.refresh(1200).await?;
    assert_eq!(r.class(), Class::Success);
    assert_eq!(r.u32(attr::LIFETIME), Some(1200));
    assert!(r.msg().has_integrity());

    let p = peer().await?;
    let paddr = p.local_addr()?;
    assert_eq!(c.create_permission(paddr).await?.class(), Class::Success);

    c.send_indication(paddr, b"hello peer").await?;
    let (got, from) = peer_recv(&p).await?.expect("the peer gets the data");
    assert_eq!(got, b"hello peer");
    assert_eq!(from, relayed);

    p.send_to(b"hello client", relayed).await?;
    assert_eq!(c.recv_data(QUIET * 5).await?, Some(Relayed::Indication(paddr, b"hello client".to_vec())));
    Ok(())
}

#[tokio::test]
async fn channel_data_flows_both_ways_over_udp_and_tcp() -> anyhow::Result<()> {
    let s = server(LOOPBACK_PEERS).await?;
    let (u, pw) = creds(&s, "bob@quark.test");
    for mut c in [TurnClient::udp(udp(&s)).await?.with_credentials(&u, &pw), TurnClient::tcp(tcp(&s)).await?.with_credentials(&u, &pw)] {
        let relayed = c.allocate().await?;
        let p = peer().await?;
        let paddr = p.local_addr()?;
        assert_eq!(c.channel_bind(0x4001, paddr).await?.class(), Class::Success);
        // Rebinding the same pair refreshes it.
        assert_eq!(c.channel_bind(0x4001, paddr).await?.class(), Class::Success);

        c.send_channel(0x4001, b"odd").await?;
        assert_eq!(peer_recv(&p).await?, Some((b"odd".to_vec(), relayed)));
        p.send_to(b"back at you", relayed).await?;
        assert_eq!(c.recv_data(QUIET * 5).await?, Some(Relayed::Channel(0x4001, b"back at you".to_vec())));
    }
    Ok(())
}

#[tokio::test]
async fn channel_binds_that_conflict_are_refused() -> anyhow::Result<()> {
    let s = server(LOOPBACK_PEERS).await?;
    let mut c = client(&s, "alice@quark.test").await?;
    c.allocate().await?;
    let (a, b) = (peer().await?.local_addr()?, peer().await?.local_addr()?);
    assert_eq!(c.channel_bind(0x4000, a).await?.class(), Class::Success);
    assert_eq!(c.channel_bind(0x4000, b).await?.code(), Some(400));
    assert_eq!(c.channel_bind(0x4002, a).await?.code(), Some(400));
    assert_eq!(c.channel_bind(0x3FFF, b).await?.code(), Some(400));
    Ok(())
}

#[tokio::test]
async fn peers_without_a_permission_get_nothing_through() -> anyhow::Result<()> {
    let s = server(LOOPBACK_PEERS).await?;
    let mut c = client(&s, "alice@quark.test").await?;
    let relayed = c.allocate().await?;
    let stranger = peer().await?;
    stranger.send_to(b"let me in", relayed).await?;
    assert_eq!(c.recv_data(QUIET).await?, None);
    c.send_indication(stranger.local_addr()?, b"psst").await?;
    let mut buf = [0u8; 64];
    assert!(tokio::time::timeout(QUIET, stranger.recv_from(&mut buf)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn loopback_and_metadata_peers_are_forbidden_by_default() -> anyhow::Result<()> {
    let s = server("").await?;
    let mut c = client(&s, "alice@quark.test").await?;
    c.allocate().await?;
    for p in ["127.0.0.2:5222", "169.254.169.254:80", "0.0.0.0:9", "224.0.0.251:5353"] {
        assert_eq!(c.create_permission(p.parse()?).await?.code(), Some(403), "{p}");
        assert_eq!(c.channel_bind(0x4000, p.parse()?).await?.code(), Some(403), "{p}");
    }
    // A public address is fine.
    assert_eq!(c.create_permission("8.8.8.8:3478".parse()?).await?.class(), Class::Success);
    Ok(())
}

#[tokio::test]
async fn the_servers_own_address_only_reaches_its_own_relayed_addresses() -> anyhow::Result<()> {
    // Here the relay's own address is 127.0.0.1. Other callers' relayed addresses there are fine
    // to talk to, but no other service on the box is.
    let s = server("").await?;
    let mut c = client(&s, "alice@quark.test").await?;
    c.allocate().await?;
    let service = peer().await?;
    assert_eq!(c.create_permission(service.local_addr()?).await?.class(), Class::Success);
    c.send_indication(service.local_addr()?, b"knock knock").await?;
    let mut buf = [0u8; 64];
    assert!(tokio::time::timeout(QUIET, service.recv_from(&mut buf)).await.is_err());
    Ok(())
}

#[tokio::test]
async fn two_callers_on_the_same_relay_reach_each_other() -> anyhow::Result<()> {
    // Without loopback peers allowed: the relay hands packets between its own allocations.
    let s = server("").await?;
    let mut a = client(&s, "alice@quark.test").await?;
    let mut b = client(&s, "bob@quark.test").await?;
    let (ra, rb) = (a.allocate().await?, b.allocate().await?);
    assert_eq!(a.create_permission(rb).await?.class(), Class::Success);
    assert_eq!(b.create_permission(ra).await?.class(), Class::Success);
    a.send_indication(rb, b"hi bob").await?;
    assert_eq!(b.recv_data(QUIET * 5).await?, Some(Relayed::Indication(ra, b"hi bob".to_vec())));
    assert_eq!(b.channel_bind(0x4abc, ra).await?.class(), Class::Success);
    b.send_indication(ra, b"hi alice").await?;
    assert_eq!(a.recv_data(QUIET * 5).await?, Some(Relayed::Indication(rb, b"hi alice".to_vec())));
    a.send_indication(rb, b"on the channel").await?;
    assert_eq!(b.recv_data(QUIET * 5).await?, Some(Relayed::Channel(0x4abc, b"on the channel".to_vec())));
    Ok(())
}

#[tokio::test]
async fn releasing_an_allocation_ends_it() -> anyhow::Result<()> {
    let s = server(LOOPBACK_PEERS).await?;
    let mut c = client(&s, "alice@quark.test").await?;
    c.allocate().await?;
    let r = c.refresh(0).await?;
    assert_eq!((r.class(), r.u32(attr::LIFETIME)), (Class::Success, Some(0)));
    assert_eq!(c.create_permission(peer().await?.local_addr()?).await?.code(), Some(437));
    assert_eq!(c.refresh(600).await?.code(), Some(437));
    // A new one can be made afterwards.
    c.allocate().await?;
    Ok(())
}

#[tokio::test]
async fn a_second_allocate_is_a_mismatch_but_a_retransmission_is_answered_again() -> anyhow::Result<()> {
    let s = server("").await?;
    let mut c = client(&s, "alice@quark.test").await?;
    c.allocate().await?;
    let tid = [9u8; 12];
    let pkt = c.signed(method::ALLOCATE, tid, |w| {
        w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
    });
    assert_eq!(c.exchange(&pkt, tid).await?.code(), Some(437));
    // A brand new allocation, then the same request again (a lost answer).
    c.refresh(0).await?;
    let a = c.exchange(&pkt, tid).await?;
    let b = c.exchange(&pkt, tid).await?;
    assert_eq!(a.class(), Class::Success);
    assert_eq!(a.xor_addr(attr::XOR_RELAYED_ADDRESS), b.xor_addr(attr::XOR_RELAYED_ADDRESS));
    Ok(())
}

#[tokio::test]
async fn tcp_allocations_end_with_their_connection() -> anyhow::Result<()> {
    let s = server(LOOPBACK_PEERS).await?;
    let (u, pw) = creds(&s, "alice@quark.test");
    let relay = s.srv.turn.relay().expect("running").clone();
    let mut c = TurnClient::tcp(tcp(&s)).await?.with_credentials(&u, &pw);
    c.allocate().await?;
    assert_eq!(relay.allocation_count(), 1);
    drop(c);
    for _ in 0..50 {
        if relay.allocation_count() == 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the allocation outlived its connection");
}

#[tokio::test]
async fn accounts_are_held_to_their_allocation_quota() -> anyhow::Result<()> {
    let s = server("\n[turn.quota]\nallocations_per_user = 1\n").await?;
    let mut a1 = client(&s, "alice@quark.test").await?;
    let mut a2 = client(&s, "alice@quark.test").await?;
    let mut b = client(&s, "bob@quark.test").await?;
    a1.allocate().await?;
    let r = a2
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
        })
        .await?;
    assert_eq!(r.code(), Some(486));
    assert!(r.msg().has_integrity());
    b.allocate().await?;
    // Freeing one makes room again.
    a1.refresh(0).await?;
    a2.allocate().await?;
    Ok(())
}

#[tokio::test]
async fn tcp_only_and_unknown_attributes_are_refused() -> anyhow::Result<()> {
    let s = server("").await?;
    let mut c = client(&s, "alice@quark.test").await?;
    let tcp_alloc = c
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[6, 0, 0, 0]);
        })
        .await?;
    assert_eq!(tcp_alloc.code(), Some(442));
    let unknown = c
        .request(method::ALLOCATE, |w| {
            w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]).attr(attr::RESERVATION_TOKEN, &[0; 8]);
        })
        .await?;
    assert_eq!(unknown.code(), Some(420));
    let listed = unknown.msg().get(attr::UNKNOWN_ATTRIBUTES).map(<[u8]>::to_vec);
    assert_eq!(listed, Some(attr::RESERVATION_TOKEN.to_be_bytes().to_vec()));
    let missing = c.request(method::ALLOCATE, |_| {}).await?;
    assert_eq!(missing.code(), Some(400));
    Ok(())
}

#[tokio::test]
async fn garbage_gets_no_answer_and_the_relay_keeps_working() -> anyhow::Result<()> {
    let s = server("").await?;
    let mut c = TurnClient::udp(udp(&s)).await?;
    for junk in [&b"GET / HTTP/1.1\r\n\r\n"[..], &[0u8; 20][..], &[0x40, 0x00, 0xFF, 0xFF][..], &[0x00, 0x01, 0x00, 0x04, 0x21, 0x12][..]] {
        c.send_raw(junk).await?;
    }
    assert_eq!(c.recv_raw(QUIET).await?, None);
    assert_eq!(c.request(method::BINDING, |_| {}).await?.class(), Class::Success);
    // TCP: a frame that is neither STUN nor ChannelData closes the connection.
    let mut t = TurnClient::tcp(tcp(&s)).await?;
    t.send_raw(&[0xC0, 0, 0, 0]).await?;
    assert!(t.recv_raw(QUIET * 5).await.is_err());
    Ok(())
}

#[tokio::test]
async fn the_snapshot_reports_the_relay_running() -> anyhow::Result<()> {
    let s = server("").await?;
    let st = quark::turn::status(&s.srv);
    assert!(st.built_in && st.running);
    assert_eq!(st.port, udp(&s).port());
    assert_eq!(udp(&s).port(), tcp(&s).port());
    Ok(())
}
