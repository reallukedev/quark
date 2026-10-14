//! The relay's sockets: the shared UDP listener, TCP connections (RFC 8656 §3.1 framing), one
//! task per allocation for peer traffic, and the expiry sweep.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};

use super::relay::{bind_udp, Allocation, ClientKey, Limits, Outcome, Relay, HEADROOM, PACKET_BUF};
use super::stun;
use crate::server::Server;

/// TCP connections at once, so a flood of idle connections can't exhaust the process.
const MAX_TCP: usize = 1024;
/// A TCP connection has this long to allocate; after that it may idle for this long between
/// packets plus the longest allocation lifetime.
const TCP_IDLE: Duration = Duration::from_secs(30);
const TCP_WRITE: Duration = Duration::from_secs(10);
/// Packets queued for a slow TCP client before new ones are dropped.
const TCP_QUEUE: usize = 256;
const SWEEP: Duration = Duration::from_secs(5);

/// Binds UDP and TCP on the same port. With port 0 the UDP port is picked first and TCP follows
/// it, retrying a few times if TCP's twin happens to be taken.
pub fn bind(addr: SocketAddr) -> anyhow::Result<(UdpSocket, TcpListener)> {
    let mut last = None;
    for _ in 0..if addr.port() == 0 { 16 } else { 1 } {
        let udp = bind_udp(addr)?;
        let port = udp.local_addr()?.port();
        match bind_tcp(SocketAddr::new(addr.ip(), port)) {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.map_or_else(|| anyhow::anyhow!("couldn't bind the relay"), anyhow::Error::from))
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let s = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() {
        s.set_only_v6(false).ok();
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    TcpListener::from_std(s.into())
}

/// Starts the listener tasks and the sweeper.
pub fn spawn(srv: &Arc<Server>, relay: Arc<Relay>, tcp: TcpListener) {
    let state_srv = Arc::downgrade(srv);
    let r = relay.clone();
    tokio::spawn(async move {
        udp_loop(&r).await;
        r.clear();
        if let Some(s) = state_srv.upgrade() {
            s.turn.set_running(false);
        }
    });
    tokio::spawn(tcp_accept(relay.clone(), tcp));
    tokio::spawn(sweeper(relay, Arc::downgrade(srv)));
}

async fn udp_loop(relay: &Relay) {
    let mut shutdown = relay.shutdown.clone();
    let mut buf = vec![0u8; 65_536];
    let mut out = Vec::with_capacity(1500);
    let mut scratch = vec![0u8; PACKET_BUF];
    loop {
        tokio::select! {
            r = relay.udp.recv_from(&mut buf) => match r {
                Ok((n, from)) => {
                    let client = ClientKey { tcp: false, addr: from };
                    if relay.handle(&buf[..n], client, None, &mut out, &mut scratch) == Outcome::Reply {
                        let _ = relay.udp.try_send_to(&out, from);
                    }
                }
                // ICMP errors from earlier sends show up here on some systems; they're harmless.
                Err(e) => tracing::trace!(error = %e, "relay receive error"),
            },
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
}

async fn tcp_accept(relay: Arc<Relay>, listener: TcpListener) {
    let mut shutdown = relay.shutdown.clone();
    let slots = Arc::new(Semaphore::new(MAX_TCP));
    loop {
        tokio::select! {
            r = listener.accept() => match r {
                Ok((stream, peer)) => {
                    let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                    let _ = stream.set_nodelay(true);
                    let r = relay.clone();
                    tokio::spawn(async move {
                        tcp_conn(&r, stream, peer).await;
                        r.remove_client(&ClientKey { tcp: true, addr: peer });
                        drop(permit);
                    });
                }
                Err(e) => {
                    tracing::debug!(error = %e, "relay accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
}

/// One TCP client: STUN messages and ChannelData back to back on the stream.
async fn tcp_conn(relay: &Relay, stream: TcpStream, peer: SocketAddr) {
    let key = ClientKey { tcp: true, addr: peer };
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(TCP_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(b) = rx.recv().await {
            match tokio::time::timeout(TCP_WRITE, wr.write_all(&b)).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
        let _ = wr.shutdown().await;
    });
    let mut shutdown = relay.shutdown.clone();
    let mut buf = vec![0u8; 2 * (65_536 + 8)];
    let mut filled = 0usize;
    let mut out = Vec::with_capacity(1500);
    let mut scratch = vec![0u8; PACKET_BUF];
    let max_idle = TCP_IDLE + Duration::from_secs(u64::from(relay.max_lifetime()));
    'conn: loop {
        // Frame and handle everything complete in the buffer.
        let mut at = 0;
        while filled - at >= 4 {
            let head = &buf[at..filled];
            let len = if head[0] & 0xC0 == 0 {
                stun::framed_len(head).unwrap_or(usize::MAX)
            } else if stun::is_channel_data(head) {
                let l = 4 + usize::from(u16::from_be_bytes([head[2], head[3]]));
                (l + 3) & !3
            } else {
                break 'conn;
            };
            if len > 65_536 + 8 {
                break 'conn;
            }
            if filled - at < len {
                break;
            }
            if relay.handle(&buf[at..at + len], key, Some(&tx), &mut out, &mut scratch) == Outcome::Reply
                && tx.send(Bytes::copy_from_slice(&out)).await.is_err()
            {
                break 'conn;
            }
            at += len;
        }
        buf.copy_within(at..filled, 0);
        filled -= at;
        let idle = if relay.has_allocation(&key) { max_idle } else { TCP_IDLE };
        tokio::select! {
            r = tokio::time::timeout(idle, rd.read(&mut buf[filled..])) => match r {
                Ok(Ok(n)) if n > 0 => filled += n,
                _ => break,
            },
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
    drop(tx);
    writer.abort();
}

/// Reads what peers send to an allocation's relayed address and passes it to the client.
pub fn spawn_allocation(mut shutdown: watch::Receiver<bool>, a: Arc<Allocation>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; PACKET_BUF];
        let mut errors = 0u32;
        loop {
            tokio::select! {
                r = a.socket.recv_from(&mut buf[HEADROOM..HEADROOM + 65_535]) => match r {
                    Ok((n, peer)) => {
                        errors = 0;
                        a.forward_to_client(&mut buf, n, peer, Instant::now());
                    }
                    Err(e) => {
                        errors += 1;
                        if errors > 100 {
                            tracing::warn!(error = %e, "relay socket keeps failing; closing it");
                            break;
                        }
                    }
                },
                _ = a.stop.notified() => break,
                r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
            }
        }
    });
}

/// Expires allocations, permissions and channels, and picks up config changes after a reload.
async fn sweeper(relay: Arc<Relay>, srv: Weak<Server>) {
    let mut shutdown = relay.shutdown.clone();
    let mut tick = tokio::time::interval(SWEEP);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let Some(s) = srv.upgrade() else { break };
                relay.set_limits(Limits::new(&s.config().turn));
                drop(s);
                relay.sweep(Instant::now());
            }
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break },
        }
    }
}
