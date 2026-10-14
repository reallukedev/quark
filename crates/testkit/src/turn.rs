//! A small TURN client (RFC 8656) over UDP or TCP, for testing the built-in relay.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context as _};
use quark::turn::stun::{self, attr, method, Class, Message, Writer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::TIMEOUT;

enum Io {
    Udp(UdpSocket, SocketAddr),
    Tcp(TcpStream, Vec<u8>),
}

/// An answer to a request.
#[derive(Debug, Clone)]
pub struct Response {
    pub raw: Vec<u8>,
}

impl Response {
    pub fn msg(&self) -> Message<'_> {
        Message::parse(&self.raw).expect("responses were parsed before being returned")
    }
    pub fn class(&self) -> Class {
        self.msg().class
    }
    /// The ERROR-CODE number, for error responses.
    pub fn code(&self) -> Option<u16> {
        self.msg().get(attr::ERROR_CODE).filter(|v| v.len() >= 4).map(|v| u16::from(v[2] & 7) * 100 + u16::from(v[3]))
    }
    pub fn xor_addr(&self, t: u16) -> Option<SocketAddr> {
        self.msg().xor_addr(t)
    }
    pub fn u32(&self, t: u16) -> Option<u32> {
        self.msg().u32_attr(t)
    }
    pub fn text(&self, t: u16) -> Option<String> {
        self.msg().str_attr(t).map(str::to_string)
    }
}

/// Data the relay passed on from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relayed {
    /// A Data indication, with the peer's address.
    Indication(SocketAddr, Vec<u8>),
    /// ChannelData on a channel number.
    Channel(u16, Vec<u8>),
}

pub struct TurnClient {
    io: Io,
    username: Option<String>,
    password: String,
    realm: Option<String>,
    nonce: Option<Vec<u8>>,
    /// Data that arrived while waiting for a response.
    backlog: VecDeque<Vec<u8>>,
}

impl TurnClient {
    pub async fn udp(server: SocketAddr) -> anyhow::Result<TurnClient> {
        let bind: SocketAddr = if server.is_ipv4() { "127.0.0.1:0".parse()? } else { "[::1]:0".parse()? };
        let s = UdpSocket::bind(bind).await?;
        Ok(Self::new(Io::Udp(s, server)))
    }

    pub async fn tcp(server: SocketAddr) -> anyhow::Result<TurnClient> {
        Ok(Self::new(Io::Tcp(TcpStream::connect(server).await?, Vec::new())))
    }

    fn new(io: Io) -> TurnClient {
        TurnClient { io, username: None, password: String::new(), realm: None, nonce: None, backlog: VecDeque::new() }
    }

    /// Long-term credentials to sign requests with, once the relay has sent a realm and nonce.
    pub fn with_credentials(mut self, username: &str, password: &str) -> TurnClient {
        self.username = Some(username.to_string());
        self.password = password.to_string();
        self
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(match &self.io {
            Io::Udp(s, _) => s.local_addr()?,
            Io::Tcp(s, _) => s.local_addr()?,
        })
    }

    pub async fn send_raw(&mut self, pkt: &[u8]) -> anyhow::Result<()> {
        match &mut self.io {
            Io::Udp(s, to) => {
                s.send_to(pkt, *to).await?;
            }
            Io::Tcp(s, _) => s.write_all(pkt).await?,
        }
        Ok(())
    }

    /// The next datagram (UDP) or frame (TCP), or None after `wait`.
    pub async fn recv_raw(&mut self, wait: Duration) -> anyhow::Result<Option<Vec<u8>>> {
        let fut = async {
            match &mut self.io {
                Io::Udp(s, _) => {
                    let mut buf = vec![0u8; 70_000];
                    let (n, _) = s.recv_from(&mut buf).await?;
                    buf.truncate(n);
                    Ok::<_, anyhow::Error>(buf)
                }
                Io::Tcp(s, pending) => loop {
                    if pending.len() >= 4 {
                        let len = if stun::is_channel_data(pending) {
                            (4 + usize::from(u16::from_be_bytes([pending[2], pending[3]])) + 3) & !3
                        } else {
                            stun::framed_len(pending).context("bad frame")?
                        };
                        if pending.len() >= len {
                            let frame: Vec<u8> = pending.drain(..len).collect();
                            return Ok(frame);
                        }
                    }
                    let mut chunk = [0u8; 8192];
                    let n = s.read(&mut chunk).await?;
                    if n == 0 {
                        bail!("the relay closed the connection");
                    }
                    pending.extend_from_slice(&chunk[..n]);
                },
            }
        };
        match tokio::time::timeout(wait, fut).await {
            Err(_) => Ok(None),
            Ok(r) => r.map(Some),
        }
    }

    /// Sends a request built by `build` (signed when credentials and a nonce are known) and
    /// returns the response. A 401 or 438 challenge is answered once with fresh realm and nonce.
    pub async fn request(&mut self, method: u16, build: impl Fn(&mut Writer)) -> anyhow::Result<Response> {
        for attempt in 0..2 {
            let tid: [u8; 12] = rand::random();
            let pkt = self.signed(method, tid, &build);
            let r = self.exchange(&pkt, tid).await?;
            let challenged = matches!(r.code(), Some(401 | 438));
            if challenged && attempt == 0 && self.username.is_some() {
                let fresh = r.msg().get(attr::NONCE).map(<[u8]>::to_vec);
                let realm = r.text(attr::REALM);
                // Only retry when the challenge tells us something new (else it's a real refusal).
                if fresh.is_some() && (fresh != self.nonce || realm != self.realm) {
                    self.nonce = fresh;
                    self.realm = realm;
                    continue;
                }
            }
            return Ok(r);
        }
        bail!("unreachable")
    }

    /// A request with transaction id `tid`, signed when a realm and nonce are known.
    pub fn signed(&self, method: u16, tid: [u8; 12], build: impl Fn(&mut Writer)) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut w = Writer::new(&mut buf, method, Class::Request, tid);
        build(&mut w);
        if let (Some(u), Some(r), Some(n)) = (&self.username, &self.realm, &self.nonce) {
            let key = quark::turn::long_term_key(u, r, &self.password);
            w.attr(attr::USERNAME, u.as_bytes()).attr(attr::REALM, r.as_bytes()).attr(attr::NONCE, n).integrity(&key);
        }
        w.fingerprint();
        buf
    }

    /// Sends a request and waits for the response with its transaction id; anything else that
    /// arrives meanwhile is kept for [`TurnClient::recv_data`].
    pub async fn exchange(&mut self, pkt: &[u8], tid: [u8; 12]) -> anyhow::Result<Response> {
        self.send_raw(pkt).await?;
        let deadline = tokio::time::Instant::now() + TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let Some(p) = self.recv_raw(left).await? else { bail!("no answer from the relay") };
            match Message::parse(&p) {
                Ok(m) if m.tid == tid && matches!(m.class, Class::Success | Class::Error) => return Ok(Response { raw: p }),
                _ => self.backlog.push_back(p),
            }
        }
    }

    /// Allocates a relayed UDP address.
    pub async fn allocate(&mut self) -> anyhow::Result<SocketAddr> {
        let r = self
            .request(method::ALLOCATE, |w| {
                w.attr(attr::REQUESTED_TRANSPORT, &[17, 0, 0, 0]);
            })
            .await?;
        if r.class() != Class::Success {
            bail!("allocate failed with {:?}", r.code());
        }
        r.xor_addr(attr::XOR_RELAYED_ADDRESS).context("no relayed address")
    }

    pub async fn refresh(&mut self, lifetime: u32) -> anyhow::Result<Response> {
        self.request(method::REFRESH, |w| {
            w.u32(attr::LIFETIME, lifetime);
        })
        .await
    }

    pub async fn create_permission(&mut self, peer: SocketAddr) -> anyhow::Result<Response> {
        self.request(method::CREATE_PERMISSION, |w| {
            w.xor_addr(attr::XOR_PEER_ADDRESS, peer);
        })
        .await
    }

    pub async fn channel_bind(&mut self, channel: u16, peer: SocketAddr) -> anyhow::Result<Response> {
        self.request(method::CHANNEL_BIND, |w| {
            w.u32(attr::CHANNEL_NUMBER, u32::from(channel) << 16).xor_addr(attr::XOR_PEER_ADDRESS, peer);
        })
        .await
    }

    pub async fn send_indication(&mut self, peer: SocketAddr, data: &[u8]) -> anyhow::Result<()> {
        let mut buf = Vec::new();
        Writer::new(&mut buf, method::SEND, Class::Indication, rand::random())
            .xor_addr(attr::XOR_PEER_ADDRESS, peer)
            .attr(attr::DATA, data)
            .fingerprint();
        self.send_raw(&buf).await
    }

    pub async fn send_channel(&mut self, channel: u16, data: &[u8]) -> anyhow::Result<()> {
        let mut buf = Vec::with_capacity(4 + data.len() + 3);
        buf.extend_from_slice(&channel.to_be_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
        if matches!(self.io, Io::Tcp(..)) {
            buf.resize((buf.len() + 3) & !3, 0);
        }
        self.send_raw(&buf).await
    }

    /// The next relayed data within `wait`.
    pub async fn recv_data(&mut self, wait: Duration) -> anyhow::Result<Option<Relayed>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let p = match self.backlog.pop_front() {
                Some(p) => p,
                None => {
                    let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                    match self.recv_raw(left).await? {
                        Some(p) => p,
                        None => return Ok(None),
                    }
                }
            };
            if let Some((ch, d)) = stun::parse_channel_data(&p) {
                return Ok(Some(Relayed::Channel(ch, d.to_vec())));
            }
            if let Ok(m) = Message::parse(&p) {
                if m.method == method::DATA && m.class == Class::Indication {
                    let peer = m.xor_addr(attr::XOR_PEER_ADDRESS).context("data without a peer")?;
                    return Ok(Some(Relayed::Indication(peer, m.get(attr::DATA).unwrap_or_default().to_vec())));
                }
            }
        }
    }
}
