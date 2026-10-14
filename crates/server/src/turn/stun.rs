//! STUN messages (RFC 8489) with the TURN additions (RFC 8656): parsing that borrows the packet,
//! and a writer that reuses one buffer, so the relay doesn't allocate per packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

pub const MAGIC: u32 = 0x2112_A442;
pub const HEADER: usize = 20;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

pub mod method {
    pub const BINDING: u16 = 0x001;
    pub const ALLOCATE: u16 = 0x003;
    pub const REFRESH: u16 = 0x004;
    pub const SEND: u16 = 0x006;
    pub const DATA: u16 = 0x007;
    pub const CREATE_PERMISSION: u16 = 0x008;
    pub const CHANNEL_BIND: u16 = 0x009;
}

pub mod attr {
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    pub const USERNAME: u16 = 0x0006;
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;
    pub const ERROR_CODE: u16 = 0x0009;
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;
    pub const CHANNEL_NUMBER: u16 = 0x000C;
    pub const LIFETIME: u16 = 0x000D;
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;
    pub const DATA: u16 = 0x0013;
    pub const REALM: u16 = 0x0014;
    pub const NONCE: u16 = 0x0015;
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
    pub const EVEN_PORT: u16 = 0x0018;
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;
    pub const DONT_FRAGMENT: u16 = 0x001A;
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    pub const RESERVATION_TOKEN: u16 = 0x0022;
    pub const PRIORITY: u16 = 0x0024;
    pub const USE_CANDIDATE: u16 = 0x0025;
    pub const SOFTWARE: u16 = 0x8022;
    pub const FINGERPRINT: u16 = 0x8028;
    pub const ICE_CONTROLLED: u16 = 0x8029;
    pub const ICE_CONTROLLING: u16 = 0x802A;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

impl Class {
    fn bits(self) -> u16 {
        match self {
            Class::Request => 0,
            Class::Indication => 1,
            Class::Success => 2,
            Class::Error => 3,
        }
    }
}

/// The 14-bit message type: method bits interleaved with the two class bits (RFC 8489 §5).
pub fn message_type(method: u16, class: Class) -> u16 {
    let c = class.bits();
    (method & 0x000F) | ((method & 0x0070) << 1) | ((method & 0x0F80) << 2) | ((c & 1) << 4) | ((c & 2) << 7)
}

fn split_type(t: u16) -> (u16, Class) {
    let method = (t & 0x000F) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0F80);
    let class = match ((t >> 4) & 1) | ((t >> 7) & 2) {
        0 => Class::Request,
        1 => Class::Indication,
        2 => Class::Success,
        _ => Class::Error,
    };
    (method, class)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("not a STUN message")]
    NotStun,
    #[error("malformed STUN message")]
    Malformed,
    #[error("bad FINGERPRINT")]
    Fingerprint,
}

/// A parsed message borrowing the packet. Attributes after MESSAGE-INTEGRITY (other than
/// FINGERPRINT) are ignored, as the RFC requires.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    buf: &'a [u8],
    pub method: u16,
    pub class: Class,
    pub tid: [u8; 12],
    /// Where the MESSAGE-INTEGRITY attribute starts, if there is one.
    integrity_at: Option<usize>,
    /// Where the attributes we honour end.
    attrs_end: usize,
    pub has_fingerprint: bool,
}

/// Whether a packet looks like STUN at all (first two bits zero and the magic cookie). Lets the
/// caller tell STUN from ChannelData cheaply.
pub fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= HEADER && buf[0] & 0xC0 == 0 && buf[4..8] == MAGIC.to_be_bytes()
}

/// The full length of the STUN message at the start of `buf`, from its header (for TCP framing).
pub fn framed_len(header: &[u8]) -> Option<usize> {
    (header.len() >= 4).then(|| HEADER + usize::from(u16::from_be_bytes([header[2], header[3]])))
}

impl<'a> Message<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Message<'a>, ParseError> {
        if !is_stun(buf) {
            return Err(ParseError::NotStun);
        }
        let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if len % 4 != 0 || HEADER + len != buf.len() {
            return Err(ParseError::Malformed);
        }
        let (method, class) = split_type(u16::from_be_bytes([buf[0], buf[1]]));
        let mut tid = [0u8; 12];
        tid.copy_from_slice(&buf[8..20]);
        let mut integrity_at = None;
        let mut attrs_end = buf.len();
        let mut has_fingerprint = false;
        let mut at = HEADER;
        while at < buf.len() {
            let (t, vlen) = attr_header(buf, at).ok_or(ParseError::Malformed)?;
            let next = at + 4 + padded(vlen);
            if next > buf.len() {
                return Err(ParseError::Malformed);
            }
            if has_fingerprint {
                // FINGERPRINT must be last.
                return Err(ParseError::Malformed);
            }
            match t {
                attr::FINGERPRINT => {
                    if vlen != 4 {
                        return Err(ParseError::Malformed);
                    }
                    let want = u32::from_be_bytes([buf[at + 4], buf[at + 5], buf[at + 6], buf[at + 7]]);
                    if crc32_with_len(buf, at) ^ FINGERPRINT_XOR != want {
                        return Err(ParseError::Fingerprint);
                    }
                    has_fingerprint = true;
                    if integrity_at.is_none() {
                        attrs_end = at;
                    }
                }
                attr::MESSAGE_INTEGRITY if integrity_at.is_none() => {
                    if vlen != 20 {
                        return Err(ParseError::Malformed);
                    }
                    integrity_at = Some(at);
                    attrs_end = at;
                }
                _ => {}
            }
            at = next;
        }
        Ok(Message { buf, method, class, tid, integrity_at, attrs_end, has_fingerprint })
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The attributes before MESSAGE-INTEGRITY (or all, without one), in order.
    pub fn attrs(&self) -> Attrs<'a> {
        Attrs { buf: &self.buf[..self.attrs_end], at: HEADER }
    }

    /// The first attribute of type `t`.
    pub fn get(&self, t: u16) -> Option<&'a [u8]> {
        self.attrs().find(|(at, _)| *at == t).map(|(_, v)| v)
    }

    pub fn has(&self, t: u16) -> bool {
        self.get(t).is_some()
    }

    pub fn has_integrity(&self) -> bool {
        self.integrity_at.is_some()
    }

    pub fn u32_attr(&self, t: u16) -> Option<u32> {
        self.get(t).and_then(|v| v.get(..4)).map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn str_attr(&self, t: u16) -> Option<&'a str> {
        self.get(t).and_then(|v| std::str::from_utf8(v).ok())
    }

    pub fn xor_addr(&self, t: u16) -> Option<SocketAddr> {
        self.get(t).and_then(|v| decode_xor_addr(v, &self.tid))
    }

    /// Every XOR address of type `t` (CreatePermission may carry several).
    pub fn xor_addrs(&self, t: u16) -> impl Iterator<Item = Option<SocketAddr>> + '_ {
        self.attrs().filter(move |(at, _)| *at == t).map(|(_, v)| decode_xor_addr(v, &self.tid))
    }

    /// Comprehension-required attributes (type < 0x8000) not in `known`; at most 8 are reported.
    pub fn unknown_required(&self, known: &[u16]) -> ([u16; 8], usize) {
        let mut out = [0u16; 8];
        let mut n = 0;
        for (t, _) in self.attrs() {
            if t < 0x8000 && !known.contains(&t) && !out[..n].contains(&t) && n < out.len() {
                out[n] = t;
                n += 1;
            }
        }
        (out, n)
    }

    /// Checks MESSAGE-INTEGRITY (HMAC-SHA1 with the long-term key) in constant time.
    pub fn check_integrity(&self, key: &[u8]) -> bool {
        let Some(at) = self.integrity_at else { return false };
        let mut mac = hmac_sha1(key);
        // The length field covers everything up to and including MESSAGE-INTEGRITY.
        let len = (at + 24 - HEADER) as u16;
        mac.update(&self.buf[..2]);
        mac.update(&len.to_be_bytes());
        mac.update(&self.buf[4..at]);
        let got = mac.finalize().into_bytes();
        got.as_slice().ct_eq(&self.buf[at + 4..at + 24]).into()
    }
}

fn hmac_sha1(key: &[u8]) -> Hmac<Sha1> {
    // HMAC takes keys of any length.
    <Hmac<Sha1> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!("HMAC accepts any key length"))
}

fn attr_header(buf: &[u8], at: usize) -> Option<(u16, usize)> {
    let h = buf.get(at..at + 4)?;
    Some((u16::from_be_bytes([h[0], h[1]]), usize::from(u16::from_be_bytes([h[2], h[3]]))))
}

fn padded(n: usize) -> usize {
    (n + 3) & !3
}

/// CRC-32 of the message up to `at`, with the header length set to include an 8-byte FINGERPRINT
/// at `at`.
fn crc32_with_len(buf: &[u8], at: usize) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(&buf[..2]);
    h.update(&((at + 8 - HEADER) as u16).to_be_bytes());
    h.update(&buf[4..at]);
    h.finalize()
}

pub struct Attrs<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Iterator for Attrs<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let (t, len) = attr_header(self.buf, self.at)?;
        let v = self.buf.get(self.at + 4..self.at + 4 + len)?;
        self.at += 4 + padded(len);
        Some((t, v))
    }
}

pub fn decode_xor_addr(v: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let port = u16::from_be_bytes([v[2], v[3]]) ^ (MAGIC >> 16) as u16;
    let m = MAGIC.to_be_bytes();
    match (v[1], v.len()) {
        (0x01, 8) => {
            let ip = Ipv4Addr::new(v[4] ^ m[0], v[5] ^ m[1], v[6] ^ m[2], v[7] ^ m[3]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        (0x02, 20) => {
            let mut o = [0u8; 16];
            for (i, b) in o.iter_mut().enumerate() {
                let k = if i < 4 { m[i] } else { tid[i - 4] };
                *b = v[4 + i] ^ k;
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
        }
        _ => None,
    }
}

/// Writes an XOR address value (family, port, address) into `out`; returns its length.
pub fn encode_xor_addr(out: &mut [u8], addr: SocketAddr, tid: &[u8; 12]) -> usize {
    let m = MAGIC.to_be_bytes();
    out[0] = 0;
    out[2..4].copy_from_slice(&(addr.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
    match addr.ip() {
        IpAddr::V4(ip) => {
            out[1] = 0x01;
            for (i, b) in ip.octets().iter().enumerate() {
                out[4 + i] = b ^ m[i];
            }
            8
        }
        IpAddr::V6(ip) => {
            out[1] = 0x02;
            for (i, b) in ip.octets().iter().enumerate() {
                let k = if i < 4 { m[i] } else { tid[i - 4] };
                out[4 + i] = b ^ k;
            }
            20
        }
    }
}

/// The largest Data indication header: STUN header, XOR-PEER-ADDRESS for IPv6, DATA's header.
pub const MAX_DATA_HEADER: usize = HEADER + 4 + 20 + 4;

/// Writes a Data indication header for `payload_len` bytes so it ends exactly at `buf[end]`, where
/// the payload already sits; returns where the header starts. The caller pads the payload to 4.
pub fn data_indication_header(buf: &mut [u8], end: usize, tid: &[u8; 12], peer: SocketAddr, payload_len: usize) -> usize {
    let alen = if peer.is_ipv4() { 8 } else { 20 };
    let start = end - (HEADER + 4 + alen + 4);
    let total = 4 + alen + 4 + padded(payload_len);
    let h = &mut buf[start..end];
    h[..2].copy_from_slice(&message_type(method::DATA, Class::Indication).to_be_bytes());
    h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    h[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    h[8..20].copy_from_slice(tid);
    h[20..22].copy_from_slice(&attr::XOR_PEER_ADDRESS.to_be_bytes());
    h[22..24].copy_from_slice(&(alen as u16).to_be_bytes());
    encode_xor_addr(&mut h[24..24 + alen], peer, tid);
    let d = 24 + alen;
    h[d..d + 2].copy_from_slice(&attr::DATA.to_be_bytes());
    h[d + 2..d + 4].copy_from_slice(&(payload_len as u16).to_be_bytes());
    start
}

/// Builds a message into a reused buffer.
pub struct Writer<'a> {
    buf: &'a mut Vec<u8>,
    tid: [u8; 12],
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut Vec<u8>, method: u16, class: Class, tid: [u8; 12]) -> Writer<'a> {
        buf.clear();
        buf.extend_from_slice(&message_type(method, class).to_be_bytes());
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&MAGIC.to_be_bytes());
        buf.extend_from_slice(&tid);
        Writer { buf, tid }
    }

    fn set_len(&mut self, len: usize) {
        let l = (len as u16).to_be_bytes();
        self.buf[2] = l[0];
        self.buf[3] = l[1];
    }

    pub fn attr(&mut self, t: u16, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&t.to_be_bytes());
        self.buf.extend_from_slice(&(v.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(v);
        let pad = padded(v.len()) - v.len();
        self.buf.extend_from_slice(&[0u8; 3][..pad]);
        let len = self.buf.len() - HEADER;
        self.set_len(len);
        self
    }

    pub fn u32(&mut self, t: u16, v: u32) -> &mut Self {
        self.attr(t, &v.to_be_bytes())
    }

    pub fn xor_addr(&mut self, t: u16, addr: SocketAddr) -> &mut Self {
        let mut v = [0u8; 20];
        let n = encode_xor_addr(&mut v, addr, &self.tid);
        self.attr(t, &v[..n])
    }

    /// ERROR-CODE with a short reason (RFC 8489 §14.8).
    pub fn error(&mut self, code: u16, reason: &str) -> &mut Self {
        let mut v = [0u8; 4 + 64];
        let r = &reason.as_bytes()[..reason.len().min(64)];
        v[2] = (code / 100) as u8;
        v[3] = (code % 100) as u8;
        v[4..4 + r.len()].copy_from_slice(r);
        self.attr(attr::ERROR_CODE, &v[..4 + r.len()])
    }

    pub fn unknown(&mut self, types: &[u16]) -> &mut Self {
        let mut v = [0u8; 16];
        let n = types.len().min(8);
        for (i, t) in types[..n].iter().enumerate() {
            v[i * 2..i * 2 + 2].copy_from_slice(&t.to_be_bytes());
        }
        self.attr(attr::UNKNOWN_ATTRIBUTES, &v[..n * 2])
    }

    /// MESSAGE-INTEGRITY with the long-term key.
    pub fn integrity(&mut self, key: &[u8]) -> &mut Self {
        let len = self.buf.len() + 24 - HEADER;
        self.set_len(len);
        let mut mac = hmac_sha1(key);
        mac.update(self.buf);
        let tag = mac.finalize().into_bytes();
        self.buf.extend_from_slice(&attr::MESSAGE_INTEGRITY.to_be_bytes());
        self.buf.extend_from_slice(&20u16.to_be_bytes());
        self.buf.extend_from_slice(&tag);
        self
    }

    pub fn fingerprint(&mut self) -> &mut Self {
        let len = self.buf.len() + 8 - HEADER;
        self.set_len(len);
        let crc = crc32fast::hash(self.buf) ^ FINGERPRINT_XOR;
        self.buf.extend_from_slice(&attr::FINGERPRINT.to_be_bytes());
        self.buf.extend_from_slice(&4u16.to_be_bytes());
        self.buf.extend_from_slice(&crc.to_be_bytes());
        self
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// ChannelData (RFC 8656 §12.4): channel numbers 0x4000–0x4FFF in the first two bytes.
pub fn is_channel_data(buf: &[u8]) -> bool {
    buf.len() >= 4 && (0x40..=0x4F).contains(&buf[0])
}

/// The channel and payload of a ChannelData message. Over UDP the datagram may carry padding
/// after the payload; anything shorter than the stated length is malformed.
pub fn parse_channel_data(buf: &[u8]) -> Option<(u16, &[u8])> {
    if !is_channel_data(buf) {
        return None;
    }
    let ch = u16::from_be_bytes([buf[0], buf[1]]);
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    buf.get(4..4 + len).map(|d| (ch, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    /// The sample request from RFC 5769 §2.1 (short-term credentials, password "VOkJxbRl1RmTxUk/WvJxBt").
    const RFC5769_REQUEST: &[u8] = &[
        0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22,
        0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04,
        0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76,
        0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56,
        0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
    ];

    #[test]
    fn parses_the_rfc5769_sample_and_checks_its_integrity_and_fingerprint() {
        let m = Message::parse(RFC5769_REQUEST).unwrap();
        assert_eq!((m.method, m.class), (method::BINDING, Class::Request));
        assert!(m.has_fingerprint);
        assert_eq!(m.str_attr(attr::USERNAME), Some("evtj:h6vY"));
        assert_eq!(m.str_attr(attr::SOFTWARE), Some("STUN test client"));
        assert!(m.check_integrity(b"VOkJxbRl1RmTxUk/WvJxBt"));
        assert!(!m.check_integrity(b"wrong"));
    }

    #[test]
    fn a_flipped_bit_fails_the_fingerprint() {
        let mut bad = RFC5769_REQUEST.to_vec();
        bad[30] ^= 1;
        assert_eq!(Message::parse(&bad).unwrap_err(), ParseError::Fingerprint);
    }

    #[test]
    fn message_types_round_trip() {
        for m in [method::BINDING, method::ALLOCATE, method::CHANNEL_BIND, 0x0FFF] {
            for c in [Class::Request, Class::Indication, Class::Success, Class::Error] {
                assert_eq!(split_type(message_type(m, c)), (m, c));
            }
        }
        assert_eq!(message_type(method::BINDING, Class::Success), 0x0101);
        assert_eq!(message_type(method::ALLOCATE, Class::Error), 0x0113);
    }

    #[test]
    fn written_messages_parse_back_with_integrity() {
        let mut buf = Vec::new();
        let peer4: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let peer6: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap();
        let mut w = Writer::new(&mut buf, method::ALLOCATE, Class::Success, TID);
        w.xor_addr(attr::XOR_RELAYED_ADDRESS, peer4).xor_addr(attr::XOR_MAPPED_ADDRESS, peer6).u32(attr::LIFETIME, 600);
        w.attr(attr::REALM, b"abc").error(437, "Mismatch").integrity(b"key").fingerprint();
        let m = Message::parse(&buf).unwrap();
        assert_eq!(m.xor_addr(attr::XOR_RELAYED_ADDRESS), Some(peer4));
        assert_eq!(m.xor_addr(attr::XOR_MAPPED_ADDRESS), Some(peer6));
        assert_eq!(m.u32_attr(attr::LIFETIME), Some(600));
        assert_eq!(m.str_attr(attr::REALM), Some("abc"));
        assert_eq!(m.get(attr::ERROR_CODE).unwrap()[2..4], [4, 37]);
        assert!(m.check_integrity(b"key"));
        assert!(m.has_fingerprint);
    }

    #[test]
    fn attributes_after_integrity_are_ignored() {
        let mut buf = Vec::new();
        Writer::new(&mut buf, method::REFRESH, Class::Request, TID).u32(attr::LIFETIME, 1).integrity(b"k");
        // Someone appends an attribute after the integrity check.
        buf.extend_from_slice(&[0x00, 0x0D, 0x00, 0x04, 0, 0, 0, 0]);
        let l = (buf.len() - HEADER) as u16;
        buf[2..4].copy_from_slice(&l.to_be_bytes());
        let m = Message::parse(&buf).unwrap();
        assert_eq!(m.u32_attr(attr::LIFETIME), Some(1));
        assert_eq!(m.attrs().count(), 1);
        assert!(m.check_integrity(b"k"));
    }

    #[test]
    fn data_indication_header_lands_right_before_the_payload() {
        for peer in ["198.51.100.7:4000", "[2001:db8::7]:4000"] {
            let peer: SocketAddr = peer.parse().unwrap();
            let mut buf = vec![0u8; MAX_DATA_HEADER + 8];
            buf[MAX_DATA_HEADER..MAX_DATA_HEADER + 5].copy_from_slice(b"hello");
            let start = data_indication_header(&mut buf, MAX_DATA_HEADER, &TID, peer, 5);
            let m = Message::parse(&buf[start..MAX_DATA_HEADER + 8]).unwrap();
            assert_eq!((m.method, m.class), (method::DATA, Class::Indication));
            assert_eq!(m.xor_addr(attr::XOR_PEER_ADDRESS), Some(peer));
            assert_eq!(m.get(attr::DATA), Some(&b"hello"[..]));
        }
    }

    #[test]
    fn unknown_required_attributes_are_reported() {
        let mut buf = Vec::new();
        Writer::new(&mut buf, method::ALLOCATE, Class::Request, TID).attr(0x0031, b"x").attr(0x8031, b"y").u32(attr::LIFETIME, 5);
        let m = Message::parse(&buf).unwrap();
        let (u, n) = m.unknown_required(&[attr::LIFETIME]);
        assert_eq!(&u[..n], &[0x0031]);
    }

    #[test]
    fn channel_data_parses_with_and_without_padding() {
        assert_eq!(parse_channel_data(&[0x40, 0x01, 0, 3, 1, 2, 3, 0]), Some((0x4001, &[1u8, 2, 3][..])));
        assert_eq!(parse_channel_data(&[0x40, 0x01, 0, 3, 1, 2, 3]), Some((0x4001, &[1u8, 2, 3][..])));
        assert_eq!(parse_channel_data(&[0x40, 0x01, 0, 9, 1, 2, 3]), None);
        assert_eq!(parse_channel_data(&[0x30, 0x01, 0, 0]), None);
    }

    #[test]
    fn malformed_headers_are_refused() {
        assert_eq!(Message::parse(&[0u8; 10]).unwrap_err(), ParseError::NotStun);
        let mut b = Vec::new();
        Writer::new(&mut b, method::BINDING, Class::Request, TID);
        let mut odd = b.clone();
        odd[3] = 2; // length not a multiple of 4
        odd.extend_from_slice(&[0, 0]);
        assert_eq!(Message::parse(&odd).unwrap_err(), ParseError::Malformed);
        let mut long = b.clone();
        long[3] = 8; // claims attributes it doesn't have
        assert_eq!(Message::parse(&long).unwrap_err(), ParseError::Malformed);
        let mut cookie = b.clone();
        cookie[4] = 0;
        assert_eq!(Message::parse(&cookie).unwrap_err(), ParseError::NotStun);
    }

    /// A tiny deterministic generator, so the fuzz tests need no extra crates and are repeatable.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut r = Lcg(7);
        for _ in 0..20_000 {
            let len = (r.next() % 120) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| r.byte()).collect();
            if b.len() >= HEADER && r.next() & 1 == 0 {
                // Make it look like STUN so parsing goes deep.
                b[0] &= 0x3F;
                b[4..8].copy_from_slice(&MAGIC.to_be_bytes());
                let l = ((b.len() - HEADER) & !3) as u16;
                b.truncate(HEADER + usize::from(l));
                b[2..4].copy_from_slice(&l.to_be_bytes());
            }
            if let Ok(m) = Message::parse(&b) {
                for (t, _) in m.attrs() {
                    let _ = m.xor_addr(t);
                    let _ = m.u32_attr(t);
                }
                let _ = m.check_integrity(b"k");
                let _ = m.unknown_required(&[]);
            }
            let _ = parse_channel_data(&b);
        }
    }

    #[test]
    fn mutated_valid_messages_never_panic() {
        let mut base = Vec::new();
        let peer: SocketAddr = "[2001:db8::1]:9".parse().unwrap();
        Writer::new(&mut base, method::CREATE_PERMISSION, Class::Request, TID)
            .xor_addr(attr::XOR_PEER_ADDRESS, peer)
            .attr(attr::USERNAME, b"1700000000:alice@quark.test")
            .attr(attr::NONCE, b"0123456789abcdef")
            .integrity(b"k")
            .fingerprint();
        let mut r = Lcg(99);
        for _ in 0..20_000 {
            let mut b = base.clone();
            for _ in 0..(1 + r.next() % 4) {
                let i = (r.next() as usize) % b.len();
                b[i] = r.byte();
            }
            if r.next() % 5 == 1 {
                b.truncate((r.next() as usize) % b.len());
            }
            if let Ok(m) = Message::parse(&b) {
                let _ = m.xor_addrs(attr::XOR_PEER_ADDRESS).count();
                let _ = m.check_integrity(b"k");
                let _ = m.str_attr(attr::USERNAME);
            }
        }
    }
}
