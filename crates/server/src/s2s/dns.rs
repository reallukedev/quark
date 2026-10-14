//! Finding and reaching a remote server: a configured route, else DNS SRV (`_xmpps-server` for
//! direct TLS, XEP-0368, merged with `_xmpp-server`, RFC 6120 §3.2), else the domain itself on
//! 5269. Addresses are tried in a staggered race (RFC 8305 style), IPv6 and IPv4 interleaved.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::turn::PeerPolicy;

/// The usual server-to-server port.
pub const DEFAULT_PORT: u16 = 5269;
/// How long one TCP connect may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait on one address before also trying the next.
const STAGGER: Duration = Duration::from_millis(250);
/// SRV targets and addresses tried, at most (a hostile zone can list hundreds).
const MAX_TARGETS: usize = 8;
const MAX_ADDRS: usize = 8;

/// A host to connect to for a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// TLS from the first byte (XEP-0368) instead of STARTTLS.
    pub direct_tls: bool,
}

impl Target {
    /// Parses a configured route: `host:port`, `[v6]:port`, or `tls://host:port` for direct TLS.
    /// The port defaults to 5269 (STARTTLS) or 5270 (direct TLS).
    pub fn parse_route(s: &str) -> Result<Target, String> {
        let (rest, direct_tls) = match s.strip_prefix("tls://") {
            Some(r) => (r, true),
            None => (s.strip_prefix("xmpp://").unwrap_or(s), false),
        };
        let default_port = if direct_tls { 5270 } else { DEFAULT_PORT };
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(|| format!("\"{s}\" has an unclosed [."))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().map_err(|_| format!("\"{s}\" has a bad port."))?,
                None if after.is_empty() => default_port,
                None => return Err(format!("\"{s}\" isn't host:port.")),
            };
            (h.to_string(), port)
        } else {
            match rest.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| format!("\"{s}\" has a bad port."))?),
                None => (rest.to_string(), default_port),
            }
        };
        let valid_host = host.parse::<IpAddr>().is_ok()
            || (!host.is_empty() && host.contains('.') && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'));
        if !valid_host || port == 0 {
            return Err(format!("\"{s}\" isn't host:port."));
        }
        Ok(Target { host, port, direct_tls })
    }
}

/// Why a domain has no targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupError {
    /// No such domain, or it says it has no XMPP service (SRV target ".").
    NotFound,
    /// DNS didn't answer.
    Failed(String),
}

/// One SRV record, as far as ordering goes.
#[derive(Debug, Clone)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub target: Target,
}

/// RFC 2782 order: by priority; within one priority, a weighted random pick each time. At equal
/// priority direct TLS goes first (it saves a round trip and hides the stream header).
pub fn order(mut records: Vec<Srv>, mut rand: impl FnMut(u32) -> u32) -> Vec<Target> {
    records.sort_by_key(|r| (r.priority, !r.target.direct_tls));
    let mut out = Vec::with_capacity(records.len());
    let mut i = 0;
    while i < records.len() {
        let p = records[i].priority;
        let tls = records[i].target.direct_tls;
        let mut group: Vec<Srv> = Vec::new();
        while i < records.len() && records[i].priority == p && records[i].target.direct_tls == tls {
            group.push(records[i].clone());
            i += 1;
        }
        while !group.is_empty() {
            let total: u32 = group.iter().map(|r| u32::from(r.weight)).sum();
            let pick = if total == 0 {
                0
            } else {
                let mut n = rand(total + 1);
                group
                    .iter()
                    .position(|r| {
                        let w = u32::from(r.weight);
                        if n <= w {
                            true
                        } else {
                            n -= w;
                            false
                        }
                    })
                    // n ≤ total, so some record matches; the fallback only satisfies the types.
                    .unwrap_or(group.len() - 1)
            };
            out.push(group.remove(pick).target);
        }
    }
    out
}

/// `domain` as DNS and TLS see it: internationalized labels become A-labels (`bücher.example`
/// is `xn--bcher-kva.example` on the wire; RFC 5890, UTS #46). None when it isn't a valid
/// domain name at all.
pub fn to_ascii(domain: &str) -> Option<String> {
    if domain.is_ascii() {
        return Some(domain.to_ascii_lowercase());
    }
    idna::domain_to_ascii(domain).ok().filter(|d| !d.is_empty())
}

/// Where to connect for `domain`: a configured route, else SRV, else the domain on 5269.
pub async fn targets(resolver: &TokioResolver, route: Option<&str>, domain: &str) -> Result<Vec<Target>, LookupError> {
    if let Some(r) = route {
        return Target::parse_route(r).map(|t| vec![t]).map_err(LookupError::Failed);
    }
    let domain = to_ascii(domain).ok_or(LookupError::NotFound)?;
    let domain = domain.as_str();
    // RFC 6761: these never resolve, so don't ask.
    if domain.ends_with(".invalid") || domain == "invalid" || domain == "localhost" || domain.ends_with(".localhost") {
        return Err(LookupError::NotFound);
    }
    // An IP literal domain (`192.0.2.1`, `[2001:db8::1]`) has no SRV records to ask for.
    if let Ok(ip) = domain.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
        return Ok(vec![Target { host: ip.to_string(), port: DEFAULT_PORT, direct_tls: false }]);
    }
    let (tls, plain) = tokio::join!(srv(resolver, "_xmpps-server._tcp.", domain, true), srv(resolver, "_xmpp-server._tcp.", domain, false));
    merge(domain, tls, plain, |n| rand::random::<u32>() % n)
}

/// One SRV lookup: the records, None when there are none, or why it failed.
type SrvAnswer = Result<Option<Vec<Srv>>, String>;

/// Combines the direct TLS and STARTTLS SRV answers. A lone "." target means that service isn't
/// offered: for `_xmpp-server` the domain has no federation at all (RFC 6120 §3.2.1), but for
/// `_xmpps-server` it only rules out direct TLS, so STARTTLS records or the domain itself on
/// 5269 are still tried (XEP-0368 §3). Likewise only a failed `_xmpp-server` lookup is fatal.
fn merge(domain: &str, tls: SrvAnswer, plain: SrvAnswer, rand: impl FnMut(u32) -> u32) -> Result<Vec<Target>, LookupError> {
    let usable = |rs: Vec<Srv>| rs.into_iter().filter(|r| r.target.host != ".").collect::<Vec<_>>();
    let denied = matches!(&plain, Ok(Some(rs)) if rs.len() == 1 && rs[0].target.host == ".");
    let mut records = Vec::new();
    match tls {
        Ok(Some(rs)) => records.extend(usable(rs)),
        Ok(None) => {}
        Err(e) => tracing::debug!(domain, error = %e, "direct TLS SRV lookup failed; trying STARTTLS"),
    }
    let failure = match plain {
        Ok(Some(rs)) => {
            records.extend(usable(rs));
            None
        }
        Ok(None) => None,
        Err(e) => Some(e),
    };
    if !records.is_empty() {
        let mut out = order(records, rand);
        out.truncate(MAX_TARGETS);
        return Ok(out);
    }
    if denied {
        return Err(LookupError::NotFound);
    }
    if let Some(e) = failure {
        return Err(LookupError::Failed(e));
    }
    Ok(vec![Target { host: domain.to_string(), port: DEFAULT_PORT, direct_tls: false }])
}

/// SRV records under `prefix` + `domain`; None when there are none.
async fn srv(resolver: &TokioResolver, prefix: &str, domain: &str, direct_tls: bool) -> Result<Option<Vec<Srv>>, String> {
    let name = format!("{prefix}{domain}.");
    match resolver.srv_lookup(name).await {
        Ok(l) => Ok(Some(
            l.answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::SRV(r) => Some(r),
                    _ => None,
                })
                .map(|r| {
                    let host = r.target.to_utf8();
                    let host = if host == "." { host } else { host.trim_end_matches('.').to_ascii_lowercase() };
                    Srv { priority: r.priority, weight: r.weight, target: Target { host, port: r.port, direct_tls } }
                })
                .collect(),
        )),
        Err(e) if e.is_no_records_found() => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The addresses of a target, IPv6 and IPv4 interleaved.
pub async fn addrs(resolver: &TokioResolver, t: &Target) -> Result<Vec<SocketAddr>, LookupError> {
    if let Ok(ip) = t.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, t.port)]);
    }
    let ips = match resolver.lookup_ip(format!("{}.", t.host)).await {
        Ok(l) => l.iter().collect::<Vec<_>>(),
        Err(e) if e.is_no_records_found() => return Err(LookupError::NotFound),
        Err(e) => return Err(LookupError::Failed(e.to_string())),
    };
    Ok(interleave(ips).into_iter().take(MAX_ADDRS).map(|ip| SocketAddr::new(ip, t.port)).collect())
}

/// The addresses federation may connect to without a configured route: public ones, plus the
/// networks in `s2s.allow_networks`. Whoever controls a domain's DNS (or names an IP literal
/// domain) chooses where we connect, so without this a server asking for dialback, or a user
/// messaging `x@127.0.0.1`, could make this server probe its own loopback services, the LAN or
/// a cloud metadata endpoint, on any port.
pub fn reachable(policy: &PeerPolicy, addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addrs.into_iter().filter(|a| policy.allows(a.ip())).collect()
}

/// IPv6 first, then alternating families (RFC 8305 §4).
fn interleave(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    let (v6, v4): (Vec<IpAddr>, Vec<IpAddr>) = ips.into_iter().partition(IpAddr::is_ipv6);
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

/// Connects to the first address that answers. A new attempt starts every [`STAGGER`] while the
/// earlier ones are still pending, so one dead address doesn't hold up the rest.
pub async fn connect(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut set = JoinSet::new();
    let mut next = addrs.iter().copied();
    let mut last_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses");
    if let Some(a) = next.next() {
        set.spawn(attempt(a));
    }
    loop {
        if set.is_empty() {
            return Err(last_err);
        }
        let more = next.len() > 0;
        tokio::select! {
            r = set.join_next() => match r {
                Some(Ok(Ok(tcp))) => return Ok(tcp),
                Some(Ok(Err(e))) => {
                    last_err = e;
                    // A failure starts the next attempt at once.
                    if let Some(a) = next.next() {
                        set.spawn(attempt(a));
                    }
                }
                Some(Err(e)) => last_err = std::io::Error::other(e.to_string()),
                None => return Err(last_err),
            },
            _ = tokio::time::sleep(STAGGER), if more => {
                if let Some(a) = next.next() {
                    set.spawn(attempt(a));
                }
            }
        }
    }
}

async fn attempt(a: SocketAddr) -> std::io::Result<TcpStream> {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{a} didn't answer"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, tls: bool) -> Target {
        Target { host: host.into(), port: 5269, direct_tls: tls }
    }

    #[test]
    fn routes_parse() {
        assert_eq!(Target::parse_route("127.0.0.1:5269").unwrap(), Target { host: "127.0.0.1".into(), port: 5269, direct_tls: false });
        assert_eq!(Target::parse_route("tls://xmpp.b.test").unwrap(), Target { host: "xmpp.b.test".into(), port: 5270, direct_tls: true });
        assert_eq!(Target::parse_route("[::1]:6000").unwrap().host, "::1");
        assert_eq!(Target::parse_route("[::1]").unwrap().port, 5269);
        for bad in ["", "nowhere", "a.test:x", "a.test:0", "[::1", "a b.test:1"] {
            assert!(Target::parse_route(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn srv_order_follows_priority_then_prefers_direct_tls() {
        let recs = vec![
            Srv { priority: 20, weight: 0, target: t("backup", false) },
            Srv { priority: 10, weight: 0, target: t("starttls", false) },
            Srv { priority: 10, weight: 0, target: t("direct", true) },
        ];
        let hosts: Vec<String> = order(recs, |_| 0).into_iter().map(|t| t.host).collect();
        assert_eq!(hosts, ["direct", "starttls", "backup"]);
    }

    #[test]
    fn srv_weights_pick_within_a_priority() {
        let recs =
            || vec![Srv { priority: 0, weight: 10, target: t("light", false) }, Srv { priority: 0, weight: 90, target: t("heavy", false) }];
        // A roll past the first record's weight lands on the second.
        assert_eq!(order(recs(), |_| 50)[0].host, "heavy");
        assert_eq!(order(recs(), |_| 5)[0].host, "light");
        assert_eq!(order(recs(), |_| 5).len(), 2);
    }

    #[test]
    fn addresses_alternate_families_v6_first() {
        let ips: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2", "::1", "::2", "10.0.0.3"].iter().map(|s| s.parse().unwrap()).collect();
        let out: Vec<String> = interleave(ips).iter().map(ToString::to_string).collect();
        assert_eq!(out, ["::1", "10.0.0.1", "::2", "10.0.0.2", "10.0.0.3"]);
    }

    #[tokio::test]
    async fn connect_skips_dead_addresses() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = l.local_addr().unwrap();
        // A port nothing listens on: refused straight away.
        let dead = {
            let d = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            d.local_addr().unwrap()
        };
        let tcp = connect(&[dead, live]).await.unwrap();
        assert_eq!(tcp.peer_addr().unwrap(), live);
        assert!(connect(&[dead]).await.is_err());
        assert!(connect(&[]).await.is_err());
    }

    fn dot(tls: bool) -> SrvAnswer {
        Ok(Some(vec![Srv { priority: 0, weight: 0, target: Target { host: ".".into(), port: 0, direct_tls: tls } }]))
    }

    #[test]
    fn no_direct_tls_still_falls_back_to_starttls() {
        // "." for _xmpps-server only rules out direct TLS: the domain itself on 5269 is next.
        let out = merge("b.test", dot(true), Ok(None), |_| 0).unwrap();
        assert_eq!(out, [Target { host: "b.test".into(), port: DEFAULT_PORT, direct_tls: false }]);
        let plain = Ok(Some(vec![Srv { priority: 5, weight: 0, target: t("xmpp.b.test", false) }]));
        assert_eq!(merge("b.test", dot(true), plain, |_| 0).unwrap()[0].host, "xmpp.b.test");
        // A failed direct TLS lookup doesn't stop STARTTLS either.
        assert_eq!(merge("b.test", Err("SERVFAIL".into()), Ok(None), |_| 0).unwrap()[0].host, "b.test");
    }

    #[test]
    fn no_federation_service_means_no_server() {
        assert_eq!(merge("b.test", Ok(None), dot(false), |_| 0), Err(LookupError::NotFound));
        assert_eq!(merge("b.test", dot(true), dot(false), |_| 0), Err(LookupError::NotFound));
        assert!(matches!(merge("b.test", Ok(None), Err("SERVFAIL".into()), |_| 0), Err(LookupError::Failed(_))));
        // Direct TLS records still count when STARTTLS is ruled out.
        let tls = Ok(Some(vec![Srv { priority: 0, weight: 0, target: t("tls.b.test", true) }]));
        assert_eq!(merge("b.test", tls, dot(false), |_| 0).unwrap()[0].host, "tls.b.test");
    }

    #[test]
    fn internationalized_domains_become_a_labels() {
        assert_eq!(to_ascii("bücher.test").as_deref(), Some("xn--bcher-kva.test"));
        assert_eq!(to_ascii("B.Test").as_deref(), Some("b.test"));
        assert_eq!(to_ascii("xn--bcher-kva.test").as_deref(), Some("xn--bcher-kva.test"));
    }

    #[test]
    fn federation_only_reaches_public_addresses_unless_allowed() {
        let a = |s: &str| SocketAddr::new(s.parse().unwrap(), 5269);
        let all = ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "fe80::1", "::ffff:127.0.0.1", "8.8.8.8", "2a00::1"];
        let strict = PeerPolicy::public_only(Vec::new());
        assert_eq!(reachable(&strict, all.iter().map(|s| a(s)).collect()), [a("8.8.8.8"), a("2a00::1")]);
        let lan = PeerPolicy::public_only(vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(reachable(&lan, vec![a("10.0.0.5"), a("192.168.1.1")]), [a("10.0.0.5")]);
    }

    fn test_resolver() -> TokioResolver {
        use hickory_resolver::config::{ResolverConfig, GOOGLE};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        TokioResolver::builder_with_config(ResolverConfig::udp_and_tcp(&GOOGLE), TokioRuntimeProvider::default()).build().unwrap()
    }

    #[tokio::test]
    async fn ip_literal_domains_skip_dns() {
        let r = test_resolver();
        assert_eq!(targets(&r, None, "127.0.0.1").await.unwrap()[0].host, "127.0.0.1");
        assert_eq!(targets(&r, None, "[::1]").await.unwrap()[0].host, "::1");
    }

    #[tokio::test]
    async fn reserved_names_are_not_looked_up() {
        let r = test_resolver();
        assert_eq!(targets(&r, None, "nowhere.invalid").await, Err(LookupError::NotFound));
        assert_eq!(targets(&r, Some("10.1.2.3:5300"), "b.test").await.unwrap()[0].port, 5300);
    }
}
