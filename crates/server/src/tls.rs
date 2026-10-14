//! Certificates: read from the cert folder, matched by name (SNI, wildcards included), swapped in
//! when the files change without dropping connections, and a self-signed fallback so TLS always
//! works on a fresh install.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::RwLock;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pemfile::Item;
use serde::Serialize;
use sha2::Digest;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertInfo {
    pub self_signed: bool,
    pub not_after: Option<i64>,
    pub issuer: Option<String>,
}

struct Entry {
    key: Arc<CertifiedKey>,
    names: Vec<String>,
    info: CertInfo,
    /// RFC 5929 tls-server-end-point binding for this certificate.
    end_point: Vec<u8>,
}

/// Picks a certificate for each connection by the name the client asked for.
pub struct CertStore {
    dir: PathBuf,
    self_signed_dir: PathBuf,
    fallback: bool,
    entries: RwLock<Vec<Arc<Entry>>>,
    /// Every certificate and key file seen at the last reload, with its modification time, so a
    /// change (or a broken file being fixed) is noticed.
    seen: RwLock<Vec<(PathBuf, Option<SystemTime>)>>,
    /// Domains we serve, for self-signed fallbacks and the default when there's no SNI.
    domains: RwLock<Vec<String>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").field("dir", &self.dir).finish_non_exhaustive()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("{0}: {1}")]
    File(PathBuf, String),
    #[error("couldn't make a certificate: {0}")]
    Generate(String),
}

impl CertStore {
    pub fn new(dir: &Path, data_dir: &Path, fallback: bool) -> Arc<CertStore> {
        Arc::new(CertStore {
            dir: dir.to_path_buf(),
            self_signed_dir: data_dir.join("self-signed"),
            fallback,
            entries: RwLock::new(Vec::new()),
            seen: RwLock::new(Vec::new()),
            domains: RwLock::new(Vec::new()),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Sets the domains we serve and makes sure each has a certificate.
    pub fn set_domains(&self, domains: Vec<String>) -> Result<usize, TlsError> {
        *self.domains.write() = domains;
        self.reload()
    }

    /// Re-reads the cert folder. Returns how many certificates are loaded.
    pub fn reload(&self) -> Result<usize, TlsError> {
        let mut entries = Vec::new();
        let pairs = pairs_in(&self.dir);
        *self.seen.write() = snapshot(&pairs);
        for (crt, key) in pairs {
            match load_entry(&crt, &key, false) {
                Ok(e) => entries.push(Arc::new(e)),
                Err(e) => tracing::warn!(error = %e, "skipping certificate"),
            }
        }
        // Real certificates first, so they win over self-signed ones for the same name.
        if self.fallback {
            for d in self.domains.read().iter() {
                if !entries.iter().any(|e| covers(&e.names, d)) {
                    entries.push(Arc::new(self.self_signed(d)?));
                }
            }
        }
        let n = entries.len();
        *self.entries.write() = entries;
        Ok(n)
    }

    /// True when a certificate file changed since it was loaded (or a new one appeared).
    pub fn changed(&self) -> bool {
        snapshot(&pairs_in(&self.dir)) != *self.seen.read()
    }

    /// Watches the cert folder and reloads when it changes. Polling works on every filesystem,
    /// bind mounts and network shares included, and costs nothing at this interval.
    pub fn watch(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                tick.tick().await;
                let Some(s) = me.upgrade() else { return };
                if s.changed() {
                    match tokio::task::spawn_blocking(move || s.reload()).await {
                        Ok(Ok(n)) => tracing::info!(certificates = n, "certificates reloaded"),
                        Ok(Err(e)) => tracing::warn!(error = %e, "certificate reload failed"),
                        Err(e) => tracing::warn!(error = %e, "certificate reload panicked"),
                    }
                }
            }
        })
    }

    fn find(&self, name: &str) -> Option<Arc<Entry>> {
        let entries = self.entries.read();
        entries.iter().find(|e| e.names.iter().any(|n| n == name)).or_else(|| entries.iter().find(|e| covers(&e.names, name))).cloned()
    }

    fn default_entry(&self) -> Option<Arc<Entry>> {
        let first = self.domains.read().first().cloned();
        first.and_then(|d| self.find(&d)).or_else(|| self.entries.read().first().cloned())
    }

    /// The certificate and key serving `name` (no default fallback), e.g. to present as a
    /// client certificate on server-to-server links.
    pub fn certified_key(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.find(name).map(|e| e.key.clone())
    }

    pub fn info(&self, name: &str) -> Option<CertInfo> {
        self.find(name).map(|e| e.info.clone())
    }

    /// The tls-server-end-point channel binding for the certificate serving `name`.
    pub fn end_point(&self, name: Option<&str>) -> Option<Vec<u8>> {
        name.and_then(|n| self.find(n)).or_else(|| self.default_entry()).map(|e| e.end_point.clone())
    }

    /// A rustls config for incoming connections, with the given ALPN protocols.
    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let mut c = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(self.clone())));
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(c)
    }

    pub fn resolver(self: &Arc<Self>) -> Arc<dyn ResolvesServerCert> {
        Arc::new(Resolver(self.clone()))
    }

    fn self_signed(&self, domain: &str) -> Result<Entry, TlsError> {
        let crt = self.self_signed_dir.join(format!("{domain}.crt"));
        let key = self.self_signed_dir.join(format!("{domain}.key"));
        if let Ok(e) = load_entry(&crt, &key, true) {
            if e.info.not_after.is_none_or(|t| t > quark_core::time::now_ms() + 7 * 86_400_000) {
                return Ok(e);
            }
        }
        let names = vec![domain.to_string(), format!("*.{domain}")];
        let ck = rcgen::generate_simple_self_signed(names).map_err(|e| TlsError::Generate(e.to_string()))?;
        std::fs::create_dir_all(&self.self_signed_dir).map_err(|e| TlsError::File(self.self_signed_dir.clone(), e.to_string()))?;
        write_private(&key, ck.key_pair.serialize_pem().as_bytes())?;
        std::fs::write(&crt, ck.cert.pem()).map_err(|e| TlsError::File(crt.clone(), e.to_string()))?;
        tracing::info!(domain, "made a self-signed certificate; put a real one in the cert folder");
        load_entry(&crt, &key, true)
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), TlsError> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).map_err(|e| TlsError::File(path.to_path_buf(), e.to_string()))?;
    f.write_all(data).map_err(|e| TlsError::File(path.to_path_buf(), e.to_string()))
}

#[derive(Debug)]
struct Resolver(Arc<CertStore>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let e = match hello.server_name() {
            Some(n) => self.0.find(&n.to_ascii_lowercase()).or_else(|| self.0.default_entry()),
            None => self.0.default_entry(),
        };
        e.map(|e| e.key.clone())
    }
}

/// Does a certificate with these names serve `name`? Wildcards cover one label.
pub fn covers(names: &[String], name: &str) -> bool {
    names.iter().any(|n| {
        n == name
            || n.strip_prefix("*.").is_some_and(|base| {
                name.strip_suffix(base)
                    .is_some_and(|label| label.ends_with('.') && label.len() > 1 && !label[..label.len() - 1].contains('.'))
            })
    })
}

fn snapshot(pairs: &[(PathBuf, PathBuf)]) -> Vec<(PathBuf, Option<SystemTime>)> {
    pairs.iter().flat_map(|(c, k)| [c, k]).map(|p| (p.clone(), mtime(p))).collect()
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// (certificate, key) file pairs: `name.crt` + `name.key`, or `name/fullchain.pem` + `privkey.pem`.
fn pairs_in(dir: &Path) -> Vec<(PathBuf, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let (c, k) = (p.join("fullchain.pem"), p.join("privkey.pem"));
            if c.is_file() && k.is_file() {
                out.push((c, k));
            }
        } else if p.extension().is_some_and(|x| x == "crt") {
            let k = p.with_extension("key");
            if k.is_file() {
                out.push((p, k));
            }
        }
    }
    out.sort();
    out
}

fn load_entry(crt: &Path, key: &Path, self_signed: bool) -> Result<Entry, TlsError> {
    let err = |p: &Path, e: String| TlsError::File(p.to_path_buf(), e);
    let crt_pem = std::fs::read(crt).map_err(|e| err(crt, e.to_string()))?;
    let key_pem = std::fs::read(key).map_err(|e| err(key, e.to_string()))?;
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut crt_pem.as_slice()).collect::<Result<_, _>>().map_err(|e| err(crt, e.to_string()))?;
    let leaf = chain.first().ok_or_else(|| err(crt, "no certificate in the file".into()))?.clone();
    let key_der = loop_key(&key_pem).ok_or_else(|| err(key, "no private key in the file".into()))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(|e| err(key, e.to_string()))?;
    let ck = CertifiedKey::new(chain, signer);
    ck.keys_match().map_err(|e| err(key, format!("the key doesn't belong to the certificate ({e})")))?;

    let (_, x) = x509_parser::parse_x509_certificate(&leaf).map_err(|e| err(crt, e.to_string()))?;
    let mut names: Vec<String> = Vec::new();
    if let Ok(Some(san)) = x.subject_alternative_name() {
        for n in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = n {
                names.push(d.to_ascii_lowercase());
            }
        }
    }
    if names.is_empty() {
        names.extend(x.subject().iter_common_name().filter_map(|c| c.as_str().ok()).map(str::to_ascii_lowercase));
    }
    let issuer = x.issuer().iter_organization().chain(x.issuer().iter_common_name()).find_map(|c| c.as_str().ok()).map(String::from);
    let not_after = Some(x.validity().not_after.timestamp() * 1000);
    // RFC 5929 §4.1: SHA-256 unless the certificate is signed with a stronger hash.
    let alg = x.signature_algorithm.algorithm.to_id_string();
    let end_point = match alg.as_str() {
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => sha2::Sha384::digest(&leaf).to_vec(),
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => sha2::Sha512::digest(&leaf).to_vec(),
        _ => sha2::Sha256::digest(&leaf).to_vec(),
    };
    Ok(Entry { key: Arc::new(ck), names, info: CertInfo { self_signed, not_after, issuer }, end_point })
}

fn loop_key(pem: &[u8]) -> Option<PrivateKeyDer<'static>> {
    for item in rustls_pemfile::read_all(&mut &pem[..]).flatten() {
        match item {
            Item::Pkcs8Key(k) => return Some(PrivateKeyDer::Pkcs8(k)),
            Item::Pkcs1Key(k) => return Some(PrivateKeyDer::Pkcs1(k)),
            Item::Sec1Key(k) => return Some(PrivateKeyDer::Sec1(k)),
            _ => {}
        }
    }
    None
}

/// TLS session facts the stream needs: SNI, ALPN and channel bindings.
pub fn session_facts<IO>(
    s: &tokio_rustls::server::TlsStream<IO>,
    store: &CertStore,
) -> (Option<String>, Option<Vec<u8>>, crate::sasl::ChannelBindings) {
    let (_, conn) = s.get_ref();
    let sni = conn.server_name().map(str::to_ascii_lowercase);
    let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
    let mut exporter = None;
    if conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3) {
        let mut buf = [0u8; 32];
        if conn.export_keying_material(&mut buf, b"EXPORTER-Channel-Binding", None).is_ok() {
            exporter = Some(buf.to_vec());
        }
    }
    let cb = crate::sasl::ChannelBindings { exporter, server_end_point: store.end_point(sni.as_deref()) };
    (sni, alpn, cb)
}

/// Domains a certificate covers, for status pages.
pub fn names_map(store: &CertStore) -> HashMap<String, CertInfo> {
    let mut m = HashMap::new();
    for e in store.entries.read().iter() {
        for n in &e.names {
            m.entry(n.clone()).or_insert_with(|| e.info.clone());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_cover_one_label() {
        let n = vec!["*.example.com".to_string(), "example.com".to_string()];
        assert!(covers(&n, "rooms.example.com"));
        assert!(covers(&n, "example.com"));
        assert!(!covers(&n, "a.b.example.com"));
        assert!(!covers(&n, "badexample.com"));
    }

    #[test]
    fn self_signed_fallback_and_reload() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certs = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let s = CertStore::new(certs.path(), data.path(), true);
        assert_eq!(s.set_domains(vec!["a.test".into()]).unwrap(), 1);
        assert!(s.info("a.test").unwrap().self_signed);
        assert!(s.info("rooms.a.test").is_some());
        assert!(!s.changed());

        // Drop a "real" certificate in: it is noticed and preferred.
        let ck = rcgen::generate_simple_self_signed(vec!["a.test".to_string()]).unwrap();
        std::fs::write(certs.path().join("a.test.crt"), ck.cert.pem()).unwrap();
        std::fs::write(certs.path().join("a.test.key"), ck.key_pair.serialize_pem()).unwrap();
        assert!(s.changed());
        assert_eq!(s.reload().unwrap(), 1);
        assert!(!s.info("a.test").unwrap().self_signed);
    }
}
