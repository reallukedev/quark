//! Certificates on server-to-server links: which CAs we trust, and TLS configs that let every
//! handshake finish so a peer without a trusted certificate can still fall back to dialback.
//! Whether a certificate is valid for a domain is decided after the handshake, per domain.

use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use rustls_pki_types::pem::PemObject;

use sha2::{Digest, Sha256};

use crate::tls::CertStore;

/// Adds one file to a trust store digest, length first so file boundaries count.
fn hash_file(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

/// The CAs we trust and a verifier built from them.
pub struct Pki {
    /// The files the extra roots came from, to notice config changes.
    pub sources: Vec<PathBuf>,
    /// A hash of what those files held, to notice them being replaced.
    pub digest: [u8; 32],
    verifier: Arc<WebPkiServerVerifier>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for Pki {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pki").field("sources", &self.sources).finish_non_exhaustive()
    }
}

impl Pki {
    /// The public web roots plus every certificate in `extra` (PEM files). Reads files: call it
    /// off the async threads.
    pub fn load(extra: &[PathBuf]) -> Result<Pki, String> {
        let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let mut digest = Sha256::new();
        for path in extra {
            let pem = std::fs::read(path).map_err(|e| format!("couldn't read {}: {e}", path.display()))?;
            hash_file(&mut digest, &pem);
            let mut n = 0;
            for c in CertificateDer::pem_slice_iter(&pem) {
                let c = c.map_err(|e| format!("{}: {e}", path.display()))?;
                roots.add(c).map_err(|e| format!("{}: {e}", path.display()))?;
                n += 1;
            }
            if n == 0 {
                return Err(format!("{} has no certificates in it.", path.display()));
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|e| format!("couldn't build the certificate verifier: {e}"))?;
        Ok(Pki { sources: extra.to_vec(), digest: digest.finalize().into(), verifier, provider })
    }

    /// The [`Pki::digest`] the files in `paths` would give now: compared with the loaded one, it
    /// says whether a file was rewritten in place (a renewed CA, a peer's new self-signed
    /// certificate) without the config changing. Reads files: call it off the async threads.
    pub fn fingerprint(paths: &[PathBuf]) -> Result<[u8; 32], String> {
        let mut digest = Sha256::new();
        for path in paths {
            let pem = std::fs::read(path).map_err(|e| format!("couldn't read {}: {e}", path.display()))?;
            hash_file(&mut digest, &pem);
        }
        Ok(digest.finalize().into())
    }

    /// Whether `chain` (leaf first) is a currently valid certificate for `domain` from a CA we
    /// trust (RFC 6125 DNS-ID, wildcards included). Internationalized domains are matched in
    /// their A-label form, the way certificates carry them (RFC 6125 §6.4.2).
    pub fn valid_for(&self, chain: &[CertificateDer<'_>], domain: &str) -> bool {
        let Some((leaf, intermediates)) = chain.split_first() else { return false };
        let Some(ascii) = super::dns::to_ascii(domain) else { return false };
        let Ok(name) = ServerName::try_from(ascii) else { return false };
        self.verifier.verify_server_cert(leaf, intermediates, &name, &[], UnixTime::now()).is_ok()
    }

    /// For connections we make. `own`: the client certificate to present (only one that's valid,
    /// since a strict peer fails the whole handshake over a certificate it can't verify).
    pub fn client_config(&self, own: Option<Arc<CertifiedKey>>, alpn: &[&[u8]]) -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
        let mut c = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Deferred(self.provider.clone())))
            .with_client_cert_resolver(Arc::new(OwnCert(own)));
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(c))
    }

    /// For connections we accept: our certificate by SNI, and the peer's certificate asked for but
    /// not required (it's checked against the domain the peer claims, for SASL EXTERNAL).
    pub fn server_config(&self, certs: &Arc<CertStore>, alpn: &[&[u8]]) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
        let mut c = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(Deferred(self.provider.clone())))
            .with_cert_resolver(certs.resolver());
        c.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(Arc::new(c))
    }
}

/// Accepts any certificate chain during the handshake (handshake signatures are still checked, so
/// the peer does hold the key) and leaves trust to [`Pki::valid_for`].
#[derive(Debug)]
struct Deferred(Arc<CryptoProvider>);

impl Deferred {
    fn tls12(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn tls13(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl ServerCertVerifier for Deferred {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls12(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

impl ClientCertVerifier for Deferred {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        false
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls12(m, c, d)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.tls13(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }
}

/// Presents our certificate for the sending domain when the peer asks for one.
#[derive(Debug)]
struct OwnCert(Option<Arc<CertifiedKey>>);

impl ResolvesClientCert for OwnCert {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.0.clone()
    }
    fn has_certs(&self) -> bool {
        self.0.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca_and_leaf(names: &[&str]) -> (String, Vec<CertificateDer<'static>>) {
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let leaf = rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        (ca_cert.pem(), vec![leaf_cert.der().clone()])
    }

    #[test]
    fn certificates_are_checked_against_trusted_cas_and_names() {
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, chain) = ca_and_leaf(&["b.test", "*.b.test"]);
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, ca_pem).unwrap();

        let public_only = Pki::load(&[]).unwrap();
        assert!(!public_only.valid_for(&chain, "b.test"), "an unknown CA isn't trusted");

        let pki = Pki::load(&[ca]).unwrap();
        assert!(pki.valid_for(&chain, "b.test"));
        assert!(pki.valid_for(&chain, "rooms.b.test"));
        assert!(!pki.valid_for(&chain, "a.test"));
        assert!(!pki.valid_for(&[], "b.test"));
    }

    #[test]
    fn a_trusted_self_signed_certificate_is_valid_for_its_names() {
        let dir = tempfile::tempdir().unwrap();
        let ck = rcgen::generate_simple_self_signed(vec!["b.test".to_string()]).unwrap();
        let path = dir.path().join("b.pem");
        std::fs::write(&path, ck.cert.pem()).unwrap();
        let pki = Pki::load(&[path]).unwrap();
        assert!(pki.valid_for(&[ck.cert.der().clone()], "b.test"));
    }

    #[test]
    fn internationalized_domains_match_their_a_labels() {
        let dir = tempfile::tempdir().unwrap();
        let ck = rcgen::generate_simple_self_signed(vec!["xn--bcher-kva.test".to_string()]).unwrap();
        let path = dir.path().join("b.pem");
        std::fs::write(&path, ck.cert.pem()).unwrap();
        let pki = Pki::load(&[path]).unwrap();
        let chain = [ck.cert.der().clone()];
        assert!(pki.valid_for(&chain, "bücher.test"));
        assert!(pki.valid_for(&chain, "xn--bcher-kva.test"));
        assert!(!pki.valid_for(&chain, "bucher.test"));
    }

    #[test]
    fn rewritten_trust_files_change_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer.pem");
        let first = rcgen::generate_simple_self_signed(vec!["b.test".to_string()]).unwrap();
        std::fs::write(&path, first.cert.pem()).unwrap();
        let pki = Pki::load(std::slice::from_ref(&path)).unwrap();
        assert_eq!(Pki::fingerprint(std::slice::from_ref(&path)).unwrap(), pki.digest);
        // Same path, new contents (even within the same second, at the same length).
        let second = rcgen::generate_simple_self_signed(vec!["b.test".to_string()]).unwrap();
        std::fs::write(&path, second.cert.pem()).unwrap();
        assert_ne!(Pki::fingerprint(std::slice::from_ref(&path)).unwrap(), pki.digest);
        let reloaded = Pki::load(std::slice::from_ref(&path)).unwrap();
        assert!(reloaded.valid_for(&[second.cert.der().clone()], "b.test"));
        assert!(!reloaded.valid_for(&[first.cert.der().clone()], "b.test"));
    }

    #[test]
    fn bad_trust_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "nothing here").unwrap();
        assert!(Pki::load(&[empty]).unwrap_err().contains("no certificates"));
        assert!(Pki::load(&[dir.path().join("missing.pem")]).is_err());
    }
}
