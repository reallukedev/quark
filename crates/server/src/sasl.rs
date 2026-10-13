//! Server side of SASL: PLAIN (RFC 4616), SCRAM-SHA-1/256/512 with and without channel binding
//! (RFC 5802, RFC 7677, RFC 9266), and FAST tokens (XEP-0484). Transport independent: the
//! stream code feeds it the client's messages and sends back what it returns.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use subtle::ConstantTimeEq;

use crate::accounts::{Accounts, ScramCredentials, ScramHash, ITERATIONS};

/// Channel binding data for this connection.
#[derive(Debug, Clone, Default)]
pub struct ChannelBindings {
    /// RFC 9266 `tls-exporter` (TLS 1.3).
    pub exporter: Option<Vec<u8>>,
    /// RFC 5929 `tls-server-end-point`: hash of our certificate.
    pub server_end_point: Option<Vec<u8>>,
}

impl ChannelBindings {
    pub fn get(&self, kind: &str) -> Option<&[u8]> {
        match kind {
            "tls-exporter" => self.exporter.as_deref(),
            "tls-server-end-point" => self.server_end_point.as_deref(),
            _ => None,
        }
    }
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.exporter.is_some() {
            v.push("tls-exporter");
        }
        if self.server_end_point.is_some() {
            v.push("tls-server-end-point");
        }
        v
    }
    pub fn any(&self) -> bool {
        self.exporter.is_some() || self.server_end_point.is_some()
    }
}

/// RFC 6120 §6.5 failure conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Aborted,
    AccountDisabled,
    CredentialsExpired,
    EncryptionRequired,
    IncorrectEncoding,
    InvalidAuthzid,
    InvalidMechanism,
    MalformedRequest,
    MechanismTooWeak,
    NotAuthorized,
    TemporaryAuthFailure,
}

impl Failure {
    pub fn as_str(self) -> &'static str {
        match self {
            Failure::Aborted => "aborted",
            Failure::AccountDisabled => "account-disabled",
            Failure::CredentialsExpired => "credentials-expired",
            Failure::EncryptionRequired => "encryption-required",
            Failure::IncorrectEncoding => "incorrect-encoding",
            Failure::InvalidAuthzid => "invalid-authzid",
            Failure::InvalidMechanism => "invalid-mechanism",
            Failure::MalformedRequest => "malformed-request",
            Failure::MechanismTooWeak => "mechanism-too-weak",
            Failure::NotAuthorized => "not-authorized",
            Failure::TemporaryAuthFailure => "temporary-auth-failure",
        }
    }
}

#[derive(Debug)]
pub enum Step {
    Challenge(Vec<u8>),
    /// Signed in as `user` (the localpart). `data` is the server's final message, if any.
    Success {
        user: String,
        data: Option<Vec<u8>>,
    },
    Failure(Failure, Option<&'static str>),
}

/// Something that can check FAST tokens (XEP-0484); implemented by the FAST store.
#[async_trait::async_trait]
pub trait TokenCheck: Send + Sync {
    /// Valid token secrets for `user` with this mechanism: the newest, and the previous one still
    /// accepted while a rotation is in flight.
    async fn tokens(&self, host: &str, user: &str, mechanism: &str) -> Vec<Vec<u8>>;
}

pub struct Context<'a> {
    pub host: &'a str,
    pub accounts: &'a Accounts,
    pub cb: &'a ChannelBindings,
    pub secure: bool,
    /// Whether `-PLUS` mechanisms were offered (a `y` gs2 flag is then a downgrade).
    pub plus_offered: bool,
    pub tokens: Option<&'a dyn TokenCheck>,
}

/// Mechanisms to offer, strongest first.
pub fn mechanisms(cb: &ChannelBindings, secure: bool) -> Vec<&'static str> {
    let mut m = Vec::new();
    if cb.any() {
        m.extend(["SCRAM-SHA-512-PLUS", "SCRAM-SHA-256-PLUS", "SCRAM-SHA-1-PLUS"]);
    }
    m.extend(["SCRAM-SHA-512", "SCRAM-SHA-256", "SCRAM-SHA-1"]);
    if secure {
        m.push("PLAIN");
    }
    m
}

pub const FAST_MECHANISMS: [&str; 2] = ["HT-SHA-256-ENDP", "HT-SHA-256-NONE"];

#[expect(clippy::large_enum_variant, reason = "one short-lived value per sign-in in progress")]
enum State {
    Scram {
        hash: ScramHash,
        client_first_bare: String,
        gs2: String,
        cb_kind: Option<String>,
        server_first: String,
        nonce: String,
        user: String,
        cred: ScramCredentials,
        known: bool,
        enabled: bool,
    },
    Done,
}

pub struct Sasl {
    state: State,
}

impl Sasl {
    /// Starts `mechanism` with the client's initial response (empty when none was sent).
    pub async fn start(ctx: &Context<'_>, mechanism: &str, initial: &[u8]) -> (Option<Sasl>, Step) {
        match mechanism {
            "PLAIN" if ctx.secure => (None, plain(ctx, initial).await),
            "PLAIN" => (None, Step::Failure(Failure::EncryptionRequired, None)),
            m if m.starts_with("HT-SHA-256-") => (None, fast(ctx, m, initial).await),
            m => {
                let (name, plus) = match m.strip_suffix("-PLUS") {
                    Some(n) => (n, true),
                    None => (m, false),
                };
                let hash = match name {
                    "SCRAM-SHA-1" => ScramHash::Sha1,
                    "SCRAM-SHA-256" => ScramHash::Sha256,
                    "SCRAM-SHA-512" => ScramHash::Sha512,
                    _ => return (None, Step::Failure(Failure::InvalidMechanism, None)),
                };
                if plus && !ctx.cb.any() {
                    return (None, Step::Failure(Failure::InvalidMechanism, None));
                }
                match scram_first(ctx, hash, plus, initial).await {
                    Ok((state, challenge)) => (Some(Sasl { state }), Step::Challenge(challenge)),
                    Err(f) => (None, Step::Failure(f, None)),
                }
            }
        }
    }

    pub fn step(&mut self, ctx: &Context<'_>, response: &[u8]) -> Step {
        match std::mem::replace(&mut self.state, State::Done) {
            State::Scram { hash, client_first_bare, gs2, cb_kind, server_first, nonce, user, cred, known, enabled } => {
                let Ok(msg) = std::str::from_utf8(response) else {
                    return Step::Failure(Failure::MalformedRequest, None);
                };
                let Some((without_proof, proof)) = msg.rsplit_once(",p=") else {
                    return Step::Failure(Failure::MalformedRequest, None);
                };
                let mut c = None;
                let mut r = None;
                for part in without_proof.split(',') {
                    if let Some(v) = part.strip_prefix("c=") {
                        c = Some(v);
                    } else if let Some(v) = part.strip_prefix("r=") {
                        r = Some(v);
                    }
                }
                let (Some(c), Some(r)) = (c, r) else {
                    return Step::Failure(Failure::MalformedRequest, None);
                };
                if r != nonce {
                    return Step::Failure(Failure::NotAuthorized, None);
                }
                // The client must echo the gs2 header plus our channel binding data.
                let mut expect = gs2.into_bytes();
                if let Some(kind) = &cb_kind {
                    match ctx.cb.get(kind) {
                        Some(d) => expect.extend_from_slice(d),
                        None => return Step::Failure(Failure::NotAuthorized, None),
                    }
                }
                let Ok(got) = B64.decode(c) else {
                    return Step::Failure(Failure::IncorrectEncoding, None);
                };
                if !bool::from(got.ct_eq(&expect)) {
                    return Step::Failure(Failure::NotAuthorized, Some("Channel binding didn't match."));
                }
                let Ok(proof) = B64.decode(proof) else {
                    return Step::Failure(Failure::IncorrectEncoding, None);
                };
                let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
                let client_sig = hash.hmac(&cred.stored_key, auth_message.as_bytes());
                if proof.len() != client_sig.len() {
                    return Step::Failure(Failure::NotAuthorized, None);
                }
                let client_key: Vec<u8> = proof.iter().zip(&client_sig).map(|(a, b)| a ^ b).collect();
                let ok = bool::from(hash.hash(&client_key).ct_eq(&cred.stored_key));
                if !ok || !known {
                    return Step::Failure(Failure::NotAuthorized, None);
                }
                if !enabled {
                    return Step::Failure(Failure::AccountDisabled, None);
                }
                let server_sig = hash.hmac(&cred.server_key, auth_message.as_bytes());
                Step::Success { user, data: Some(format!("v={}", B64.encode(server_sig)).into_bytes()) }
            }
            State::Done => Step::Failure(Failure::MalformedRequest, None),
        }
    }
}

async fn plain(ctx: &Context<'_>, initial: &[u8]) -> Step {
    let mut parts = initial.split(|b| *b == 0);
    let (Some(authzid), Some(authcid), Some(pass), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Step::Failure(Failure::MalformedRequest, None);
    };
    let (Ok(authzid), Ok(authcid), Ok(pass)) = (std::str::from_utf8(authzid), std::str::from_utf8(authcid), std::str::from_utf8(pass))
    else {
        return Step::Failure(Failure::IncorrectEncoding, None);
    };
    let Some(user) = localpart(authcid, ctx.host) else {
        return Step::Failure(Failure::NotAuthorized, None);
    };
    if !authzid.is_empty() && localpart(authzid, ctx.host).as_deref() != Some(user.as_str()) {
        return Step::Failure(Failure::InvalidAuthzid, None);
    }
    match ctx.accounts.info(ctx.host, &user).await {
        Ok(Some(i)) if !i.enabled => return Step::Failure(Failure::AccountDisabled, None),
        Ok(_) => {}
        Err(_) => return Step::Failure(Failure::TemporaryAuthFailure, None),
    }
    match ctx.accounts.verify_password(ctx.host, &user, pass).await {
        Ok(true) => Step::Success { user, data: None },
        Ok(false) => Step::Failure(Failure::NotAuthorized, None),
        Err(_) => Step::Failure(Failure::TemporaryAuthFailure, None),
    }
}

/// FAST (XEP-0484): `username \0 HMAC(token, "Initiator" || cb-data)`.
async fn fast(ctx: &Context<'_>, mechanism: &str, initial: &[u8]) -> Step {
    let Some(tokens) = ctx.tokens else {
        return Step::Failure(Failure::InvalidMechanism, None);
    };
    let Some(i) = initial.iter().position(|b| *b == 0) else {
        return Step::Failure(Failure::MalformedRequest, None);
    };
    let Ok(name) = std::str::from_utf8(&initial[..i]) else {
        return Step::Failure(Failure::IncorrectEncoding, None);
    };
    let Some(user) = localpart(name, ctx.host) else {
        return Step::Failure(Failure::NotAuthorized, None);
    };
    let cb: &[u8] = match mechanism {
        "HT-SHA-256-NONE" => &[],
        "HT-SHA-256-ENDP" => match ctx.cb.server_end_point.as_deref() {
            Some(d) => d,
            None => return Step::Failure(Failure::InvalidMechanism, None),
        },
        "HT-SHA-256-EXPR" => match ctx.cb.exporter.as_deref() {
            Some(d) => d,
            None => return Step::Failure(Failure::InvalidMechanism, None),
        },
        _ => return Step::Failure(Failure::InvalidMechanism, None),
    };
    let given = &initial[i + 1..];
    let mut msg = b"Initiator".to_vec();
    msg.extend_from_slice(cb);
    for token in tokens.tokens(ctx.host, &user, mechanism).await {
        let expect = ScramHash::Sha256.hmac(&token, &msg);
        if bool::from(expect.ct_eq(given)) {
            let mut resp = b"Responder".to_vec();
            resp.extend_from_slice(cb);
            return Step::Success { user, data: Some(ScramHash::Sha256.hmac(&token, &resp)) };
        }
    }
    Step::Failure(Failure::NotAuthorized, None)
}

/// The localpart of an authcid: a bare username, or `user@host` for this host.
fn localpart(s: &str, host: &str) -> Option<String> {
    let j = match s.split_once('@') {
        Some((u, h)) => quark_core::Jid::from_parts(Some(u), h, None).ok().filter(|j| j.domain() == host)?,
        None => quark_core::Jid::from_parts(Some(s), host, None).ok()?,
    };
    j.node().map(str::to_string)
}

async fn scram_first(ctx: &Context<'_>, hash: ScramHash, plus: bool, initial: &[u8]) -> Result<(State, Vec<u8>), Failure> {
    let msg = std::str::from_utf8(initial).map_err(|_| Failure::IncorrectEncoding)?;
    // gs2-header: flag "," [authzid] ","
    let mut it = msg.splitn(3, ',');
    let (flag, authz, bare) = match (it.next(), it.next(), it.next()) {
        (Some(f), Some(a), Some(b)) => (f, a, b),
        _ => return Err(Failure::MalformedRequest),
    };
    let cb_kind = match flag {
        "n" if !plus => None,
        // The client could bind but thinks we can't: someone stripped -PLUS from our list.
        "y" if !plus && ctx.plus_offered => return Err(Failure::NotAuthorized),
        "y" if !plus => None,
        f if plus => Some(f.strip_prefix("p=").filter(|k| ctx.cb.get(k).is_some()).ok_or(Failure::NotAuthorized)?.to_string()),
        _ => return Err(Failure::MalformedRequest),
    };
    let gs2 = format!("{flag},{authz},");
    let mut user = None;
    let mut cnonce = None;
    for part in bare.split(',') {
        if let Some(v) = part.strip_prefix("n=") {
            user = Some(v.replace("=2C", ",").replace("=3D", "="));
        } else if let Some(v) = part.strip_prefix("r=") {
            cnonce = Some(v.to_string());
        } else if part.starts_with("m=") {
            return Err(Failure::MalformedRequest);
        }
    }
    let (Some(raw_user), Some(cnonce)) = (user, cnonce) else {
        return Err(Failure::MalformedRequest);
    };
    if cnonce.is_empty() || cnonce.contains(',') {
        return Err(Failure::MalformedRequest);
    }
    let user = localpart(&crate::accounts::saslprep(&raw_user), ctx.host).ok_or(Failure::NotAuthorized)?;
    if let Some(a) = authz.strip_prefix("a=") {
        if localpart(a, ctx.host).as_deref() != Some(user.as_str()) {
            return Err(Failure::InvalidAuthzid);
        }
    }
    let (cred, known, enabled) = match ctx.accounts.scram(ctx.host, &user, hash).await {
        Ok(Some((c, en))) => (c, true, en),
        Ok(None) => (decoy(hash, ctx.host, &user), false, true),
        Err(_) => return Err(Failure::TemporaryAuthFailure),
    };
    let mut sn = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut sn);
    let nonce = format!("{cnonce}{}", B64.encode(sn));
    let server_first = format!("r={nonce},s={},i={}", B64.encode(&cred.salt), cred.iterations);
    let out = server_first.clone().into_bytes();
    Ok((State::Scram { hash, client_first_bare: bare.to_string(), gs2, cb_kind, server_first, nonce, user, cred, known, enabled }, out))
}

/// Made-up but stable credentials for an unknown user, so a sign-in attempt doesn't reveal which
/// usernames exist.
fn decoy(hash: ScramHash, host: &str, user: &str) -> ScramCredentials {
    let seed = decoy_key();
    let salt = ScramHash::Sha256.hmac(seed, format!("{host}\0{user}").as_bytes())[..16].to_vec();
    let mut stored = vec![0u8; hash.hash(b"").len()];
    rand::thread_rng().fill_bytes(&mut stored);
    ScramCredentials { salt, iterations: ITERATIONS, stored_key: stored.clone(), server_key: stored }
}

fn decoy_key() -> &'static [u8] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        k
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Role;
    use crate::db::Db;

    async fn accounts() -> Accounts {
        let db = Db::memory().unwrap();
        db.migrate(&[&crate::accounts::MIGRATION]).unwrap();
        let a = Accounts::new(db);
        a.create("a.test", "user", "pencil-pencil", Role::Member).await.unwrap();
        a
    }

    fn ctx<'a>(a: &'a Accounts, cb: &'a ChannelBindings) -> Context<'a> {
        Context { host: "a.test", accounts: a, cb, secure: true, plus_offered: cb.any(), tokens: None }
    }

    /// A minimal SCRAM client, to drive the server through a full exchange.
    fn client_final(hash: ScramHash, password: &str, client_first_bare: &str, server_first: &str, gs2_cb: &[u8]) -> (String, Vec<u8>) {
        let mut salt = None;
        let mut iters = 0;
        let mut nonce = "";
        for p in server_first.split(',') {
            if let Some(v) = p.strip_prefix("s=") {
                salt = Some(B64.decode(v).unwrap());
            } else if let Some(v) = p.strip_prefix("i=") {
                iters = v.parse().unwrap();
            } else if let Some(v) = p.strip_prefix("r=") {
                nonce = v;
            }
        }
        let salted = hash.salted_password(password.as_bytes(), &salt.unwrap(), iters);
        let client_key = hash.hmac(&salted, b"Client Key");
        let stored = hash.hash(&client_key);
        let without = format!("c={},r={nonce}", B64.encode(gs2_cb));
        let auth = format!("{client_first_bare},{server_first},{without}");
        let sig = hash.hmac(&stored, auth.as_bytes());
        let proof: Vec<u8> = client_key.iter().zip(&sig).map(|(a, b)| a ^ b).collect();
        let server_key = hash.hmac(&salted, b"Server Key");
        (format!("{without},p={}", B64.encode(proof)), hash.hmac(&server_key, auth.as_bytes()))
    }

    #[tokio::test]
    async fn scram_sha256_succeeds_and_proves_server() {
        let a = accounts().await;
        let cb = ChannelBindings::default();
        let c = ctx(&a, &cb);
        let bare = "n=user,r=abcdef";
        let (s, step) = Sasl::start(&c, "SCRAM-SHA-256", format!("n,,{bare}").as_bytes()).await;
        let Step::Challenge(sf) = step else { panic!("{step:?}") };
        let sf = String::from_utf8(sf).unwrap();
        let (fin, server_sig) = client_final(ScramHash::Sha256, "pencil-pencil", bare, &sf, b"n,,");
        match s.unwrap().step(&c, fin.as_bytes()) {
            Step::Success { user, data } => {
                assert_eq!(user, "user");
                assert_eq!(data.unwrap(), format!("v={}", B64.encode(server_sig)).into_bytes());
            }
            s => panic!("{s:?}"),
        }
    }

    #[tokio::test]
    async fn scram_wrong_password_fails() {
        let a = accounts().await;
        let cb = ChannelBindings::default();
        let c = ctx(&a, &cb);
        let bare = "n=user,r=abcdef";
        let (s, Step::Challenge(sf)) = Sasl::start(&c, "SCRAM-SHA-1", format!("n,,{bare}").as_bytes()).await else { panic!() };
        let (fin, _) = client_final(ScramHash::Sha1, "wrong", bare, &String::from_utf8(sf).unwrap(), b"n,,");
        assert!(matches!(s.unwrap().step(&c, fin.as_bytes()), Step::Failure(Failure::NotAuthorized, _)));
    }

    #[tokio::test]
    async fn scram_plus_checks_binding() {
        let a = accounts().await;
        let cb = ChannelBindings { exporter: Some(vec![7; 32]), server_end_point: None };
        let c = ctx(&a, &cb);
        let bare = "n=user,r=xyz";
        let (s, Step::Challenge(sf)) = Sasl::start(&c, "SCRAM-SHA-256-PLUS", format!("p=tls-exporter,,{bare}").as_bytes()).await else {
            panic!()
        };
        let sf = String::from_utf8(sf).unwrap();
        let mut good = b"p=tls-exporter,,".to_vec();
        good.extend_from_slice(&[7; 32]);
        let (fin, _) = client_final(ScramHash::Sha256, "pencil-pencil", bare, &sf, &good);
        assert!(matches!(s.unwrap().step(&c, fin.as_bytes()), Step::Success { .. }));
    }

    #[tokio::test]
    async fn downgrade_is_detected() {
        let a = accounts().await;
        let cb = ChannelBindings { exporter: Some(vec![1; 32]), server_end_point: None };
        let c = ctx(&a, &cb);
        let (_, step) = Sasl::start(&c, "SCRAM-SHA-256", b"y,,n=user,r=abc").await;
        assert!(matches!(step, Step::Failure(Failure::NotAuthorized, _)));
    }

    #[tokio::test]
    async fn unknown_user_gets_a_challenge_then_fails() {
        let a = accounts().await;
        let cb = ChannelBindings::default();
        let c = ctx(&a, &cb);
        let bare = "n=nobody,r=abc";
        let (s, Step::Challenge(sf)) = Sasl::start(&c, "SCRAM-SHA-256", format!("n,,{bare}").as_bytes()).await else { panic!() };
        let (fin, _) = client_final(ScramHash::Sha256, "x", bare, &String::from_utf8(sf).unwrap(), b"n,,");
        assert!(matches!(s.unwrap().step(&c, fin.as_bytes()), Step::Failure(Failure::NotAuthorized, _)));
    }

    #[tokio::test]
    async fn plain_works_only_when_secure() {
        let a = accounts().await;
        let cb = ChannelBindings::default();
        let mut c = ctx(&a, &cb);
        assert!(matches!(Sasl::start(&c, "PLAIN", b"\0user\0pencil-pencil").await.1, Step::Success { .. }));
        assert!(matches!(Sasl::start(&c, "PLAIN", b"\0user\0nope").await.1, Step::Failure(Failure::NotAuthorized, _)));
        c.secure = false;
        assert!(matches!(Sasl::start(&c, "PLAIN", b"\0user\0pencil-pencil").await.1, Step::Failure(Failure::EncryptionRequired, _)));
    }
}
