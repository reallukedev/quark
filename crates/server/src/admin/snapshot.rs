//! `snapshot`: everything Gluon's dashboard shows, in one answer (docs/admin-api.md).

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use serde_json::{json, Value};

use crate::modules::{invites, muc};
use crate::server::{Host, Server};
use crate::sessions::SessionHandle;

/// Module names for what the core itself does (the rest come from `Module::snapshot_names`).
const CORE: &[&str] = &["tls", "saslauth", "smacks", "csi_simple", "carbons"];

pub async fn snapshot(srv: &Arc<Server>) -> Value {
    let c = srv.config();
    let mut hosts = Vec::new();
    for h in srv.hosts() {
        hosts.push(host(srv, &h).await);
    }
    let (s2s_in, s2s_out) = srv.remote().map(|r| r.counts()).unwrap_or((0, 0));
    json!({
        "server": "quark",
        "version": env!("CARGO_PKG_VERSION"),
        "startedAt": srv.started_at,
        "configFile": c.path.display().to_string(),
        "certDir": srv.certs.dir().display().to_string(),
        "hosts": hosts,
        "turn": crate::turn::status(srv),
        "stats": {
            "c2s": srv.sessions.total(),
            "s2sIn": s2s_in,
            "s2sOut": s2s_out,
            "stanzasIn": srv.stats.stanzas_in.load(Ordering::Relaxed),
            "stanzasOut": srv.stats.stanzas_out.load(Ordering::Relaxed),
        },
    })
}

async fn host(srv: &Arc<Server>, h: &Arc<Host>) -> Value {
    let settings = h.settings();
    let mut devices: HashMap<String, Vec<Value>> = HashMap::new();
    let mut sessions = srv.sessions.on_host(&h.domain);
    sessions.sort_by_key(|s| s.info.since);
    for s in &sessions {
        let Some(user) = s.jid.node() else { continue };
        devices.entry(user.to_string()).or_default().push(device(s));
    }
    let accounts = match srv.accounts.list(&h.domain).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, host = %h.domain, "couldn't list accounts for the snapshot");
            Vec::new()
        }
    };
    let accounts: Vec<Value> = accounts
        .into_iter()
        .map(|a| {
            json!({
                "user": a.user,
                "role": a.role,
                "enabled": a.enabled,
                "created": Some(a.created).filter(|&t| t > 0),
                "passwordChanged": Some(a.password_changed).filter(|&t| t > 0),
                "lastActive": a.last_active,
                "devices": devices.remove(&a.user).unwrap_or_default(),
            })
        })
        .collect();
    let rooms = if settings.groups.on { muc::list_rooms(srv, &settings.groups.host).await } else { Vec::new() };
    json!({
        "host": h.domain,
        "settings": &*settings,
        "admins": h.config_admins(),
        "accounts": accounts,
        "invites": invites::list(srv, &h.domain).await,
        "rooms": rooms,
        "groupsHost": settings.groups.on.then(|| settings.groups.host.clone()),
        "filesHost": settings.files.on.then(|| settings.files.host.clone()),
        "modules": modules(srv, h),
        "requireEncryption": srv.config().tls.require_c2s,
        "tls": srv.certs.info(&h.domain),
    })
}

fn device(s: &SessionHandle) -> Value {
    let flags = s.flags.lock();
    json!({
        "resource": s.jid.resource().unwrap_or_default(),
        "client": client_name(s),
        "ip": s.info.ip.map(|ip| ip.to_string()),
        "secure": s.info.secure,
        "since": Some(s.info.since).filter(|&t| t > 0),
        "resumable": flags.resumable,
        "inactive": flags.inactive,
    })
}

/// What the module list says is on for `h`, core first, each name once.
fn modules(srv: &Server, h: &Host) -> Vec<&'static str> {
    let settings = h.settings();
    let mut out: Vec<&'static str> = CORE.to_vec();
    if settings.federation {
        out.push("s2s");
    }
    for m in &srv.modules {
        out.extend(m.snapshot_names(h));
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|n| seen.insert(*n));
    out
}

/// The app a device runs, for people: SASL2's user-agent when it sent one, else a guess from
/// the resource ("Conversations.Xy3z" is Conversations, "gajim.AB12CD" is Gajim).
pub fn client_name(s: &SessionHandle) -> Option<String> {
    if let Some(c) = s.info.client.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        return Some(c.chars().take(64).collect());
    }
    guess_client(s.jid.resource()?)
}

fn guess_client(resource: &str) -> Option<String> {
    const KNOWN: &[(&str, &str)] = &[
        ("conversations", "Conversations"),
        ("monocles", "monocles chat"),
        ("cheogram", "Cheogram"),
        ("gajim", "Gajim"),
        ("dino", "Dino"),
        ("monal", "Monal"),
        ("siskin", "Siskin IM"),
        ("beagle", "Beagle IM"),
        ("movim", "Movim"),
        ("converse", "Converse"),
        ("profanity", "Profanity"),
        ("psi", "Psi"),
        ("pidgin", "Pidgin"),
        ("blabber", "blabber.im"),
        ("snikket", "Snikket"),
        ("kaidan", "Kaidan"),
    ];
    let stem = resource.split(['.', '-', '_', ' ', '/']).next().unwrap_or_default().to_lowercase();
    KNOWN.iter().find(|(k, _)| stem == *k).map(|(_, name)| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::guess_client;

    #[test]
    fn guesses_clients_from_resources() {
        assert_eq!(guess_client("Conversations.Xy3z").as_deref(), Some("Conversations"));
        assert_eq!(guess_client("gajim.AB12CD").as_deref(), Some("Gajim"));
        assert_eq!(guess_client("Monal-iOS.9f2a").as_deref(), Some("Monal"));
        assert_eq!(guess_client("laptop"), None);
        assert_eq!(guess_client(""), None);
    }
}
