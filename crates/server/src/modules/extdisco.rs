//! External service discovery (XEP-0215): STUN and TURN servers for calls, with short-lived
//! TURN credentials (TURN REST scheme) for the built-in relay or an external one set through the
//! admin API. Only local accounts get credentials.

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, StanzaError};

use super::{ok, IqCtx, IqResult, IqTarget, Module};
use crate::server::Host;
use crate::turn::{self, Credentials};

pub struct ExtDisco;

/// One advertised service.
struct Service {
    host: String,
    port: u16,
    kind: &'static str,
    transport: &'static str,
    creds: Option<Credentials>,
}

impl Service {
    fn to_element(&self) -> Element {
        let mut el = Element::new("service", ns::EXTDISCO)
            .attr_set("host", self.host.as_str())
            .attr_set("port", self.port.to_string())
            .attr_set("type", self.kind)
            .attr_set("transport", self.transport);
        if let Some(c) = &self.creds {
            el = el
                .attr_set("username", c.username.as_str())
                .attr_set("password", c.password.as_str())
                .attr_set("expires", quark_core::time::xep82(c.expires_ms))
                .attr_set("restricted", "1");
        }
        el
    }
}

/// What the account may use right now: the external relay when one is set, else the built-in
/// relay when it's running, else nothing.
async fn services(cx: &IqCtx<'_>, user: &str) -> Result<Vec<Service>, StanzaError> {
    let cfg = cx.srv.config();
    let ttl = u64::from(cfg.turn.credential_hours) * 3600;
    let now = quark_core::time::now_ms();
    let calls_host = cx.host.settings().calls.host.clone();
    let (host, port, secret) = match turn::external(cx.srv).await.map_err(|_| StanzaError::internal())? {
        Some(ext) => (ext.host.unwrap_or(calls_host), ext.port.unwrap_or(3478), ext.secret),
        None => match (cx.srv.turn.relay(), cx.srv.turn.addrs()) {
            (Some(relay), Some((udp, _))) if cx.srv.turn.running() => {
                (cfg.turn.public_host.clone().unwrap_or(calls_host), udp.port(), relay.secret().to_string())
            }
            _ => return Ok(Vec::new()),
        },
    };
    let creds = turn::rest_credentials(&secret, user, ttl, now);
    Ok(vec![
        Service { host: host.clone(), port, kind: "stun", transport: "udp", creds: None },
        Service { host: host.clone(), port, kind: "turn", transport: "udp", creds: Some(creds.clone()) },
        Service { host, port, kind: "turn", transport: "tcp", creds: Some(creds) },
    ])
}

#[async_trait]
impl Module for ExtDisco {
    fn name(&self) -> &'static str {
        "external_services"
    }

    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().calls.on {
            vec!["external_services", "turn_external"]
        } else {
            Vec::new()
        }
    }

    fn server_features(&self, host: &Host) -> Vec<&'static str> {
        if host.settings().calls.on {
            vec![ns::EXTDISCO]
        } else {
            Vec::new()
        }
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::EXTDISCO, IqTarget::Server)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        if cx.kind != IqType::Get {
            return Err(StanzaError::bad_request());
        }
        if !cx.host.settings().calls.on {
            return Err(StanzaError::service_unavailable().with_text("Calls are turned off on this server."));
        }
        let Some(user) = cx.local_sender() else {
            return Err(StanzaError::forbidden().with_text("Only accounts on this server can use its call relay."));
        };
        let all = services(cx, &user.to_string()).await?;
        match cx.payload.name() {
            "services" => {
                let kind = cx.payload.attr("type");
                let list = all.iter().filter(|s| kind.is_none_or(|k| k == s.kind)).map(Service::to_element);
                ok(Element::new("services", ns::EXTDISCO).attr_opt("type", kind).children_from(list))
            }
            "credentials" => {
                // Each requested service (by host and type, optionally port) gets fresh credentials.
                let mut out = Vec::new();
                for want in cx.payload.children().filter(|c| c.is("service", ns::EXTDISCO)) {
                    let port = want.attr("port").and_then(|p| p.parse::<u16>().ok());
                    out.extend(
                        all.iter()
                            .filter(|s| s.creds.is_some())
                            .filter(|s| want.attr("host") == Some(s.host.as_str()) && want.attr("type").is_none_or(|t| t == s.kind))
                            .filter(|s| port.is_none_or(|p| p == s.port))
                            .map(Service::to_element),
                    );
                }
                if out.is_empty() {
                    return Err(StanzaError::item_not_found().with_text("There are no credentials for that service."));
                }
                ok(Element::new("credentials", ns::EXTDISCO).children_from(out))
            }
            _ => Err(StanzaError::bad_request()),
        }
    }
}
