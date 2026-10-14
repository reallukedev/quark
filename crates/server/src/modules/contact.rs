//! Contact addresses (XEP-0157) and the welcome message.

use std::sync::Arc;

use async_trait::async_trait;
use quark_core::{ns, Element};

use super::{Event, Module};
use crate::server::{Host, Server};

pub struct Contact;

#[async_trait]
impl Module for Contact {
    fn name(&self) -> &'static str {
        "server_contact_info"
    }

    fn snapshot_names(&self, host: &Host) -> Vec<&'static str> {
        let mut v = vec!["server_contact_info"];
        if host.settings().welcome.is_some() {
            v.push("welcome");
        }
        v
    }

    fn server_forms(&self, host: &Host) -> Vec<Element> {
        let addresses = addresses(host);
        if addresses.is_empty() {
            return Vec::new();
        }
        vec![serverinfo_form(&addresses)]
    }

    async fn on_event(&self, srv: &Arc<Server>, ev: &Event) {
        let Event::AccountCreated { jid } = ev else { return };
        let Some(host) = srv.host(jid.domain()) else { return };
        let Some(text) = host.settings().welcome.clone() else { return };
        let body = text.replace("$username", jid.node().unwrap_or_default()).replace("$host", &host.domain);
        let mut m = quark_core::stanza::chat_message(&host.domain, &jid.to_string(), "chat", &body);
        // Kept offline until the first sign-in, like any message.
        m.append(Element::new("store", ns::HINTS));
        srv.route(m).await;
    }
}

/// Who to contact about the server, as `xmpp:` URIs: the contact from the settings, else the
/// admins in the config file (what Prosody does too).
pub fn addresses(host: &Host) -> Vec<String> {
    match host.settings().contact.as_deref() {
        Some(c) => vec![format!("xmpp:{}", c.trim_start_matches("xmpp:"))],
        None => host.config_admins().iter().map(|a| format!("xmpp:{a}")).collect(),
    }
}

/// The XEP-0128 form with XEP-0157 addresses. The one contact is used for every role: on a home
/// server the admin is also the abuse and support contact.
fn serverinfo_form(addresses: &[String]) -> Element {
    let field = |var: &str| {
        Element::new("field", ns::DATA_FORMS)
            .attr_set("var", var)
            .attr_set("type", "list-multi")
            .children_from(addresses.iter().map(|a| Element::new("value", ns::DATA_FORMS).text(a.clone())))
    };
    Element::new("x", ns::DATA_FORMS)
        .attr_set("type", "result")
        .child(
            Element::new("field", ns::DATA_FORMS)
                .attr_set("var", "FORM_TYPE")
                .attr_set("type", "hidden")
                .child(Element::new("value", ns::DATA_FORMS).text(ns::SERVER_INFO)),
        )
        .child(field("abuse-addresses"))
        .child(field("admin-addresses"))
        .child(field("security-addresses"))
        .child(field("support-addresses"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_lists_every_role() {
        let f = serverinfo_form(&["xmpp:me@a.test".into()]);
        let vars: Vec<&str> = f.children().filter_map(|c| c.attr("var")).collect();
        assert_eq!(vars, ["FORM_TYPE", "abuse-addresses", "admin-addresses", "security-addresses", "support-addresses"]);
        assert_eq!(f.children().nth(2).and_then(|c| c.child_text("value", ns::DATA_FORMS)).as_deref(), Some("xmpp:me@a.test"));
    }
}
