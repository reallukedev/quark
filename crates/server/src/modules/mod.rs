//! The extension points features plug into. A [`Module`] answers IQs, adds disco features and
//! stream features, hooks the stanza pipeline, provides components (group chats, uploads) and
//! reacts to [`Event`]s. Modules are registered once at startup in [`all`].

use std::sync::Arc;

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{Element, Jid, StanzaError};

use crate::db::Migration;
use crate::server::{Host, Server};
use crate::sessions::SessionHandle;

pub mod adhoc;
pub mod blocking;
pub mod carbons;
pub mod contact;
pub mod disco;
pub mod extdisco;
pub mod invites;
pub mod last;
pub mod mam;
pub mod muc;
pub mod offline;
pub mod pep;
pub mod ping;
pub mod presence;
pub mod private;
pub mod push;
pub mod register;
pub mod roster;
pub mod time;
pub mod upload;
pub mod vcard;
pub mod version;

/// Where an IQ is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IqTarget {
    /// The server's own domain (or no `to`).
    Server,
    /// A local account's bare JID, answered by the server on the account's behalf (PEP, vCard,
    /// MAM, roster when it's the sender's own).
    Account,
}

/// An IQ for a module to answer.
pub struct IqCtx<'a> {
    pub srv: &'a Arc<Server>,
    pub host: &'a Arc<Host>,
    /// Who sent it: a full JID for local clients, any JID from other servers.
    pub from: &'a Jid,
    /// The server domain or the bare account JID it's addressed to.
    pub to: &'a Jid,
    pub iq: &'a Element,
    /// The IQ's first child.
    pub payload: &'a Element,
    pub kind: IqType,
    /// The sender's session, when it's a local client.
    pub session: Option<&'a Arc<SessionHandle>>,
}

impl IqCtx<'_> {
    /// Whether the IQ comes from the account it's about (a client asking about itself).
    pub fn from_self(&self) -> bool {
        self.from.to_bare() == self.to.to_bare()
    }
    /// The sender's bare JID, if they have an account on this domain.
    pub fn local_sender(&self) -> Option<Jid> {
        (self.from.domain() == self.host.domain && self.from.node().is_some()).then(|| self.from.to_bare())
    }
    pub fn is_admin(&self) -> bool {
        self.local_sender().is_some_and(|j| self.host.is_admin_jid(&j))
    }
}

/// What a module returns for an IQ: `Ok(Some(payload))` → result with payload, `Ok(None)` → empty
/// result, `Err` → error reply. [`IqReply::Handled`] means the module replied itself (MAM sends
/// messages first, then the result).
pub enum IqReply {
    Result(Option<Element>),
    Handled,
}

pub type IqResult = Result<IqReply, StanzaError>;

pub fn ok(payload: Element) -> IqResult {
    Ok(IqReply::Result(Some(payload)))
}

pub fn ok_empty() -> IqResult {
    Ok(IqReply::Result(None))
}

/// What a pipeline hook decides.
#[derive(Debug)]
pub enum Flow {
    Continue,
    /// Drop the stanza without a reply.
    Stop,
    /// Refuse it with an error to the sender.
    Reject(StanzaError),
}

/// A stanza on its way through the pipeline.
pub struct StanzaCtx<'a> {
    pub srv: &'a Arc<Server>,
    /// The local domain involved (the recipient's for inbound, the sender's for outbound).
    pub host: &'a Arc<Host>,
    pub from: &'a Jid,
    pub to: &'a Jid,
    /// Set when a local client sent it.
    pub session: Option<&'a Arc<SessionHandle>>,
}

/// Something that happened, for modules that keep their own state.
#[derive(Debug, Clone)]
pub enum Event {
    /// A client finished signing in and bound a resource.
    SessionStarted {
        jid: Jid,
    },
    /// A client sent available presence (initial or update). `presence` is what was broadcast.
    Available {
        jid: Jid,
        presence: Element,
    },
    /// A client went offline for good (not just hibernating).
    SessionEnded {
        jid: Jid,
    },
    /// `contact` now receives `user`'s presence (subscription from/both).
    SubscriptionApproved {
        user: Jid,
        contact: Jid,
    },
    /// `contact` no longer receives `user`'s presence.
    SubscriptionRevoked {
        user: Jid,
        contact: Jid,
    },
    AccountCreated {
        jid: Jid,
    },
    /// Remove everything stored for this account.
    AccountDeleted {
        jid: Jid,
    },
    /// A domain's settings changed (components may come or go).
    SettingsChanged {
        domain: String,
    },
}

/// A disco#info identity (XEP-0030).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub category: &'static str,
    pub kind: &'static str,
    pub name: Option<String>,
}

impl Identity {
    pub fn to_element(&self) -> Element {
        Element::new("identity", quark_core::ns::DISCO_INFO)
            .attr_set("category", self.category)
            .attr_set("type", self.kind)
            .attr_opt("name", self.name.clone())
    }
}

/// A service on its own subdomain (group chats, uploads). Stanzas addressed to that domain, or
/// any JID under it, go to `handle`.
#[async_trait]
pub trait Component: Send + Sync + 'static {
    /// The component's domain, e.g. `rooms.example.com`.
    fn domain(&self) -> &str;
    /// A stanza addressed to this component. `from` is already checked.
    async fn handle(&self, srv: &Arc<Server>, from: Jid, to: Jid, stanza: Element);
}

#[async_trait]
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    /// Tables this module owns. Rows tied to an account should reference
    /// `accounts(host, user) ON DELETE CASCADE`.
    fn migrations(&self) -> Vec<&'static Migration> {
        Vec::new()
    }

    /// Background work (expiry sweeps…), started once.
    fn start(&self, _srv: &Arc<Server>) {}

    /// Prosody-compatible module names for the admin snapshot, when active on `host`.
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        Vec::new()
    }

    /// disco#info features on the server domain.
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        Vec::new()
    }

    fn server_identities(&self, _host: &Host) -> Vec<Identity> {
        Vec::new()
    }

    /// Extended service discovery forms (XEP-0128) for the server domain.
    fn server_forms(&self, _host: &Host) -> Vec<Element> {
        Vec::new()
    }

    /// disco#info features on an account's bare JID.
    fn account_features(&self, _host: &Host) -> Vec<&'static str> {
        Vec::new()
    }

    fn account_identities(&self, _host: &Host) -> Vec<Identity> {
        Vec::new()
    }

    /// disco#items on an account's bare JID (PEP nodes), for the node asked about.
    async fn account_items(&self, _cx: &IqCtx<'_>) -> Vec<Element> {
        Vec::new()
    }

    /// disco#items on the server domain (components announce themselves here).
    fn server_items(&self, _host: &Host) -> Vec<Element> {
        Vec::new()
    }

    /// Stream features for a signed-in client (`<sm/>`, `<csi/>`, `<ver/>`…).
    fn stream_features(&self, _host: &Host) -> Vec<Element> {
        Vec::new()
    }

    /// The IQ payload namespaces this module answers, and where.
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[]
    }

    async fn handle_iq(&self, _cx: &IqCtx<'_>) -> IqResult {
        Err(StanzaError::service_unavailable())
    }

    /// Components this module runs for `host`, given its current settings.
    fn components(&self, _srv: &Arc<Server>, _host: &Arc<Host>) -> Vec<Arc<dyn Component>> {
        Vec::new()
    }

    /// Any stanza a local client sends to someone else, before routing.
    async fn stanza_out(&self, _cx: &StanzaCtx<'_>, _stanza: &mut Element) -> Flow {
        Flow::Continue
    }

    /// Any stanza for a local account (bare or full), before delivery.
    async fn stanza_in(&self, _cx: &StanzaCtx<'_>, _stanza: &mut Element) -> Flow {
        Flow::Continue
    }

    /// A message a local client sent, after `stanza_out` (archiving, stanza-id).
    async fn message_out(&self, _cx: &StanzaCtx<'_>, _msg: &mut Element) -> Flow {
        Flow::Continue
    }

    /// A message for a local account, after `stanza_in` and before delivery (archiving, push).
    async fn message_in(&self, _cx: &StanzaCtx<'_>, _msg: &mut Element) -> Flow {
        Flow::Continue
    }

    /// A message for a local account that no online device could take. Return `Stop` once stored.
    async fn message_undelivered(&self, _cx: &StanzaCtx<'_>, _msg: &Element) -> Flow {
        Flow::Continue
    }

    async fn on_event(&self, _srv: &Arc<Server>, _ev: &Event) {}
}

/// Every module, in hook order: filters (blocking) first, then storage, then the rest.
pub fn all() -> Vec<Arc<dyn Module>> {
    vec![
        // Filters first: a blocked sender's stanza never reaches storage.
        Arc::new(blocking::Blocking),
        Arc::new(roster::Roster),
        Arc::new(presence::Presence),
        Arc::new(disco::Disco),
        Arc::new(ping::Ping),
        Arc::new(version::Version),
        Arc::new(time::Time),
        Arc::new(last::Last),
        Arc::new(vcard::VCard),
        Arc::new(private::Private),
        Arc::new(register::Register),
        Arc::new(invites::Invites),
        Arc::new(adhoc::AdHoc),
        Arc::new(contact::Contact),
        Arc::new(extdisco::ExtDisco),
        Arc::new(carbons::Carbons),
        Arc::new(pep::Pep),
        Arc::new(muc::Muc),
        Arc::new(upload::Upload),
        Arc::new(crate::http::Web),
        // Archive before push, so notifications can carry the stanza id.
        Arc::new(mam::Mam),
        Arc::new(push::Push),
        // Last, so archiving and push run before a message is stored offline.
        Arc::new(offline::Offline),
    ]
}
