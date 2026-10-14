//! Message Carbons (XEP-0280): the enable/disable IQs. Copies are made in `router`. Also
//! announces Client State Indication (XEP-0352), which the session actor implements.

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, StanzaError};

use super::{ok_empty, IqCtx, IqResult, IqTarget, Module};
use crate::server::Host;

pub struct Carbons;

#[async_trait]
impl Module for Carbons {
    fn name(&self) -> &'static str {
        "carbons"
    }

    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        // Stream management and CSI live in the session actor; they're announced from here.
        vec!["carbons", "csi_simple", "smacks"]
    }

    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::CARBONS, ns::CARBONS_RULES]
    }

    fn stream_features(&self, _host: &Host) -> Vec<Element> {
        vec![Element::new("csi", ns::CSI)]
    }

    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::CARBONS, IqTarget::Server), (ns::CARBONS, IqTarget::Account)]
    }

    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        // A device turns carbons on for itself; nobody else can.
        let Some(session) = cx.session.filter(|s| s.jid == *cx.from && (cx.to.node().is_none() || cx.from_self())) else {
            return Err(StanzaError::not_allowed().with_text("Only a signed-in device can turn carbons on or off for itself."));
        };
        if cx.kind != IqType::Set {
            return Err(StanzaError::bad_request());
        }
        let on = match cx.payload.name() {
            "enable" => true,
            "disable" => false,
            _ => return Err(StanzaError::bad_request()),
        };
        session.flags.lock().carbons = on;
        ok_empty()
    }
}
