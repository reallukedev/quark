//! Entity Time (XEP-0202).

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, StanzaError};

use super::{ok, IqCtx, IqResult, IqTarget, Module};
use crate::server::Host;

pub struct Time;

#[async_trait]
impl Module for Time {
    fn name(&self) -> &'static str {
        "time"
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["time"]
    }
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::TIME]
    }
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::TIME, IqTarget::Server)]
    }
    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        if cx.kind != IqType::Get {
            return Err(StanzaError::bad_request());
        }
        let now = quark_core::time::now_ms();
        ok(Element::new("time", ns::TIME).text_child("tzo", ns::TIME, "+00:00").text_child("utc", ns::TIME, quark_core::time::xep82(now)))
    }
}
