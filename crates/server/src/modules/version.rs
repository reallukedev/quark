//! Software Version (XEP-0092). Answers with the name and version only: the OS would tell an
//! attacker more than it tells anyone else.

use async_trait::async_trait;
use quark_core::stanza::IqType;
use quark_core::{ns, Element, StanzaError};

use super::{ok, IqCtx, IqResult, IqTarget, Module};
use crate::server::Host;

pub struct Version;

#[async_trait]
impl Module for Version {
    fn name(&self) -> &'static str {
        "version"
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["version"]
    }
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::VERSION]
    }
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::VERSION, IqTarget::Server)]
    }
    async fn handle_iq(&self, cx: &IqCtx<'_>) -> IqResult {
        if cx.kind != IqType::Get {
            return Err(StanzaError::bad_request());
        }
        ok(Element::new("query", ns::VERSION).text_child("name", ns::VERSION, "Quark").text_child(
            "version",
            ns::VERSION,
            env!("CARGO_PKG_VERSION"),
        ))
    }
}
