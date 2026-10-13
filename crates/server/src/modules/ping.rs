//! XMPP Ping (XEP-0199).

use async_trait::async_trait;
use quark_core::ns;

use super::{ok_empty, IqCtx, IqResult, IqTarget, Module};
use crate::server::Host;

pub struct Ping;

#[async_trait]
impl Module for Ping {
    fn name(&self) -> &'static str {
        "ping"
    }
    fn snapshot_names(&self, _host: &Host) -> Vec<&'static str> {
        vec!["ping"]
    }
    fn server_features(&self, _host: &Host) -> Vec<&'static str> {
        vec![ns::PING]
    }
    fn iq_namespaces(&self) -> &'static [(&'static str, IqTarget)] {
        &[(ns::PING, IqTarget::Server)]
    }
    async fn handle_iq(&self, _cx: &IqCtx<'_>) -> IqResult {
        ok_empty()
    }
}
