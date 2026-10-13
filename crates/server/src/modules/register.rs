//! In-band registration (XEP-0077) with invites (XEP-0401 / XEP-0379), and changing the password
//! once signed in.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use quark_core::{Element, StanzaError};

use super::Module;
use crate::server::{Host, Server};

pub struct Register;

#[async_trait]
impl Module for Register {
    fn name(&self) -> &'static str {
        "register"
    }
}

/// A registration IQ before sign-in. Returns the reply to send.
pub async fn preauth(_srv: &Arc<Server>, _host: &Arc<Host>, iq: &Element, _secure: bool, _ip: Option<IpAddr>) -> Option<Element> {
    quark_core::stanza::error_reply(iq, &StanzaError::not_allowed())
}
