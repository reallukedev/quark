//! Message Archive Management (XEP-0313) with stanza ids (XEP-0359): per-account archives, and
//! the storage and query engine group chats reuse for their own archives.

use std::sync::Arc;

use async_trait::async_trait;
use quark_core::{Element, Jid, StanzaError};

use super::{IqReply, Module};
use crate::server::Server;

pub struct Mam;

#[async_trait]
impl Module for Mam {
    fn name(&self) -> &'static str {
        "mam"
    }
}

/// Archives `msg` in `archive` (a bare account JID or a room JID) and returns its stanza id.
/// `with` is the other party (the contact, or the occupant's real/room JID).
pub async fn store(_srv: &Arc<Server>, _archive: &Jid, _with: &Jid, _msg: &Element) -> Result<String, StanzaError> {
    Err(StanzaError::feature_not_implemented())
}

/// Answers a MAM query `iq` against `archive`: results are sent from `archive` to `to`, then the
/// final IQ result. Access control is the caller's job.
pub async fn query(_srv: &Arc<Server>, _archive: &Jid, _iq: &Element, _to: &Jid) -> Result<IqReply, StanzaError> {
    Err(StanzaError::feature_not_implemented())
}

/// Deletes an archive (account or room gone).
pub async fn delete_archive(_srv: &Arc<Server>, _archive: &Jid) -> Result<(), StanzaError> {
    Ok(())
}
