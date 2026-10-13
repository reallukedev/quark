//! Personal Eventing (XEP-0163) on XEP-0060 nodes: avatars, OMEMO keys, bookmarks, nicknames.

use async_trait::async_trait;

use super::Module;

pub struct Pep;

#[async_trait]
impl Module for Pep {
    fn name(&self) -> &'static str {
        "pep"
    }
}
