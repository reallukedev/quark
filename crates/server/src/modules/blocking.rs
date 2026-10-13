//! Blocking Command (XEP-0191) and spam reports (XEP-0377).

use async_trait::async_trait;

use super::Module;

pub struct Blocking;

#[async_trait]
impl Module for Blocking {
    fn name(&self) -> &'static str {
        "blocklist"
    }
}
