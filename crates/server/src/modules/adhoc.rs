//! Ad-Hoc Commands (XEP-0050) with service administration (XEP-0133).

use async_trait::async_trait;

use super::Module;

pub struct AdHoc;

#[async_trait]
impl Module for AdHoc {
    fn name(&self) -> &'static str {
        "adhoc"
    }
}
