//! Message Carbons (XEP-0280): the enable/disable IQs. Copies are made in `router`.

use async_trait::async_trait;

use super::Module;

pub struct Carbons;

#[async_trait]
impl Module for Carbons {
    fn name(&self) -> &'static str {
        "carbons"
    }
}
