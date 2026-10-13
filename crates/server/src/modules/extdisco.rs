//! External service discovery (XEP-0215): TURN credentials for calls.

use async_trait::async_trait;

use super::Module;

pub struct ExtDisco;

#[async_trait]
impl Module for ExtDisco {
    fn name(&self) -> &'static str {
        "external_services"
    }
}
