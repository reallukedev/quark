//! Contact addresses (XEP-0157) and the welcome message.

use async_trait::async_trait;

use super::Module;

pub struct Contact;

#[async_trait]
impl Module for Contact {
    fn name(&self) -> &'static str {
        "server_contact_info"
    }
}
