//! Push Notifications (XEP-0357).

use async_trait::async_trait;

use super::Module;

pub struct Push;

#[async_trait]
impl Module for Push {
    fn name(&self) -> &'static str {
        "cloud_notify"
    }
}
