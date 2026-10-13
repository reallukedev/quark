//! HTTP File Upload (XEP-0363): the slot-granting component. Files are served by `http`.

use async_trait::async_trait;

use super::Module;

pub struct Upload;

#[async_trait]
impl Module for Upload {
    fn name(&self) -> &'static str {
        "http_file_share"
    }
}
