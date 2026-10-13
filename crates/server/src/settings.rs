//! Per-domain chat settings, the same shape as Gluon's `ChatSettings`. Stored in the database and
//! applied live: every part of the server reads them through [`crate::server::Host::settings`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignUp {
    /// Only admins make accounts.
    Closed,
    /// People with an invite link (XEP-0401) can make one.
    Invite,
    /// Anyone can register in-band (XEP-0077).
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum History {
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "1w")]
    Week,
    #[serde(rename = "1m")]
    Month,
    #[serde(rename = "3m")]
    Quarter,
    #[serde(rename = "1y")]
    Year,
    #[serde(rename = "never")]
    Forever,
}

impl History {
    /// How long archived messages are kept, in milliseconds; None keeps them for good.
    pub fn keep_ms(self) -> Option<i64> {
        const DAY: i64 = 86_400_000;
        match self {
            History::Off => Some(0),
            History::Week => Some(7 * DAY),
            History::Month => Some(31 * DAY),
            History::Quarter => Some(92 * DAY),
            History::Year => Some(366 * DAY),
            History::Forever => None,
        }
    }
    pub fn on(self) -> bool {
        self != History::Off
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WhoCreates {
    Everyone,
    Admins,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Groups {
    pub on: bool,
    pub host: String,
    pub who_creates: WhoCreates,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Files {
    pub on: bool,
    pub host: String,
    pub max_mb: u32,
    pub keep_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Calls {
    pub on: bool,
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub sign_up: SignUp,
    pub history: History,
    pub groups: Groups,
    pub files: Files,
    /// Push notifications (XEP-0357).
    pub push: bool,
    /// Server-to-server links.
    pub federation: bool,
    /// WebSocket (RFC 7395) and BOSH (XEP-0206).
    pub web: bool,
    pub calls: Calls,
    /// A message every new account gets.
    pub welcome: Option<String>,
    /// The admin contact (XEP-0157), a bare JID.
    pub contact: Option<String>,
}

impl Settings {
    pub fn defaults(domain: &str) -> Settings {
        Settings {
            sign_up: SignUp::Invite,
            history: History::Quarter,
            groups: Groups { on: true, host: format!("rooms.{domain}"), who_creates: WhoCreates::Everyone },
            files: Files { on: true, host: format!("upload.{domain}"), max_mb: 100, keep_days: 30 },
            push: true,
            federation: true,
            web: true,
            calls: Calls { on: true, host: domain.to_string() },
            welcome: None,
            contact: None,
        }
    }

    /// Checks values that serde can't: component hosts, sizes, the contact address.
    pub fn validate(&self, domain: &str) -> Result<(), String> {
        for (what, h) in [("group chats", &self.groups.host), ("files", &self.files.host)] {
            let j = quark_core::Jid::domain_jid(h).map_err(|_| format!("The {what} address \"{h}\" isn't a valid domain."))?;
            if j.domain() == domain {
                return Err(format!("The {what} address must differ from {domain}, e.g. rooms.{domain}."));
            }
        }
        if self.groups.on && self.files.on && self.groups.host == self.files.host {
            return Err("Group chats and files need different addresses.".into());
        }
        if self.files.max_mb == 0 || self.files.max_mb > 10_240 {
            return Err("The file size limit must be between 1 MB and 10 GB.".into());
        }
        if self.files.keep_days > 36_500 {
            return Err("Files can be kept for at most 100 years.".into());
        }
        if let Some(c) = &self.contact {
            let j =
                quark_core::Jid::parse(c.trim_start_matches("xmpp:")).map_err(|_| format!("The contact \"{c}\" isn't a chat address."))?;
            if j.node().is_none() {
                return Err(format!("The contact \"{c}\" needs a name before the @."));
            }
        }
        if let Some(w) = &self.welcome {
            if w.len() > 4096 {
                return Err("The welcome message is too long (4 KB at most).".into());
            }
        }
        Ok(())
    }

    /// Fills in fields left out of a partial settings object.
    pub fn merged(mut self, p: &PartialSettings) -> Settings {
        if let Some(v) = p.sign_up {
            self.sign_up = v;
        }
        if let Some(v) = p.history {
            self.history = v;
        }
        if let Some(v) = &p.groups {
            self.groups = v.clone();
        }
        if let Some(v) = &p.files {
            self.files = v.clone();
        }
        if let Some(v) = p.push {
            self.push = v;
        }
        if let Some(v) = p.federation {
            self.federation = v;
        }
        if let Some(v) = p.web {
            self.web = v;
        }
        if let Some(v) = &p.calls {
            self.calls = v.clone();
        }
        if let Some(v) = &p.welcome {
            self.welcome = Some(v.clone()).filter(|s| !s.is_empty());
        }
        if let Some(v) = &p.contact {
            self.contact = Some(v.clone()).filter(|s| !s.is_empty());
        }
        self
    }
}

/// Settings in the config file: any subset, in snake_case or camelCase.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialSettings {
    #[serde(default, alias = "signUp")]
    pub sign_up: Option<SignUp>,
    #[serde(default)]
    pub history: Option<History>,
    #[serde(default)]
    pub groups: Option<Groups>,
    #[serde(default)]
    pub files: Option<Files>,
    #[serde(default)]
    pub push: Option<bool>,
    #[serde(default)]
    pub federation: Option<bool>,
    #[serde(default)]
    pub web: Option<bool>,
    #[serde(default)]
    pub calls: Option<Calls>,
    #[serde(default)]
    pub welcome: Option<String>,
    #[serde(default)]
    pub contact: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gluon_shape_round_trips() {
        let json = r#"{"signUp":"invite","history":"3m","groups":{"on":true,"host":"rooms.a.test","whoCreates":"everyone"},
            "files":{"on":true,"host":"upload.a.test","maxMb":100,"keepDays":30},"push":true,"federation":true,"web":false,
            "calls":{"on":false,"host":"a.test"},"welcome":null,"contact":null}"#;
        let s: Settings = serde_json::from_str(json).unwrap();
        assert_eq!(s.history, History::Quarter);
        let back: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(back["groups"]["whoCreates"], "everyone");
        assert_eq!(back["files"]["maxMb"], 100);
    }

    #[test]
    fn validate_refuses_same_host() {
        let mut s = Settings::defaults("a.test");
        s.groups.host = "a.test".into();
        assert!(s.validate("a.test").is_err());
    }

    #[test]
    fn merged_overrides_given_fields_only() {
        let p = PartialSettings { sign_up: Some(SignUp::Open), ..Default::default() };
        let s = Settings::defaults("a.test").merged(&p);
        assert_eq!(s.sign_up, SignUp::Open);
        assert_eq!(s.history, History::Quarter);
    }
}
