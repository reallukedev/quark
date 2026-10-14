//! Room configuration (XEP-0045 §10.2, `muc#roomconfig`): what is stored, the form owners see,
//! and reading their answers back.

use quark_core::Element;
use serde::{Deserialize, Serialize};

use crate::modules::forms::{Form, Values};

pub const ROOMCONFIG: &str = "http://jabber.org/protocol/muc#roomconfig";
pub const ROOMINFO: &str = "http://jabber.org/protocol/muc#roominfo";

/// The most people a room can hold, whatever its owner asks for.
pub const MAX_USERS_CAP: u32 = 1000;
/// The most messages a room keeps to show people as they join.
pub const HISTORY_CAP: u32 = 100;
const MAX_NAME: usize = 256;
const MAX_DESCRIPTION: usize = 2048;
const MAX_PASSWORD: usize = 256;

/// Who sees occupants' real addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Whois {
    /// Semi-anonymous: only moderators.
    Moderators,
    /// Non-anonymous: everyone in the room.
    Anyone,
}

/// Who may send private messages to others in the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowPm {
    Anyone,
    Participants,
    Moderators,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Config {
    pub name: Option<String>,
    pub description: Option<String>,
    pub language: Option<String>,
    /// Kept when the last person leaves (and across restarts).
    pub persistent: bool,
    /// Listed in the service's disco#items.
    pub public: bool,
    pub members_only: bool,
    /// People without an affiliation join as visitors and need voice to talk.
    pub moderated: bool,
    pub password: Option<String>,
    pub whois: Whois,
    pub allow_pm: AllowPm,
    /// Occupants (not only admins) may invite people; in members-only rooms the invitee becomes
    /// a member.
    pub allow_invites: bool,
    /// Occupants (not only moderators) may change the subject.
    pub change_subject: bool,
    /// Messages shown to people as they join.
    pub history_length: u32,
    /// Messages go to the room's archive (XEP-0313).
    pub archive: bool,
    pub max_users: u32,
    /// Visitors may ask moderators for voice.
    pub voice_requests: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: None,
            description: None,
            language: None,
            persistent: false,
            public: true,
            members_only: false,
            moderated: false,
            password: None,
            whois: Whois::Moderators,
            allow_pm: AllowPm::Anyone,
            allow_invites: false,
            change_subject: false,
            history_length: 20,
            archive: true,
            max_users: 200,
            voice_requests: true,
        }
    }
}

/// What a submitted configuration changed that occupants must be told (XEP-0045 §10.2.1).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// Status codes for the notice: 104 always, 170/171 logging, 172/173 anonymity.
    pub codes: Vec<u16>,
    pub became_members_only: bool,
    pub became_temporary: bool,
}

impl Config {
    pub fn non_anonymous(&self) -> bool {
        self.whois == Whois::Anyone
    }

    /// The configuration form an owner fills in.
    pub fn form(&self, owners: &[String], admins: &[String]) -> Element {
        let s = |o: &Option<String>| o.clone().unwrap_or_default();
        let whois = match self.whois {
            Whois::Anyone => "anyone",
            Whois::Moderators => "moderators",
        };
        let pm = match self.allow_pm {
            AllowPm::Anyone => "anyone",
            AllowPm::Participants => "participants",
            AllowPm::Moderators => "moderators",
            AllowPm::None => "none",
        };
        let max = self.max_users.to_string();
        let history = self.history_length.to_string();
        Form::new("form", ROOMCONFIG)
            .title("Group chat settings")
            .instructions("Change the settings below and save them.")
            .field("muc#roomconfig_roomname", "text-single", "Name", Some(&s(&self.name)))
            .field("muc#roomconfig_roomdesc", "text-single", "Description", Some(&s(&self.description)))
            .field("muc#roomconfig_lang", "text-single", "Language", Some(&s(&self.language)))
            .boolean("muc#roomconfig_persistentroom", "Keep the group chat when everyone has left", self.persistent)
            .boolean("muc#roomconfig_publicroom", "List it in the directory", self.public)
            .boolean("muc#roomconfig_membersonly", "Members only", self.members_only)
            .boolean("muc#roomconfig_moderatedroom", "Only people with a voice can talk", self.moderated)
            .boolean("muc#roomconfig_allowvoicerequests", "Visitors can ask for a voice", self.voice_requests)
            .boolean("muc#roomconfig_passwordprotectedroom", "Needs a password", self.password.is_some())
            .field("muc#roomconfig_roomsecret", "text-private", "Password", Some(&s(&self.password)))
            .list(
                "muc#roomconfig_whois",
                "Who can see people's addresses",
                whois,
                &[("moderators", "Moderators only"), ("anyone", "Anyone in the group chat")],
            )
            .list(
                "muc#roomconfig_allowpm",
                "Who can send private messages",
                pm,
                &[("anyone", "Anyone"), ("participants", "Anyone with a voice"), ("moderators", "Moderators only"), ("none", "Nobody")],
            )
            .boolean("muc#roomconfig_allowinvites", "Anyone can invite people", self.allow_invites)
            .boolean("muc#roomconfig_changesubject", "Anyone can change the subject", self.change_subject)
            .field("muc#roomconfig_historylength", "text-single", "Messages shown to people joining", Some(&history))
            .boolean("muc#roomconfig_enablearchiving", "Keep a message archive", self.archive)
            .list(
                "muc#roomconfig_maxusers",
                "Most people at once",
                &max,
                &[("10", "10"), ("20", "20"), ("50", "50"), ("100", "100"), ("200", "200"), ("500", "500"), ("1000", "1000")],
            )
            .field_values("muc#roomconfig_roomowners", "jid-multi", "Owners", owners.iter().map(String::as_str))
            .field_values("muc#roomconfig_roomadmins", "jid-multi", "Admins", admins.iter().map(String::as_str))
            .build()
    }

    /// Applies a submitted form. Fields left out keep their value; unknown fields are ignored
    /// (clients send server-specific ones). Returns what occupants must be told.
    pub fn apply(&mut self, v: &Values) -> Result<Changes, String> {
        let mut next = self.clone();
        let text = |var: &str, max: usize, what: &str| -> Result<Option<Option<String>>, String> {
            match v.get(var) {
                None if !v.has(var) => Ok(None),
                None => Ok(Some(None)),
                Some(t) if t.len() > max => Err(format!("The {what} is too long.")),
                Some(t) => Ok(Some(Some(t.trim().to_string()).filter(|t| !t.is_empty()))),
            }
        };
        if let Some(n) = text("muc#roomconfig_roomname", MAX_NAME, "name")? {
            next.name = n;
        }
        if let Some(d) = text("muc#roomconfig_roomdesc", MAX_DESCRIPTION, "description")? {
            next.description = d;
        }
        if let Some(l) = text("muc#roomconfig_lang", 32, "language")? {
            next.language = l;
        }
        let set = |slot: &mut bool, var: &str| -> Result<(), String> {
            if let Some(b) = v.boolean(var)? {
                *slot = b;
            }
            Ok(())
        };
        set(&mut next.persistent, "muc#roomconfig_persistentroom")?;
        set(&mut next.public, "muc#roomconfig_publicroom")?;
        set(&mut next.members_only, "muc#roomconfig_membersonly")?;
        set(&mut next.moderated, "muc#roomconfig_moderatedroom")?;
        set(&mut next.voice_requests, "muc#roomconfig_allowvoicerequests")?;
        set(&mut next.allow_invites, "muc#roomconfig_allowinvites")?;
        set(&mut next.change_subject, "muc#roomconfig_changesubject")?;
        set(&mut next.archive, "muc#roomconfig_enablearchiving")?;
        // Older clients and ejabberd say "logging" for the archive.
        set(&mut next.archive, "muc#roomconfig_enablelogging")?;

        let secret = text("muc#roomconfig_roomsecret", MAX_PASSWORD, "password")?;
        match v.boolean("muc#roomconfig_passwordprotectedroom")? {
            Some(true) => {
                let pw = secret.flatten().or_else(|| self.password.clone());
                if pw.is_none() {
                    return Err("A password-protected group chat needs a password.".into());
                }
                next.password = pw;
            }
            Some(false) => next.password = None,
            None => {
                if let Some(s) = secret {
                    next.password = s;
                }
            }
        }
        if let Some(w) = v.get("muc#roomconfig_whois") {
            next.whois = match w {
                "anyone" => Whois::Anyone,
                "moderators" => Whois::Moderators,
                _ => return Err("Who can see addresses must be \"anyone\" or \"moderators\".".into()),
            };
        }
        if let Some(p) = v.get("muc#roomconfig_allowpm") {
            next.allow_pm = match p {
                "anyone" | "1" | "true" => AllowPm::Anyone,
                "participants" => AllowPm::Participants,
                "moderators" => AllowPm::Moderators,
                "none" | "0" | "false" => AllowPm::None,
                _ => return Err("Who can send private messages isn't one of the choices.".into()),
            };
        }
        if let Some(h) = v.get("muc#roomconfig_historylength") {
            let n: u32 = h.trim().parse().map_err(|_| "The history length needs to be a number.".to_string())?;
            next.history_length = n.min(HISTORY_CAP);
        }
        if let Some(m) = v.get("muc#roomconfig_maxusers") {
            let m = m.trim();
            // Some clients send "none" or an empty value for "no limit": that's the cap here.
            next.max_users = if m.is_empty() || m == "none" || m == "0" {
                MAX_USERS_CAP
            } else {
                m.parse::<u32>().map_err(|_| "The most people at once needs to be a number.".to_string())?.clamp(1, MAX_USERS_CAP)
            };
        }

        let mut c = Changes { codes: vec![104], ..Default::default() };
        if next.archive != self.archive {
            c.codes.push(if next.archive { 170 } else { 171 });
        }
        if next.whois != self.whois {
            c.codes.push(if next.whois == Whois::Anyone { 172 } else { 173 });
        }
        c.became_members_only = next.members_only && !self.members_only;
        c.became_temporary = !next.persistent && self.persistent;
        *self = next;
        Ok(c)
    }

    /// disco#info features describing the room (XEP-0045 §6.4).
    pub fn features(&self) -> [&'static str; 6] {
        [
            if self.persistent { "muc_persistent" } else { "muc_temporary" },
            if self.public { "muc_public" } else { "muc_hidden" },
            if self.members_only { "muc_membersonly" } else { "muc_open" },
            if self.moderated { "muc_moderated" } else { "muc_unmoderated" },
            if self.non_anonymous() { "muc_nonanonymous" } else { "muc_semianonymous" },
            if self.password.is_some() { "muc_passwordprotected" } else { "muc_unsecured" },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submit(fields: &[(&str, &str)]) -> Values {
        let mut f = Form::new("submit", ROOMCONFIG);
        for (k, v) in fields {
            f = f.field(k, "text-single", "", Some(v));
        }
        Values::parse(&f.build())
    }

    #[test]
    fn applies_fields_and_reports_privacy_changes() {
        let mut c = Config::default();
        let ch = c
            .apply(&submit(&[
                ("muc#roomconfig_roomname", "Family"),
                ("muc#roomconfig_persistentroom", "1"),
                ("muc#roomconfig_membersonly", "true"),
                ("muc#roomconfig_whois", "anyone"),
                ("muc#roomconfig_enablearchiving", "0"),
                ("muc#roomconfig_historylength", "5000"),
                ("x-unknown", "ignored"),
            ]))
            .unwrap();
        assert_eq!(c.name.as_deref(), Some("Family"));
        assert!(c.persistent && c.members_only && !c.archive);
        assert_eq!(c.history_length, HISTORY_CAP);
        assert_eq!(ch.codes, vec![104, 171, 172]);
        assert!(ch.became_members_only);
    }

    #[test]
    fn password_needs_a_secret() {
        let mut c = Config::default();
        assert!(c.apply(&submit(&[("muc#roomconfig_passwordprotectedroom", "1")])).is_err());
        assert_eq!(c.password, None, "a refused form changes nothing");
        c.apply(&submit(&[("muc#roomconfig_passwordprotectedroom", "1"), ("muc#roomconfig_roomsecret", "pw")])).unwrap();
        assert_eq!(c.password.as_deref(), Some("pw"));
        c.apply(&submit(&[("muc#roomconfig_passwordprotectedroom", "0")])).unwrap();
        assert_eq!(c.password, None);
    }

    #[test]
    fn form_round_trips() {
        let mut c = Config { name: Some("x".into()), moderated: true, ..Default::default() };
        let form = c.form(&[], &[]);
        let mut back = Config::default();
        let mut v = Values::parse(&form);
        // A form sent back as is changes nothing.
        back.apply(&v).unwrap();
        assert_eq!(back, c);
        v = submit(&[("muc#roomconfig_maxusers", "none")]);
        c.apply(&v).unwrap();
        assert_eq!(c.max_users, MAX_USERS_CAP);
    }
}
