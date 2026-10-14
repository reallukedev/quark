//! Node configuration (XEP-0060 §16.4.4 `pubsub#node_config`): the stored shape, the data form
//! it is shown and changed as, publish-options preconditions (§7.1.5), and the defaults each
//! well-known PEP node gets.

use quark_core::{ns, Element};
use serde::{Deserialize, Serialize};

/// The most items one node keeps; what `pubsub#max_items = max` means.
pub const MAX_ITEMS: u32 = 1024;

const NODE_CONFIG: &str = "http://jabber.org/protocol/pubsub#node_config";
pub const PUBLISH_OPTIONS: &str = "http://jabber.org/protocol/pubsub#publish-options";

/// Who may read a node's items and get its notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Open,
    Presence,
    Roster,
    Whitelist,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Access::Open => "open",
            Access::Presence => "presence",
            Access::Roster => "roster",
            Access::Whitelist => "whitelist",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "open" => Access::Open,
            "presence" => Access::Presence,
            "roster" => Access::Roster,
            "whitelist" => Access::Whitelist,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendLast {
    Never,
    OnSub,
    OnSubAndPresence,
}

impl SendLast {
    fn as_str(self) -> &'static str {
        match self {
            SendLast::Never => "never",
            SendLast::OnSub => "on_sub",
            SendLast::OnSubAndPresence => "on_sub_and_presence",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "never" => SendLast::Never,
            "on_sub" => SendLast::OnSub,
            "on_sub_and_presence" => SendLast::OnSubAndPresence,
            _ => return None,
        })
    }
    pub fn on_presence(self) -> bool {
        self == SendLast::OnSubAndPresence
    }
    pub fn on_sub(self) -> bool {
        self != SendLast::Never
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationType {
    Headline,
    Normal,
}

impl NotificationType {
    pub fn as_str(self) -> &'static str {
        match self {
            NotificationType::Headline => "headline",
            NotificationType::Normal => "normal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemReply {
    Owner,
    Publisher,
}

/// One node's settings, stored as JSON. Unknown or missing fields fall back to the defaults, so
/// adding a field never needs a migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub title: Option<String>,
    pub description: Option<String>,
    pub access: Access,
    /// For [`Access::Roster`]: the owner's roster groups whose members may read.
    pub roster_groups: Vec<String>,
    pub max_items: u32,
    pub persist: bool,
    pub send_last: SendLast,
    pub deliver_notifications: bool,
    pub deliver_payloads: bool,
    pub notify_retract: bool,
    pub notify_delete: bool,
    pub notify_config: bool,
    pub notification_type: NotificationType,
    pub payload_type: Option<String>,
    pub itemreply: ItemReply,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            title: None,
            description: None,
            access: Access::Presence,
            roster_groups: Vec::new(),
            max_items: 1,
            persist: true,
            send_last: SendLast::OnSubAndPresence,
            deliver_notifications: true,
            deliver_payloads: true,
            notify_retract: true,
            notify_delete: true,
            notify_config: false,
            notification_type: NotificationType::Headline,
            payload_type: None,
            itemreply: ItemReply::Owner,
        }
    }
}

/// A field the form had that can't be used, by `var`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadField(pub String);

/// Longest title, description or payload type kept.
const MAX_TEXT: usize = 1024;
const MAX_GROUPS: usize = 64;

impl NodeConfig {
    /// How many items the node really keeps: one when items aren't persistent (the last one is
    /// still needed for new subscribers and contacts coming online).
    pub fn keep(&self) -> u32 {
        if self.persist {
            self.max_items.clamp(1, MAX_ITEMS)
        } else {
            1
        }
    }

    /// Applies the fields of a submitted form. Fields this server doesn't know are ignored, so
    /// clients can send options from newer specs without failing.
    pub fn apply_form(&mut self, form: &Element) -> Result<(), BadField> {
        for f in form.children().filter(|c| c.is("field", ns::DATA_FORMS)) {
            let Some(var) = f.attr("var") else { continue };
            let values: Vec<String> = f.children().filter(|v| v.is("value", ns::DATA_FORMS)).map(|v| v.text_content()).collect();
            let one = values.first().map(|v| v.trim()).unwrap_or("");
            let bad = || BadField(var.to_string());
            match var {
                "pubsub#title" => self.title = text(one).ok_or_else(bad)?,
                "pubsub#description" => self.description = text(one).ok_or_else(bad)?,
                "pubsub#type" => self.payload_type = text(one).ok_or_else(bad)?,
                "pubsub#access_model" => self.access = Access::parse(one).ok_or_else(bad)?,
                "pubsub#roster_groups_allowed" => {
                    if values.len() > MAX_GROUPS || values.iter().any(|g| g.len() > MAX_TEXT) {
                        return Err(bad());
                    }
                    let mut g = values;
                    g.sort_unstable();
                    g.dedup();
                    self.roster_groups = g;
                }
                "pubsub#max_items" => self.max_items = max_items(one).ok_or_else(bad)?,
                "pubsub#persist_items" => self.persist = boolean(one).ok_or_else(bad)?,
                "pubsub#send_last_published_item" => self.send_last = SendLast::parse(one).ok_or_else(bad)?,
                "pubsub#deliver_notifications" => self.deliver_notifications = boolean(one).ok_or_else(bad)?,
                "pubsub#deliver_payloads" => self.deliver_payloads = boolean(one).ok_or_else(bad)?,
                "pubsub#notify_retract" => self.notify_retract = boolean(one).ok_or_else(bad)?,
                "pubsub#notify_delete" => self.notify_delete = boolean(one).ok_or_else(bad)?,
                "pubsub#notify_config" => self.notify_config = boolean(one).ok_or_else(bad)?,
                "pubsub#notification_type" => {
                    self.notification_type = match one {
                        "headline" => NotificationType::Headline,
                        "normal" => NotificationType::Normal,
                        _ => return Err(bad()),
                    }
                }
                "pubsub#itemreply" => {
                    self.itemreply = match one {
                        "owner" => ItemReply::Owner,
                        "publisher" => ItemReply::Publisher,
                        _ => return Err(bad()),
                    }
                }
                // Only the owner publishes to a personal node; asking for exactly that is fine.
                "pubsub#publish_model" if one == "publishers" => {}
                "pubsub#publish_model" => return Err(bad()),
                // Supported as given: nothing to store.
                "pubsub#presence_based_delivery" | "pubsub#purge_offline" if boolean(one) == Some(false) => {}
                "pubsub#presence_based_delivery" | "pubsub#purge_offline" => return Err(bad()),
                _ => {}
            }
        }
        Ok(())
    }

    /// Checks publish-options against an existing node (XEP-0060 §7.1.5): every option this
    /// server knows must already hold. Returns the first field that doesn't.
    pub fn satisfies(&self, options: &Element) -> Result<(), BadField> {
        let mut want = self.clone();
        want.apply_form(options)?;
        if want == *self {
            return Ok(());
        }
        // Name the first differing field, for the error text.
        let var = differing_field(self, &want);
        Err(BadField(var.to_string()))
    }

    /// The configuration as a form (`type='form'` for owners to edit).
    pub fn to_form(&self, node: Option<&str>) -> Element {
        let b = |v: bool| if v { "1" } else { "0" }.to_string();
        let max = if self.max_items >= MAX_ITEMS { "max".to_string() } else { self.max_items.to_string() };
        let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", "form");
        x.append(field("FORM_TYPE", "hidden", None, &[NODE_CONFIG.to_string()]));
        if let Some(n) = node {
            x.append(field("pubsub#node", "fixed", Some("Node"), &[n.to_string()]));
        }
        x.append(field("pubsub#title", "text-single", Some("A friendly name for the node"), opt(&self.title)));
        x.append(field("pubsub#description", "text-single", Some("A description of the node"), opt(&self.description)));
        x.append(options(
            field("pubsub#access_model", "list-single", Some("Who may see the items"), &[self.access.as_str().to_string()]),
            &["open", "presence", "roster", "whitelist"],
        ));
        x.append(field("pubsub#roster_groups_allowed", "list-multi", Some("Roster groups allowed to see the items"), &self.roster_groups));
        x.append(field("pubsub#max_items", "text-single", Some("How many items to keep"), &[max]));
        x.append(field("pubsub#persist_items", "boolean", Some("Keep items"), &[b(self.persist)]));
        x.append(options(
            field(
                "pubsub#send_last_published_item",
                "list-single",
                Some("When to send the last item"),
                &[self.send_last.as_str().to_string()],
            ),
            &["never", "on_sub", "on_sub_and_presence"],
        ));
        x.append(field("pubsub#deliver_notifications", "boolean", Some("Send notifications"), &[b(self.deliver_notifications)]));
        x.append(field("pubsub#deliver_payloads", "boolean", Some("Include the item in notifications"), &[b(self.deliver_payloads)]));
        x.append(field("pubsub#notify_retract", "boolean", Some("Notify when items are removed"), &[b(self.notify_retract)]));
        x.append(field("pubsub#notify_delete", "boolean", Some("Notify when the node is deleted"), &[b(self.notify_delete)]));
        x.append(field("pubsub#notify_config", "boolean", Some("Notify when the configuration changes"), &[b(self.notify_config)]));
        x.append(options(
            field(
                "pubsub#notification_type",
                "list-single",
                Some("Message type of notifications"),
                &[self.notification_type.as_str().to_string()],
            ),
            &["headline", "normal"],
        ));
        x.append(field("pubsub#type", "text-single", Some("Payload type"), opt(&self.payload_type)));
        x.append(options(
            field(
                "pubsub#itemreply",
                "list-single",
                Some("Who replies to items"),
                &[match self.itemreply {
                    ItemReply::Owner => "owner",
                    ItemReply::Publisher => "publisher",
                }
                .to_string()],
            ),
            &["owner", "publisher"],
        ));
        x.append(options(
            field("pubsub#publish_model", "list-single", Some("Who may publish"), &["publishers".to_string()]),
            &["publishers"],
        ));
        x
    }
}

fn differing_field(a: &NodeConfig, b: &NodeConfig) -> &'static str {
    if a.access != b.access {
        "pubsub#access_model"
    } else if a.max_items != b.max_items {
        "pubsub#max_items"
    } else if a.persist != b.persist {
        "pubsub#persist_items"
    } else if a.send_last != b.send_last {
        "pubsub#send_last_published_item"
    } else if a.roster_groups != b.roster_groups {
        "pubsub#roster_groups_allowed"
    } else if a.deliver_notifications != b.deliver_notifications {
        "pubsub#deliver_notifications"
    } else if a.deliver_payloads != b.deliver_payloads {
        "pubsub#deliver_payloads"
    } else if a.notify_retract != b.notify_retract {
        "pubsub#notify_retract"
    } else if a.notify_delete != b.notify_delete {
        "pubsub#notify_delete"
    } else if a.notification_type != b.notification_type {
        "pubsub#notification_type"
    } else if a.title != b.title {
        "pubsub#title"
    } else if a.description != b.description {
        "pubsub#description"
    } else if a.payload_type != b.payload_type {
        "pubsub#type"
    } else if a.itemreply != b.itemreply {
        "pubsub#itemreply"
    } else {
        "pubsub#notify_config"
    }
}

fn opt(v: &Option<String>) -> &[String] {
    v.as_slice()
}

fn text(v: &str) -> Option<Option<String>> {
    if v.len() > MAX_TEXT {
        return None;
    }
    Some((!v.is_empty()).then(|| v.to_string()))
}

fn boolean(v: &str) -> Option<bool> {
    match v {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

/// A number, or `max` for the most this server allows. Larger numbers are capped rather than
/// refused: a client asking for 10 000 bookmarks wants "as many as possible".
fn max_items(v: &str) -> Option<u32> {
    if v == "max" {
        return Some(MAX_ITEMS);
    }
    let n: u64 = v.parse().ok()?;
    (n >= 1).then(|| n.min(u64::from(MAX_ITEMS)) as u32)
}

pub fn field(var: &str, kind: &str, label: Option<&str>, values: &[String]) -> Element {
    let mut f = Element::new("field", ns::DATA_FORMS).attr_set("var", var).attr_set("type", kind).attr_opt("label", label);
    for v in values {
        f.append(Element::new("value", ns::DATA_FORMS).text(v.clone()));
    }
    f
}

fn options(mut f: Element, opts: &[&str]) -> Element {
    for o in opts {
        f.append(Element::new("option", ns::DATA_FORMS).child(Element::new("value", ns::DATA_FORMS).text(*o)));
    }
    f
}

/// Nodes that hold the account's private data (bookmarks, read markers): nobody else may read
/// them, even when a client forgets to say so.
fn private_node(node: &str) -> bool {
    matches!(node, "storage:bookmarks" | "urn:xmpp:bookmarks:1" | "urn:xmpp:mds:displayed:0" | "urn:xmpp:mds:read:0")
        || node.starts_with("urn:xmpp:bookmarks:")
}

/// Nodes holding public encryption keys: readable by anyone, so people who aren't contacts
/// (in group chats, or before accepting a request) can still start an encrypted chat.
fn key_node(node: &str) -> bool {
    node == "eu.siacs.conversations.axolotl.devicelist"
        || node.starts_with("eu.siacs.conversations.axolotl.bundles:")
        || node == "urn:xmpp:omemo:2:devices"
        || node == "urn:xmpp:omemo:2:bundles"
        || node == "urn:xmpp:openpgp:0:public-keys"
        || node.starts_with("urn:xmpp:openpgp:0:public-keys:")
}

/// The configuration a new node starts with. XEP-0060 leaves defaults to the service; these
/// follow what each well-known node's spec asks clients to request, so a client that forgets
/// publish-options still gets safe, working settings.
pub fn defaults_for(node: &str) -> NodeConfig {
    let mut c = NodeConfig::default();
    if private_node(node) {
        c.access = Access::Whitelist;
        c.send_last = SendLast::Never;
        // The legacy bookmarks node holds one document; the others hold one item per entry.
        if node != "storage:bookmarks" {
            c.max_items = MAX_ITEMS;
        }
    } else if key_node(node) {
        c.access = Access::Open;
        if node == "urn:xmpp:omemo:2:bundles" {
            c.max_items = MAX_ITEMS;
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(fields: &[(&str, &str)]) -> Element {
        let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", "submit");
        x.append(field("FORM_TYPE", "hidden", None, &[PUBLISH_OPTIONS.to_string()]));
        for (k, v) in fields {
            x.append(field(k, "text-single", None, &[v.to_string()]));
        }
        x
    }

    #[test]
    fn preconditions_compare_typed_values() {
        let c = defaults_for("urn:xmpp:bookmarks:1");
        assert!(c
            .satisfies(&form(&[("pubsub#persist_items", "true"), ("pubsub#max_items", "max"), ("pubsub#access_model", "whitelist")]))
            .is_ok());
        assert!(c.satisfies(&form(&[("pubsub#persist_items", "1"), ("pubsub#send_last_published_item", "never")])).is_ok());
        assert_eq!(c.satisfies(&form(&[("pubsub#access_model", "open")])), Err(BadField("pubsub#access_model".into())));
        assert_eq!(c.satisfies(&form(&[("pubsub#max_items", "lots")])), Err(BadField("pubsub#max_items".into())));
        // Options this server doesn't know don't block publishing.
        assert!(c.satisfies(&form(&[("urn:example#whatever", "x")])).is_ok());
    }

    #[test]
    fn max_items_caps_and_rejects_zero() {
        let mut c = NodeConfig::default();
        c.apply_form(&form(&[("pubsub#max_items", "100000")])).unwrap();
        assert_eq!(c.max_items, MAX_ITEMS);
        assert!(c.apply_form(&form(&[("pubsub#max_items", "0")])).is_err());
        c.apply_form(&form(&[("pubsub#persist_items", "false")])).unwrap();
        assert_eq!(c.keep(), 1);
    }

    #[test]
    fn well_known_nodes_get_safe_defaults() {
        assert_eq!(defaults_for("storage:bookmarks").access, Access::Whitelist);
        assert_eq!(defaults_for("urn:xmpp:bookmarks:1").max_items, MAX_ITEMS);
        assert_eq!(defaults_for("eu.siacs.conversations.axolotl.devicelist").access, Access::Open);
        assert_eq!(defaults_for("eu.siacs.conversations.axolotl.bundles:1234").access, Access::Open);
        assert_eq!(defaults_for("urn:xmpp:avatar:data").access, Access::Presence);
        assert_eq!(defaults_for("http://jabber.org/protocol/tune").max_items, 1);
    }

    #[test]
    fn form_round_trips() {
        let mut c = defaults_for("urn:xmpp:omemo:2:bundles");
        c.title = Some("Keys".into());
        let mut f = c.to_form(Some("n"));
        f.set_attr("type", "submit");
        let mut d = NodeConfig::default();
        d.apply_form(&f).unwrap();
        assert_eq!(c, d);
    }

    #[test]
    fn stored_json_tolerates_missing_fields() {
        let c: NodeConfig = serde_json::from_str(r#"{"access":"open"}"#).unwrap();
        assert_eq!(c.access, Access::Open);
        assert_eq!(c.max_items, 1);
    }
}
