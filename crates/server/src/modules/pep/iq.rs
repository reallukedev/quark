//! The XEP-0060 requests a PEP service answers: publish, retract, items, create, subscribe and
//! the owner's configure, delete, purge, subscriptions and affiliations.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use quark_core::stanza::{iq_result, IqType};
use quark_core::{ns, Condition, Element, Jid, StanzaError};

use super::config::{defaults_for, NodeConfig, MAX_ITEMS, PUBLISH_OPTIONS};
use super::store::{self, Affiliation, Item, Owner};
use super::{db_err, Origin, State, MAX_ACCOUNT_BYTES, MAX_ITEM_BYTES, MAX_NAME, MAX_NODES, MAX_PER_NODE};
use crate::modules::roster;
use crate::modules::{ok, ok_empty, IqCtx, IqReply, IqResult};
use crate::server::Server;

/// Room left in an items reply for the stanza around the payloads.
const REPLY_SLACK: u64 = 4096;

/// Payload bytes an items reply may carry: what fits in a stanza here and on other servers
/// (the configured c2s and s2s stanza limits), so a node full of large items is sent in part
/// rather than in a stanza nobody accepts.
fn reply_budget(srv: &Server) -> usize {
    let l = &srv.config().limits;
    usize::try_from(l.c2s_stanza_bytes.min(l.s2s_stanza_bytes).saturating_sub(REPLY_SLACK).max(1024)).unwrap_or(usize::MAX)
}

/// A pubsub error with its XEP-0060 application condition.
pub(super) fn perr(cond: Condition, app: &str) -> StanzaError {
    StanzaError::new(cond).with_app(Element::new(app, ns::PUBSUB_ERRORS))
}

fn unsupported(feature: &str) -> StanzaError {
    StanzaError::feature_not_implemented().with_app(Element::new("unsupported", ns::PUBSUB_ERRORS).attr_set("feature", feature))
}

fn precondition(var: &str) -> StanzaError {
    perr(Condition::Conflict, "precondition-not-met").with_text(format!("The node's {var} doesn't match the publish options."))
}

fn node_attr(op: &Element) -> Result<&str, StanzaError> {
    match op.attr("node") {
        Some(n) if !n.is_empty() && n.len() <= MAX_NAME => Ok(n),
        Some(n) if !n.is_empty() => Err(StanzaError::new(Condition::NotAcceptable).with_text("That node name is too long.")),
        _ => Err(perr(Condition::BadRequest, "nodeid-required")),
    }
}

/// The data form inside `parent`, if any.
fn form(parent: Option<&Element>) -> Option<&Element> {
    parent?.get_child("x", ns::DATA_FORMS)
}

fn not_found() -> StanzaError {
    StanzaError::item_not_found().with_text("There's no such node.")
}

/// Who may read a node (XEP-0060 §6.1.3 and §12.1, XEP-0163 §4.3.1). `contact` is the owner's
/// roster item for the asker.
pub(super) fn access(cfg: &NodeConfig, owner: bool, contact: Option<&roster::Item>, aff: Option<Affiliation>) -> Result<(), StanzaError> {
    use super::config::Access;
    if owner {
        return Ok(());
    }
    match aff {
        Some(Affiliation::Outcast) => return Err(perr(Condition::Forbidden, "blocked")),
        Some(_) => return Ok(()),
        None => {}
    }
    let subscribed = contact.is_some_and(|i| i.subscription.sends_to_contact());
    match cfg.access {
        Access::Open => Ok(()),
        Access::Presence if subscribed => Ok(()),
        Access::Presence => Err(perr(Condition::NotAuthorized, "presence-subscription-required")),
        Access::Roster if subscribed && contact.is_some_and(|i| i.groups.iter().any(|g| cfg.roster_groups.contains(g))) => Ok(()),
        Access::Roster => Err(perr(Condition::NotAuthorized, "not-in-roster-group")),
        Access::Whitelist => Err(perr(Condition::NotAllowed, "closed-node")),
    }
}

/// Explicit subscribers from other servers one node takes, in all and from any one domain:
/// each publish sends a notification to every one of them.
const MAX_REMOTE_SUBSCRIBERS: usize = 128;
const MAX_SUBSCRIBERS_PER_DOMAIN: usize = 16;

/// Whether a JID on another server may subscribe explicitly. Being able to read an open node
/// isn't enough: it has to be someone the account knows (a contact with a presence
/// subscription either way, or affiliated with the node), so strangers can't sign arbitrary
/// addresses up for a stream of notifications, and only so many per domain and in all.
/// `remote` are the node's current subscribers on other servers.
fn remote_may_subscribe(viewer: &Viewer, jid: &Jid, remote: &[Jid]) -> Result<(), StanzaError> {
    let known = viewer.contact.as_ref().is_some_and(|c| c.subscription.sends_to_contact() || c.subscription.receives_from_contact())
        || !viewer.affs.is_empty();
    if !known {
        return Err(perr(Condition::NotAuthorized, "presence-subscription-required")
            .with_text("Only contacts on other servers can subscribe here."));
    }
    if remote.len() >= MAX_REMOTE_SUBSCRIBERS || remote.iter().filter(|s| s.domain() == jid.domain()).count() >= MAX_SUBSCRIBERS_PER_DOMAIN
    {
        return Err(StanzaError::new(Condition::ResourceConstraint).with_text("This node has too many subscribers from other servers."));
    }
    Ok(())
}

/// How to treat a node that a publish creates or finds.
pub(super) enum Opts {
    /// Defaults for a new node, nothing to check on an existing one.
    None,
    /// publish-options: preconditions on an existing node, settings for a new one.
    Form(Element),
    /// Create with exactly this configuration (server-side syncing).
    Create(NodeConfig),
}

/// A stored publish, ready for notifications.
pub(super) struct Published {
    pub node: String,
    pub cfg: NodeConfig,
    pub item: Item,
    /// Older items the node's limit pushed out.
    pub trimmed: Vec<String>,
}

/// The requester's standing towards an account's nodes.
pub(super) struct Viewer {
    pub owner: bool,
    pub contact: Option<roster::Item>,
    pub affs: HashMap<String, Affiliation>,
}

impl Viewer {
    pub fn may(&self, node: &str, cfg: &NodeConfig) -> Result<(), StanzaError> {
        access(cfg, self.owner, self.contact.as_ref(), self.affs.get(node).copied())
    }
}

impl State {
    pub(super) async fn handle_iq(self: &Arc<Self>, cx: &IqCtx<'_>) -> IqResult {
        let owner = match cx.to.node() {
            Some(u) => Owner { host: cx.host.domain.clone(), user: u.to_string() },
            None => match cx.local_sender().as_ref().and_then(Owner::of) {
                Some(o) => o,
                // The domain itself has no pubsub service, only its accounts do.
                None => return Err(StanzaError::service_unavailable()),
            },
        };
        let is_owner = cx.from.to_bare() == owner.jid();
        let Some(op) = cx.payload.first_child() else {
            return Err(StanzaError::bad_request().with_text("The request is empty."));
        };
        if cx.payload.ns() == ns::PUBSUB_OWNER {
            if !is_owner {
                return Err(StanzaError::forbidden().with_text("Only the account itself can manage its nodes."));
            }
            return match (cx.kind, op.name()) {
                (IqType::Get, "configure") => self.get_config(cx.srv, &owner, op).await,
                (IqType::Set, "configure") => self.set_config(cx, &owner, op).await,
                (IqType::Get, "default") => ok(Element::new("pubsub", ns::PUBSUB_OWNER)
                    .child(Element::new("default", ns::PUBSUB_OWNER).child(NodeConfig::default().to_form(None)))),
                (IqType::Set, "delete") => self.delete_node(cx, &owner, op).await,
                (IqType::Set, "purge") => self.purge_node(cx, &owner, op).await,
                (IqType::Get, "subscriptions") => self.node_subscriptions(cx.srv, &owner, op).await,
                (IqType::Set, "subscriptions") => self.set_subscriptions(cx.srv, &owner, op).await,
                (IqType::Get, "affiliations") => self.node_affiliations(cx.srv, &owner, op).await,
                (IqType::Set, "affiliations") => self.set_affiliations(cx.srv, &owner, op).await,
                _ => Err(StanzaError::feature_not_implemented()),
            };
        }
        match (cx.kind, op.name()) {
            (IqType::Set, "publish") if is_owner => self.publish_iq(cx, &owner, op).await,
            (IqType::Set, "publish") => Err(perr(Condition::Forbidden, "publish").with_text("Only the account itself can publish here.")),
            (IqType::Set, "retract") if is_owner => self.retract_iq(cx, &owner, op).await,
            (IqType::Set, "retract") => Err(StanzaError::forbidden()),
            (IqType::Set, "create") if is_owner => {
                self.create_iq(cx.srv, &owner, op, form(cx.payload.get_child("configure", ns::PUBSUB))).await
            }
            (IqType::Set, "create") => Err(StanzaError::forbidden()),
            (IqType::Set, "subscribe") => self.subscribe_iq(cx, &owner, op).await,
            (IqType::Set, "unsubscribe") => self.unsubscribe_iq(cx, &owner, op).await,
            (IqType::Get, "items") => self.items_iq(cx, &owner, op).await,
            (IqType::Get, "subscriptions") => self.my_subscriptions(cx, &owner, op).await,
            (IqType::Get, "affiliations") => self.my_affiliations(cx, &owner, op, is_owner).await,
            (_, "options" | "default") => Err(unsupported("subscription-options")),
            _ => Err(StanzaError::feature_not_implemented()),
        }
    }

    /// The requester's roster standing and affiliations, for checking access to many nodes.
    pub(super) async fn viewer(&self, srv: &Arc<Server>, o: &Owner, requester: &Jid) -> Result<Viewer, StanzaError> {
        let bare = requester.to_bare();
        if bare == o.jid() {
            return Ok(Viewer { owner: true, contact: None, affs: HashMap::new() });
        }
        let contact = roster::item(srv, &o.host, &o.user, &bare).await.map_err(db_err)?;
        let (oo, b) = (o.clone(), bare.to_string());
        let affs = srv.db.read(move |c| store::affiliations_of(c, &oo, &b)).await.map_err(db_err)?.into_iter().collect();
        Ok(Viewer { owner: false, contact, affs })
    }

    async fn publish_iq(self: &Arc<Self>, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?;
        let mut items = op.children().filter(|c| c.is("item", ns::PUBSUB));
        let (Some(item), None) = (items.next(), items.next()) else {
            return Err(perr(Condition::BadRequest, "item-required").with_text("Publish exactly one item."));
        };
        let mut payloads = item.children();
        let payload = match (payloads.next(), payloads.next()) {
            (Some(p), None) => p,
            (None, _) => return Err(perr(Condition::BadRequest, "payload-required")),
            _ => return Err(perr(Condition::BadRequest, "invalid-payload").with_text("An item holds exactly one element.")),
        };
        let id = match item.attr("id") {
            Some(i) if i.len() > MAX_NAME => return Err(StanzaError::new(Condition::NotAcceptable).with_text("That item id is too long.")),
            Some(i) if !i.is_empty() => i.to_string(),
            _ => quark_core::new_id(),
        };
        let opts = match form(cx.payload.get_child("publish-options", ns::PUBSUB)) {
            Some(f) => {
                let ft = f.children().find(|c| c.attr("var") == Some("FORM_TYPE")).and_then(|c| c.child_text("value", ns::DATA_FORMS));
                if ft.as_deref().is_some_and(|t| t != PUBLISH_OPTIONS) {
                    return Err(StanzaError::bad_request().with_text("Publish options need the publish-options form type."));
                }
                Opts::Form(f.clone())
            }
            None => Opts::None,
        };
        let published = self.store_item(cx.srv, o, node, id, payload.clone(), opts).await?;
        let reply = Element::new("pubsub", ns::PUBSUB).child(
            Element::new("publish", ns::PUBSUB)
                .attr_set("node", node)
                .child(Element::new("item", ns::PUBSUB).attr_set("id", published.item.id.clone())),
        );
        // The publisher hears back before anyone gets the notification.
        crate::router::reply(cx.srv, cx.session, iq_result(cx.iq).child(reply)).await;
        self.after_publish(cx.srv, o, &published, Origin::Client).await;
        Ok(IqReply::Handled)
    }

    /// Stores an item, creating the node when needed.
    pub(super) async fn store_item(
        &self,
        srv: &Arc<Server>,
        o: &Owner,
        node: &str,
        id: String,
        mut payload: Element,
        opts: Opts,
    ) -> Result<Published, StanzaError> {
        payload.strip_whitespace();
        let xml = payload.to_xml();
        if xml.len() > MAX_ITEM_BYTES {
            return Err(perr(Condition::NotAcceptable, "payload-too-big").with_text("That item is too big."));
        }
        // Only the account publishes to its own nodes (the server too, on its behalf).
        let item = Item { id, publisher: Some(o.jid().to_string()), xml, updated: quark_core::time::now_ms() };
        let (o, node) = (o.clone(), node.to_string());
        srv.db
            .write(move |t| {
                // Checked before anything is written: an error here still commits.
                let (total, this) = store::usage(t, &o, &node, &item.id)?;
                if total - this + item.xml.len() as i64 > MAX_ACCOUNT_BYTES {
                    return Ok(Err(StanzaError::new(Condition::ResourceConstraint)
                        .with_text("This account is storing too much already; remove something first.")));
                }
                let cfg = match store::node(t, &o, &node)? {
                    Some(cfg) => {
                        if let Opts::Form(f) = &opts {
                            if let Err(bad) = cfg.satisfies(f) {
                                return Ok(Err(precondition(&bad.0)));
                            }
                        }
                        cfg
                    }
                    None => {
                        if store::node_count(t, &o)? >= MAX_NODES {
                            return Ok(
                                Err(perr(Condition::NotAllowed, "max-nodes-exceeded").with_text("This account has too many nodes.")),
                            );
                        }
                        let cfg = match opts {
                            Opts::Create(c) => c,
                            Opts::None => defaults_for(&node),
                            Opts::Form(f) => {
                                let mut c = defaults_for(&node);
                                if let Err(bad) = c.apply_form(&f) {
                                    return Ok(Err(precondition(&bad.0)));
                                }
                                c
                            }
                        };
                        store::create(t, &o, &node, &cfg)?;
                        cfg
                    }
                };
                // A limit at the most this server keeps means "as many as possible": the client
                // never asked to lose its oldest bookmark, so a full node refuses instead.
                if cfg.persist && cfg.max_items >= MAX_ITEMS {
                    let (count, replaces) = store::fill(t, &o, &node, &item.id)?;
                    if !replaces && count >= MAX_ITEMS {
                        return Ok(Err(StanzaError::new(Condition::ResourceConstraint)
                            .with_text(format!("This node is full ({MAX_ITEMS} items); remove one first."))));
                    }
                }
                let trimmed = store::put_item(t, &o, &node, &item, cfg.keep())?;
                Ok(Ok(Published { node, cfg, item, trimmed }))
            })
            .await
            .map_err(db_err)?
    }

    /// Notifications and conversions after a publish.
    pub(super) async fn after_publish(self: &Arc<Self>, srv: &Arc<Server>, o: &Owner, p: &Published, origin: Origin) {
        if p.cfg.deliver_notifications {
            let ev = super::deliver::item_event(&p.node, &p.cfg, &p.item);
            self.notify(srv, o, &p.node, &p.cfg, ev).await;
        }
        // Items the limit pushed out are deleted like retracted ones (XEP-0060 §7.1.2).
        if !p.trimmed.is_empty() {
            self.after_retract(srv, o, &p.node, &p.cfg, &p.trimmed, None).await;
        }
        if origin == Origin::Client {
            self.node_changed(srv, o, &p.node).await;
        }
    }

    /// Conversions to keep other representations in step after a client changed `node`.
    /// (Boxed: the conversions publish too, which would make this future contain itself.)
    fn node_changed<'a>(
        self: &'a Arc<Self>,
        srv: &'a Arc<Server>,
        o: &'a Owner,
        node: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match node {
                super::avatar::METADATA | super::avatar::DATA => self.avatar_changed(srv, o).await,
                super::bookmarks::NODE => self.bookmarks2_changed(srv, o).await,
                super::bookmarks::LEGACY_NODE => self.legacy_pep_bookmarks_changed(srv, o).await,
                _ => {}
            }
        })
    }

    async fn retract_iq(self: &Arc<Self>, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let ids: Vec<String> = op
            .children()
            .filter(|c| c.is("item", ns::PUBSUB))
            .filter_map(|c| c.attr("id"))
            .filter(|i| !i.is_empty())
            .map(String::from)
            .collect();
        if ids.is_empty() {
            return Err(perr(Condition::BadRequest, "item-required"));
        }
        let notify = match op.attr("notify") {
            Some("true" | "1") => Some(true),
            Some("false" | "0") => Some(false),
            _ => None,
        };
        let (cfg, removed) = self.remove_items(cx.srv, o, &node, ids).await?;
        if removed.is_empty() {
            return Err(StanzaError::item_not_found().with_text("There's no such item."));
        }
        crate::router::reply(cx.srv, cx.session, iq_result(cx.iq)).await;
        self.after_retract(cx.srv, o, &node, &cfg, &removed, notify).await;
        self.node_changed(cx.srv, o, &node).await;
        Ok(IqReply::Handled)
    }

    /// Deletes items, returning the node's configuration and the ids that existed.
    pub(super) async fn remove_items(
        &self,
        srv: &Arc<Server>,
        o: &Owner,
        node: &str,
        ids: Vec<String>,
    ) -> Result<(NodeConfig, Vec<String>), StanzaError> {
        let (oo, n) = (o.clone(), node.to_string());
        srv.db
            .write(move |t| {
                let Some(cfg) = store::node(t, &oo, &n)? else { return Ok(Err(not_found())) };
                let mut removed = Vec::new();
                for id in ids {
                    if store::retract(t, &oo, &n, &id)? {
                        removed.push(id);
                    }
                }
                Ok(Ok((cfg, removed)))
            })
            .await
            .map_err(db_err)?
    }

    pub(super) async fn after_retract(
        &self,
        srv: &Arc<Server>,
        o: &Owner,
        node: &str,
        cfg: &NodeConfig,
        ids: &[String],
        notify: Option<bool>,
    ) {
        if !cfg.deliver_notifications || !notify.unwrap_or(cfg.notify_retract) {
            return;
        }
        let mut items = Element::new("items", ns::PUBSUB_EVENT).attr_set("node", node);
        for id in ids {
            items.append(Element::new("retract", ns::PUBSUB_EVENT).attr_set("id", id.clone()));
        }
        self.notify(srv, o, node, cfg, Element::new("event", ns::PUBSUB_EVENT).child(items)).await;
    }

    async fn items_iq(&self, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let max = match op.attr("max_items") {
            Some(m) => Some(
                m.parse::<u32>()
                    .ok()
                    .filter(|m| *m > 0)
                    .ok_or_else(|| StanzaError::bad_request().with_text("max_items must be a positive number."))?,
            ),
            None => None,
        };
        let ids: Vec<String> = op
            .children()
            .filter(|c| c.is("item", ns::PUBSUB))
            .filter_map(|c| c.attr("id"))
            .map(String::from)
            .take(MAX_PER_NODE as usize)
            .collect();
        let requester = cx.from.to_bare();
        let is_owner = requester == o.jid();
        let (oo, n, r) = (o.clone(), node.clone(), requester.to_string());
        let budget = reply_budget(cx.srv);
        let found = cx
            .srv
            .db
            .read(move |c| {
                let Some(cfg) = store::node(c, &oo, &n)? else { return Ok(None) };
                let aff = if is_owner { None } else { store::affiliation(c, &oo, &n, &r)? };
                let (items, total) = if ids.is_empty() {
                    store::items_within(c, &oo, &n, max, budget)?
                } else {
                    let items = store::items_by_id(c, &oo, &n, &ids, budget)?;
                    let n = items.len() as u32;
                    (items, n)
                };
                Ok(Some((cfg, aff, items, total)))
            })
            .await
            .map_err(db_err)?;
        let Some((cfg, aff, items, total)) = found else { return Err(not_found()) };
        if !is_owner {
            let contact = if aff.is_none() && matches!(cfg.access, super::config::Access::Presence | super::config::Access::Roster) {
                roster::item(cx.srv, &o.host, &o.user, &requester).await.map_err(db_err)?
            } else {
                None
            };
            access(&cfg, false, contact.as_ref(), aff)?;
        }
        let mut el = Element::new("items", ns::PUBSUB).attr_set("node", node);
        for it in &items {
            el.append(it.shown(ns::PUBSUB, &cfg, true));
        }
        let mut reply = Element::new("pubsub", ns::PUBSUB).child(el);
        // Cut short to fit a stanza: say which part this is, the newest (XEP-0060 §6.5.4).
        if (items.len() as u32) < total {
            if let (Some(first), Some(last)) = (items.first(), items.last()) {
                reply.append(
                    Element::new("set", ns::RSM)
                        .child(
                            Element::new("first", ns::RSM)
                                .attr_set("index", (total - items.len() as u32).to_string())
                                .text(first.id.clone()),
                        )
                        .text_child("last", ns::RSM, last.id.clone())
                        .text_child("count", ns::RSM, total.to_string()),
                );
            }
        }
        ok(reply)
    }

    async fn create_iq(&self, srv: &Arc<Server>, o: &Owner, op: &Element, config: Option<&Element>) -> IqResult {
        let (node, instant) = match op.attr("node") {
            Some(n) if !n.is_empty() => (node_attr(op)?.to_string(), false),
            _ => (quark_core::new_id(), true),
        };
        let mut cfg = defaults_for(&node);
        if let Some(f) = config {
            if f.attr("type") != Some("cancel") {
                cfg.apply_form(f)
                    .map_err(|b| StanzaError::new(Condition::NotAcceptable).with_text(format!("The value for {} isn't supported.", b.0)))?;
            }
        }
        let (oo, n) = (o.clone(), node.clone());
        srv.db
            .write(move |t| {
                if store::node(t, &oo, &n)?.is_some() {
                    return Ok(Err(StanzaError::new(Condition::Conflict).with_text("That node already exists.")));
                }
                if store::node_count(t, &oo)? >= MAX_NODES {
                    return Ok(Err(perr(Condition::NotAllowed, "max-nodes-exceeded").with_text("This account has too many nodes.")));
                }
                store::create(t, &oo, &n, &cfg)?;
                Ok(Ok(()))
            })
            .await
            .map_err(db_err)??;
        if instant {
            return ok(Element::new("pubsub", ns::PUBSUB).child(Element::new("create", ns::PUBSUB).attr_set("node", node)));
        }
        ok_empty()
    }

    async fn subscribe_iq(self: &Arc<Self>, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let jid = op.attr("jid").and_then(|j| Jid::parse(j).ok()).ok_or_else(|| perr(Condition::BadRequest, "invalid-jid"))?;
        if jid.to_bare() != cx.from.to_bare() {
            return Err(perr(Condition::BadRequest, "invalid-jid").with_text("You can only subscribe yourself."));
        }
        let viewer = self.viewer(cx.srv, o, cx.from).await?;
        let (oo, n, j) = (o.clone(), node.clone(), jid.to_string());
        let cfg = cx
            .srv
            .db
            .read(move |c| {
                let Some(cfg) = store::node(c, &oo, &n)? else { return Ok(None) };
                Ok(Some((cfg, store::subscribers(c, &oo, &n)?)))
            })
            .await
            .map_err(db_err)?;
        let Some((cfg, subs)) = cfg else { return Err(not_found()) };
        viewer.may(&node, &cfg)?;
        if !subs.contains(&j) {
            if subs.len() as u32 >= MAX_PER_NODE {
                return Err(StanzaError::new(Condition::ResourceConstraint).with_text("This node has too many subscribers."));
            }
            if !cx.srv.is_local(jid.domain()) {
                let remote: Vec<Jid> = subs.iter().filter_map(|s| Jid::parse(s).ok()).filter(|s| !cx.srv.is_local(s.domain())).collect();
                remote_may_subscribe(&viewer, &jid, &remote)?;
            }
        }
        let (oo, n) = (o.clone(), node.clone());
        cx.srv.db.write(move |t| store::subscribe(t, &oo, &n, &j)).await.map_err(db_err)?;
        let reply = Element::new("pubsub", ns::PUBSUB).child(
            Element::new("subscription", ns::PUBSUB)
                .attr_set("node", node.clone())
                .attr_set("jid", jid.to_string())
                .attr_set("subscription", "subscribed"),
        );
        crate::router::reply(cx.srv, cx.session, iq_result(cx.iq).child(reply)).await;
        if cfg.send_last.on_sub() && cfg.deliver_notifications {
            self.send_last_item(cx.srv, o, &node, &cfg, &jid).await;
        }
        Ok(IqReply::Handled)
    }

    async fn unsubscribe_iq(&self, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let jid = op.attr("jid").and_then(|j| Jid::parse(j).ok()).ok_or_else(|| perr(Condition::BadRequest, "invalid-jid"))?;
        if jid.to_bare() != cx.from.to_bare() {
            return Err(perr(Condition::BadRequest, "invalid-jid"));
        }
        let (oo, j) = (o.clone(), jid.to_string());
        let gone = cx
            .srv
            .db
            .write(move |t| {
                if store::node(t, &oo, &node)?.is_none() {
                    return Ok(None);
                }
                store::unsubscribe(t, &oo, &node, &j).map(Some)
            })
            .await
            .map_err(db_err)?;
        match gone {
            None => Err(not_found()),
            Some(false) => Err(perr(Condition::UnexpectedRequest, "not-subscribed")),
            Some(true) => ok_empty(),
        }
    }

    async fn my_subscriptions(&self, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let oo = o.clone();
        let all = cx.srv.db.read(move |c| store::all_subscriptions(c, &oo)).await.map_err(db_err)?;
        let me = cx.from.to_bare();
        let only = op.attr("node");
        let mut el = Element::new("subscriptions", ns::PUBSUB).attr_opt("node", only);
        for (node, jid) in all {
            if only.is_some_and(|n| n != node) || Jid::parse(&jid).map(|j| j.to_bare()) != Ok(me.clone()) {
                continue;
            }
            el.append(
                Element::new("subscription", ns::PUBSUB).attr_set("node", node).attr_set("jid", jid).attr_set("subscription", "subscribed"),
            );
        }
        ok(Element::new("pubsub", ns::PUBSUB).child(el))
    }

    async fn my_affiliations(&self, cx: &IqCtx<'_>, o: &Owner, op: &Element, is_owner: bool) -> IqResult {
        let (oo, me) = (o.clone(), cx.from.to_bare().to_string());
        let list: Vec<(String, Affiliation)> = cx
            .srv
            .db
            .read(move |c| {
                if is_owner {
                    Ok(store::nodes(c, &oo)?.into_iter().map(|(n, _)| (n, Affiliation::Owner)).collect())
                } else {
                    store::affiliations_of(c, &oo, &me)
                }
            })
            .await
            .map_err(db_err)?;
        let only = op.attr("node");
        let mut el = Element::new("affiliations", ns::PUBSUB).attr_opt("node", only);
        for (node, a) in list.into_iter().filter(|(n, _)| only.is_none_or(|o| o == n)) {
            el.append(Element::new("affiliation", ns::PUBSUB).attr_set("node", node).attr_set("affiliation", a.as_str()));
        }
        ok(Element::new("pubsub", ns::PUBSUB).child(el))
    }

    async fn load_config(&self, srv: &Arc<Server>, o: &Owner, node: &str) -> Result<NodeConfig, StanzaError> {
        let (oo, n) = (o.clone(), node.to_string());
        srv.db.read(move |c| store::node(c, &oo, &n)).await.map_err(db_err)?.ok_or_else(not_found)
    }

    async fn get_config(&self, srv: &Arc<Server>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?;
        let cfg = self.load_config(srv, o, node).await?;
        ok(Element::new("pubsub", ns::PUBSUB_OWNER)
            .child(Element::new("configure", ns::PUBSUB_OWNER).attr_set("node", node).child(cfg.to_form(Some(node)))))
    }

    async fn set_config(self: &Arc<Self>, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let Some(f) = op.get_child("x", ns::DATA_FORMS) else {
            return Err(StanzaError::bad_request().with_text("The configuration form is missing."));
        };
        if f.attr("type") == Some("cancel") {
            return ok_empty();
        }
        let mut cfg = self.load_config(cx.srv, o, &node).await?;
        cfg.apply_form(f)
            .map_err(|b| StanzaError::new(Condition::NotAcceptable).with_text(format!("The value for {} isn't supported.", b.0)))?;
        let (oo, n, c2) = (o.clone(), node.clone(), cfg.clone());
        let existed = cx
            .srv
            .db
            .write(move |t| {
                if store::node(t, &oo, &n)?.is_none() {
                    return Ok(None);
                }
                store::configure(t, &oo, &n, &c2).map(Some)
            })
            .await
            .map_err(db_err)?;
        let Some(trimmed) = existed else { return Err(not_found()) };
        crate::router::reply(cx.srv, cx.session, iq_result(cx.iq)).await;
        if !trimmed.is_empty() {
            self.after_retract(cx.srv, o, &node, &cfg, &trimmed, None).await;
        }
        if cfg.notify_config && cfg.deliver_notifications {
            let ev = Element::new("event", ns::PUBSUB_EVENT)
                .child(Element::new("configuration", ns::PUBSUB_EVENT).attr_set("node", node.clone()));
            self.notify(cx.srv, o, &node, &cfg, ev).await;
        }
        // Access may have changed (who sees the avatar, say).
        self.node_changed(cx.srv, o, &node).await;
        Ok(IqReply::Handled)
    }

    async fn delete_node(self: &Arc<Self>, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let cfg = self.load_config(cx.srv, o, &node).await?;
        // Who to tell is worked out before the subscriptions go with the node.
        let to = if cfg.notify_delete && cfg.deliver_notifications { self.recipients(cx.srv, o, &node, &cfg).await } else { Vec::new() };
        let (oo, n) = (o.clone(), node.clone());
        if !cx.srv.db.write(move |t| store::delete(t, &oo, &n)).await.map_err(db_err)? {
            return Err(not_found());
        }
        crate::router::reply(cx.srv, cx.session, iq_result(cx.iq)).await;
        let ev = Element::new("event", ns::PUBSUB_EVENT).child(Element::new("delete", ns::PUBSUB_EVENT).attr_set("node", node.clone()));
        self.send_event(cx.srv, o, &cfg, &ev, to).await;
        self.node_changed(cx.srv, o, &node).await;
        Ok(IqReply::Handled)
    }

    async fn purge_node(self: &Arc<Self>, cx: &IqCtx<'_>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let (oo, n) = (o.clone(), node.clone());
        let cfg = cx
            .srv
            .db
            .write(move |t| {
                let cfg = store::node(t, &oo, &n)?;
                if cfg.is_some() {
                    store::purge(t, &oo, &n)?;
                }
                Ok(cfg)
            })
            .await
            .map_err(db_err)?
            .ok_or_else(not_found)?;
        crate::router::reply(cx.srv, cx.session, iq_result(cx.iq)).await;
        if cfg.deliver_notifications && cfg.notify_retract {
            let ev = Element::new("event", ns::PUBSUB_EVENT).child(Element::new("purge", ns::PUBSUB_EVENT).attr_set("node", node.clone()));
            self.notify(cx.srv, o, &node, &cfg, ev).await;
        }
        self.node_changed(cx.srv, o, &node).await;
        Ok(IqReply::Handled)
    }

    async fn node_subscriptions(&self, srv: &Arc<Server>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let (oo, n) = (o.clone(), node.clone());
        let subs = srv
            .db
            .read(move |c| if store::node(c, &oo, &n)?.is_some() { store::subscribers(c, &oo, &n).map(Some) } else { Ok(None) })
            .await
            .map_err(db_err)?
            .ok_or_else(not_found)?;
        let mut el = Element::new("subscriptions", ns::PUBSUB_OWNER).attr_set("node", node);
        for j in subs {
            el.append(Element::new("subscription", ns::PUBSUB_OWNER).attr_set("jid", j).attr_set("subscription", "subscribed"));
        }
        ok(Element::new("pubsub", ns::PUBSUB_OWNER).child(el))
    }

    async fn set_subscriptions(&self, srv: &Arc<Server>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let mut changes = Vec::new();
        for s in op.children().filter(|c| c.is("subscription", ns::PUBSUB_OWNER)) {
            let jid = s.attr("jid").and_then(|j| Jid::parse(j).ok()).ok_or_else(|| perr(Condition::BadRequest, "invalid-jid"))?;
            let on = match s.attr("subscription") {
                Some("subscribed") => true,
                Some("none") => false,
                _ => {
                    return Err(StanzaError::new(Condition::NotAcceptable).with_text("Subscriptions can only be set to subscribed or none."))
                }
            };
            changes.push((jid.to_string(), on));
        }
        let (oo, n) = (o.clone(), node);
        srv.db
            .write(move |t| {
                if store::node(t, &oo, &n)?.is_none() {
                    return Ok(Err(not_found()));
                }
                for (j, on) in changes {
                    if !on {
                        store::unsubscribe(t, &oo, &n, &j)?;
                    } else if store::subscription_count(t, &oo, &n)? < MAX_PER_NODE {
                        store::subscribe(t, &oo, &n, &j)?;
                    }
                }
                Ok(Ok(()))
            })
            .await
            .map_err(db_err)??;
        ok_empty()
    }

    async fn node_affiliations(&self, srv: &Arc<Server>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let (oo, n) = (o.clone(), node.clone());
        let affs = srv
            .db
            .read(move |c| if store::node(c, &oo, &n)?.is_some() { store::affiliations(c, &oo, &n).map(Some) } else { Ok(None) })
            .await
            .map_err(db_err)?
            .ok_or_else(not_found)?;
        let mut el = Element::new("affiliations", ns::PUBSUB_OWNER).attr_set("node", node);
        el.append(Element::new("affiliation", ns::PUBSUB_OWNER).attr_set("jid", o.jid().to_string()).attr_set("affiliation", "owner"));
        for (j, a) in affs {
            el.append(Element::new("affiliation", ns::PUBSUB_OWNER).attr_set("jid", j).attr_set("affiliation", a.as_str()));
        }
        ok(Element::new("pubsub", ns::PUBSUB_OWNER).child(el))
    }

    async fn set_affiliations(&self, srv: &Arc<Server>, o: &Owner, op: &Element) -> IqResult {
        let node = node_attr(op)?.to_string();
        let mut changes = Vec::new();
        for a in op.children().filter(|c| c.is("affiliation", ns::PUBSUB_OWNER)) {
            let jid = a.attr("jid").and_then(|j| Jid::parse(j).ok()).ok_or_else(|| perr(Condition::BadRequest, "invalid-jid"))?.to_bare();
            if jid == o.jid() {
                return Err(StanzaError::new(Condition::NotAcceptable).with_text("The account always owns its nodes."));
            }
            let aff = match a.attr("affiliation") {
                Some("none") => None,
                Some(s @ ("member" | "publisher" | "outcast")) => Affiliation::parse(s),
                _ => {
                    return Err(
                        StanzaError::new(Condition::NotAcceptable).with_text("Only member, publisher, outcast or none can be given.")
                    )
                }
            };
            changes.push((jid.to_string(), aff));
        }
        let (oo, n) = (o.clone(), node);
        srv.db
            .write(move |t| {
                if store::node(t, &oo, &n)?.is_none() {
                    return Ok(Err(not_found()));
                }
                for (j, a) in changes {
                    if a.is_some() && store::affiliation(t, &oo, &n, &j)?.is_none() && store::affiliation_count(t, &oo, &n)? >= MAX_PER_NODE
                    {
                        return Ok(Err(StanzaError::new(Condition::ResourceConstraint).with_text("This node has too many affiliations.")));
                    }
                    store::set_affiliation(t, &oo, &n, &j, a)?;
                }
                Ok(Ok(()))
            })
            .await
            .map_err(db_err)??;
        ok_empty()
    }

    /// disco#items on the account: the nodes the asker may see, or one node's item ids.
    pub(super) async fn disco_items(&self, cx: &IqCtx<'_>) -> Vec<Element> {
        let Some(o) = Owner::of(cx.to) else { return Vec::new() };
        let Ok(viewer) = self.viewer(cx.srv, &o, cx.from).await else { return Vec::new() };
        let owner_jid = o.jid().to_string();
        let want = cx.payload.attr("node").map(str::to_string);
        let oo = o.clone();
        let found = cx
            .srv
            .db
            .read(move |c| {
                let nodes = store::nodes(c, &oo)?;
                match want {
                    None => Ok((nodes, Vec::new())),
                    Some(w) => {
                        let nodes: Vec<_> = nodes.into_iter().filter(|(n, _)| *n == w).collect();
                        let ids = if nodes.is_empty() { Vec::new() } else { store::item_ids(c, &oo, &w)? };
                        Ok((nodes, ids))
                    }
                }
            })
            .await;
        let Ok((nodes, ids)) = found else { return Vec::new() };
        let visible = nodes.into_iter().filter(|(n, cfg)| viewer.may(n, cfg).is_ok());
        if cx.payload.attr("node").is_none() {
            return visible
                .map(|(n, cfg)| {
                    Element::new("item", ns::DISCO_ITEMS).attr_set("jid", owner_jid.clone()).attr_set("node", n).attr_opt("name", cfg.title)
                })
                .collect();
        }
        if visible.count() == 0 {
            return Vec::new();
        }
        ids.into_iter().map(|id| Element::new("item", ns::DISCO_ITEMS).attr_set("jid", owner_jid.clone()).attr_set("name", id)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::config::Access;
    use super::*;
    use crate::modules::roster::Subscription;

    fn contact(sub: Subscription, groups: &[&str]) -> roster::Item {
        let mut it = roster::Item::new(Jid::bare_unchecked("c", "x"));
        it.subscription = sub;
        it.groups = groups.iter().map(|g| g.to_string()).collect();
        it
    }

    fn cfg(access: Access) -> NodeConfig {
        NodeConfig { access, roster_groups: vec!["Family".into()], ..NodeConfig::default() }
    }

    fn cond(r: Result<(), StanzaError>) -> Option<(Condition, String)> {
        r.err().map(|e| (e.condition, e.app.map(|a| a.name().to_string()).unwrap_or_default()))
    }

    #[test]
    fn access_models() {
        let both = contact(Subscription::Both, &["Family"]);
        let to = contact(Subscription::To, &[]);
        let friend = contact(Subscription::From, &["Friends"]);
        assert!(access(&cfg(Access::Open), false, None, None).is_ok());
        assert!(access(&cfg(Access::Presence), false, Some(&both), None).is_ok());
        assert_eq!(
            cond(access(&cfg(Access::Presence), false, Some(&to), None)),
            Some((Condition::NotAuthorized, "presence-subscription-required".into()))
        );
        assert!(access(&cfg(Access::Roster), false, Some(&both), None).is_ok());
        assert_eq!(
            cond(access(&cfg(Access::Roster), false, Some(&friend), None)),
            Some((Condition::NotAuthorized, "not-in-roster-group".into()))
        );
        assert_eq!(cond(access(&cfg(Access::Whitelist), false, Some(&both), None)), Some((Condition::NotAllowed, "closed-node".into())));
        assert!(access(&cfg(Access::Whitelist), false, None, Some(Affiliation::Member)).is_ok());
        assert!(access(&cfg(Access::Whitelist), true, None, None).is_ok());
        assert_eq!(
            cond(access(&cfg(Access::Open), false, None, Some(Affiliation::Outcast))),
            Some((Condition::Forbidden, "blocked".into()))
        );
    }
}
