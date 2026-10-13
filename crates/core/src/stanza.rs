//! Stanza helpers: kinds, errors (RFC 6120 §8.3) and replies.

use crate::jid::Jid;
use crate::ns;
use crate::xml::Element;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorType {
    Auth,
    Cancel,
    Continue,
    Modify,
    Wait,
}

impl ErrorType {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorType::Auth => "auth",
            ErrorType::Cancel => "cancel",
            ErrorType::Continue => "continue",
            ErrorType::Modify => "modify",
            ErrorType::Wait => "wait",
        }
    }
}

/// RFC 6120 §8.3.3 defined conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Condition {
    BadRequest,
    Conflict,
    FeatureNotImplemented,
    Forbidden,
    Gone,
    InternalServerError,
    ItemNotFound,
    JidMalformed,
    NotAcceptable,
    NotAllowed,
    NotAuthorized,
    PolicyViolation,
    RecipientUnavailable,
    Redirect,
    RegistrationRequired,
    RemoteServerNotFound,
    RemoteServerTimeout,
    ResourceConstraint,
    ServiceUnavailable,
    SubscriptionRequired,
    UndefinedCondition,
    UnexpectedRequest,
}

impl Condition {
    pub fn as_str(self) -> &'static str {
        use Condition::*;
        match self {
            BadRequest => "bad-request",
            Conflict => "conflict",
            FeatureNotImplemented => "feature-not-implemented",
            Forbidden => "forbidden",
            Gone => "gone",
            InternalServerError => "internal-server-error",
            ItemNotFound => "item-not-found",
            JidMalformed => "jid-malformed",
            NotAcceptable => "not-acceptable",
            NotAllowed => "not-allowed",
            NotAuthorized => "not-authorized",
            PolicyViolation => "policy-violation",
            RecipientUnavailable => "recipient-unavailable",
            Redirect => "redirect",
            RegistrationRequired => "registration-required",
            RemoteServerNotFound => "remote-server-not-found",
            RemoteServerTimeout => "remote-server-timeout",
            ResourceConstraint => "resource-constraint",
            ServiceUnavailable => "service-unavailable",
            SubscriptionRequired => "subscription-required",
            UndefinedCondition => "undefined-condition",
            UnexpectedRequest => "unexpected-request",
        }
    }

    /// The usual error type for this condition.
    pub fn default_type(self) -> ErrorType {
        use Condition::*;
        match self {
            BadRequest | JidMalformed | NotAcceptable | PolicyViolation | Redirect => ErrorType::Modify,
            Forbidden | NotAuthorized | RegistrationRequired | SubscriptionRequired => ErrorType::Auth,
            InternalServerError | RecipientUnavailable | RemoteServerTimeout | ResourceConstraint | UnexpectedRequest => ErrorType::Wait,
            _ => ErrorType::Cancel,
        }
    }
}

/// An error to put in a stanza reply, with optional human text and an application condition.
#[derive(Clone, Debug)]
pub struct StanzaError {
    pub condition: Condition,
    pub kind: ErrorType,
    pub text: Option<String>,
    pub app: Option<Box<Element>>,
    /// `by`: the entity that generated the error (RFC 6120 §8.3.2).
    pub by: Option<String>,
}

impl StanzaError {
    pub fn new(condition: Condition) -> Self {
        StanzaError { condition, kind: condition.default_type(), text: None, app: None, by: None }
    }
    pub fn with_text(mut self, t: impl Into<String>) -> Self {
        self.text = Some(t.into());
        self
    }
    pub fn with_type(mut self, t: ErrorType) -> Self {
        self.kind = t;
        self
    }
    pub fn with_app(mut self, e: Element) -> Self {
        self.app = Some(Box::new(e));
        self
    }
    pub fn by(mut self, by: impl Into<String>) -> Self {
        self.by = Some(by.into());
        self
    }

    pub fn bad_request() -> Self {
        Self::new(Condition::BadRequest)
    }
    pub fn not_allowed() -> Self {
        Self::new(Condition::NotAllowed)
    }
    pub fn forbidden() -> Self {
        Self::new(Condition::Forbidden)
    }
    pub fn item_not_found() -> Self {
        Self::new(Condition::ItemNotFound)
    }
    pub fn service_unavailable() -> Self {
        Self::new(Condition::ServiceUnavailable)
    }
    pub fn feature_not_implemented() -> Self {
        Self::new(Condition::FeatureNotImplemented)
    }
    pub fn internal() -> Self {
        Self::new(Condition::InternalServerError)
    }

    pub fn to_element(&self) -> Element {
        let mut e = Element::new("error", ns::CLIENT).attr_set("type", self.kind.as_str()).attr_opt("by", self.by.clone());
        e.append(Element::new(self.condition.as_str(), ns::STANZAS));
        if let Some(t) = &self.text {
            e.append(Element::new("text", ns::STANZAS).attr_set("xml:lang", "en").text(t.clone()));
        }
        if let Some(a) = &self.app {
            e.append((**a).clone());
        }
        e
    }

    /// Reads an `<error/>` child back.
    pub fn from_stanza(el: &Element) -> Option<StanzaError> {
        let e = el.get_child("error", ns::CLIENT)?;
        let cond = e.children().find(|c| c.ns() == ns::STANZAS && c.name() != "text")?;
        let condition = ALL_CONDITIONS.iter().copied().find(|c| c.as_str() == cond.name()).unwrap_or(Condition::UndefinedCondition);
        let kind = match e.attr("type") {
            Some("auth") => ErrorType::Auth,
            Some("continue") => ErrorType::Continue,
            Some("modify") => ErrorType::Modify,
            Some("wait") => ErrorType::Wait,
            _ => ErrorType::Cancel,
        };
        Some(StanzaError {
            condition,
            kind,
            text: e.child_text("text", ns::STANZAS),
            app: e.children().find(|c| c.ns() != ns::STANZAS).cloned().map(Box::new),
            by: e.attr("by").map(String::from),
        })
    }
}

const ALL_CONDITIONS: [Condition; 22] = {
    use Condition::*;
    [
        BadRequest,
        Conflict,
        FeatureNotImplemented,
        Forbidden,
        Gone,
        InternalServerError,
        ItemNotFound,
        JidMalformed,
        NotAcceptable,
        NotAllowed,
        NotAuthorized,
        PolicyViolation,
        RecipientUnavailable,
        Redirect,
        RegistrationRequired,
        RemoteServerNotFound,
        RemoteServerTimeout,
        ResourceConstraint,
        ServiceUnavailable,
        SubscriptionRequired,
        UndefinedCondition,
        UnexpectedRequest,
    ]
};

impl From<Condition> for StanzaError {
    fn from(c: Condition) -> Self {
        StanzaError::new(c)
    }
}

impl std::fmt::Display for StanzaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.condition.as_str())?;
        if let Some(t) = &self.text {
            write!(f, ": {t}")?;
        }
        Ok(())
    }
}

impl std::error::Error for StanzaError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IqType {
    Get,
    Set,
    Result,
    Error,
}

pub fn iq_type(el: &Element) -> Option<IqType> {
    match el.attr("type")? {
        "get" => Some(IqType::Get),
        "set" => Some(IqType::Set),
        "result" => Some(IqType::Result),
        "error" => Some(IqType::Error),
        _ => None,
    }
}

/// Parses the `to`/`from` attribute, `None` when absent, `Err` when malformed.
pub fn jid_attr(el: &Element, k: &str) -> Result<Option<Jid>, StanzaError> {
    match el.attr(k) {
        None => Ok(None),
        Some(s) => Jid::parse(s).map(Some).map_err(|_| StanzaError::new(Condition::JidMalformed)),
    }
}

/// An error reply to `el`: `from` and `to` swapped, the original payload dropped for IQs.
/// Returns None for stanzas that must never be answered with an error (errors, IQ results).
pub fn error_reply(el: &Element, err: &StanzaError) -> Option<Element> {
    if el.attr("type") == Some("error") || (el.name() == "iq" && el.attr("type") == Some("result")) {
        return None;
    }
    let mut r = Element::new(el.name(), ns::CLIENT).attr_set("type", "error");
    r.set_attr_opt("id", el.attr("id"));
    r.set_attr_opt("to", el.attr("from"));
    r.set_attr_opt("from", el.attr("to"));
    if el.name() != "iq" {
        // Messages and presence carry their content back (RFC 6120 §8.3.1 allows it); keep it small.
        for c in el.children().filter(|c| c.name() == "body" || c.name() == "thread") {
            r.append(c.clone());
        }
    } else if let Some(p) = el.first_child() {
        r.append(p.clone());
    }
    r.append(err.to_element());
    Some(r)
}

/// An empty `type='result'` reply to an IQ.
pub fn iq_result(iq: &Element) -> Element {
    let mut r = Element::new("iq", ns::CLIENT).attr_set("type", "result");
    r.set_attr_opt("id", iq.attr("id"));
    r.set_attr_opt("to", iq.attr("from"));
    r.set_attr_opt("from", iq.attr("to"));
    r
}

/// A result reply carrying `payload`.
pub fn iq_result_with(iq: &Element, payload: Element) -> Element {
    iq_result(iq).child(payload)
}

/// A new IQ request.
pub fn iq(kind: &str, id: &str, from: Option<&str>, to: Option<&str>, payload: Element) -> Element {
    Element::new("iq", ns::CLIENT).attr_set("type", kind).attr_set("id", id).attr_opt("from", from).attr_opt("to", to).child(payload)
}

/// `<message/>` with a body.
pub fn chat_message(from: &str, to: &str, kind: &str, body: &str) -> Element {
    Element::new("message", ns::CLIENT)
        .attr_set("from", from)
        .attr_set("to", to)
        .attr_set("type", kind)
        .attr_set("id", crate::new_id())
        .text_child("body", ns::CLIENT, body)
}

/// `<delay/>` (XEP-0203) for a time in milliseconds since the epoch.
pub fn delay(from: &str, at_ms: i64) -> Element {
    Element::new("delay", ns::DELAY).attr_set("from", from).attr_set("stamp", crate::time::xep82(at_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_reply_swaps() {
        let iq = Element::parse("<iq xmlns='jabber:client' type='get' id='x' from='a@b/c' to='b'><q xmlns='u'/></iq>").unwrap();
        let r = error_reply(&iq, &StanzaError::service_unavailable()).unwrap();
        assert_eq!(r.attr("to"), Some("a@b/c"));
        assert_eq!(r.attr("from"), Some("b"));
        let e = StanzaError::from_stanza(&r).unwrap();
        assert_eq!(e.condition, Condition::ServiceUnavailable);
        assert!(error_reply(&r, &StanzaError::bad_request()).is_none());
    }
}
