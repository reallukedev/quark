//! A small, namespace-aware XML tree for stanzas, its serializer, and parsers: one for complete
//! documents (WebSocket frames, stored stanzas) and an incremental one for XML streams.

use std::fmt::Write as _;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::NsReader;
use tokio::io::{AsyncRead, BufReader, ReadBuf};

const READ_AHEAD: u64 = 16 * 1024;

/// The deepest nesting accepted inside one stanza. Real stanzas stay under 20 levels.
pub const MAX_DEPTH: usize = 64;

use crate::ns;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Text(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    name: String,
    ns: String,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}

impl Element {
    pub fn new(name: impl Into<String>, ns: impl Into<String>) -> Self {
        Element { name: name.into(), ns: ns.into(), attrs: Vec::new(), children: Vec::new() }
    }

    // ---------------------------------------------------------------- builder style

    pub fn attr_set(mut self, k: &str, v: impl Into<String>) -> Self {
        self.set_attr(k, v);
        self
    }

    /// Sets the attribute when `v` is Some.
    pub fn attr_opt(mut self, k: &str, v: Option<impl Into<String>>) -> Self {
        if let Some(v) = v {
            self.set_attr(k, v);
        }
        self
    }

    pub fn child(mut self, c: Element) -> Self {
        self.children.push(Node::Element(c));
        self
    }

    pub fn children_from(mut self, cs: impl IntoIterator<Item = Element>) -> Self {
        self.children.extend(cs.into_iter().map(Node::Element));
        self
    }

    pub fn text(mut self, t: impl Into<String>) -> Self {
        let t = t.into();
        if !t.is_empty() {
            self.children.push(Node::Text(t));
        }
        self
    }

    /// `<name xmlns=ns>text</name>` as a child.
    pub fn text_child(self, name: &str, ns: &str, t: impl Into<String>) -> Self {
        self.child(Element::new(name, ns).text(t))
    }

    // ---------------------------------------------------------------- reading

    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn ns(&self) -> &str {
        &self.ns
    }
    pub fn is(&self, name: &str, ns: &str) -> bool {
        self.name == name && self.ns == ns
    }
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
    pub fn attrs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.attrs.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
    pub fn nodes(&self) -> &[Node] {
        &self.children
    }
    pub fn children(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }
    pub fn children_mut(&mut self) -> impl Iterator<Item = &mut Element> {
        self.children.iter_mut().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            Node::Text(_) => None,
        })
    }
    pub fn get_child(&self, name: &str, ns: &str) -> Option<&Element> {
        self.children().find(|e| e.is(name, ns))
    }
    pub fn get_child_mut(&mut self, name: &str, ns: &str) -> Option<&mut Element> {
        self.children_mut().find(|e| e.is(name, ns))
    }
    /// First child element in a namespace, whatever its name.
    pub fn child_ns(&self, ns: &str) -> Option<&Element> {
        self.children().find(|e| e.ns == ns)
    }
    pub fn has_child(&self, name: &str, ns: &str) -> bool {
        self.get_child(name, ns).is_some()
    }
    /// The first child element, ignoring whitespace text.
    pub fn first_child(&self) -> Option<&Element> {
        self.children().next()
    }
    /// Direct text content, concatenated.
    pub fn text_content(&self) -> String {
        let mut s = String::new();
        for n in &self.children {
            if let Node::Text(t) = n {
                s.push_str(t);
            }
        }
        s
    }
    /// Text of a child element, if the child exists.
    pub fn child_text(&self, name: &str, ns: &str) -> Option<String> {
        self.get_child(name, ns).map(|c| c.text_content())
    }

    // ---------------------------------------------------------------- changing

    pub fn set_attr(&mut self, k: &str, v: impl Into<String>) {
        let v = v.into();
        if let Some(slot) = self.attrs.iter_mut().find(|(n, _)| n == k) {
            slot.1 = v;
        } else {
            self.attrs.push((k.to_string(), v));
        }
    }
    pub fn set_attr_opt(&mut self, k: &str, v: Option<impl Into<String>>) {
        match v {
            Some(v) => self.set_attr(k, v),
            None => self.remove_attr(k),
        }
    }
    pub fn remove_attr(&mut self, k: &str) {
        self.attrs.retain(|(n, _)| n != k);
    }
    pub fn set_ns(&mut self, ns: impl Into<String>) {
        self.ns = ns.into();
    }
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }
    pub fn append(&mut self, c: Element) {
        self.children.push(Node::Element(c));
    }
    pub fn prepend(&mut self, c: Element) {
        self.children.insert(0, Node::Element(c));
    }
    pub fn append_text(&mut self, t: impl Into<String>) {
        self.children.push(Node::Text(t.into()));
    }
    pub fn set_text(&mut self, t: impl Into<String>) {
        self.children.retain(|n| matches!(n, Node::Element(_)));
        self.children.push(Node::Text(t.into()));
    }
    /// Removes child elements matching `f`, returning how many went.
    pub fn remove_children(&mut self, mut f: impl FnMut(&Element) -> bool) -> usize {
        let before = self.children.len();
        self.children.retain(|n| match n {
            Node::Element(e) => !f(e),
            Node::Text(_) => true,
        });
        before - self.children.len()
    }
    pub fn remove_child(&mut self, name: &str, ns: &str) -> Option<Element> {
        let i = self.children.iter().position(|n| matches!(n, Node::Element(e) if e.is(name, ns)))?;
        match self.children.remove(i) {
            Node::Element(e) => Some(e),
            Node::Text(_) => unreachable!(),
        }
    }
    pub fn clear_children(&mut self) {
        self.children.clear();
    }
    pub fn take_children(&mut self) -> Vec<Node> {
        std::mem::take(&mut self.children)
    }
    /// Drops whitespace-only text nodes recursively (for comparing and storing).
    pub fn strip_whitespace(&mut self) {
        self.children.retain(|n| !matches!(n, Node::Text(t) if t.trim().is_empty()));
        for c in self.children_mut() {
            c.strip_whitespace();
        }
    }
    /// Renames every element in namespace `from` to `to` (jabber:server ⇄ jabber:client).
    pub fn rewrite_ns(&mut self, from: &str, to: &str) {
        if self.ns == from {
            self.ns = to.to_string();
        }
        for c in self.children_mut() {
            c.rewrite_ns(from, to);
        }
    }

    // ---------------------------------------------------------------- serializing

    /// Serializes as a standalone document fragment, always declaring its namespace.
    pub fn to_xml(&self) -> String {
        let mut s = String::with_capacity(256);
        self.write(&mut s, "", "", true);
        s
    }

    /// Serializes for a stream whose default namespace is `stream_ns`. Elements in jabber:client
    /// that inherit it from the stanza are written in the stream's namespace (jabber:server on
    /// server-to-server links), while explicitly nested jabber:client stanzas (inside a
    /// `<forwarded/>`, say) keep their own declaration. Elements in the streams namespace use
    /// the `stream:` prefix the stream header declared.
    pub fn to_stream_xml(&self, stream_ns: &str) -> String {
        let mut s = String::with_capacity(256);
        self.write_into_stream(&mut s, stream_ns);
        s
    }

    pub fn write_into_stream(&self, out: &mut String, stream_ns: &str) {
        if self.ns == ns::CLIENT || self.ns == stream_ns {
            // Inherit the stream's default namespace.
            self.write(out, &self.ns, stream_ns, false);
        } else {
            self.write(out, stream_ns, stream_ns, false);
        }
    }

    /// `parent_real`: the namespace the parent element is really in; `parent_written`: the default
    /// namespace in scope where this element is written. `declare_stream`: declare the `stream:`
    /// prefix if this element needs it (no stream header did).
    fn write(&self, out: &mut String, parent_real: &str, parent_written: &str, declare_stream: bool) {
        out.push('<');
        // Stream-level elements keep their customary prefix; some clients match on it literally.
        let prefixed = self.ns == ns::STREAM;
        if prefixed {
            out.push_str("stream:");
        }
        out.push_str(&self.name);
        let written: &str = if prefixed {
            if declare_stream {
                out.push_str(" xmlns:stream='");
                out.push_str(ns::STREAM);
                out.push('\'');
            }
            parent_written
        } else {
            let w = if self.ns == parent_real { parent_written } else { self.ns.as_str() };
            if w != parent_written {
                out.push_str(" xmlns='");
                escape_attr(out, w);
                out.push('\'');
            }
            w
        };
        for (k, v) in &self.attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("='");
            escape_attr(out, v);
            out.push('\'');
        }
        if self.children.is_empty() {
            out.push_str("/>");
            return;
        }
        out.push('>');
        let declare_below = declare_stream && !prefixed;
        for n in &self.children {
            match n {
                Node::Element(e) => e.write(out, &self.ns, written, declare_below),
                Node::Text(t) => escape_text(out, t),
            }
        }
        out.push_str("</");
        if prefixed {
            out.push_str("stream:");
        }
        out.push_str(&self.name);
        out.push('>');
    }

    /// Parses one complete element (a WebSocket frame, a stored stanza).
    pub fn parse(s: &str) -> Result<Element, XmlError> {
        let mut r = NsReader::from_str(s);
        configure(r.config_mut());
        let mut stack: Vec<Element> = Vec::new();
        loop {
            let (res, ev) = r.read_resolved_event().map_err(XmlError::from)?;
            let ens = element_ns(&res);
            match ev {
                Event::Start(e) => {
                    if stack.len() >= MAX_DEPTH {
                        return Err(XmlError::TooDeep);
                    }
                    stack.push(start_element(ens, &e)?)
                }
                Event::Empty(e) => {
                    let el = start_element(ens, &e)?;
                    match stack.last_mut() {
                        Some(p) => p.append(el),
                        None => return finish_single(&mut r, el),
                    }
                }
                Event::End(_) => {
                    let el = stack.pop().ok_or(XmlError::Malformed("unexpected end tag".into()))?;
                    match stack.last_mut() {
                        Some(p) => p.append(el),
                        None => return finish_single(&mut r, el),
                    }
                }
                Event::Text(t) => {
                    let t = t.unescape().map_err(XmlError::from)?;
                    match stack.last_mut() {
                        Some(p) => p.append_text(t.into_owned()),
                        None if t.trim().is_empty() => {}
                        None => return Err(XmlError::Malformed("text outside an element".into())),
                    }
                }
                Event::CData(t) => {
                    let t = String::from_utf8(t.into_inner().into_owned()).map_err(|_| XmlError::Malformed("invalid UTF-8".into()))?;
                    if let Some(p) = stack.last_mut() {
                        p.append_text(t);
                    }
                }
                Event::Decl(_) => {}
                Event::Comment(_) | Event::PI(_) | Event::DocType(_) => return Err(XmlError::Restricted),
                Event::Eof => return Err(XmlError::Malformed("incomplete document".into())),
            }
        }
    }
}

fn finish_single(r: &mut NsReader<&[u8]>, el: Element) -> Result<Element, XmlError> {
    loop {
        match r.read_event().map_err(XmlError::from)? {
            Event::Eof => return Ok(el),
            Event::Text(t) if t.iter().all(|b| b.is_ascii_whitespace()) => {}
            _ => return Err(XmlError::Malformed("more than one root element".into())),
        }
    }
}

impl std::fmt::Display for Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_xml())
    }
}

pub fn escape_text(out: &mut String, t: &str) {
    for c in t.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            c => out.push(c),
        }
    }
}

pub fn escape_attr(out: &mut String, t: &str) {
    for c in t.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

pub fn escape(t: &str) -> String {
    let mut s = String::with_capacity(t.len());
    escape_attr(&mut s, t);
    s
}

#[derive(Debug, thiserror::Error)]
pub enum XmlError {
    #[error("not well-formed: {0}")]
    Malformed(String),
    #[error("comments, processing instructions and DTDs aren't allowed")]
    Restricted,
    #[error("stanza too big")]
    TooBig,
    /// Elements nested deeper than [`MAX_DEPTH`]: nothing legitimate does that, and deep trees
    /// would overflow the stack when dropped or copied.
    #[error("elements nested too deeply")]
    TooDeep,
    /// The stream header is `<stream>` in the wrong namespace.
    #[error("wrong stream namespace")]
    InvalidNamespace,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

impl From<quick_xml::Error> for XmlError {
    fn from(e: quick_xml::Error) -> Self {
        match e {
            quick_xml::Error::Io(io) => XmlError::Io(std::io::Error::new(io.kind(), io.to_string())),
            other => XmlError::Malformed(other.to_string()),
        }
    }
}

impl From<quick_xml::events::attributes::AttrError> for XmlError {
    fn from(e: quick_xml::events::attributes::AttrError) -> Self {
        XmlError::Malformed(e.to_string())
    }
}

fn configure(c: &mut quick_xml::reader::Config) {
    c.check_end_names = true;
    c.expand_empty_elements = false;
    c.trim_text(false);
}

fn resolved_ns(res: &ResolveResult) -> String {
    match res {
        ResolveResult::Bound(n) => String::from_utf8_lossy(n.as_ref()).into_owned(),
        _ => String::new(),
    }
}

/// The element's namespace, or an error for an undeclared prefix.
fn element_ns(res: &ResolveResult) -> Result<String, XmlError> {
    if matches!(res, ResolveResult::Unknown(_)) {
        return Err(XmlError::Malformed("undeclared namespace prefix".into()));
    }
    Ok(resolved_ns(res))
}

fn start_element(ns: Result<String, XmlError>, e: &BytesStart) -> Result<Element, XmlError> {
    let local = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
    let mut el = Element::new(local, ns?);
    for a in e.attributes() {
        let a = a?;
        let key = a.key.as_ref();
        // Namespace declarations are resolved into element namespaces and re-made on output.
        // (Attributes in foreign namespaces other than xml: are vanishingly rare in XMPP and keep
        // their prefixed name.)
        if key == b"xmlns" || key.starts_with(b"xmlns:") {
            continue;
        }
        let k = std::str::from_utf8(key).map_err(|_| XmlError::Malformed("invalid UTF-8".into()))?;
        let v = a.unescape_value().map_err(XmlError::from)?;
        el.attrs.push((k.to_string(), v.into_owned()));
    }
    Ok(el)
}

// -------------------------------------------------------------------- streams

/// What a stream yields.
#[derive(Debug)]
pub enum StreamEvent {
    /// `<stream:stream …>` with its attributes (`to`, `from`, `version`, `xml:lang`, `id`) and its
    /// default namespace.
    Open {
        attrs: Vec<(String, String)>,
        default_ns: String,
    },
    Stanza(Element),
    /// `</stream:stream>`.
    Close,
}

impl StreamEvent {
    pub fn open_attr<'a>(attrs: &'a [(String, String)], k: &str) -> Option<&'a str> {
        attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }
}

/// Counts bytes read so a stanza can be refused once it grows past a limit.
pub struct Counting<R> {
    inner: R,
    count: Arc<AtomicU64>,
    /// Reading past this many bytes in total fails, so one huge text node can't eat memory.
    limit: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counting<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        let total = self.count.fetch_add(n as u64, Ordering::Relaxed) + n as u64;
        if total > self.limit.load(Ordering::Relaxed) {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "stanza too big")));
        }
        r
    }
}

impl<R> Counting<R> {
    pub fn into_inner(self) -> R {
        self.inner
    }
    pub fn get_ref(&self) -> &R {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

/// Reads an XMPP stream: the stream header, then top-level elements one by one. Not cancel safe:
/// run it in its own task, or only await it to completion.
pub struct StreamReader<R> {
    reader: NsReader<BufReader<Counting<R>>>,
    buf: Vec<u8>,
    count: Arc<AtomicU64>,
    limit: Arc<AtomicU64>,
    stack: Vec<Element>,
    opened: bool,
    /// Largest top-level element, in bytes.
    pub max_stanza: u64,
    /// jabber:server elements become jabber:client, so the rest of the server sees one namespace.
    pub server_ns: bool,
}

impl<R: AsyncRead + Unpin> StreamReader<R> {
    pub fn new(inner: R, max_stanza: u64) -> Self {
        let count = Arc::new(AtomicU64::new(0));
        let limit = Arc::new(AtomicU64::new(max_stanza + READ_AHEAD));
        let br = BufReader::with_capacity(READ_AHEAD as usize, Counting { inner, count: count.clone(), limit: limit.clone() });
        Self::from_buf(br, count, limit, max_stanza)
    }

    fn from_buf(br: BufReader<Counting<R>>, count: Arc<AtomicU64>, limit: Arc<AtomicU64>, max_stanza: u64) -> Self {
        let mut reader = NsReader::from_reader(br);
        configure(reader.config_mut());
        StreamReader { reader, buf: Vec::with_capacity(4096), count, limit, stack: Vec::new(), opened: false, max_stanza, server_ns: false }
    }

    /// Starts parsing afresh on the same connection (after SASL or a stream restart), keeping any
    /// bytes already read ahead.
    pub fn restart(self) -> Self {
        let server_ns = self.server_ns;
        let br = self.reader.into_inner();
        let mut s = Self::from_buf(br, self.count, self.limit, self.max_stanza);
        s.server_ns = server_ns;
        s
    }

    /// The underlying transport, for STARTTLS. Bytes read ahead are dropped: a client must not
    /// send anything after `<starttls/>` until the server answers.
    pub fn into_inner(self) -> R {
        self.reader.into_inner().into_inner().into_inner()
    }

    pub fn get_ref(&self) -> &R {
        self.reader.get_ref().get_ref().get_ref()
    }

    /// Something that isn't XML (an HTTP request, a TLS handshake on the plain port) is refused
    /// right away instead of waiting for a `<` that never comes.
    async fn check_first_byte(&mut self) -> Result<(), XmlError> {
        use tokio::io::AsyncBufReadExt;
        let br = self.reader.get_mut();
        loop {
            let buf = br.fill_buf().await?;
            let Some(&b) = buf.first() else { return Ok(()) };
            if b == b'<' {
                return Ok(());
            }
            // A UTF-8 byte order mark or whitespace may come first.
            let skip = if buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
                3
            } else if b.is_ascii_whitespace() {
                1
            } else {
                return Err(XmlError::Malformed("not XML".into()));
            };
            br.consume(skip);
        }
    }

    /// Total bytes read from the transport so far (for rate limits and stats).
    pub fn bytes_read(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Bytes buffered but not yet parsed (STARTTLS injection check).
    pub fn has_buffered(&self) -> bool {
        !self.reader.get_ref().buffer().is_empty()
    }

    pub async fn next(&mut self) -> Result<Option<StreamEvent>, XmlError> {
        if !self.opened {
            self.check_first_byte().await?;
        }
        loop {
            if self.stack.is_empty() {
                // Each top-level element gets its own allowance, counted from what's been read so far.
                self.limit.store(self.count.load(Ordering::Relaxed) + self.max_stanza + READ_AHEAD, Ordering::Relaxed);
            }
            self.buf.clear();
            let (res, ev) = match self.reader.read_resolved_event_into_async(&mut self.buf).await {
                Ok((res, ev)) => (element_ns(&res), ev),
                Err(quick_xml::Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidData && e.to_string() == "stanza too big" => {
                    return Err(XmlError::TooBig)
                }
                Err(e) => return Err(e.into()),
            };
            match ev {
                Event::Decl(_) => {}
                Event::Start(e) if !self.opened => {
                    let name = e.local_name();
                    if name.as_ref() != b"stream" {
                        return Err(XmlError::Malformed("expected <stream:stream>".into()));
                    }
                    if !matches!(&res, Ok(n) if n == ns::STREAM) {
                        return Err(XmlError::InvalidNamespace);
                    }
                    let mut attrs = Vec::new();
                    for a in e.attributes() {
                        let a = a?;
                        let k = String::from_utf8_lossy(a.key.as_ref()).into_owned();
                        if k == "xmlns" || k.starts_with("xmlns:") {
                            continue;
                        }
                        let v = a.unescape_value().map_err(XmlError::from)?.into_owned();
                        attrs.push((k, v));
                    }
                    let (dres, _) = self.reader.resolve_element(quick_xml::name::QName(b"x"));
                    let default_ns = resolved_ns(&dres);
                    self.opened = true;
                    return Ok(Some(StreamEvent::Open { attrs, default_ns }));
                }
                Event::Start(e) => {
                    let mut el = start_element(res, &e)?;
                    if self.server_ns && el.ns == ns::SERVER {
                        el.ns = ns::CLIENT.to_string();
                    }
                    if self.stack.len() >= MAX_DEPTH {
                        return Err(XmlError::TooDeep);
                    }
                    self.stack.push(el);
                }
                Event::Empty(e) => {
                    let mut el = start_element(res, &e)?;
                    if self.server_ns && el.ns == ns::SERVER {
                        el.ns = ns::CLIENT.to_string();
                    }
                    match self.stack.last_mut() {
                        Some(p) => p.append(el),
                        None => return Ok(Some(StreamEvent::Stanza(el))),
                    }
                }
                Event::End(_) => match self.stack.pop() {
                    None => return Ok(Some(StreamEvent::Close)),
                    Some(el) => match self.stack.last_mut() {
                        Some(p) => p.append(el),
                        None => return Ok(Some(StreamEvent::Stanza(el))),
                    },
                },
                Event::Text(t) => {
                    if let Some(p) = self.stack.last_mut() {
                        let t = t.unescape().map_err(XmlError::from)?;
                        p.append_text(t.into_owned());
                    } else if !t.iter().all(|b| b.is_ascii_whitespace()) {
                        return Err(XmlError::Malformed("text between stanzas".into()));
                    }
                }
                Event::CData(t) => {
                    if let Some(p) = self.stack.last_mut() {
                        let t = String::from_utf8(t.into_inner().into_owned()).map_err(|_| XmlError::Malformed("invalid UTF-8".into()))?;
                        p.append_text(t);
                    }
                }
                Event::Comment(_) | Event::PI(_) | Event::DocType(_) => return Err(XmlError::Restricted),
                Event::Eof => return Ok(None),
            }
        }
    }
}

/// The opening tag of a stream we send. `ns` is jabber:client or jabber:server.
pub fn stream_header(default_ns: &str, from: Option<&str>, to: Option<&str>, id: Option<&str>, extra: &[(&str, &str)]) -> String {
    let mut s = String::from("<?xml version='1.0'?><stream:stream xmlns='");
    s.push_str(default_ns);
    s.push_str("' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' xml:lang='en'");
    for (k, v) in [("from", from), ("to", to), ("id", id)] {
        if let Some(v) = v {
            let _ = write!(s, " {k}='{}'", escape(v));
        }
    }
    for (k, v) in extra {
        let _ = write!(s, " {k}='{}'", escape(v));
    }
    s.push('>');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let src = "<message xmlns='jabber:client' to='a@b' type='chat'><body>hi &amp; &lt;bye&gt;</body><x xmlns='urn:x'><y a='&apos;'/></x></message>";
        let el = Element::parse(src).unwrap();
        assert_eq!(el.name(), "message");
        assert_eq!(el.ns(), ns::CLIENT);
        assert_eq!(el.child_text("body", ns::CLIENT).unwrap(), "hi & <bye>");
        assert_eq!(el.get_child("x", "urn:x").unwrap().get_child("y", "urn:x").unwrap().attr("a"), Some("'"));
        assert_eq!(Element::parse(&el.to_xml()).unwrap(), el);
    }

    #[test]
    fn prefixes_resolve() {
        let el = Element::parse("<a xmlns='u:1' xmlns:p='u:2'><p:b/><c/></a>").unwrap();
        assert!(el.has_child("b", "u:2"));
        assert!(el.has_child("c", "u:1"));
    }

    #[test]
    fn deep_nesting_is_refused() {
        let deep = format!("{}{}", "<a xmlns='x'>".repeat(MAX_DEPTH + 1), "</a>".repeat(MAX_DEPTH + 1));
        assert!(matches!(Element::parse(&deep), Err(XmlError::TooDeep)));
        let ok = format!("{}{}", "<a xmlns='x'>".repeat(MAX_DEPTH), "</a>".repeat(MAX_DEPTH));
        assert!(Element::parse(&ok).is_ok());
    }

    #[test]
    fn restricted_xml_refused() {
        assert!(matches!(Element::parse("<a xmlns='x'><!-- no --></a>"), Err(XmlError::Restricted)));
        assert!(Element::parse("<!DOCTYPE a><a/>").is_err());
    }

    #[test]
    fn stream_ns_mapping() {
        let inner = Element::new("message", ns::CLIENT).child(Element::new("body", ns::CLIENT).text("x"));
        let el = Element::new("message", ns::CLIENT).attr_set("to", "a@b").child(Element::new("forwarded", ns::FORWARD).child(inner));
        let s = el.to_stream_xml(ns::SERVER);
        assert_eq!(s, "<message to='a@b'><forwarded xmlns='urn:xmpp:forward:0'><message xmlns='jabber:client'><body>x</body></message></forwarded></message>");
        let c = el.to_stream_xml(ns::CLIENT);
        assert!(c.starts_with("<message to="));
    }

    #[test]
    fn stream_elements_keep_their_prefix() {
        let f = Element::new("features", ns::STREAM).child(Element::new("bind", ns::BIND));
        assert_eq!(f.to_stream_xml(ns::CLIENT), "<stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>");
        assert_eq!(f.to_xml(), "<stream:features xmlns:stream='http://etherx.jabber.org/streams'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></stream:features>");
        assert_eq!(Element::parse(&f.to_xml()).unwrap(), f);
    }

    #[tokio::test]
    async fn stream_reader() {
        let data = b"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='example.com' version='1.0'>\n<iq type='get' id='1'><ping xmlns='urn:xmpp:ping'/></iq><presence/></stream:stream>";
        let mut r = StreamReader::new(&data[..], 1 << 16);
        match r.next().await.unwrap().unwrap() {
            StreamEvent::Open { attrs, default_ns } => {
                assert_eq!(default_ns, ns::CLIENT);
                assert_eq!(StreamEvent::open_attr(&attrs, "to"), Some("example.com"));
            }
            e => panic!("{e:?}"),
        }
        match r.next().await.unwrap().unwrap() {
            StreamEvent::Stanza(el) => {
                assert!(el.is("iq", ns::CLIENT));
                assert!(el.has_child("ping", ns::PING));
            }
            e => panic!("{e:?}"),
        }
        assert!(matches!(r.next().await.unwrap().unwrap(), StreamEvent::Stanza(e) if e.name() == "presence"));
        assert!(matches!(r.next().await.unwrap().unwrap(), StreamEvent::Close));
    }

    #[tokio::test]
    async fn stream_limit() {
        let mut data = b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><message><body>".to_vec();
        data.extend(std::iter::repeat_n(b'a', 100_000));
        data.extend(b"</body></message>");
        let mut r = StreamReader::new(&data[..], 1024);
        r.next().await.unwrap();
        assert!(matches!(r.next().await, Err(XmlError::TooBig)));
    }
}
