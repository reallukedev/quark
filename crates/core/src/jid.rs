//! JIDs (RFC 7622), normalized on parse so they compare and hash as plain strings.

use std::fmt;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Jid {
    node: Option<String>,
    domain: String,
    resource: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JidError {
    #[error("empty domain")]
    EmptyDomain,
    #[error("empty localpart")]
    EmptyNode,
    #[error("empty resource")]
    EmptyResource,
    #[error("part too long")]
    TooLong,
    #[error("invalid character")]
    Invalid,
}

impl Jid {
    pub fn parse(s: &str) -> Result<Jid, JidError> {
        let (rest, resource) = match s.find('/') {
            Some(i) => (&s[..i], Some(&s[i + 1..])),
            None => (s, None),
        };
        let (node, domain) = match rest.rfind('@') {
            Some(i) => (Some(&rest[..i]), &rest[i + 1..]),
            None => (None, rest),
        };
        Jid::from_parts(node, domain, resource)
    }

    pub fn from_parts(node: Option<&str>, domain: &str, resource: Option<&str>) -> Result<Jid, JidError> {
        let domain = prep_domain(domain)?;
        let node = match node {
            Some(n) => Some(prep_node(n)?),
            None => None,
        };
        let resource = match resource {
            Some(r) => Some(prep_resource(r)?),
            None => None,
        };
        Ok(Jid { node, domain, resource })
    }

    /// A domain JID, e.g. `example.com`.
    pub fn domain_jid(domain: &str) -> Result<Jid, JidError> {
        Jid::from_parts(None, domain, None)
    }

    /// A bare JID from parts already known to be normalized (no checks).
    pub fn bare_unchecked(node: &str, domain: &str) -> Jid {
        Jid { node: Some(node.to_string()), domain: domain.to_string(), resource: None }
    }

    pub fn node(&self) -> Option<&str> {
        self.node.as_deref()
    }
    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
    }
    pub fn is_bare(&self) -> bool {
        self.resource.is_none()
    }
    pub fn is_full(&self) -> bool {
        self.resource.is_some()
    }
    pub fn is_domain(&self) -> bool {
        self.node.is_none() && self.resource.is_none()
    }
    pub fn to_bare(&self) -> Jid {
        Jid { node: self.node.clone(), domain: self.domain.clone(), resource: None }
    }
    pub fn with_resource(&self, r: &str) -> Result<Jid, JidError> {
        Ok(Jid { node: self.node.clone(), domain: self.domain.clone(), resource: Some(prep_resource(r)?) })
    }
    /// `node@domain` or `domain`.
    pub fn bare_str(&self) -> String {
        match &self.node {
            Some(n) => format!("{n}@{}", self.domain),
            None => self.domain.clone(),
        }
    }
}

impl fmt::Display for Jid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(n) = &self.node {
            write!(f, "{n}@")?;
        }
        f.write_str(&self.domain)?;
        if let Some(r) = &self.resource {
            write!(f, "/{r}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Jid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Jid({self})")
    }
}

impl FromStr for Jid {
    type Err = JidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Jid::parse(s)
    }
}

fn prep_node(n: &str) -> Result<String, JidError> {
    if n.is_empty() {
        return Err(JidError::EmptyNode);
    }
    // Fast path: plain ASCII lowercase needs no stringprep.
    let out = if n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-+".contains(&b)) {
        n.to_string()
    } else {
        stringprep::nodeprep(n).map_err(|_| JidError::Invalid)?.into_owned()
    };
    if out.is_empty() {
        return Err(JidError::EmptyNode);
    }
    if out.len() > 1023 {
        return Err(JidError::TooLong);
    }
    if out.contains(['"', '&', '\'', '/', ':', '<', '>', '@']) {
        return Err(JidError::Invalid);
    }
    Ok(out)
}

fn prep_domain(d: &str) -> Result<String, JidError> {
    let d = d.strip_suffix('.').unwrap_or(d);
    if d.is_empty() {
        return Err(JidError::EmptyDomain);
    }
    let out = if d.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') {
        d.to_string()
    } else if d.starts_with('[') && d.ends_with(']') {
        d.to_ascii_lowercase()
    } else {
        stringprep::nameprep(d).map_err(|_| JidError::Invalid)?.into_owned()
    };
    if out.len() > 1023 {
        return Err(JidError::TooLong);
    }
    if out.contains(['@', '/', ' ', '<', '>', '\'', '"', '&']) || out.starts_with('.') || out.contains("..") {
        return Err(JidError::Invalid);
    }
    Ok(out)
}

fn prep_resource(r: &str) -> Result<String, JidError> {
    if r.is_empty() {
        return Err(JidError::EmptyResource);
    }
    let out = if r.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
        r.to_string()
    } else {
        stringprep::resourceprep(r).map_err(|_| JidError::Invalid)?.into_owned()
    };
    if out.is_empty() {
        return Err(JidError::EmptyResource);
    }
    if out.len() > 1023 {
        return Err(JidError::TooLong);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let j = Jid::parse("Juliet@Example.COM/Balcony Phone").unwrap();
        assert_eq!(j.node(), Some("juliet"));
        assert_eq!(j.domain(), "example.com");
        assert_eq!(j.resource(), Some("Balcony Phone"));
        assert_eq!(j.to_string(), "juliet@example.com/Balcony Phone");
        assert_eq!(j.to_bare().to_string(), "juliet@example.com");
        // Resources keep slashes after the first.
        assert_eq!(Jid::parse("a@b/c/d").unwrap().resource(), Some("c/d"));
        assert!(Jid::parse("@b").is_err());
        assert!(Jid::parse("a@").is_err());
        assert!(Jid::parse("a@b/").is_err());
        assert!(Jid::parse("example.com").unwrap().is_domain());
        assert_eq!(Jid::parse("ÄBC@example.com").unwrap().node(), Some("äbc"));
    }
}
