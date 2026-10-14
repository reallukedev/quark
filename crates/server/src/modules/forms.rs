//! Just enough of Data Forms (XEP-0004) for the modules that ask people things (room settings,
//! voice requests, room and account registration, ad-hoc commands): building forms and reading
//! submitted values, with caps on how much of a submission is read.

use std::collections::HashMap;

use quark_core::{ns, Element};

/// A form being built.
pub struct Form(Element);

impl Form {
    /// `kind` is `form`, `submit` or `result`; `form_type` goes in the hidden FORM_TYPE field.
    pub fn new(kind: &str, form_type: &str) -> Form {
        Form(Element::new("x", ns::DATA_FORMS).attr_set("type", kind).child(
            Element::new("field", ns::DATA_FORMS).attr_set("var", "FORM_TYPE").attr_set("type", "hidden").text_child(
                "value",
                ns::DATA_FORMS,
                form_type,
            ),
        ))
    }

    pub fn title(mut self, t: &str) -> Form {
        self.0.prepend(Element::new("title", ns::DATA_FORMS).text(t));
        self
    }

    pub fn instructions(mut self, t: &str) -> Form {
        self.0.prepend(Element::new("instructions", ns::DATA_FORMS).text(t));
        self
    }

    /// A field with one value (or none).
    pub fn field(self, var: &str, kind: &str, label: &str, value: Option<&str>) -> Form {
        self.field_values(var, kind, label, value.into_iter())
    }

    pub fn boolean(self, var: &str, label: &str, value: bool) -> Form {
        self.field(var, "boolean", label, Some(if value { "1" } else { "0" }))
    }

    pub fn field_values<'a>(mut self, var: &str, kind: &str, label: &str, values: impl Iterator<Item = &'a str>) -> Form {
        let mut f = Element::new("field", ns::DATA_FORMS).attr_set("var", var).attr_set("type", kind);
        if !label.is_empty() {
            f.set_attr("label", label);
        }
        for v in values {
            f.append(Element::new("value", ns::DATA_FORMS).text(v));
        }
        self.0.append(f);
        self
    }

    /// A list-single field with its options as (value, label).
    pub fn list(mut self, var: &str, label: &str, value: &str, options: &[(&str, &str)]) -> Form {
        let mut f = Element::new("field", ns::DATA_FORMS).attr_set("var", var).attr_set("type", "list-single").attr_set("label", label);
        f.append(Element::new("value", ns::DATA_FORMS).text(value));
        for (v, l) in options {
            f.append(Element::new("option", ns::DATA_FORMS).attr_set("label", *l).text_child("value", ns::DATA_FORMS, *v));
        }
        self.0.append(f);
        self
    }

    /// Marks the most recently added field as required.
    pub fn required(mut self) -> Form {
        if let Some(f) = self.0.children_mut().filter(|c| c.name() == "field").last() {
            f.append(Element::new("required", ns::DATA_FORMS));
        }
        self
    }

    pub fn build(self) -> Element {
        self.0
    }
}

/// The values of a submitted form, by field name.
#[derive(Debug, Default)]
pub struct Values(HashMap<String, Vec<String>>);

/// Submitted forms are small; anything bigger is someone being silly.
const MAX_FIELDS: usize = 64;
pub const MAX_VALUES: usize = 64;

impl Values {
    pub fn parse(x: &Element) -> Values {
        Values::parse_up_to(x, MAX_VALUES)
    }

    /// [`Values::parse`] keeping up to `max_values` values a field (a list of accounts, the
    /// lines of a long message) rather than [`MAX_VALUES`]. Fields stay capped.
    pub fn parse_up_to(x: &Element, max_values: usize) -> Values {
        let mut m: HashMap<String, Vec<String>> = HashMap::new();
        for f in x.children().filter(|c| c.is("field", ns::DATA_FORMS)).take(MAX_FIELDS) {
            let Some(var) = f.attr("var") else { continue };
            let vals = f.children().filter(|c| c.is("value", ns::DATA_FORMS)).take(max_values).map(|v| v.text_content()).collect();
            m.insert(var.to_string(), vals);
        }
        Values(m)
    }

    /// Every value of a field, none when it wasn't sent.
    pub fn all(&self, var: &str) -> &[String] {
        self.0.get(var).map_or(&[], Vec::as_slice)
    }

    pub fn form_type(&self) -> Option<&str> {
        self.get("FORM_TYPE")
    }

    /// The first value, if the field was sent.
    pub fn get(&self, var: &str) -> Option<&str> {
        self.0.get(var).and_then(|v| v.first()).map(String::as_str)
    }

    pub fn has(&self, var: &str) -> bool {
        self.0.contains_key(var)
    }

    /// A boolean field: None when absent, Err when it isn't a boolean.
    pub fn boolean(&self, var: &str) -> Result<Option<bool>, String> {
        match self.0.get(var).map(|v| v.first().map(|s| s.trim())) {
            None => Ok(None),
            Some(None) => Ok(Some(false)),
            Some(Some("1" | "true")) => Ok(Some(true)),
            Some(Some("0" | "false" | "")) => Ok(Some(false)),
            Some(Some(_)) => Err(format!("The field {var} needs to be true or false.")),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.keys().all(|k| k == "FORM_TYPE")
    }
}

/// The first `jabber:x:data` form among `el`'s children, with its `type`.
pub fn find(el: &Element) -> Option<&Element> {
    el.get_child("x", ns::DATA_FORMS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_reads_back() {
        let f = Form::new("submit", "urn:test").boolean("a", "A", true).field("b", "text-single", "B", Some("hi")).build();
        let v = Values::parse(&f);
        assert_eq!(v.form_type(), Some("urn:test"));
        assert_eq!(v.boolean("a"), Ok(Some(true)));
        assert_eq!(v.get("b"), Some("hi"));
        assert_eq!(v.boolean("missing"), Ok(None));
        assert!(!v.is_empty());
    }

    #[test]
    fn submissions_are_capped() {
        let mut x = Element::new("x", ns::DATA_FORMS).attr_set("type", "submit");
        for i in 0..MAX_FIELDS + 10 {
            x.append(Element::new("field", ns::DATA_FORMS).attr_set("var", format!("f{i}")));
        }
        let mut many = Element::new("field", ns::DATA_FORMS).attr_set("var", "many");
        for i in 0..MAX_VALUES + 10 {
            many.append(Element::new("value", ns::DATA_FORMS).text(i.to_string()));
        }
        assert!(!Values::parse(&x).has(&format!("f{MAX_FIELDS}")));
        let x = Element::new("x", ns::DATA_FORMS).child(many);
        assert_eq!(Values::parse(&x).all("many").len(), MAX_VALUES);
        assert_eq!(Values::parse_up_to(&x, 500).all("many").len(), MAX_VALUES + 10);
        assert!(Values::parse(&x).all("missing").is_empty());
    }

    #[test]
    fn bad_booleans_are_refused() {
        let f = Form::new("submit", "urn:test").field("a", "boolean", "", Some("maybe")).build();
        assert!(Values::parse(&f).boolean("a").is_err());
    }
}
