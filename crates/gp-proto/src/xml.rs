//! Simple XML tree parser for GlobalProtect protocol responses.

use std::str;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::error::ProtoError;

/// A lightweight XML tree node for convenient traversal.
#[derive(Debug, Clone, Default)]
pub struct XmlNode {
    pub name: String,
    pub attributes: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    /// Parse an XML string into a tree rooted at the document element.
    pub fn parse(xml: &str) -> Result<Self, ProtoError> {
        let mut reader = Reader::from_str(xml);

        // Sentinel root — the real root element will become its only child.
        let mut stack = vec![XmlNode::default()];

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    stack.push(Self::from_start(e));
                }
                Ok(Event::End(_)) => {
                    let node = stack.pop().unwrap_or_default();
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(Self::from_start(e));
                    }
                }
                Ok(Event::Text(ref e)) => {
                    // `BytesText::unescape` was removed in
                    // quick-xml 0.39; `xml_content` is the
                    // replacement and does both the encoding
                    // decode and the entity unescape, plus
                    // XML 1.1 end-of-line normalization per
                    // W3C spec. For GlobalProtect XML
                    // responses that normalization is a
                    // no-op (no embedded CR/NEL in text
                    // content), so the behaviour change
                    // from 0.36 is invisible to our parser.
                    if let Ok(text) = e.xml_content() {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            if let Some(current) = stack.last_mut() {
                                if current.text.is_empty() {
                                    current.text = trimmed.to_string();
                                } else {
                                    current.text.push(' ');
                                    current.text.push_str(trimmed);
                                }
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(ProtoError::XmlParse(e.to_string())),
                _ => {}
            }
        }

        let root = stack.pop().unwrap_or_default();
        root.children
            .into_iter()
            .next()
            .ok_or_else(|| ProtoError::XmlParse("empty XML document".into()))
    }

    fn from_start(e: &quick_xml::events::BytesStart<'_>) -> Self {
        let name = str::from_utf8(e.name().as_ref()).unwrap_or("").to_string();
        let attributes = e
            .attributes()
            .filter_map(|a| {
                let a = a.ok()?;
                let k = str::from_utf8(a.key.as_ref()).ok()?.to_string();
                let v = str::from_utf8(&a.value).ok()?.to_string();
                Some((k, v))
            })
            .collect();
        Self {
            name,
            attributes,
            text: String::new(),
            children: Vec::new(),
        }
    }

    /// Find a direct child element by tag name.
    pub fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Get the text content of a direct child element.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|c| c.text.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Get an attribute value.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Iterate over direct children with the given tag name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Navigate to a descendant by a slash-separated path (e.g. `"gateways/external/list"`).
    pub fn at(&self, path: &str) -> Option<&XmlNode> {
        let mut current = self;
        for part in path.split('/') {
            current = current.child(part)?;
        }
        Some(current)
    }

    /// Get the text content of a descendant at the given path.
    pub fn text_at(&self, path: &str) -> Option<&str> {
        self.at(path)
            .map(|n| n.text.as_str())
            .filter(|s| !s.is_empty())
    }

    /// Recursively find the first descendant with the given tag name (depth-first).
    pub fn find(&self, name: &str) -> Option<&XmlNode> {
        for child in &self.children {
            if child.name == name {
                return Some(child);
            }
            if let Some(found) = child.find(name) {
                return Some(found);
            }
        }
        None
    }

    /// Find the text content of the first descendant with the given tag name.
    pub fn find_text(&self, name: &str) -> Option<&str> {
        self.find(name)
            .map(|n| n.text.as_str())
            .filter(|s| !s.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let xml = r#"<root><child>hello</child><other attr="val"/></root>"#;
        let node = XmlNode::parse(xml).unwrap();
        assert_eq!(node.name, "root");
        assert_eq!(node.child_text("child"), Some("hello"));
        assert_eq!(node.child("other").unwrap().attr("attr"), Some("val"));
    }

    #[test]
    fn parse_nested_path() {
        let xml = r#"<a><b><c>deep</c></b></a>"#;
        let node = XmlNode::parse(xml).unwrap();
        assert_eq!(node.text_at("b/c"), Some("deep"));
    }
}
