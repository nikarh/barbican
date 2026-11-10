//! Reading UCI files (OpenWrt's `/etc/config/*`): sections of options and lists.
//!
//! ```text
//! config barbican 'main'
//!     option enabled '1'
//!
//! config upstream
//!     option url 'http://192.0.2.10:7380'
//!     list tag 'a'
//! ```

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub kind: String,
    pub name: Option<String>,
    pub options: Vec<(String, String)>,
    pub lists: Vec<(String, String)>,
}

impl Section {
    #[must_use]
    pub fn option(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[cfg(test)]
    #[must_use]
    pub fn list(&self, key: &str) -> Vec<&str> {
        self.lists
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("line {line}: {message}")]
pub struct Error {
    pub line: usize,
    pub message: String,
}

/// Splits a line into words, as UCI does: quotes (single or double) group, a backslash escapes.
fn words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        match chars.peek() {
            None | Some('#') => return Ok(words),
            _ => {}
        }
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() {
                break;
            }
            chars.next();
            match c {
                '\'' => loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => word.push(c),
                        None => return Err("unterminated quote".to_owned()),
                    }
                },
                '"' => loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => {
                            if let Some(c) = chars.next() {
                                word.push(c);
                            }
                        }
                        Some(c) => word.push(c),
                        None => return Err("unterminated quote".to_owned()),
                    }
                },
                '\\' => {
                    if let Some(c) = chars.next() {
                        word.push(c);
                    }
                }
                c => word.push(c),
            }
        }
        words.push(word);
    }
}

pub fn parse(text: &str) -> Result<Vec<Section>, Error> {
    let mut sections: Vec<Section> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let error = |message: String| Error {
            line: i + 1,
            message,
        };
        let words = words(line).map_err(error)?;
        match words.as_slice() {
            [] => {}
            [keyword, kind, rest @ ..] if keyword == "config" => sections.push(Section {
                kind: kind.clone(),
                name: rest.first().cloned(),
                ..Section::default()
            }),
            [keyword, key, value] if keyword == "option" || keyword == "list" => {
                let section = sections
                    .last_mut()
                    .ok_or_else(|| error(format!("{keyword} outside a section")))?;
                let entry = (key.clone(), value.clone());
                if keyword == "option" {
                    section.options.push(entry);
                } else {
                    section.lists.push(entry);
                }
            }
            [keyword, ..] if keyword == "package" => {}
            _ => return Err(error(format!("not understood: {line:?}"))),
        }
    }
    Ok(sections)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses() {
        let text = r#"
# a comment
config barbican 'main'
	option enabled '1'
	option state "/etc/barbican/state.json"

config upstream 'server'
	option url 'http://192.0.2.10:7380'
	option token it\'s
	list tag a
	list tag 'b c'

config upstream
	option url http://198.51.100.1:7380
"#;
        let sections = parse(text).unwrap();
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].name.as_deref(), Some("main"));
        assert_eq!(sections[0].option("enabled"), Some("1"));
        assert_eq!(
            sections[0].option("state"),
            Some("/etc/barbican/state.json")
        );
        assert_eq!(sections[1].option("token"), Some("it's"));
        assert_eq!(sections[1].list("tag"), vec!["a", "b c"]);
        assert_eq!(sections[2].name, None);
        assert_eq!(sections[2].option("url"), Some("http://198.51.100.1:7380"));
    }

    #[test]
    fn errors() {
        assert_eq!(parse("option a b").unwrap_err().line, 1);
        assert!(parse("config a\n option x 'y").is_err());
        assert!(parse("config a\n frobnicate").is_err());
    }
}
