//! Minimal, dependency-free JSON value, serializer and parser.
//!
//! Only what the RPC wire protocol needs: compact serialization of requests and
//! lenient parsing of single-line responses. Object key order is preserved.

/// A JSON value. Numbers are kept as `f64`; the wire protocol only carries
/// integer counts, which serialize without a fractional part.
#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl std::fmt::Display for Json {
    /// Serialize to a compact JSON string (no insignificant whitespace).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

impl Json {
    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => {
                if n.is_finite() && n.fract() == 0.0 {
                    out.push_str(&(*n as i64).to_string());
                } else {
                    out.push_str(&n.to_string());
                }
            }
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    /// Look up a key in an object value.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(items) => Some(items),
            _ => None,
        }
    }

    /// Borrow an object's fields as `(key, value)` pairs, in document order.
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(fields) => Some(fields),
            _ => None,
        }
    }

    /// Parse a JSON document from text.
    pub fn parse(text: &str) -> Result<Json, String> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        parser.skip_ws();
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.pos != parser.bytes.len() {
            return Err(format!("trailing data at byte {}", parser.pos));
        }
        Ok(value)
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.bytes.get(self.pos) {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Json::Str(self.parse_string()?)),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(&b) if b == b'-' || b.is_ascii_digit() => self.parse_number(),
            Some(&b) => Err(format!("unexpected byte '{}' at {}", b as char, self.pos)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '{'
        let mut fields = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b'"') {
                return Err(format!("expected object key at {}", self.pos));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') {
                return Err(format!("expected ':' at {}", self.pos));
            }
            self.pos += 1;
            let value = self.parse_value()?;
            fields.push((key, value));
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.pos)),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.pos += 1; // consume '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            let value = self.parse_value()?;
            items.push(value);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.pos)),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.pos += 1; // consume opening '"'
        let mut s = String::new();
        loop {
            let b = *self
                .bytes
                .get(self.pos)
                .ok_or("unterminated string".to_string())?;
            self.pos += 1;
            match b {
                b'"' => return Ok(s),
                b'\\' => {
                    let esc = *self
                        .bytes
                        .get(self.pos)
                        .ok_or("unterminated escape".to_string())?;
                    self.pos += 1;
                    match esc {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'u' => s.push(self.parse_unicode_escape()?),
                        other => return Err(format!("invalid escape '\\{}'", other as char)),
                    }
                }
                // Raw UTF-8 continuation: collect the whole sequence verbatim.
                _ => {
                    let start = self.pos - 1;
                    while let Some(&nb) = self.bytes.get(self.pos) {
                        if nb >= 0x80 {
                            self.pos += 1;
                        } else {
                            break;
                        }
                    }
                    let slice = &self.bytes[start..self.pos];
                    match std::str::from_utf8(slice) {
                        Ok(chunk) => s.push_str(chunk),
                        Err(_) => return Err("invalid UTF-8 in string".to_string()),
                    }
                }
            }
        }
    }

    /// Parse the four hex digits after `\u`, joining a surrogate pair if present.
    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        let high = self.parse_hex4()?;
        if (0xD800..=0xDBFF).contains(&high) {
            // Expect a following "\uXXXX" low surrogate.
            if self.bytes.get(self.pos) == Some(&b'\\')
                && self.bytes.get(self.pos + 1) == Some(&b'u')
            {
                self.pos += 2;
                let low = self.parse_hex4()?;
                if (0xDC00..=0xDFFF).contains(&low) {
                    let c = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
                    return char::from_u32(c).ok_or("invalid surrogate pair".to_string());
                }
                return Err("invalid low surrogate".to_string());
            }
            return Err("unpaired high surrogate".to_string());
        }
        char::from_u32(high).ok_or("invalid unicode escape".to_string())
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let b = *self
                .bytes
                .get(self.pos)
                .ok_or("truncated unicode escape".to_string())?;
            let digit = (b as char)
                .to_digit(16)
                .ok_or("invalid hex digit in unicode escape".to_string())?;
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b'-' || b == b'+' || b == b'.' || b == b'e' || b == b'E' || b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap();
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number '{}'", text))
    }

    fn parse_bool(&mut self) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Json::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Json::Bool(false))
        } else {
            Err(format!("invalid literal at {}", self.pos))
        }
    }

    fn parse_null(&mut self) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Json::Null)
        } else {
            Err(format!("invalid literal at {}", self.pos))
        }
    }
}

/// Builder for an RPC request object; preserves field insertion order and only
/// emits optional fields when a value is supplied (so server defaults apply).
pub struct Req(Vec<(String, Json)>);

impl Req {
    /// Start a request for the named procedure.
    pub fn new(procedure: &str) -> Req {
        Req(vec![(
            "procedure".to_string(),
            Json::Str(procedure.to_string()),
        )])
    }

    /// Required string field.
    pub fn str(mut self, key: &str, value: impl Into<String>) -> Req {
        self.0.push((key.to_string(), Json::Str(value.into())));
        self
    }

    /// Optional string field.
    pub fn opt_str(mut self, key: &str, value: Option<String>) -> Req {
        if let Some(v) = value {
            self.0.push((key.to_string(), Json::Str(v)));
        }
        self
    }

    /// Optional integer field.
    pub fn opt_int(mut self, key: &str, value: Option<i64>) -> Req {
        if let Some(v) = value {
            self.0.push((key.to_string(), Json::Num(v as f64)));
        }
        self
    }

    /// Required integer field.
    pub fn int(mut self, key: &str, value: i64) -> Req {
        self.0.push((key.to_string(), Json::Num(value as f64)));
        self
    }

    /// Optional boolean field.
    pub fn opt_bool(mut self, key: &str, value: Option<bool>) -> Req {
        if let Some(v) = value {
            self.0.push((key.to_string(), Json::Bool(v)));
        }
        self
    }

    /// Required boolean field. Always emits the value — callers must
    /// supply the field's documented default when the user did not pass
    /// an explicit flag, so the wire carries the resolved value.
    pub fn bool(mut self, key: &str, value: bool) -> Req {
        self.0.push((key.to_string(), Json::Bool(value)));
        self
    }

    /// Optional raw JSON field.
    pub fn opt_json(mut self, key: &str, value: Option<Json>) -> Req {
        if let Some(v) = value {
            self.0.push((key.to_string(), v));
        }
        self
    }

    /// Finish building.
    pub fn build(self) -> Json {
        Json::Obj(self.0)
    }
}
