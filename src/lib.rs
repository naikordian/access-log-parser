use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};

pub const CSV_HEADER: [&str; 15] = [
    "remote_host",
    "ident",
    "remote_user",
    "timestamp",
    "request",
    "method",
    "request_target",
    "request_path",
    "extension",
    "query_string",
    "protocol",
    "status",
    "bytes_sent",
    "referer",
    "user_agent",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub remote_host: String,
    pub ident: Option<String>,
    pub remote_user: Option<String>,
    pub timestamp: String,
    pub request: Option<String>,
    pub method: Option<String>,
    pub request_target: Option<String>,
    pub request_path: Option<String>,
    pub extension: Option<String>,
    pub query_string: Option<String>,
    pub protocol: Option<String>,
    pub status: u16,
    pub bytes_sent: Option<u64>,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
}

impl LogRecord {
    pub fn csv_fields(&self) -> [String; 15] {
        [
            self.remote_host.clone(),
            self.ident.clone().unwrap_or_default(),
            self.remote_user.clone().unwrap_or_default(),
            self.timestamp.clone(),
            self.request.clone().unwrap_or_default(),
            self.method.clone().unwrap_or_default(),
            self.request_target.clone().unwrap_or_default(),
            self.request_path.clone().unwrap_or_default(),
            self.extension.clone().unwrap_or_default(),
            self.query_string.clone().unwrap_or_default(),
            self.protocol.clone().unwrap_or_default(),
            self.status.to_string(),
            self.bytes_sent
                .map(|value| value.to_string())
                .unwrap_or_default(),
            self.referer.clone().unwrap_or_default(),
            self.user_agent.clone().unwrap_or_default(),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    offset: usize,
    message: String,
}

impl ParseError {
    fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "byte {}: {}", self.offset + 1, self.message)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug)]
struct QuotedValue {
    bytes: Vec<u8>,
    literal_spaces: Vec<usize>,
}

struct Lexer<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn advance(&mut self) {
        self.position = self.position.saturating_add(1);
    }

    fn advance_by(&mut self, amount: usize) {
        self.position = self.position.saturating_add(amount);
    }

    fn unquoted(&mut self, field: &str) -> Result<Vec<u8>, ParseError> {
        let start = self.position;
        let length = self.input[start..]
            .iter()
            .position(|&byte| byte == b' ')
            .unwrap_or_else(|| self.input.len().saturating_sub(start));
        self.advance_by(length);

        if self.position == start {
            return Err(ParseError::new(start, format!("missing {field}")));
        }

        Ok(self.input[start..self.position].to_vec())
    }

    fn bracketed(&mut self, field: &str) -> Result<Vec<u8>, ParseError> {
        self.expect_byte(b'[', format!("expected '[' before {field}"))?;
        let start = self.position;
        let length = self.input[start..]
            .iter()
            .position(|&byte| byte == b']')
            .ok_or_else(|| ParseError::new(start, format!("unterminated {field}")))?;
        if length == 0 {
            return Err(ParseError::new(start, format!("empty {field}")));
        }
        let value = self.input[start..start.saturating_add(length)].to_vec();
        self.advance_by(length);
        self.advance();
        Ok(value)
    }

    fn quoted(&mut self, field: &str) -> Result<QuotedValue, ParseError> {
        self.expect_byte(b'"', format!("expected quote before {field}"))?;
        let start = self.position;
        let mut bytes = Vec::new();
        let mut literal_spaces = Vec::new();

        while let Some(&byte) = self.input.get(self.position) {
            match byte {
                b'"' => {
                    self.advance();
                    return Ok(QuotedValue {
                        bytes,
                        literal_spaces,
                    });
                }
                b'\\' => {
                    let escape_offset = self.position;
                    self.advance();
                    let escaped = self.input.get(self.position).copied().ok_or_else(|| {
                        ParseError::new(escape_offset, format!("incomplete escape in {field}"))
                    })?;
                    match escaped {
                        b'"' | b'\\' => {
                            bytes.push(escaped);
                            self.advance();
                        }
                        b'x' => {
                            let escape = &self.input[self.position..];
                            let high = escape.get(1).copied();
                            let low = escape.get(2).copied();
                            let decoded = match (high.and_then(hex_value), low.and_then(hex_value))
                            {
                                (Some(high), Some(low)) => high.wrapping_shl(4).wrapping_add(low),
                                _ => {
                                    return Err(ParseError::new(
                                        escape_offset,
                                        format!("invalid hexadecimal escape in {field}"),
                                    ));
                                }
                            };
                            bytes.push(decoded);
                            self.advance_by(3);
                        }
                        _ => {
                            return Err(ParseError::new(
                                escape_offset,
                                format!("unknown escape in {field}"),
                            ));
                        }
                    }
                }
                b' ' => {
                    literal_spaces.push(bytes.len());
                    bytes.push(byte);
                    self.advance();
                }
                _ => {
                    bytes.push(byte);
                    self.advance();
                }
            }
        }

        Err(ParseError::new(start, format!("unterminated {field}")))
    }

    fn separator(&mut self) -> Result<(), ParseError> {
        self.expect_byte(b' ', "expected a space between fields")?;
        let extra_spaces = self.input[self.position..]
            .iter()
            .take_while(|&&byte| byte == b' ')
            .count();
        self.advance_by(extra_spaces);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ParseError> {
        let trailing_spaces = self.input[self.position..]
            .iter()
            .take_while(|&&byte| byte == b' ')
            .count();
        self.advance_by(trailing_spaces);
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(ParseError::new(self.position, "unexpected trailing data"))
        }
    }

    fn expect_byte(&mut self, expected: u8, message: impl Into<String>) -> Result<(), ParseError> {
        if self.input.get(self.position) == Some(&expected) {
            self.advance();
            Ok(())
        } else {
            Err(ParseError::new(self.position, message))
        }
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

fn utf8(bytes: Vec<u8>, field: &str, offset: usize) -> Result<String, ParseError> {
    String::from_utf8(bytes).map_err(|error| {
        ParseError::new(
            offset.saturating_add(error.utf8_error().valid_up_to()),
            format!("{field} is not valid UTF-8"),
        )
    })
}

fn nullable(value: String) -> Option<String> {
    (value != "-").then_some(value)
}

fn normalize_timestamp(value: &str, offset: usize) -> Result<String, ParseError> {
    let timestamp = DateTime::parse_from_str(value, "%d/%b/%Y:%H:%M:%S %z")
        .map_err(|error| ParseError::new(offset, format!("invalid timestamp: {error}")))?;
    Ok(timestamp
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn split_request_target(target: &str) -> (String, Option<String>, Option<String>) {
    let (path, query_string) = match target.split_once('?') {
        Some((path, query_string)) => (path, Some(query_string.to_owned())),
        None => (target, None),
    };
    let extension = path
        .rsplit('/')
        .next()
        .and_then(|segment| segment.rsplit_once('.'))
        .and_then(|(stem, extension)| {
            (!stem.is_empty() && !extension.is_empty()).then(|| extension.to_owned())
        });

    (path.to_owned(), extension, query_string)
}

pub fn parse_line(line: &[u8]) -> Result<LogRecord, ParseError> {
    let mut lexer = Lexer::new(line);

    let offset = lexer.position;
    let remote_host = utf8(lexer.unquoted("remote host")?, "remote host", offset)?;
    lexer.separator()?;

    let offset = lexer.position;
    let ident = nullable(utf8(lexer.unquoted("ident")?, "ident", offset)?);
    lexer.separator()?;

    let offset = lexer.position;
    let remote_user = nullable(utf8(lexer.unquoted("remote user")?, "remote user", offset)?);
    lexer.separator()?;

    let offset = lexer.position;
    let timestamp = utf8(
        lexer.bracketed("timestamp")?,
        "timestamp",
        offset.saturating_add(1),
    )?;
    let timestamp = normalize_timestamp(&timestamp, offset.saturating_add(1))?;
    lexer.separator()?;

    let request_offset = lexer.position;
    let request_value = lexer.quoted("request")?;
    let request = utf8(
        request_value.bytes,
        "request",
        request_offset.saturating_add(1),
    )?;
    lexer.separator()?;

    let status_offset = lexer.position;
    let status_text = utf8(lexer.unquoted("status")?, "status", status_offset)?;
    if status_text.len() != 3 || !status_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseError::new(
            status_offset,
            "status must be three digits",
        ));
    }
    let status = status_text
        .parse()
        .map_err(|_| ParseError::new(status_offset, "status is out of range"))?;
    lexer.separator()?;

    let bytes_offset = lexer.position;
    let bytes_text = utf8(lexer.unquoted("bytes sent")?, "bytes sent", bytes_offset)?;
    let bytes_sent = if bytes_text == "-" {
        None
    } else if !bytes_text.is_empty() && bytes_text.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(
            bytes_text
                .parse()
                .map_err(|_| ParseError::new(bytes_offset, "bytes sent is out of range"))?,
        )
    } else {
        return Err(ParseError::new(
            bytes_offset,
            "bytes sent must be digits or '-'",
        ));
    };
    lexer.separator()?;

    let referer_offset = lexer.position;
    let referer = nullable(utf8(
        lexer.quoted("referer")?.bytes,
        "referer",
        referer_offset.saturating_add(1),
    )?);
    lexer.separator()?;

    let user_agent_offset = lexer.position;
    let user_agent = nullable(utf8(
        lexer.quoted("user agent")?.bytes,
        "user agent",
        user_agent_offset.saturating_add(1),
    )?);
    lexer.finish()?;

    let (request, method, request_target, request_path, extension, query_string, protocol) =
        if request == "-" {
            (None, None, None, None, None, None, None)
        } else {
            if request_value.literal_spaces.len() != 2 {
                return Err(ParseError::new(
                    request_offset.saturating_add(1),
                    "request must contain method, target, and protocol",
                ));
            }
            let first = request_value.literal_spaces[0];
            let second = request_value.literal_spaces[1];
            if first == 0
                || second == first.saturating_add(1)
                || second.saturating_add(1) >= request.len()
            {
                return Err(ParseError::new(
                    request_offset.saturating_add(1),
                    "request method, target, and protocol must be non-empty",
                ));
            }
            let method = request[..first].to_owned();
            let request_target = request[first.saturating_add(1)..second].to_owned();
            let protocol = request[second.saturating_add(1)..].to_owned();
            let (request_path, extension, query_string) = split_request_target(&request_target);
            (
                Some(request),
                Some(method),
                Some(request_target),
                Some(request_path),
                extension,
                query_string,
                Some(protocol),
            )
        };

    Ok(LogRecord {
        remote_host,
        ident,
        remote_user,
        timestamp,
        request,
        method,
        request_target,
        request_path,
        extension,
        query_string,
        protocol,
        status,
        bytes_sent,
        referer,
        user_agent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = br#"255.102.154.224 - - [07/Oct/2025:07:35:03 +0700] "HEAD /1.php HTTP/1.0" 302 137 "https://sub1.example/" "Test Agent""#;

    #[test]
    fn parses_combined_log_and_normalizes_timestamp() {
        let record = parse_line(VALID).unwrap();

        assert_eq!(record.remote_host, "255.102.154.224");
        assert_eq!(record.ident, None);
        assert_eq!(record.remote_user, None);
        assert_eq!(record.timestamp, "2025-10-07T00:35:03Z");
        assert_eq!(record.request.as_deref(), Some("HEAD /1.php HTTP/1.0"));
        assert_eq!(record.method.as_deref(), Some("HEAD"));
        assert_eq!(record.request_target.as_deref(), Some("/1.php"));
        assert_eq!(record.request_path.as_deref(), Some("/1.php"));
        assert_eq!(record.extension.as_deref(), Some("php"));
        assert_eq!(record.query_string, None);
        assert_eq!(record.protocol.as_deref(), Some("HTTP/1.0"));
        assert_eq!(record.status, 302);
        assert_eq!(record.bytes_sent, Some(137));
        assert_eq!(record.referer.as_deref(), Some("https://sub1.example/"));
        assert_eq!(record.user_agent.as_deref(), Some("Test Agent"));
    }

    #[test]
    fn decodes_supported_quoted_escapes() {
        let line = br#"192.0.2.10 - alice [07/Oct/2025:07:35:03 +0700] "GET /search?q=\x22rust\x22 HTTP/1.1" 200 123 "-" "ExampleBot/1.0 \"crawler\" \\ Windows""#;
        let record = parse_line(line).unwrap();

        assert_eq!(record.request_target.as_deref(), Some("/search?q=\"rust\""));
        assert_eq!(record.request_path.as_deref(), Some("/search"));
        assert_eq!(record.extension, None);
        assert_eq!(record.query_string.as_deref(), Some("q=\"rust\""));
        assert_eq!(
            record.user_agent.as_deref(),
            Some("ExampleBot/1.0 \"crawler\" \\ Windows")
        );
        assert_eq!(record.referer, None);
    }

    #[test]
    fn decodes_every_hexadecimal_digit_case() {
        for (input, expected) in [
            (b'0', Some(0)),
            (b'9', Some(9)),
            (b'a', Some(10)),
            (b'f', Some(15)),
            (b'A', Some(10)),
            (b'F', Some(15)),
            (b'g', None),
        ] {
            assert_eq!(hex_value(input), expected, "input: {}", char::from(input));
        }
    }

    #[test]
    fn accepts_extra_field_separators_and_trailing_spaces() {
        let line = br#"255.102.154.224   -  -   [07/Oct/2025:07:35:03 +0700]  "HEAD /1.php HTTP/1.0"   302  137   "-"  "Test Agent"   "#;
        let record = parse_line(line).unwrap();

        assert_eq!(record.remote_host, "255.102.154.224");
        assert_eq!(record.request_target.as_deref(), Some("/1.php"));
        assert_eq!(record.status, 302);
        assert_eq!(record.bytes_sent, Some(137));
        assert_eq!(record.user_agent.as_deref(), Some("Test Agent"));
    }

    #[test]
    fn allows_hex_encoded_space_inside_request_target() {
        let line =
            br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET /a\x20b HTTP/1.1" 200 0 "-" "-""#;
        let record = parse_line(line).unwrap();

        assert_eq!(record.request_target.as_deref(), Some("/a b"));
    }

    #[test]
    fn accepts_missing_request_and_nullable_fields() {
        let line = br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "-" 400 - "-" "-""#;
        let record = parse_line(line).unwrap();

        assert_eq!(record.request, None);
        assert_eq!(record.method, None);
        assert_eq!(record.request_target, None);
        assert_eq!(record.request_path, None);
        assert_eq!(record.extension, None);
        assert_eq!(record.query_string, None);
        assert_eq!(record.protocol, None);
        assert_eq!(record.bytes_sent, None);
        assert_eq!(record.referer, None);
        assert_eq!(record.user_agent, None);
    }

    #[test]
    fn rejects_unknown_escape() {
        let line = br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET / HTTP/1.1" 200 1 "-" "bad\qagent""#;
        let error = parse_line(line).unwrap_err();

        assert!(error.to_string().contains("unknown escape in user agent"));
    }

    #[test]
    fn rejects_invalid_utf8_after_hex_decoding() {
        let line =
            br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET / HTTP/1.1" 200 1 "-" "\xFF""#;
        let error = parse_line(line).unwrap_err();

        let expected_offset = line
            .windows(4)
            .position(|window| window == br"\xFF")
            .unwrap();
        assert_eq!(error.offset, expected_offset);
        assert_eq!(
            error.to_string(),
            format!(
                "byte {}: user agent is not valid UTF-8",
                expected_offset + 1
            )
        );
    }

    #[test]
    fn reports_utf8_error_after_valid_prefix_at_exact_offset() {
        let error = utf8(vec![b'a', 0xff], "test field", 10).unwrap_err();

        assert_eq!(error.offset, 11);
        assert_eq!(error.to_string(), "byte 12: test field is not valid UTF-8");
    }

    #[test]
    fn rejects_invalid_timestamp() {
        let line = br#"192.0.2.10 - - [31/Feb/2025:07:35:03 +0700] "GET / HTTP/1.1" 200 1 "-" "-""#;
        let error = parse_line(line).unwrap_err();

        let expected_offset = line.iter().position(|&byte| byte == b'[').unwrap() + 1;
        assert_eq!(error.offset, expected_offset);
        assert!(error.to_string().contains("invalid timestamp"));
    }

    #[test]
    fn reports_invalid_request_utf8_at_content_offset() {
        let line =
            br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET /\xFF HTTP/1.1" 200 1 "-" "-""#;
        let error = parse_line(line).unwrap_err();
        let request_start = line.iter().position(|&byte| byte == b'"').unwrap() + 1;
        let valid_prefix = b"GET /".len();

        assert_eq!(error.offset, request_start + valid_prefix);
        assert!(error.to_string().contains("request is not valid UTF-8"));
    }

    #[test]
    fn reports_invalid_referer_utf8_at_content_offset() {
        let line = br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET / HTTP/1.1" 200 1 "prefix\xFF" "-""#;
        let error = parse_line(line).unwrap_err();
        let escape_offset = line
            .windows(4)
            .position(|window| window == br"\xFF")
            .unwrap();

        assert_eq!(error.offset, escape_offset);
        assert!(error.to_string().contains("referer is not valid UTF-8"));
    }

    #[test]
    fn rejects_request_without_three_parts() {
        let line = br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET /" 200 1 "-" "-""#;
        let error = parse_line(line).unwrap_err();

        let expected_offset = line.iter().position(|&byte| byte == b'"').unwrap() + 1;
        assert_eq!(error.offset, expected_offset);
        assert!(error.to_string().contains("method, target, and protocol"));
    }

    #[test]
    fn rejects_wrong_length_and_non_digit_statuses() {
        for status in ["20", "2x0"] {
            let line = format!(
                r#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET / HTTP/1.1" {status} 1 "-" "-""#
            );
            let error = parse_line(line.as_bytes()).unwrap_err();

            assert_eq!(error.message, "status must be three digits");
        }
    }

    #[test]
    fn rejects_non_digit_byte_count_with_specific_error() {
        let line =
            br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET / HTTP/1.1" 200 invalid "-" "-""#;
        let error = parse_line(line).unwrap_err();

        assert_eq!(error.message, "bytes sent must be digits or '-'");
    }

    #[test]
    fn rejects_each_empty_request_component() {
        for request in [" / HTTP/1.1", "GET  HTTP/1.1", "GET / "] {
            let line =
                format!(r#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "{request}" 200 1 "-" "-""#);
            let error = parse_line(line.as_bytes()).unwrap_err();

            assert_eq!(
                error.message, "request method, target, and protocol must be non-empty",
                "request: {request:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_data() {
        let mut line = VALID.to_vec();
        line.extend_from_slice(b" surprise");
        let error = parse_line(&line).unwrap_err();

        assert!(error.to_string().contains("unexpected trailing data"));
    }

    #[test]
    fn splits_path_extension_and_raw_query_string() {
        let line = br#"192.0.2.10 - - [07/Oct/2025:07:35:03 +0700] "GET /1.php?code=anon42aa906fd184&state=anon25e7ea81614c HTTP/1.0" 200 1 "-" "-""#;
        let record = parse_line(line).unwrap();

        assert_eq!(record.request_path.as_deref(), Some("/1.php"));
        assert_eq!(record.extension.as_deref(), Some("php"));
        assert_eq!(
            record.query_string.as_deref(),
            Some("code=anon42aa906fd184&state=anon25e7ea81614c")
        );
    }

    #[test]
    fn derives_extension_from_only_the_final_path_segment() {
        for (target, expected) in [
            ("/assets/app.min.JS", Some("JS")),
            ("/archive", None),
            ("/.well-known", None),
            ("/path/file.", None),
            ("/directory.with-dot/file", None),
        ] {
            let (_, extension, _) = split_request_target(target);
            assert_eq!(extension.as_deref(), expected, "target: {target}");
        }
    }

    #[test]
    fn splits_query_only_on_the_first_question_mark() {
        let (path, extension, query_string) = split_request_target("/a.php?one?two");

        assert_eq!(path, "/a.php");
        assert_eq!(extension.as_deref(), Some("php"));
        assert_eq!(query_string.as_deref(), Some("one?two"));
    }
}
