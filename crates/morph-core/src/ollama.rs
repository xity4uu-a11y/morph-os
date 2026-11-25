use crate::error::MorphError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum bytes read from a local HTTP/1.1 response to prevent unbounded memory growth.
const DEFAULT_HTTP_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Parsed HTTP/1.1 endpoint descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub host: String,
    pub port: u16,
    pub base_path: String,
}

impl ParsedUrl {
    /// Parses an `http://host[:port][/path]` URL without external crates.
    pub fn parse_http(url: &str) -> Result<Self, MorphError> {
        let trimmed = url.trim();
        let rest = trimmed.strip_prefix("http://").ok_or_else(|| {
            MorphError::UpstreamError(format!(
                "unsupported URL scheme in '{trimmed}' (only local http:// is supported by morph-os)"
            ))
        })?;

        let (authority, path_part) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, ""),
        };

        if authority.is_empty() {
            return Err(MorphError::UpstreamError(format!(
                "missing host in URL '{trimmed}'"
            )));
        }

        let (host, port) = if let Some(bracket_end) = authority.find(']') {
            if !authority.starts_with('[') {
                return Err(MorphError::UpstreamError(format!(
                    "malformed IPv6 authority '{authority}'"
                )));
            }
            let h = authority[1..bracket_end].to_string();
            let after = &authority[bracket_end + 1..];
            let p = if let Some(port_str) = after.strip_prefix(':') {
                port_str.parse::<u16>().map_err(|_| {
                    MorphError::UpstreamError(format!("invalid port in '{authority}'"))
                })?
            } else if after.is_empty() {
                80
            } else {
                return Err(MorphError::UpstreamError(format!(
                    "malformed IPv6 port in '{authority}'"
                )));
            };
            (h, p)
        } else if let Some((h, p_str)) = authority.rsplit_once(':') {
            let p = p_str.parse::<u16>().map_err(|_| {
                MorphError::UpstreamError(format!("invalid port in '{authority}'"))
            })?;
            (h.to_string(), p)
        } else {
            (authority.to_string(), 80)
        };

        let base_path = path_part.trim_end_matches('/').to_string();
        Ok(Self {
            host,
            port,
            base_path,
        })
    }

    /// Returns true if and only if the host is strictly a loopback address.
    pub fn is_loopback(&self) -> bool {
        let h = self.host.to_ascii_lowercase();
        h == "127.0.0.1" || h == "localhost" || h == "::1"
    }

    pub fn socket_addr_string(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn host_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Raw HTTP/1.1 response captured over a pure-Tokio TcpStream.
#[derive(Debug, Clone)]
pub struct RawHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawHttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Sends a pure-Tokio HTTP/1.1 request with timeout, header forwarding, chunked decoding, and byte cap.
pub async fn send_http1_request(
    parsed: &ParsedUrl,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
    timeout_ms: u64,
    max_response_bytes: usize,
) -> Result<RawHttpResponse, MorphError> {
    let target = parsed.socket_addr_string();
    let timeout_dur = Duration::from_millis(timeout_ms.max(50));

    let fut = async {
        let mut stream = TcpStream::connect(&target)
            .await
            .map_err(|e| MorphError::UpstreamError(format!("connect to {target} failed: {e}")))?;

        let full_path = if parsed.base_path.is_empty() {
            if path_and_query.starts_with('/') {
                path_and_query.to_string()
            } else {
                format!("/{path_and_query}")
            }
        } else if path_and_query.starts_with('/') {
            format!("{}{}", parsed.base_path, path_and_query)
        } else {
            format!("{}/{}", parsed.base_path, path_and_query)
        };

        let mut req_buf = Vec::with_capacity(256 + body.len());
        req_buf.extend_from_slice(format!("{method} {full_path} HTTP/1.1\r\n").as_bytes());
        req_buf.extend_from_slice(format!("Host: {}\r\n", parsed.host_header()).as_bytes());
        req_buf.extend_from_slice(b"Connection: close\r\n");

        let mut has_content_length = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host")
                || k.eq_ignore_ascii_case("connection")
                || k.eq_ignore_ascii_case("transfer-encoding")
                || k.eq_ignore_ascii_case("accept-encoding")
            {
                continue;
            }
            if k.eq_ignore_ascii_case("content-length") {
                has_content_length = true;
            }
            let clean_k = k.replace(['\r', '\n'], "");
            let clean_v = v.replace(['\r', '\n'], "");
            req_buf.extend_from_slice(format!("{clean_k}: {clean_v}\r\n").as_bytes());
        }
        if !has_content_length && !body.is_empty() {
            req_buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        req_buf.extend_from_slice(b"\r\n");
        req_buf.extend_from_slice(body);

        stream
            .write_all(&req_buf)
            .await
            .map_err(|e| MorphError::UpstreamError(format!("write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| MorphError::UpstreamError(format!("flush failed: {e}")))?;

        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| MorphError::UpstreamError(format!("read failed: {e}")))?;
            if n == 0 {
                break;
            }
            if raw.len().saturating_add(n) > max_response_bytes {
                return Err(MorphError::BufferLimitExceeded {
                    limit_bytes: max_response_bytes,
                    observed_bytes: raw.len().saturating_add(n),
                });
            }
            raw.extend_from_slice(&chunk[..n]);
        }

        parse_http1_response(&raw)
    };

    tokio::time::timeout(timeout_dur, fut).await.map_err(|_| MorphError::Timeout {
        operation: format!("http1 {method} {target}"),
        timeout_ms,
    })?
}

fn parse_http1_response(raw: &[u8]) -> Result<RawHttpResponse, MorphError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| MorphError::UpstreamError("incomplete HTTP/1.1 response headers".into()))?;

    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| MorphError::UpstreamError("empty HTTP status line".into()))?;

    let mut status_parts = status_line.split_whitespace();
    let _http_ver = status_parts.next();
    let status_code = status_parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            MorphError::UpstreamError(format!("invalid HTTP status line: '{status_line}'"))
        })?;

    let mut headers = Vec::new();
    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().ok();
            }
            headers.push((key, val));
        }
    }

    let raw_body = &raw[header_end + 4..];
    let body = if is_chunked {
        decode_chunked_body(raw_body)?
    } else if let Some(len) = content_length {
        raw_body[..raw_body.len().min(len)].to_vec()
    } else {
        raw_body.to_vec()
    };

    Ok(RawHttpResponse {
        status: status_code,
        headers,
        body,
    })
}

fn decode_chunked_body(input: &[u8]) -> Result<Vec<u8>, MorphError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < input.len() {
        let line_end = input[cursor..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| MorphError::UpstreamError("malformed chunked size line".into()))?;
        let size_str = std::str::from_utf8(&input[cursor..cursor + line_end])
            .map_err(|_| MorphError::UpstreamError("invalid UTF-8 in chunk size".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| MorphError::UpstreamError(format!("invalid chunk size '{size_str}'")))?;
        cursor += line_end + 2;
        if chunk_size == 0 {
            break;
        }
        if cursor + chunk_size > input.len() {
            return Err(MorphError::UpstreamError(
                "truncated chunked transfer payload".into(),
            ));
        }
        out.extend_from_slice(&input[cursor..cursor + chunk_size]);
        cursor += chunk_size;
        if input.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        }
    }
    Ok(out)
}

/// Strictly loopback-only local Ollama HTTP/1.1 client (`127.0.0.1` / `localhost` / `[::1]`).
#[derive(Debug, Clone)]
pub struct OllamaClient {
    endpoint: ParsedUrl,
    base_url: String,
    model: String,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OllamaChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OllamaChatRequest {
    model: String,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    messages: Vec<OllamaChatMessage>,
}

#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    message: Option<OllamaChatMessage>,
    response: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Option<Vec<OllamaTagEntry>>,
}

#[derive(Debug, Deserialize)]
struct OllamaTagEntry {
    name: String,
}

impl OllamaClient {
    /// Creates a new local Ollama client, rejecting any non-loopback endpoint.
    pub fn new(base_url: &str, model: &str, timeout_ms: u64) -> Result<Self, MorphError> {
        let parsed = ParsedUrl::parse_http(base_url)?;
        if !parsed.is_loopback() {
            return Err(MorphError::NonLoopbackEndpoint(base_url.to_string()));
        }
        Ok(Self {
            endpoint: parsed,
            base_url: base_url.to_string(),
            model: model.to_string(),
            timeout_ms: timeout_ms.max(200),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Queries `GET /api/tags` on the local Ollama server.
    pub async fn list_models(&self) -> Result<Vec<String>, MorphError> {
        let resp = send_http1_request(
            &self.endpoint,
            "GET",
            "/api/tags",
            &[("Accept".into(), "application/json".into())],
            &[],
            self.timeout_ms,
            DEFAULT_HTTP_MAX_BYTES,
        )
        .await
        .map_err(|e| MorphError::OllamaUnavailable(e.to_string()))?;

        if resp.status < 200 || resp.status >= 300 {
            return Err(MorphError::OllamaUnavailable(format!(
                "GET /api/tags returned HTTP {}",
                resp.status
            )));
        }
        let parsed: OllamaTagsResponse = serde_json::from_slice(&resp.body)?;
        Ok(parsed
            .models
            .unwrap_or_default()
            .into_iter()
            .map(|m| m.name)
            .collect())
    }

    /// Invokes `POST /api/chat` on local Ollama to mutate a payload using a rule prompt.
    pub async fn chat(
        &self,
        system_prompt: &str,
        payload: &str,
        expect_json: bool,
    ) -> Result<String, MorphError> {
        let req_body = OllamaChatRequest {
            model: self.model.clone(),
            stream: false,
            format: if expect_json {
                Some("json".to_string())
            } else {
                None
            },
            messages: vec![
                OllamaChatMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                OllamaChatMessage {
                    role: "user".to_string(),
                    content: payload.to_string(),
                },
            ],
        };

        let bytes = serde_json::to_vec(&req_body)?;
        let resp = send_http1_request(
            &self.endpoint,
            "POST",
            "/api/chat",
            &[
                ("Content-Type".into(), "application/json".into()),
                ("Accept".into(), "application/json".into()),
            ],
            &bytes,
            self.timeout_ms,
            DEFAULT_HTTP_MAX_BYTES,
        )
        .await
        .map_err(|e| MorphError::OllamaUnavailable(e.to_string()))?;

        if resp.status < 200 || resp.status >= 300 {
            let preview = String::from_utf8_lossy(&resp.body);
            return Err(MorphError::OllamaUnavailable(format!(
                "POST /api/chat returned HTTP {}: {}",
                resp.status,
                preview.chars().take(200).collect::<String>()
            )));
        }

        let parsed: OllamaChatResponse = serde_json::from_slice(&resp.body)?;
        let content = parsed
            .message
            .map(|m| m.content)
            .or(parsed.response)
            .ok_or_else(|| {
                MorphError::OllamaUnavailable("Ollama response contained no message content".into())
            })?;

        let trimmed = strip_markdown_fences(content.trim());
        if expect_json {
            let _: Value = serde_json::from_str(&trimmed).map_err(|e| {
                MorphError::OllamaUnavailable(format!(
                    "Ollama output was not valid JSON: {e}"
                ))
            })?;
        }
        Ok(trimmed)
    }
}

fn strip_markdown_fences(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix("```") {
        let without_lang = match rest.find('\n') {
            Some(idx) => &rest[idx + 1..],
            None => rest,
        };
        if let Some(body) = without_lang.strip_suffix("```") {
            return body.trim().to_string();
        }
    }
    raw.to_string()
}

// ============================================================================
// Deterministic Built-In Mutators (Zero-Network, Sub-Millisecond Fallback Core)
// ============================================================================

/// Case conversion style for JSON keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStyle {
    SnakeCase,
    CamelCase,
}

/// Summary of deterministic PII redaction matches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionReport {
    pub emails_redacted: usize,
    pub ipv4_redacted: usize,
    pub ssn_redacted: usize,
    pub cards_redacted: usize,
    pub tokens_redacted: usize,
    pub phones_redacted: usize,
}

impl RedactionReport {
    pub fn total(&self) -> usize {
        self.emails_redacted
            + self.ipv4_redacted
            + self.ssn_redacted
            + self.cards_redacted
            + self.tokens_redacted
            + self.phones_redacted
    }
}

/// Normalizes a column header or key into clean `snake_case`.
pub fn to_snake_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 4);
    let mut prev_was_underscore = true;
    let mut prev_was_lower_or_digit = false;

    for ch in input.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            if ch.is_ascii_uppercase() {
                if prev_was_lower_or_digit && !prev_was_underscore {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
                prev_was_lower_or_digit = false;
                prev_was_underscore = false;
            } else {
                out.push(ch);
                prev_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
                prev_was_underscore = false;
            }
        } else if !prev_was_underscore {
            out.push('_');
            prev_was_underscore = true;
            prev_was_lower_or_digit = false;
        }
    }

    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "field".to_string()
    } else {
        trimmed
    }
}

/// Converts a key into `camelCase`.
pub fn to_camel_case(input: &str) -> String {
    let snake = to_snake_case(input);
    let mut out = String::with_capacity(snake.len());
    let mut upper_next = false;
    for (idx, ch) in snake.chars().enumerate() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next && idx > 0 {
            out.push(ch.to_ascii_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
            upper_next = false;
        }
    }
    out
}

/// Parses a scalar cell string into a typed JSON value (bool, null, integer, float, or string).
pub fn parse_typed_scalar(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("null")
        || trimmed.eq_ignore_ascii_case("n/a")
        || trimmed == "-"
        || trimmed == "--"
    {
        return Value::Null;
    }
    if trimmed.eq_ignore_ascii_case("true") {
        return Value::Bool(true);
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return Value::Bool(false);
    }
    // Preserve leading-zero numeric identifiers (e.g. "00123") as strings unless "0".
    let looks_leading_zero = trimmed.len() > 1
        && trimmed.starts_with('0')
        && trimmed.chars().all(|c| c.is_ascii_digit());
    if !looks_leading_zero {
        if let Ok(i) = trimmed.parse::<i64>() {
            return Value::Number(i.into());
        }
        if let Ok(f) = trimmed.parse::<f64>() {
            if f.is_finite() {
                if let Some(num) = serde_json::Number::from_f64(f) {
                    return Value::Number(num);
                }
            }
        }
    }
    Value::String(trimmed.to_string())
}

fn is_separator_line(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return true;
    }
    t.chars()
        .all(|c| matches!(c, '-' | '=' | '+' | '|' | '_' | ' ' | '\t' | '~' | '*'))
}

fn split_pipe_row(line: &str) -> Vec<String> {
    let trimmed = line.trim().trim_matches('|');
    trimmed
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn split_two_or_more_spaces(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut current = String::new();
    let mut space_run = 0usize;

    for ch in line.trim().chars() {
        if ch == '\t' {
            if !current.is_empty() {
                cols.push(current.trim().to_string());
                current.clear();
            }
            space_run = 0;
        } else if ch == ' ' {
            space_run += 1;
            if space_run >= 2 {
                if !current.is_empty() {
                    cols.push(current.trim().to_string());
                    current.clear();
                }
            } else {
                current.push(' ');
            }
        } else {
            space_run = 0;
            current.push(ch);
        }
    }
    if !current.trim().is_empty() {
        cols.push(current.trim().to_string());
    }
    cols
}

fn detect_column_starts(header_line: &str) -> Vec<usize> {
    let bytes = header_line.as_bytes();
    let mut starts = Vec::new();
    let mut i = 0usize;
    let mut space_run = 2usize; // start of line counts as column boundary
    while i < bytes.len() {
        if bytes[i] == b' ' || bytes[i] == b'\t' {
            space_run += 1;
        } else {
            if space_run >= 2 {
                starts.push(i);
            }
            space_run = 0;
        }
        i += 1;
    }
    starts
}

fn slice_fixed_columns(line: &str, starts: &[usize]) -> Vec<String> {
    let mut cells = Vec::with_capacity(starts.len());
    let len = line.len();
    for (idx, &start) in starts.iter().enumerate() {
        if start >= len {
            cells.push(String::new());
            continue;
        }
        let end = if idx + 1 < starts.len() {
            starts[idx + 1].min(len)
        } else {
            len
        };
        // Ensure char boundaries for UTF-8 safety
        let safe_start = floor_char_boundary(line, start);
        let safe_end = floor_char_boundary(line, end);
        if safe_start <= safe_end {
            cells.push(line[safe_start..safe_end].trim().to_string());
        } else {
            cells.push(String::new());
        }
    }
    cells
}

fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Converts legacy unstructured CLI ASCII tables (pipe-delimited, bordered, tab-separated,
/// or fixed-width multi-space columns) into a strict JSON array of typed objects.
pub fn ascii_table_to_json(input: &str) -> Result<Value, MorphError> {
    let non_empty: Vec<&str> = input
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    if non_empty.is_empty() {
        return Err(MorphError::InvalidInput(
            "empty input cannot be parsed as an ASCII table".into(),
        ));
    }

    // Filter out preamble/banner lines before the header if a table border or pipe block exists,
    // while keeping non-separator lines.
    let content_lines: Vec<&str> = non_empty
        .iter()
        .copied()
        .filter(|l| !is_separator_line(l))
        .collect();

    if content_lines.len() < 2 {
        // Fallback: try key-value parser if there is no multi-row table
        if let Ok(kv) = kv_to_json(input) {
            return Ok(kv);
        }
        return Err(MorphError::InvalidInput(
            "ASCII table requires at least a header row and one data row".into(),
        ));
    }

    // Detect if this is a pipe-delimited table
    let pipe_lines: Vec<&str> = content_lines
        .iter()
        .copied()
        .filter(|l| l.contains('|'))
        .collect();

    let (headers_raw, rows): (Vec<String>, Vec<Vec<String>>) = if pipe_lines.len() >= 2 {
        let hdr = split_pipe_row(pipe_lines[0]);
        let data = pipe_lines[1..].iter().map(|l| split_pipe_row(l)).collect();
        (hdr, data)
    } else {
        // Find the first line that yields >= 2 columns when split by >=2 spaces or tabs
        let header_idx = content_lines
            .iter()
            .position(|l| split_two_or_more_spaces(l).len() >= 2)
            .unwrap_or(0);

        let header_line = content_lines[header_idx];
        let mut hdr = split_two_or_more_spaces(header_line);
        let starts = detect_column_starts(header_line);

        let use_single_space = hdr.len() < 2;
        if use_single_space {
            hdr = header_line
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
        }

        let mut data = Vec::new();
        for &row_line in &content_lines[header_idx + 1..] {
            // Skip footer summary lines like "Total: 4 rows" when they have only 1 column
            if row_line.trim_start().starts_with("Total") && row_line.contains(':') {
                continue;
            }
            let cells = if use_single_space {
                let mut parts: Vec<String> = row_line
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
                if parts.len() > hdr.len() && !hdr.is_empty() {
                    let tail = parts.split_off(hdr.len() - 1).join(" ");
                    parts.push(tail);
                }
                parts
            } else {
                let multi = split_two_or_more_spaces(row_line);
                if multi.len() == hdr.len() {
                    multi
                } else if starts.len() == hdr.len() {
                    slice_fixed_columns(row_line, &starts)
                } else {
                    multi
                }
            };
            if !cells.is_empty() && cells.iter().any(|c| !c.is_empty()) {
                data.push(cells);
            }
        }
        (hdr, data)
    };

    if headers_raw.is_empty() || rows.is_empty() {
        return Err(MorphError::InvalidInput(
            "could not extract columns and rows from ASCII table".into(),
        ));
    }

    let headers: Vec<String> = headers_raw.iter().map(|h| to_snake_case(h)).collect();
    let mut records = Vec::with_capacity(rows.len());

    for row in rows {
        let mut obj = Map::new();
        for (idx, col_name) in headers.iter().enumerate() {
            let cell = row.get(idx).map(|s| s.as_str()).unwrap_or("");
            obj.insert(col_name.clone(), parse_typed_scalar(cell));
        }
        records.push(Value::Object(obj));
    }

    Ok(Value::Array(records))
}

/// Converts unstructured key-value text (`key: value`, `key = value`, optional `[section]` headers)
/// into a strict nested JSON object with typed scalar inference.
pub fn kv_to_json(input: &str) -> Result<Value, MorphError> {
    let mut root = Map::new();
    let mut current_section: Option<String> = None;
    let mut parsed_pairs = 0usize;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') && line.len() > 2 {
            let sec = to_snake_case(&line[1..line.len() - 1]);
            current_section = Some(sec.clone());
            root.entry(sec).or_insert_with(|| Value::Object(Map::new()));
            continue;
        }

        let split = line
            .split_once('=')
            .or_else(|| line.split_once(':'));

        if let Some((k, v)) = split {
            let key = to_snake_case(k);
            let val = parse_typed_scalar(v.trim().trim_matches('"').trim_matches('\''));
            if let Some(sec) = &current_section {
                if let Some(Value::Object(sec_map)) = root.get_mut(sec) {
                    sec_map.insert(key, val);
                }
            } else {
                root.insert(key, val);
            }
            parsed_pairs += 1;
        }
    }

    if parsed_pairs == 0 {
        return Err(MorphError::InvalidInput(
            "no key-value pairs found in input".into(),
        ));
    }

    Ok(Value::Object(root))
}

/// Converts an XML payload into structured JSON using a zero-dependency recursive-descent parser.
/// Handles XML declarations, comments, CDATA, attributes (`@attr`), self-closing tags,
/// entity unescaping, and repeated sibling tags promoted to JSON arrays.
pub fn xml_to_json(input: &str) -> Result<Value, MorphError> {
    let mut parser = XmlParser::new(input);
    parser.skip_prolog()?;
    let (root_name, root_val) = parser.parse_element()?;
    let mut root_obj = Map::new();
    root_obj.insert(to_snake_case(&root_name), root_val);
    Ok(Value::Object(root_obj))
}

struct XmlParser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> XmlParser<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, pos: 0 }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.rest().chars().next() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn skip_prolog(&mut self) -> Result<(), MorphError> {
        loop {
            self.skip_ws();
            if self.rest().starts_with("<?") {
                let end = self
                    .rest()
                    .find("?>")
                    .ok_or_else(|| MorphError::InvalidInput("unclosed XML declaration".into()))?;
                self.pos += end + 2;
            } else if self.rest().starts_with("<!--") {
                let end = self
                    .rest()
                    .find("-->")
                    .ok_or_else(|| MorphError::InvalidInput("unclosed XML comment".into()))?;
                self.pos += end + 3;
            } else if self.rest().starts_with("<!DOCTYPE") {
                let end = self
                    .rest()
                    .find('>')
                    .ok_or_else(|| MorphError::InvalidInput("unclosed XML DOCTYPE".into()))?;
                self.pos += end + 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn read_name(&mut self) -> Result<String, MorphError> {
        let start = self.pos;
        while let Some(ch) = self.rest().chars().next() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | '.') {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(MorphError::InvalidInput(format!(
                "expected XML identifier at byte offset {}",
                self.pos
            )));
        }
        Ok(self.src[start..self.pos].to_string())
    }

    fn parse_element(&mut self) -> Result<(String, Value), MorphError> {
        self.skip_prolog()?;
        if !self.rest().starts_with('<') {
            return Err(MorphError::InvalidInput(format!(
                "expected '<' at byte offset {}",
                self.pos
            )));
        }
        self.pos += 1;
        let tag_name = self.read_name()?;
        let mut attrs: Vec<(String, String)> = Vec::new();

        loop {
            self.skip_ws();
            if self.rest().starts_with("/>") {
                self.pos += 2;
                return Ok((tag_name, build_xml_value(attrs, Vec::new(), String::new())));
            }
            if self.rest().starts_with('>') {
                self.pos += 1;
                break;
            }
            if self.rest().is_empty() {
                return Err(MorphError::InvalidInput(format!(
                    "unclosed start tag <{tag_name}>"
                )));
            }
            let attr_name = self.read_name()?;
            self.skip_ws();
            if !self.rest().starts_with('=') {
                return Err(MorphError::InvalidInput(format!(
                    "expected '=' after attribute '{attr_name}'"
                )));
            }
            self.pos += 1;
            self.skip_ws();
            let quote = self.rest().chars().next().ok_or_else(|| {
                MorphError::InvalidInput(format!("expected quote for attribute '{attr_name}'"))
            })?;
            if quote != '"' && quote != '\'' {
                return Err(MorphError::InvalidInput(format!(
                    "invalid quote '{quote}' for attribute '{attr_name}'"
                )));
            }
            self.pos += 1;
            let val_end = self.rest().find(quote).ok_or_else(|| {
                MorphError::InvalidInput(format!("unclosed attribute value for '{attr_name}'"))
            })?;
            let raw_val = &self.rest()[..val_end];
            self.pos += val_end + 1;
            attrs.push((attr_name, decode_xml_entities(raw_val)));
        }

        let mut children: Vec<(String, Value)> = Vec::new();
        let mut text_acc = String::new();

        loop {
            if self.rest().is_empty() {
                return Err(MorphError::InvalidInput(format!(
                    "missing closing tag </{tag_name}>"
                )));
            }
            if self.rest().starts_with("<!--") {
                let end = self
                    .rest()
                    .find("-->")
                    .ok_or_else(|| MorphError::InvalidInput("unclosed XML comment".into()))?;
                self.pos += end + 3;
            } else if self.rest().starts_with("<![CDATA[") {
                self.pos += 9;
                let end = self
                    .rest()
                    .find("]]>")
                    .ok_or_else(|| MorphError::InvalidInput("unclosed CDATA section".into()))?;
                text_acc.push_str(&self.rest()[..end]);
                self.pos += end + 3;
            } else if self.rest().starts_with("</") {
                self.pos += 2;
                let close_name = self.read_name()?;
                self.skip_ws();
                if !self.rest().starts_with('>') {
                    return Err(MorphError::InvalidInput(format!(
                        "expected '>' closing </{close_name}>"
                    )));
                }
                self.pos += 1;
                if close_name != tag_name {
                    return Err(MorphError::InvalidInput(format!(
                        "mismatched closing tag: expected </{tag_name}>, got </{close_name}>"
                    )));
                }
                break;
            } else if self.rest().starts_with('<') {
                let child = self.parse_element()?;
                children.push(child);
            } else {
                let next_lt = self.rest().find('<').unwrap_or(self.rest().len());
                let raw_text = &self.rest()[..next_lt];
                text_acc.push_str(&decode_xml_entities(raw_text));
                self.pos += next_lt;
            }
        }

        Ok((tag_name, build_xml_value(attrs, children, text_acc)))
    }
}

fn build_xml_value(
    attrs: Vec<(String, String)>,
    children: Vec<(String, Value)>,
    text: String,
) -> Value {
    let trimmed_text = text.trim();
    if attrs.is_empty() && children.is_empty() {
        return if trimmed_text.is_empty() {
            Value::Null
        } else {
            parse_typed_scalar(trimmed_text)
        };
    }

    let mut obj = Map::new();
    for (k, v) in attrs {
        obj.insert(format!("@{}", to_snake_case(&k)), parse_typed_scalar(&v));
    }
    for (child_name, child_val) in children {
        let key = to_snake_case(&child_name);
        match obj.get_mut(&key) {
            Some(Value::Array(arr)) => arr.push(child_val),
            Some(existing) => {
                let prev = std::mem::replace(existing, Value::Null);
                *existing = Value::Array(vec![prev, child_val]);
            }
            None => {
                obj.insert(key, child_val);
            }
        }
    }
    if !trimmed_text.is_empty() {
        obj.insert("text".to_string(), parse_typed_scalar(trimmed_text));
    }
    Value::Object(obj)
}

fn decode_xml_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp_idx) = rest.find('&') {
        out.push_str(&rest[..amp_idx]);
        rest = &rest[amp_idx + 1..];
        if let Some(semi_idx) = rest.find(';') {
            let entity = &rest[..semi_idx];
            match entity {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                num if num.starts_with("#x") || num.starts_with("#X") => {
                    if let Ok(code) = u32::from_str_radix(&num[2..], 16) {
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                        }
                    }
                }
                num if num.starts_with('#') => {
                    if let Ok(code) = num[1..].parse::<u32>() {
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                        }
                    }
                }
                other => {
                    out.push('&');
                    out.push_str(other);
                    out.push(';');
                }
            }
            rest = &rest[semi_idx + 1..];
        } else {
            out.push('&');
            break;
        }
    }
    out.push_str(rest);
    out
}

/// Extracts an HTML `<table>` snippet into a strict JSON array of typed objects.
pub fn html_table_to_json(input: &str) -> Result<Value, MorphError> {
    let lower = input.to_ascii_lowercase();
    let mut rows: Vec<(bool, Vec<String>)> = Vec::new();
    let mut cursor = 0usize;

    while let Some(tr_rel) = lower[cursor..].find("<tr") {
        let tr_start = cursor + tr_rel;
        let Some(tr_open_end_rel) = lower[tr_start..].find('>') else {
            break;
        };
        let content_start = tr_start + tr_open_end_rel + 1;
        let Some(tr_close_rel) = lower[content_start..].find("</tr>") else {
            break;
        };
        let row_slice = &input[content_start..content_start + tr_close_rel];
        let row_lower = &lower[content_start..content_start + tr_close_rel];

        let mut cells = Vec::new();
        let mut is_header_row = false;
        let mut cell_cursor = 0usize;

        while cell_cursor < row_lower.len() {
            let next_th = row_lower[cell_cursor..].find("<th");
            let next_td = row_lower[cell_cursor..].find("<td");
            let (is_th, rel) = match (next_th, next_td) {
                (Some(a), Some(b)) if a < b => (true, a),
                (Some(a), None) => (true, a),
                (_, Some(b)) => (false, b),
                (None, None) => break,
            };
            if is_th {
                is_header_row = true;
            }
            let c_start = cell_cursor + rel;
            let Some(gt_rel) = row_lower[c_start..].find('>') else {
                break;
            };
            let inner_start = c_start + gt_rel + 1;
            let close_tag = if is_th { "</th>" } else { "</td>" };
            let Some(close_rel) = row_lower[inner_start..].find(close_tag) else {
                break;
            };
            let raw_cell = &row_slice[inner_start..inner_start + close_rel];
            let cleaned = decode_xml_entities(&strip_html_tags(raw_cell))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            cells.push(cleaned);
            cell_cursor = inner_start + close_rel + close_tag.len();
        }

        if !cells.is_empty() {
            rows.push((is_header_row, cells));
        }
        cursor = content_start + tr_close_rel + 5;
    }

    if rows.is_empty() {
        return Err(MorphError::InvalidInput(
            "no HTML table rows (<tr>/<th>/<td>) found".into(),
        ));
    }

    let (headers, data_rows) = if rows[0].0 || rows.len() >= 2 {
        let hdrs: Vec<String> = rows[0].1.iter().map(|h| to_snake_case(h)).collect();
        (hdrs, &rows[1..])
    } else {
        let hdrs: Vec<String> = (0..rows[0].1.len()).map(|i| format!("col_{i}")).collect();
        (hdrs, &rows[..])
    };

    let mut out = Vec::with_capacity(data_rows.len());
    for (_, cells) in data_rows {
        let mut obj = Map::new();
        for (idx, key) in headers.iter().enumerate() {
            let val = cells.get(idx).map(|s| s.as_str()).unwrap_or("");
            obj.insert(key.clone(), parse_typed_scalar(val));
        }
        out.push(Value::Object(obj));
    }

    Ok(Value::Array(out))
}

fn strip_html_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Recursively translates JSON schema fields: renames keys, converts casing (`snake_case` <-> `camelCase`),
/// drops deprecated fields, and injects metadata fields at the root object level.
pub fn rename_json_fields(
    value: &Value,
    mappings: &BTreeMap<String, String>,
    case_style: Option<CaseStyle>,
    drop_fields: &[String],
    add_fields: &BTreeMap<String, Value>,
) -> Value {
    let mut transformed = transform_json_node(value, mappings, case_style, drop_fields);
    if !add_fields.is_empty() {
        if let Value::Object(ref mut map) = transformed {
            for (k, v) in add_fields {
                map.insert(k.clone(), v.clone());
            }
        }
    }
    transformed
}

fn transform_json_node(
    value: &Value,
    mappings: &BTreeMap<String, String>,
    case_style: Option<CaseStyle>,
    drop_fields: &[String],
) -> Value {
    match value {
        Value::Object(map) => {
            let mut next = Map::with_capacity(map.len());
            for (k, v) in map {
                if drop_fields.iter().any(|d| d == k) {
                    continue;
                }
                let mapped = mappings.get(k).cloned().unwrap_or_else(|| match case_style {
                    Some(CaseStyle::SnakeCase) => to_snake_case(k),
                    Some(CaseStyle::CamelCase) => to_camel_case(k),
                    None => k.clone(),
                });
                let child = transform_json_node(v, mappings, case_style, drop_fields);
                next.insert(mapped, child);
            }
            Value::Object(next)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| transform_json_node(item, mappings, case_style, drop_fields))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Deterministic zero-dependency PII scanner & redactor for streams, logs, and API payloads.
/// Redacts emails, IPv4 addresses, US SSNs, Luhn-valid payment card numbers, bearer/API tokens,
/// and North American phone numbers.
pub fn redact_pii(input: &str) -> (String, RedactionReport) {
    let mut report = RedactionReport::default();
    let step1 = redact_bearer_and_api_tokens(input, &mut report);
    let step2 = redact_emails(&step1, &mut report);
    let step3 = redact_ssn(&step2, &mut report);
    let step4 = redact_cards(&step3, &mut report);
    let step5 = redact_ipv4(&step4, &mut report);
    let step6 = redact_phones(&step5, &mut report);
    (step6, report)
}

fn redact_bearer_and_api_tokens(input: &str, report: &mut RedactionReport) -> String {
    let prefixes = ["sk_live_", "sk_test_", "ghp_", "gho_", "xoxb-", "AIza"];
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        // Handle "Bearer <token>"
        if input[i..].starts_with("Bearer ") {
            let tok_start = i + 7;
            let mut tok_end = tok_start;
            while tok_end < bytes.len() && is_token_char(bytes[tok_end]) {
                tok_end += 1;
            }
            if tok_end - tok_start >= 12 {
                out.push_str("Bearer [REDACTED:TOKEN]");
                report.tokens_redacted += 1;
                i = tok_end;
                continue;
            }
        }

        let mut matched_prefix = false;
        for prefix in prefixes {
            if input[i..].starts_with(prefix) {
                let mut end = i + prefix.len();
                while end < bytes.len() && is_token_char(bytes[end]) {
                    end += 1;
                }
                if end - i >= prefix.len() + 8 {
                    out.push_str("[REDACTED:API_KEY]");
                    report.tokens_redacted += 1;
                    i = end;
                    matched_prefix = true;
                    break;
                }
            }
        }
        if matched_prefix {
            continue;
        }

        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')
}

fn redact_emails(input: &str, report: &mut RedactionReport) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if is_email_local_char(bytes[i]) {
            let start = i;
            let mut j = i;
            while j < bytes.len() && is_email_local_char(bytes[j]) {
                j += 1;
            }
            if j > start && j < bytes.len() && bytes[j] == b'@' {
                let domain_start = j + 1;
                let mut k = domain_start;
                while k < bytes.len() && is_email_domain_char(bytes[k]) {
                    k += 1;
                }
                let domain = &input[domain_start..k];
                if domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && domain.rsplit('.').next().map(|tld| tld.len() >= 2).unwrap_or(false)
                {
                    out.push_str("[REDACTED:EMAIL]");
                    report.emails_redacted += 1;
                    i = k;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn is_email_local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_email_domain_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
}

fn redact_ssn(input: &str, report: &mut RedactionReport) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if i + 11 <= bytes.len() {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let next_ok = i + 11 == bytes.len() || !bytes[i + 11].is_ascii_digit();
            let s = &bytes[i..i + 11];
            if prev_ok
                && next_ok
                && s[0..3].iter().all(u8::is_ascii_digit)
                && s[3] == b'-'
                && s[4..6].iter().all(u8::is_ascii_digit)
                && s[6] == b'-'
                && s[7..11].iter().all(u8::is_ascii_digit)
            {
                out.push_str("[REDACTED:SSN]");
                report.ssn_redacted += 1;
                i += 11;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_cards(input: &str, report: &mut RedactionReport) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_digit()) {
            let mut j = i;
            let mut digits = Vec::new();
            while j < bytes.len() {
                if bytes[j].is_ascii_digit() {
                    digits.push(bytes[j] - b'0');
                    j += 1;
                } else if (bytes[j] == b'-' || bytes[j] == b' ')
                    && j + 1 < bytes.len()
                    && bytes[j + 1].is_ascii_digit()
                {
                    j += 1;
                } else {
                    break;
                }
            }
            if (13..=19).contains(&digits.len()) && luhn_valid(&digits) {
                out.push_str("[REDACTED:CARD]");
                report.cards_redacted += 1;
                i = j;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn luhn_valid(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = d as u32;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn redact_ipv4(input: &str, report: &mut RedactionReport) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric()) {
            let mut j = i;
            let mut octets = 0usize;
            let mut valid = true;
            while octets < 4 {
                let oct_start = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() && j - oct_start < 3 {
                    j += 1;
                }
                if j == oct_start {
                    valid = false;
                    break;
                }
                let part = &input[oct_start..j];
                if part.parse::<u8>().is_err() {
                    valid = false;
                    break;
                }
                octets += 1;
                if octets < 4 {
                    if j < bytes.len() && bytes[j] == b'.' {
                        j += 1;
                    } else {
                        valid = false;
                        break;
                    }
                }
            }
            let boundary_ok = j == bytes.len()
                || (!bytes[j].is_ascii_alphanumeric() && bytes[j] != b'.');
            if valid && octets == 4 && boundary_ok {
                let candidate = &input[i..j];
                // Preserve loopback addresses used for local diagnostics
                if candidate != "127.0.0.1" {
                    out.push_str("[REDACTED:IPV4]");
                    report.ipv4_redacted += 1;
                    i = j;
                    continue;
                }
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn redact_phones(input: &str, report: &mut RedactionReport) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while i < bytes.len() {
        if i + 12 <= bytes.len() {
            let prev_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
            let next_ok = i + 12 == bytes.len() || !bytes[i + 12].is_ascii_digit();
            let s = &bytes[i..i + 12];
            if prev_ok
                && next_ok
                && s[0..3].iter().all(u8::is_ascii_digit)
                && (s[3] == b'-' || s[3] == b'.')
                && s[4..7].iter().all(u8::is_ascii_digit)
                && s[7] == s[3]
                && s[8..12].iter().all(u8::is_ascii_digit)
            {
                out.push_str("[REDACTED:PHONE]");
                report.phones_redacted += 1;
                i += 12;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Serializes a JSON value (array of objects or single object) into RFC 4180 CSV.
pub fn json_to_csv(value: &Value) -> Result<String, MorphError> {
    let rows: Vec<&Map<String, Value>> = match value {
        Value::Array(items) => items.iter().filter_map(Value::as_object).collect(),
        Value::Object(map) => vec![map],
        _ => {
            return Err(MorphError::SerializationError(
                "CSV serialization requires a JSON object or array of objects".into(),
            ))
        }
    };

    if rows.is_empty() {
        return Ok(String::new());
    }

    let mut columns: Vec<String> = Vec::new();
    for row in &rows {
        for key in row.keys() {
            if !columns.contains(key) {
                columns.push(key.clone());
            }
        }
    }

    let mut out = String::new();
    out.push_str(
        &columns
            .iter()
            .map(|c| csv_escape(c))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');

    for row in rows {
        let line: Vec<String> = columns
            .iter()
            .map(|col| {
                let cell = match row.get(col) {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => other.to_string(),
                };
                csv_escape(&cell)
            })
            .collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }

    Ok(out)
}

fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Serializes a JSON array into newline-delimited JSON (NDJSON), or a single object as one line.
pub fn json_to_ndjson(value: &Value) -> Result<String, MorphError> {
    match value {
        Value::Array(items) => {
            let mut lines = Vec::with_capacity(items.len());
            for item in items {
                lines.push(serde_json::to_string(item)?);
            }
            Ok(lines.join("\n"))
        }
        other => Ok(serde_json::to_string(other)?),
    }
}

/// Computes a hex-encoded SHA-256 digest of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}
