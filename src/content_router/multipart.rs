// multipart/form-data handler — boundary parsing, per-part routing, binary passthrough
use bytes::Bytes;
use crate::replacement::Redaction;
use super::{RouterError, json, plain};

/// handle a multipart/form-data body
///
/// splits body on boundary, routes text parts through scan/replace,
/// binary parts pass through unchanged.
pub fn handle(body: Bytes, boundary: &str) -> Result<(Bytes, Vec<Redaction>), RouterError> {
    let delimiter = format!("--{boundary}");
    let delimiter_bytes = delimiter.as_bytes();
    let final_delimiter = format!("--{boundary}--");
    let final_delimiter_bytes = final_delimiter.as_bytes();

    let body_slice = body.as_ref();

    // find all delimiter positions
    let mut parts: Vec<&[u8]> = Vec::new();
    let mut search_from = 0;

    while search_from < body_slice.len() {
        // find next delimiter
        let pos = find_bytes(body_slice, delimiter_bytes, search_from);
        match pos {
            None => break,
            Some(p) => {
                // check if this is the final delimiter
                if body_slice[p..].starts_with(final_delimiter_bytes) {
                    break;
                }
                // skip past delimiter + optional \r\n
                let part_start = p + delimiter_bytes.len();
                let part_start = skip_crlf(body_slice, part_start);

                // find end of this part (next delimiter)
                let next_delimiter = find_bytes(body_slice, delimiter_bytes, part_start);
                let part_end = match next_delimiter {
                    Some(np) => {
                        // trim trailing \r\n before delimiter
                        if np >= 2 && &body_slice[np - 2..np] == b"\r\n" {
                            np - 2
                        } else if np >= 1 && body_slice[np - 1] == b'\n' {
                            np - 1
                        } else {
                            np
                        }
                    }
                    None => body_slice.len(),
                };

                if part_start < part_end {
                    parts.push(&body_slice[part_start..part_end]);
                }
                search_from = part_start;
            }
        }
    }

    let mut all_redactions: Vec<Redaction> = Vec::new();
    let mut processed_parts: Vec<Vec<u8>> = Vec::with_capacity(parts.len());

    for part in parts {
        // split part into headers + body at first blank line
        let (headers_bytes, part_body) = split_part_headers(part);
        let part_ct = extract_part_content_type(headers_bytes);

        let (replaced_body, mut redactions) = if is_binary_part(&part_ct) {
            // binary: pass through unchanged
            (part_body.to_vec(), vec![])
        } else {
            // text: route to appropriate handler
            let body_bytes = Bytes::copy_from_slice(part_body);
            let result = if part_ct.starts_with("application/json") {
                json::handle(body_bytes)?
            } else {
                plain::handle(body_bytes)?
            };
            (result.0.to_vec(), result.1)
        };

        all_redactions.append(&mut redactions);

        // reassemble part: headers + blank line + body
        let mut reassembled = headers_bytes.to_vec();
        replaced_body.iter().for_each(|b| reassembled.push(*b));
        processed_parts.push(reassembled);
    }

    // reassemble full multipart body
    let mut output: Vec<u8> = Vec::new();
    for part in &processed_parts {
        output.extend_from_slice(delimiter_bytes);
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(part);
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(final_delimiter_bytes);
    output.extend_from_slice(b"--");

    Ok((Bytes::from(output), all_redactions))
}

/// find first occurrence of needle in haystack starting at offset
fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// skip \r\n or \n at position
fn skip_crlf(data: &[u8], pos: usize) -> usize {
    if pos + 1 < data.len() && data[pos] == b'\r' && data[pos + 1] == b'\n' {
        pos + 2
    } else if pos < data.len() && data[pos] == b'\n' {
        pos + 1
    } else {
        pos
    }
}

/// split part bytes into (headers_section_with_blank_line, body_section)
fn split_part_headers(part: &[u8]) -> (&[u8], &[u8]) {
    // find \r\n\r\n or \n\n separator
    if let Some(pos) = find_bytes(part, b"\r\n\r\n", 0) {
        (&part[..pos + 4], &part[pos + 4..])
    } else if let Some(pos) = find_bytes(part, b"\n\n", 0) {
        (&part[..pos + 2], &part[pos + 2..])
    } else {
        // no blank line found — treat entire part as body with no headers
        (b"", part)
    }
}

/// extract Content-Type value from part headers bytes
fn extract_part_content_type(headers_bytes: &[u8]) -> String {
    let headers_str = String::from_utf8_lossy(headers_bytes).to_ascii_lowercase();
    for line in headers_str.lines() {
        if let Some(val) = line.strip_prefix("content-type:") {
            return val.trim().to_string();
        }
    }
    String::new()
}

/// returns true if part content type is binary
fn is_binary_part(ct: &str) -> bool {
    ct.starts_with("image/")
        || ct.starts_with("audio/")
        || ct.starts_with("video/")
        || ct == "application/octet-stream"
}
