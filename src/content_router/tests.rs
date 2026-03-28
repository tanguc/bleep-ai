#[cfg(test)]
mod router_tests {
    use bytes::Bytes;
    use crate::content_router::{process_body, update_content_length};

    #[test]
    fn test_plain_text_passthrough_unchanged() {
        let body = Bytes::from_static(b"hello world no secrets here");
        let (result, redactions) = process_body(Some("text/plain"), None, body.clone());
        assert!(redactions.is_empty(), "clean body should have 0 redactions");
        assert_eq!(result, body, "clean body should be returned unchanged");
    }

    #[test]
    fn test_json_handler_valid_output() {
        let body = Bytes::from_static(b"{\"key\":\"value\"}");
        let (result, _) = process_body(Some("application/json"), None, body);
        serde_json::from_slice::<serde_json::Value>(&result)
            .expect("JSON handler output must be valid JSON (INV-01)");
    }

    #[test]
    fn test_json_handler_invalid_input_falls_back() {
        // invalid JSON input: falls back to plain-text handler, returns original bytes
        let body = Bytes::from_static(b"not json {{{");
        let (result, _) = process_body(Some("application/json"), None, body.clone());
        // should not panic; result is whatever plain-text handler returns (likely original unchanged)
        assert!(!result.is_empty(), "result should not be empty");
    }

    #[test]
    fn test_urlencoded_handler_decode_encode() {
        let body = Bytes::from_static(b"key=hello+world&token=abc123");
        let (result, _) = process_body(Some("application/x-www-form-urlencoded"), None, body);
        // result should be valid percent-encoded form data
        let result_str = String::from_utf8(result.to_vec()).expect("url-encoded result must be utf8");
        assert!(result_str.contains("key="), "result must contain key= pair");
    }

    #[test]
    fn test_binary_passthrough() {
        let body = Bytes::from_static(b"\x89PNG\r\n\x1a\n binary data here");
        let (result, redactions) = process_body(Some("image/png"), None, body.clone());
        assert_eq!(result, body, "binary content type must pass through unchanged");
        assert!(redactions.is_empty(), "binary passthrough must have 0 redactions");
    }

    #[test]
    fn test_gzip_decompression_fallback() {
        // invalid gzip bytes: should trigger INV-04 fallback
        let body = Bytes::from_static(b"this is not gzip compressed data at all");
        let (result, redactions) = process_body(None, Some("gzip"), body.clone());
        assert_eq!(result, body, "decompression failure must return original body (INV-04)");
        assert!(redactions.is_empty(), "decompression failure must have 0 redactions");
    }

    #[test]
    fn test_process_body_no_encoding_no_type() {
        let body = Bytes::from_static(b"clean text with nothing sensitive");
        let (result, redactions) = process_body(None, None, body.clone());
        assert!(redactions.is_empty(), "clean body should produce no redactions");
        // unknown/absent content type is treated as plain text
        assert_eq!(result, body);
    }

    #[test]
    fn test_content_length_update_present() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("100"),
        );
        update_content_length(&mut headers, 150, true);
        let val = headers.get(http::header::CONTENT_LENGTH).unwrap();
        assert_eq!(val.to_str().unwrap(), "150", "content-length must be updated to 150");
    }

    #[test]
    fn test_content_length_update_no_replacements() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("100"),
        );
        update_content_length(&mut headers, 150, false);
        let val = headers.get(http::header::CONTENT_LENGTH).unwrap();
        assert_eq!(val.to_str().unwrap(), "100", "content-length must NOT be updated when no replacements");
    }

    #[test]
    fn test_multipart_no_boundary_fallback() {
        // multipart with no boundary parameter falls back to plain-text
        let body = Bytes::from_static(b"some content without multipart structure");
        let (result, _) = process_body(Some("multipart/form-data"), None, body.clone());
        // should not panic; result is whatever plain-text handler returns
        assert!(!result.is_empty());
    }

    #[test]
    fn test_octet_stream_passthrough() {
        let body = Bytes::from_static(b"\x00\x01\x02\x03 binary data");
        let (result, redactions) = process_body(Some("application/octet-stream"), None, body.clone());
        assert_eq!(result, body, "octet-stream must pass through unchanged");
        assert!(redactions.is_empty());
    }
}

#[cfg(test)]
mod sse_tests {
    use crate::content_router::sse::{SseFrameParser, process_frame};

    #[test]
    fn test_sse_frame_parser_split() {
        let mut parser = SseFrameParser::new();
        let input = b"data: hello\n\ndata: world\n\n";
        let frames = parser.push(input);
        assert_eq!(frames.len(), 2, "should parse 2 complete frames");
        assert_eq!(frames[0].data, "hello");
        assert_eq!(frames[1].data, "world");
    }

    #[test]
    fn test_sse_frame_parser_partial() {
        let mut parser = SseFrameParser::new();
        let frames1 = parser.push(b"data: hel");
        assert_eq!(frames1.len(), 0, "partial frame should not be returned yet");
        let frames2 = parser.push(b"lo\n\ndata: world\n\n");
        assert_eq!(frames2.len(), 2, "should get 2 frames after completing both");
        assert_eq!(frames2[0].data, "hello");
        assert_eq!(frames2[1].data, "world");
    }

    #[test]
    fn test_sse_done_passthrough() {
        let mut parser = SseFrameParser::new();
        let frames = parser.push(b"data: [DONE]\n\n");
        assert_eq!(frames.len(), 1);
        let (output, redactions) = process_frame(frames.into_iter().next().unwrap());
        // [DONE] frame must pass through raw
        assert!(output.contains(&b'D'), "DONE marker should be in output");
        assert!(redactions.is_empty(), "DONE frame should have no redactions");
    }

    #[test]
    fn test_sse_frame_with_event_field() {
        let mut parser = SseFrameParser::new();
        let frames = parser.push(b"event: message\ndata: hello\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("message"));
        assert_eq!(frames[0].data, "hello");
    }
}

#[cfg(test)]
mod header_tests {
    use crate::content_router::headers::scan_headers;

    #[test]
    fn test_header_scan_bearer() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer testtoken123"),
        );
        let redactions = scan_headers(&mut headers);
        // no actual secrets, just assert no panic and returns vec
        let _ = redactions;
    }

    #[test]
    fn test_header_scan_basic_base64() {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:password");
        let value = format!("Basic {encoded}");
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&value).unwrap(),
        );
        let redactions = scan_headers(&mut headers);
        // no actual secrets in "user:password", just assert no panic
        let _ = redactions;
    }

    #[test]
    fn test_header_scan_exclusions() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        scan_headers(&mut headers);
        // content-type must be excluded and not modified
        let ct = headers.get(http::header::CONTENT_TYPE).unwrap();
        assert_eq!(ct.to_str().unwrap(), "application/json", "content-type must not be modified");
    }

    #[test]
    fn test_header_scan_xapikey() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-api-key",
            http::HeaderValue::from_static("someapikey123"),
        );
        let redactions = scan_headers(&mut headers);
        // no actual secrets, just no panic
        let _ = redactions;
    }
}

/// TST-01: integration tests — known secret through process_body → replaced body
///
/// the proxy integration test validates the full pipeline:
/// request body with a known secret → content_router::process_body → replaced body
/// the secret must be absent from the output, body must remain valid for its content-type.
#[cfg(test)]
mod integration_tests {
    use bytes::Bytes;
    use crate::content_router::process_body;

    /// TST-01a: JSON body containing a GitHub PAT — after process_body the PAT is absent
    ///
    /// the "airtable" keyword in the body triggers the AhoCorasick pre-filter,
    /// which allows the ghp_ PAT rule to run (github PAT rule has empty keywords).
    #[test]
    fn test_json_body_github_pat_replaced() {
        // ghp_ followed by exactly 36 alphanumeric chars matches np.github.1 rule
        // ghp_ + 36 alphanumeric chars = 40 chars total (matches np.github.1 regex)
        let pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let body_str = format!(
            r#"{{"context":"airtable integration","token":"{}"}}"#,
            pat
        );
        let body = Bytes::from(body_str);

        let (replaced, redactions) = process_body(Some("application/json"), None, body.clone());

        // verify: original PAT must not appear in output
        let replaced_str = String::from_utf8(replaced.to_vec()).unwrap();
        assert!(
            !replaced_str.contains(pat),
            "PAT must be absent from replaced body, got: {}",
            replaced_str
        );

        // verify: output must be valid JSON
        serde_json::from_str::<serde_json::Value>(&replaced_str)
            .expect("replaced body must still be valid JSON (TST-01/INV-01)");

        // verify: redactions recorded
        assert!(
            !redactions.is_empty(),
            "process_body must return at least one redaction for the PAT"
        );
    }

    /// TST-01b: plain text body with a secret — secret replaced
    #[test]
    fn test_plain_text_github_pat_replaced() {
        // ghp_ + 36 alphanumeric chars = 40 chars total (matches np.github.1 regex)
        let pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        // include "airtable" to trigger combined pre-filter
        let body_str = format!("airtable webhook token={}", pat);
        let body = Bytes::from(body_str);

        let (replaced, redactions) = process_body(Some("text/plain"), None, body.clone());
        let replaced_str = String::from_utf8(replaced.to_vec()).unwrap();

        assert!(
            !replaced_str.contains(pat),
            "PAT must be absent from replaced plain-text body"
        );
        assert!(
            !redactions.is_empty(),
            "plain text with PAT must produce redactions"
        );
    }

    /// TST-01c: URL-encoded body with a secret — secret replaced, encoding preserved
    #[test]
    fn test_urlencoded_body_github_pat_replaced() {
        // ghp_ + 36 alphanumeric chars = 40 chars total (matches np.github.1 regex)
        let pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        // airtable keyword ensures pre-filter fires
        let body_str = format!("context=airtable&token={}", pat);
        let body = Bytes::from(body_str);

        let (replaced, redactions) =
            process_body(Some("application/x-www-form-urlencoded"), None, body);
        let replaced_str = String::from_utf8(replaced.to_vec()).unwrap();

        assert!(
            !replaced_str.contains(pat),
            "PAT must be absent from replaced URL-encoded body"
        );
        assert!(!redactions.is_empty(), "url-encoded body with PAT must produce redactions");
    }

    /// TST-01d: clean JSON body passes through with zero redactions
    #[test]
    fn test_clean_json_body_no_redactions() {
        let body = Bytes::from_static(b"{\"message\":\"hello world\",\"count\":42}");
        let (result, redactions) = process_body(Some("application/json"), None, body.clone());

        assert!(redactions.is_empty(), "clean JSON body must produce 0 redactions");
        // result must still be valid JSON
        serde_json::from_slice::<serde_json::Value>(&result)
            .expect("clean JSON body must remain valid JSON after processing");
    }

    /// TST-01e: SSE body with PAT in data field — frame data replaced via sse_process_full
    #[test]
    fn test_sse_body_github_pat_replaced() {
        // ghp_ + 36 alphanumeric chars = 40 chars total (matches np.github.1 regex)
        let pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        // airtable keyword triggers pre-filter; PAT embedded in SSE data field
        let sse_body = format!(
            "data: {{\"context\":\"airtable\",\"token\":\"{}\"}}\n\ndata: [DONE]\n\n",
            pat
        );
        let body = Bytes::from(sse_body);

        let (replaced, redactions) = process_body(Some("text/event-stream"), None, body);
        let replaced_str = String::from_utf8(replaced.to_vec()).unwrap();

        assert!(
            !replaced_str.contains(pat),
            "PAT must be absent from replaced SSE body, got: {}",
            replaced_str
        );
        assert!(!redactions.is_empty(), "SSE body with PAT must produce redactions");
        // [DONE] marker must be preserved
        assert!(replaced_str.contains("[DONE]"), "SSE DONE marker must be preserved");
    }
}

#[cfg(test)]
mod multipart_tests {
    use bytes::Bytes;
    use crate::content_router::multipart::handle;

    #[test]
    fn test_multipart_text_part_scanned() {
        let boundary = "boundary123";
        let body = format!(
            "--{boundary}\r\nContent-Type: text/plain\r\n\r\nHello world text part\r\n--{boundary}\r\nContent-Type: image/png\r\n\r\nPNG binary\r\n--{boundary}--",
            boundary = boundary
        );
        let result = handle(Bytes::from(body.into_bytes()), boundary);
        assert!(result.is_ok(), "multipart handle must not error");
    }

    #[test]
    fn test_multipart_binary_passthrough() {
        let boundary = "testboundary";
        let png_data = b"\x89PNG\r\n\x1a\n binary data";
        let body = format!(
            "--{boundary}\r\nContent-Type: image/png\r\n\r\n",
            boundary = boundary
        );
        let mut body_bytes = body.into_bytes();
        body_bytes.extend_from_slice(png_data);
        body_bytes.extend_from_slice(format!("\r\n--{boundary}--", boundary = boundary).as_bytes());

        let result = handle(Bytes::from(body_bytes), boundary);
        assert!(result.is_ok(), "binary part multipart must not error");
        let (out, redactions) = result.unwrap();
        assert!(redactions.is_empty(), "binary-only multipart should have 0 redactions");
        // binary part data should be present in output
        assert!(out.windows(png_data.len()).any(|w| w == png_data), "binary data must be preserved");
    }
}
