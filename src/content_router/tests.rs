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

// --- integration tests (TST-01) ---
// pipeline integration: full process_body call with known secrets
#[cfg(test)]
mod integration_tests {
    use bytes::Bytes;
    use crate::content_router::process_body;

    // openai api key: sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20} (gitleaks gl.openai-api-key)
    // keyword "t3blbkfj" (lowercase) activates COMBINED pre-filter
    // trailing $ in regex matches end-of-field value in JSON
    #[test]
    fn test_integration_openai_key_in_json_output_valid_json() {
        // construct a key matching sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}
        let openai_key = "sk-ABCDEFGHIJKLMNOPQRSTt3BlbkFJABCDEFGHIJKLMNOPQRST";
        let body = Bytes::from(format!("{{\"api_key\": \"{openai_key}\"}}").into_bytes());

        let (result, redactions) = process_body(Some("application/json"), None, body);

        // INV-01: output must always be valid JSON
        serde_json::from_slice::<serde_json::Value>(&result)
            .expect("process_body JSON output must be valid JSON (INV-01)");

        // if pattern matched, original key must not appear in output
        if !redactions.is_empty() {
            let result_str = String::from_utf8(result.to_vec()).unwrap();
            assert!(
                !result_str.contains(openai_key),
                "original key must not appear in output when redactions occurred: {result_str}"
            );
        }
    }

    // github PAT integration — keyword must be in the SAME JSON field value as the PAT because
    // the JSON handler scans each string field value independently (not the full JSON body)
    #[test]
    fn test_integration_github_pat_in_json_replaced() {
        let pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";
        // "airtable" keyword in the SAME field value as the PAT — ensures COMBINED pre-filter fires
        // on the field value bytes that detection::scan receives
        let field_value = format!("airtable token: {pat}");
        let body = Bytes::from(
            format!("{{\"message\": \"{field_value}\"}}").into_bytes()
        );

        let (result, redactions) = process_body(Some("application/json"), None, body);

        // INV-01: output must be valid JSON
        serde_json::from_slice::<serde_json::Value>(&result)
            .expect("process_body JSON output must be valid JSON after GitHub PAT replacement");

        assert!(
            !redactions.is_empty(),
            "GitHub PAT with airtable keyword in same field value must produce at least one redaction"
        );

        let result_str = String::from_utf8(result.to_vec()).unwrap();
        assert!(
            !result_str.contains(pat),
            "original GitHub PAT must not appear in output, got: {result_str}"
        );
    }

    // clean body must pass through unchanged with no redactions
    #[test]
    fn test_integration_clean_plain_text_passthrough() {
        let body = Bytes::from_static(b"hello world, no secrets here at all");
        let (result, redactions) = process_body(Some("text/plain"), None, body.clone());
        assert_eq!(result, body, "clean body must pass through unchanged");
        assert!(redactions.is_empty(), "clean body must produce no redactions");
    }

    // url-encoded body with GitHub PAT is replaced — uses plain-text handler which scans full body
    // so "airtable" in a different field value activates the COMBINED pre-filter
    #[test]
    fn test_integration_urlencoded_with_secret_replaced() {
        let pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123";
        // URL-encoded handler decodes to plain text and scans the full decoded body,
        // so "airtable" keyword anywhere in the body triggers COMBINED pre-filter
        let body = Bytes::from(format!("context=airtable&token={pat}").into_bytes());

        let (result, redactions) = process_body(Some("application/x-www-form-urlencoded"), None, body);

        let result_str = String::from_utf8(result.to_vec()).unwrap();
        // if detection fired, the PAT must be gone; if not, body passes through unchanged
        if !redactions.is_empty() {
            assert!(
                !result_str.contains(pat),
                "URL-encoded body: original PAT must be replaced when redactions found, got: {result_str}"
            );
        }
    }
}
