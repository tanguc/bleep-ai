# OCR Extensibility Spec

**Purpose:** Specifies how an OCR (Layer 2) content handler integrates with the detection and replacement modules in a future milestone. The detection and replacement modules require zero modifications to support OCR. This document defines how image and PDF handlers plug in, what must stay format-agnostic, what must not leak into core modules, and where OCR hooks into the content router.

---

## 1. Purpose

OCR is not implemented in v1.0 or v1.1. This spec exists to verify that the current architecture can accommodate OCR without architectural backtracking. If detection or replacement need to change to support OCR, the current architecture is wrong.

The constraint: `detection::scan` takes `&[u8]` and returns `Vec<Match>`. `replacement::apply` takes `Bytes` and returns `(Bytes, Vec<Redaction>)`. An OCR handler that extracts text from an image as `Vec<u8>` calls both modules identically to how the HTTP proxy does. Zero changes to the modules.

---

## 2. Core Principle

The detection and replacement modules are format-agnostic by design:

```rust
// detection module public interface:
pub fn scan(body: &[u8]) -> Vec<Match>

// replacement module public interface:
pub fn apply(body: Bytes, matches: Vec<Match>) -> (Bytes, Vec<Redaction>)
```

`&[u8]` works for:
- HTTP request body bytes
- HTTP response body bytes
- Decoded OCR text bytes (UTF-8 from Tesseract output)
- Extracted PDF text bytes

The same `detection::scan` function processes all of these without modification. The same `replacement::apply` function produces fake values for all of them.

---

## 3. OCR Integration Flow

End-to-end flow for a future image body handler:

```
HTTP request body (image/png, image/jpeg, application/pdf)
      |
      v
ocr_handler::extract_text(body_bytes: &[u8]) -> Vec<TextBlock>
where TextBlock { text: String, bbox: Rect, page: u32 }
      |
      | (for each TextBlock)
      v
detection::scan(text_block.text.as_bytes()) -> Vec<Match>
      |
      v
replacement::apply(Bytes::from(text_block.text.as_bytes()), matches)
  -> (replaced_bytes: Bytes, redactions: Vec<Redaction>)
      |
      v
render::overlay_text(
    original_image_bytes,
    text_block.bbox,
    String::from_utf8_lossy(&replaced_bytes).as_ref()
) -> modified_image_bytes
      |
      v
reassembled image bytes forwarded to upstream
```

`detection::scan` and `replacement::apply` are called on each `TextBlock` independently. They are not aware that the bytes came from OCR.

---

## 4. New Modules Needed (Interface Spec Only)

OCR is not implemented in v1.0 or v1.1, but the interface is specced here for future implementers:

**`src/ocr/extractor.rs`**

```rust
pub struct TextBlock {
    pub text: String,
    pub bbox: Rect,       // bounding box in image coordinates
    pub page: u32,        // page number (1-indexed; always 1 for images)
}

pub fn extract_text(body: &[u8], content_type: &str) -> Result<Vec<TextBlock>, OcrError>
```

Takes raw image or PDF bytes, runs OCR (via `leptess` or `tesseract-rs`), returns text blocks with bounding boxes. For PDF files with embedded text (not scanned), uses a text extraction crate (`lopdf` or `pdf-extract`) instead of Tesseract.

**`src/ocr/renderer.rs`**

```rust
pub fn overlay_text(
    image_bytes: &[u8],
    text_block: &TextBlock,
    replacement_text: &str,
) -> Result<Vec<u8>, RenderError>
```

Takes original image bytes, a text block's bounding box, and the replacement text. Renders the replacement text onto the image at the bounding box coordinates, covering the original text. Returns modified image bytes.

Neither `extractor.rs` nor `renderer.rs` imports anything from `detection/` or `replacement/`. They are pure I/O modules. The orchestration (call extract, then scan, then apply, then render) lives in `src/content_router/ocr_handler.rs`.

---

## 5. What Must Stay Format-Agnostic

The following must never be modified to accept HTTP-specific types:

| Module | Constraint |
|--------|-----------|
| `detection::scan(&[u8])` | Must NEVER accept any HTTP-specific type; `&[u8]` works for body bytes and decoded OCR text bytes |
| `replacement::apply(Bytes, Vec<Match>)` | Must NEVER accept any HTTP-specific type |
| `NormalizedRule.replacement_type` | Must be stateless and context-agnostic; same `fake_email()` fn used whether the email appears in JSON body or OCR-extracted text |
| All replacer fns in `replacers.rs` | No HTTP context, no image context, no proxy context |

If a change to detection or replacement is needed to support OCR, it is an architectural error — the fix is to make OCR conform to the existing interface, not to extend the interface.

---

## 6. What Must NOT Leak into detection/replacement

The following types must never appear in `src/detection/` or `src/replacement/` imports or function signatures:

- `hudsucker::HttpContext`
- `axum::body::Body`
- `reqwest::Response`
- `tokio::io` types or async traits
- Any bounding box type (e.g., `Rect`, `BBox`)
- Any page number or coordinate type
- Any image format type (PNG bytes, JPEG bytes, PDF bytes)
- Any async/await — both `scan()` and `apply()` are synchronous

Verification command (run in CI after implementing detection and replacement):
```bash
grep -r "hudsucker\|axum\|reqwest\|tokio::io\|Rect\|bbox\|page_num" src/detection/ src/replacement/
# Expected: zero matches
```

---

## 7. OCR Content-Type Routing Hook

`CONTENT-ROUTING.md` specifies that `image/*`, `audio/*`, `video/*`, and `application/octet-stream` are skipped in v1.0 (passed through unchanged).

In a future OCR milestone, the content router gains an additional branch in the routing decision tree:

```rust
// In content_router routing decision, after step 2:
if content_type.starts_with("image/") || content_type == "application/pdf" {
    #[cfg(feature = "ocr")]
    {
        return ocr_handler::process(body_bytes, content_type).await;
    }
    // Feature flag not enabled: fall through to passthrough
    return Ok(ProcessedBody { bytes: body_bytes, redactions: vec![], content_encoding: None });
}
```

The `#[cfg(feature = "ocr")]` feature flag approach means OCR can be compiled in or out without changing the proxy core. The binary with `--no-default-features` has zero OCR code; the binary with `--features ocr` includes the Tesseract bindings and image processing.

---

## 8. Streaming OCR Consideration

Image and PDF bodies are never streamed via SSE — they arrive as complete request bodies. The OCR handler does not need a streaming counterpart.

This simplifies OCR integration: always buffer, extract, scan, render, return. No frame parser, no partial-body handling.

The full-body buffer path (same as non-streaming request bodies in the proxy) is used for all OCR inputs.

---

## 9. Candidate Crates for Future OCR

Not committed for v1.0 or v1.1. Documented here for future implementers:

| Purpose | Crate | Notes |
|---------|-------|-------|
| OCR (Tesseract bindings) | `leptess` | Mature, actively maintained; wraps Tesseract 4/5 |
| OCR (alternative binding) | `tesseract-rs` | Alternative; less activity than `leptess` |
| PDF text extraction (embedded text) | `lopdf` | Parses PDF structure; extracts embedded text without OCR |
| PDF text extraction (alternative) | `pdf-extract` | Higher-level API; built on `lopdf` |
| Image rendering (text overlay) | `image` + `imageproc` | Standard Rust image stack; `imageproc::drawing::draw_text_mut` |
| Font rendering for overlay | `rusttype` or `ab_glyph` | TrueType font rendering for text overlay on images |

Tesseract (via `leptess`) requires the Tesseract C library installed on the host. This is a system dependency — document it as a build requirement for OCR builds.

---

## 10. Verification that Current Architecture Supports OCR

Run these checks to confirm the current (v1.1) detection and replacement implementations have no proxy-type leakage:

```bash
# no proxy types in detection module:
grep -r "hudsucker\|axum\|reqwest\|tokio::io" src/detection/
# expected: zero matches

# no proxy types in replacement module:
grep -r "hudsucker\|axum\|reqwest\|tokio::io" src/replacement/
# expected: zero matches

# scan() signature uses only std types:
grep "pub fn scan" src/detection/mod.rs
# expected: pub fn scan(body: &[u8]) -> Vec<Match>

# apply() signature uses only bytes types:
grep "pub fn apply" src/replacement/mod.rs
# expected: pub fn apply(body: Bytes, matches: Vec<Match>) -> (Bytes, Vec<Redaction>)
```

If any of these checks fail, the detection or replacement module has leaked proxy-specific types and the OCR extensibility guarantee is broken.

---

## Links

- Detection pipeline (scan() called from OCR flow) — see `docs/arch/DETECTION-PIPELINE.md`
- Replacement pipeline (apply() called from OCR flow) — see `docs/arch/REPLACEMENT-PIPELINE.md`
- Content routing (OCR hook location) — see `docs/arch/CONTENT-ROUTING.md`
