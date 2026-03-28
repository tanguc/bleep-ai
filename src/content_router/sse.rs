// SSE (Server-Sent Events) streaming handler
// per-frame processing — does not buffer the full stream
// implements INV-07 architecture (per-frame emit)

use bytes::Bytes;
use crate::replacement::Redaction;

/// single parsed SSE frame
pub struct SseFrame {
    /// event: field (optional)
    pub event: Option<String>,
    /// id: field (optional)
    pub id: Option<String>,
    /// data: field value
    pub data: String,
    /// original raw frame bytes (for passthrough)
    pub raw: Vec<u8>,
}

/// stateful SSE frame parser — buffers bytes until complete frames are available
pub struct SseFrameParser {
    buffer: Vec<u8>,
}

impl SseFrameParser {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    /// push a chunk into the buffer; return any complete frames found
    ///
    /// frames are delimited by b"\n\n".
    /// incomplete frames remain in buffer until next push.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseFrame> {
        self.buffer.extend_from_slice(chunk);
        self.drain_frames()
    }

    /// return remaining buffer content as a final partial frame if non-empty
    pub fn flush(&mut self) -> Option<SseFrame> {
        if self.buffer.is_empty() {
            return None;
        }
        let raw = std::mem::take(&mut self.buffer);
        Some(parse_frame(&raw))
    }

    /// drain all complete frames (delimited by \n\n) from the buffer
    fn drain_frames(&mut self) -> Vec<SseFrame> {
        let mut frames = Vec::new();
        loop {
            // find next \n\n delimiter
            let pos = find_double_newline(&self.buffer);
            match pos {
                None => break,
                Some(end) => {
                    let frame_bytes = self.buffer[..end].to_vec();
                    // advance past \n\n
                    let skip = if end + 2 <= self.buffer.len()
                        && self.buffer[end] == b'\n'
                        && self.buffer[end + 1] == b'\n'
                    {
                        end + 2
                    } else {
                        end + 1
                    };
                    self.buffer.drain(..skip);
                    frames.push(parse_frame(&frame_bytes));
                }
            }
        }
        frames
    }
}

/// process a single SSE frame: scan data field, apply replacement, reassemble
///
/// one dedup map per frame (not per stream) per spec.
/// data: [DONE] passes through unchanged.
pub fn process_frame(frame: SseFrame) -> (Vec<u8>, Vec<Redaction>) {
    // SSE stream end marker: pass through unchanged
    if frame.data.trim() == "[DONE]" {
        return (frame.raw, vec![]);
    }

    // try to parse data field as JSON and route to JSON handler
    // note: json::handle already uses scan_field for isolated string values
    let data_bytes = Bytes::copy_from_slice(frame.data.as_bytes());
    let (replaced_data_bytes, redactions) = if serde_json::from_str::<serde_json::Value>(&frame.data).is_ok() {
        match crate::content_router::json::handle(data_bytes) {
            Ok(pair) => pair,
            Err(_) => {
                // fallback: scan data field as isolated field bytes
                let matches = crate::detection::scan_field(frame.data.as_bytes());
                let d = Bytes::copy_from_slice(frame.data.as_bytes());
                crate::replacement::apply(d, matches)
            }
        }
    } else {
        // plain text data field — scan_field since data is isolated from surrounding context
        let matches = crate::detection::scan_field(frame.data.as_bytes());
        let d = Bytes::copy_from_slice(frame.data.as_bytes());
        crate::replacement::apply(d, matches)
    };

    let replaced_data = String::from_utf8_lossy(&replaced_data_bytes).into_owned();

    // reassemble frame with updated data field
    let mut output = Vec::new();
    if let Some(event) = &frame.event {
        output.extend_from_slice(b"event: ");
        output.extend_from_slice(event.as_bytes());
        output.push(b'\n');
    }
    if let Some(id) = &frame.id {
        output.extend_from_slice(b"id: ");
        output.extend_from_slice(id.as_bytes());
        output.push(b'\n');
    }
    output.extend_from_slice(b"data: ");
    output.extend_from_slice(replaced_data.as_bytes());
    output.push(b'\n');

    (output, redactions)
}

/// convenience function for non-streaming path — processes all frames in a body
pub fn sse_process_full(body: Bytes) -> (Bytes, Vec<Redaction>) {
    let mut parser = SseFrameParser::new();
    let mut frames = parser.push(&body);
    if let Some(last) = parser.flush() {
        frames.push(last);
    }

    let mut output: Vec<u8> = Vec::new();
    let mut all_redactions: Vec<Redaction> = Vec::new();

    for frame in frames {
        let (frame_bytes, mut redactions) = process_frame(frame);
        output.extend_from_slice(&frame_bytes);
        output.extend_from_slice(b"\n\n");
        all_redactions.append(&mut redactions);
    }

    (Bytes::from(output), all_redactions)
}

/// parse raw SSE frame bytes into SseFrame struct
fn parse_frame(raw: &[u8]) -> SseFrame {
    let text = String::from_utf8_lossy(raw);
    let mut event: Option<String> = None;
    let mut id: Option<String> = None;
    let mut data_lines: Vec<&str> = Vec::new();

    for line in text.lines() {
        if let Some(val) = line.strip_prefix("event:") {
            event = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("id:") {
            id = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("data:") {
            data_lines.push(val.trim());
        }
    }

    SseFrame {
        event,
        id,
        data: data_lines.join("\n"),
        raw: raw.to_vec(),
    }
}

/// find position of b"\n\n" or b"\r\n\r\n" in data
fn find_double_newline(data: &[u8]) -> Option<usize> {
    // check for \r\n\r\n first
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 2); // return position of the second \r\n start
    }
    // then \n\n
    data.windows(2).position(|w| w == b"\n\n")
}
