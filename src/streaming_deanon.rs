// streaming_deanon — wrap a hyper body so each frame is deanonymized in
// place as bytes flow through, with a rolling lookahead buffer so fakes
// that span multiple SSE events (the common case with Anthropic's
// per-token streaming) still get replaced.
//
// Why this exists:
//   Anthropic's v1/messages endpoint streams replies as `text/event-stream`,
//   with one `content_block_delta` event per token. A fake email like
//   `rezl0fm@example.org` tokenises as ~7 BPE pieces, so it arrives across
//   7 separate SSE frames. Substring replacement on each frame in isolation
//   never sees the complete fake. We solve that with a delayed-emission
//   rolling buffer: always hold back the last `max_fake_len - 1` bytes so a
//   fake can never sit straddling the boundary between what we've emitted
//   and what's still in the pipe.
//
// How it works:
//   - On every poll, append the incoming chunk to `pending`.
//   - Run substring replacement (fake → original) over the whole `pending`.
//   - Emit `pending[..len - hold_back]` and keep the rest for next time.
//   - `hold_back = max_fake_len - 1` guarantees no in-progress fake gets
//     emitted prematurely, even if it spans an arbitrary number of frames.
//   - On end-of-stream, flush whatever's left.
//
// This intentionally only handles uncompressed bodies — the request handler
// asks the upstream for `Accept-Encoding: gzip;q=0` for that reason. If a
// non-compliant origin sends gzip anyway, we'd need a streaming gzip
// decoder here (not implemented yet).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use hudsucker::hyper::body::{Body, Frame, SizeHint};

use crate::replacement::Redaction;

/// A streaming body wrapper that deanonymizes bytes as they pass through.
pub struct StreamingDeanon<B> {
    inner: B,
    /// fake → original lookup. Built once at construction so per-chunk work
    /// is a single hash lookup per candidate, not a scan of N redactions.
    mapping: Arc<HashMap<String, String>>,
    /// max length of any fake in `mapping`. Sets the size of the lookahead
    /// window we hold back from emission. If `mapping` is empty this is 0
    /// and we degrade to pass-through.
    max_fake_len: usize,
    /// bytes accumulated and corrected but not yet safe to emit (could be
    /// the leading edge of a fake that spans into the next chunk).
    pending: Vec<u8>,
    /// upstream body has signalled end-of-stream; flush `pending` on next poll.
    inner_done: bool,
    /// flush has happened; the next poll returns None.
    flushed: bool,
}

impl<B> StreamingDeanon<B> {
    pub fn new(
        inner: B,
        in_flight: &[Redaction],
        dictionary: &[(String, String)],
    ) -> Self {
        // build a single fake → original map. in_flight wins on conflict —
        // it's the freshest, most authoritative mapping for this request.
        let mut mapping: HashMap<String, String> =
            HashMap::with_capacity(in_flight.len() + dictionary.len());
        let mut max_fake_len = 0usize;
        for (fake, original) in dictionary {
            if fake.is_empty() {
                continue;
            }
            max_fake_len = max_fake_len.max(fake.len());
            mapping.insert(fake.clone(), original.clone());
        }
        for r in in_flight {
            if r.fake.is_empty() {
                continue;
            }
            max_fake_len = max_fake_len.max(r.fake.len());
            mapping.insert(r.fake.clone(), r.original.clone());
        }
        Self {
            inner,
            mapping: Arc::new(mapping),
            max_fake_len,
            pending: Vec::new(),
            inner_done: false,
            flushed: false,
        }
    }
}

/// Walk `bytes` and replace every occurrence of any fake in `mapping` with
/// its original. Exact-byte substitution.
fn deanonymize_in_place(bytes: &[u8], mapping: &HashMap<String, String>) -> Vec<u8> {
    if mapping.is_empty() || bytes.is_empty() {
        return bytes.to_vec();
    }
    let mut result = bytes.to_vec();
    for (fake, original) in mapping {
        let fake_bytes = fake.as_bytes();
        if fake_bytes.is_empty() || result.len() < fake_bytes.len() {
            continue;
        }
        // quick reject: avoid rebuilding the Vec when the fake isn't present.
        if !result.windows(fake_bytes.len()).any(|w| w == fake_bytes) {
            continue;
        }
        let original_bytes = original.as_bytes();
        let mut out = Vec::with_capacity(result.len());
        let mut i = 0;
        while i < result.len() {
            if result[i..].starts_with(fake_bytes) {
                out.extend_from_slice(original_bytes);
                i += fake_bytes.len();
            } else {
                out.push(result[i]);
                i += 1;
            }
        }
        result = out;
    }
    result
}

impl<B> Body for StreamingDeanon<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // 1. terminal state — we've already flushed.
        if self.flushed {
            return Poll::Ready(None);
        }
        // 2. upstream finished and we still owe the client the tail bytes.
        if self.inner_done {
            self.flushed = true;
            if self.pending.is_empty() {
                return Poll::Ready(None);
            }
            // last chance to apply substitutions to bytes we held back.
            let tail = std::mem::take(&mut self.pending);
            let processed = deanonymize_in_place(&tail, &self.mapping);
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(processed)))));
        }

        // 3. pull the next frame from upstream.
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.inner_done = true;
                // re-poll so the inner_done branch above fires this cycle.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Some(Ok(frame))) => {
                // non-data frames (trailers) don't carry body bytes — emit them
                // unchanged so HTTP/2 trailers etc. still reach the client.
                let data = match frame.into_data() {
                    Ok(d) => d,
                    Err(non_data) => return Poll::Ready(Some(Ok(non_data))),
                };
                self.pending.extend_from_slice(&data);

                // run substitutions across the whole pending buffer so a fake
                // that starts in a prior chunk and finishes in this one is
                // caught.
                let corrected = deanonymize_in_place(&self.pending, &self.mapping);
                self.pending = corrected;

                // hold back enough bytes that an in-progress fake can never
                // straddle the boundary between emitted and unemitted bytes.
                // `max_fake_len - 1` is the smallest safe window: a fake of
                // length L needs the L-th byte before being detectable; the
                // L-1 bytes before it are unsafe until we get one more.
                let hold = self.max_fake_len.saturating_sub(1);
                if self.pending.len() <= hold {
                    // not enough buffered to emit anything safely yet — wait
                    // for more input.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let emit_len = self.pending.len() - hold;
                let emitted: Vec<u8> = self.pending.drain(..emit_len).collect();
                if emitted.is_empty() {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(emitted)))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.flushed
    }

    fn size_hint(&self) -> SizeHint {
        // can't predict — substitution may shrink or grow the body.
        SizeHint::default()
    }
}
