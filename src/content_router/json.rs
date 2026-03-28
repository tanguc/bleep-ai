// json handler — parse -> scan -> replace -> validate -> re-serialize
// implements INV-01: replacement never produces invalid JSON

use bytes::Bytes;
use tracing::{error, warn};
use crate::replacement::Redaction;
use super::{plain, RouterError};

/// handle a JSON body: validate, replace string values, validate output
///
/// if input is invalid JSON: falls back to plain-text handler (still scans raw bytes)
/// if replacement produces invalid JSON: reverts to original bytes (INV-01 safety)
pub fn handle(body: Bytes) -> Result<(Bytes, Vec<Redaction>), RouterError> {
    // step 1: validate input is JSON
    if serde_json::from_slice::<serde_json::Value>(&body).is_err() {
        warn!("[bleep] JSON parse failed, falling back to plain-text handler");
        return plain::handle(body);
    }

    // step 2: walk JSON string values, scan, replace
    let original = body.clone();
    let (replaced, redactions) = crate::replacement::json_replace(body);

    // step 3: validate output is still valid JSON (INV-01 defense-in-depth)
    if serde_json::from_slice::<serde_json::Value>(&replaced).is_err() {
        let rule_id = redactions
            .first()
            .map(|r| r.rule_id.as_str())
            .unwrap_or("unknown");
        error!(
            "[bleep] replacement produced invalid JSON for rule {rule_id}, reverting to original body"
        );
        error!("[bleep] INV-01 violation: replacement produced invalid JSON (rule: {rule_id}), reverting to original body");
        return Ok((original, vec![]));
    }

    Ok((replaced, redactions))
}
