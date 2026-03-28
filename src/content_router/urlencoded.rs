// url-encoded handler — decode values, scan, replace, re-encode
// implements INV-02 via architecture: scan once on decoded values, apply once

use bytes::Bytes;
use crate::replacement::Redaction;
use super::RouterError;

/// handle application/x-www-form-urlencoded body
///
/// decodes each form value, scans for secrets, replaces, and re-encodes.
/// preserves all keys unchanged; only values are scanned.
pub fn handle(body: Bytes) -> Result<(Bytes, Vec<Redaction>), RouterError> {
    // parse key=value pairs from percent-encoded body
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(body.as_ref())
        .into_owned()
        .collect();

    let mut all_redactions: Vec<Redaction> = Vec::new();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());

    for (key, value) in pairs {
        let value_bytes = Bytes::copy_from_slice(value.as_bytes());
        // use scan_field: decoded form values are context-isolated
        let matches = crate::detection::scan_field(&value_bytes);
        let replaced_value = if matches.is_empty() {
            value
        } else {
            let (replaced_bytes, mut redactions) = crate::replacement::apply(value_bytes, matches);
            all_redactions.append(&mut redactions);
            String::from_utf8_lossy(&replaced_bytes).into_owned()
        };
        serializer.append_pair(&key, &replaced_value);
    }

    let result = serializer.finish();
    Ok((Bytes::from(result), all_redactions))
}
