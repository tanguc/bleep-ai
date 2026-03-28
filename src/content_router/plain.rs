// plain text handler — raw byte scan + replace, no structural validation
use bytes::Bytes;
use crate::replacement::Redaction;
use super::RouterError;

/// scan and replace raw bytes without any structural parsing
pub fn handle(body: Bytes) -> Result<(Bytes, Vec<Redaction>), RouterError> {
    let matches = crate::detection::scan(&body);
    let (replaced, redactions) = crate::replacement::apply(body, matches);
    Ok((replaced, redactions))
}
