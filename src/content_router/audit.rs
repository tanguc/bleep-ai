// audit log writer — SAF-08: JSONL per-redaction entries
// original values only written to audit log, never to event bus or stdout

use serde::Serialize;
use crate::replacement::Redaction;

/// one audit log entry per redaction event
#[derive(Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub request_id: String,
    pub content_type: String,
    pub rule_id: String,
    /// original matched value — audit log only, never event bus or stdout
    pub original: String,
    pub fake: String,
    pub confidence: String,
    pub span_start: usize,
    pub span_end: usize,
}

/// write audit entries to JSONL log file (append mode)
///
/// creates file if it doesn't exist.
/// each entry written as one JSON line.
pub fn write_audit_entries(
    entries: &[AuditEntry],
    log_path: &std::path::Path,
) -> std::io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    use std::io::Write;
    if let Some(parent) = log_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    for entry in entries {
        let line =
            serde_json::to_string(entry).map_err(|e| std::io::Error::other(e.to_string()))?;
        writeln!(file, "{line}")?;
    }

    Ok(())
}

/// convert redactions to audit entries with request context
pub fn make_audit_entries(
    request_id: &str,
    content_type: &str,
    redactions: &[Redaction],
) -> Vec<AuditEntry> {
    let timestamp = chrono::Utc::now().to_rfc3339();
    redactions
        .iter()
        .map(|r| AuditEntry {
            timestamp: timestamp.clone(),
            request_id: request_id.to_string(),
            content_type: content_type.to_string(),
            rule_id: r.rule_id.clone(),
            original: r.original.clone(),
            fake: r.fake.clone(),
            confidence: String::new(), // populated from Match in Phase 5 when we have the confidence field
            span_start: r.span.start,
            span_end: r.span.end,
        })
        .collect()
}
