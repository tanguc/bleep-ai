use std::ops::Range;

/// record of a single replacement — forward map entry for de-anonymization
pub struct Redaction {
    /// rule that triggered this replacement
    pub rule_id: String,
    /// top-level taxonomy category (secret, pii, infra)
    pub category: String,
    /// subcategory (e.g. "email", "aws", "github")
    pub subcategory: String,
    /// severity level from the rule (low, medium, high, critical)
    pub severity: String,
    /// UTF-8 lossy decode of the original matched bytes — audit log only, never sent externally
    pub original: String,
    /// substituted fake value written into body — safe for event bus and TUI display
    pub fake: String,
    /// byte position in the original body before any splicing
    pub span: Range<usize>,
}
