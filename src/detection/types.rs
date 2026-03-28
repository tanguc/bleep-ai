use std::ops::Range;
use std::sync::Arc;

use crate::types::rule::NormalizedRule;

pub struct Match {
    pub rule: Arc<NormalizedRule>,
    pub span: Range<usize>,
    pub raw: Vec<u8>,
    pub confidence_boost: bool,
}
