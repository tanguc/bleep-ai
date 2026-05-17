//! SQLite-backed redaction history for the menu-bar dashboard.
//!
//! v1 stored aggregatable metadata only (rule id, category, subcategory,
//! severity, direction, timestamp).
//!
//! v2 adds a sibling table `redaction_entries` carrying the per-row `original`
//! and `fake` values, so the dashboard's drill-down view can show what was
//! actually replaced — not just the count. Originals previously lived only in
//! the JSONL audit log; they're now also readable via the loopback stats
//! server. Keep that in mind if you ever expose the stats server beyond
//! 127.0.0.1.
//!
//! Single global connection guarded by a Mutex (SQLite is single-writer; our
//! write rate is small enough that contention is invisible in profiling).

use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

use crate::replacement::Redaction;

const SCHEMA_VERSION: i64 = 2;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS redactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    rule_id     TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    subcategory TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    direction   TEXT    NOT NULL,
    request_id  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_redactions_ts ON redactions(ts);
CREATE INDEX IF NOT EXISTS idx_redactions_category ON redactions(category, subcategory);
CREATE INDEX IF NOT EXISTS idx_redactions_request_id ON redactions(request_id);
"#;

// Sibling table — the secret half. Split from `redactions` so the metadata
// half can stay queryable even if we later encrypt/restrict this one. FK
// cascade keeps the two in sync on row delete (retention prune, vacuum, etc).
const SCHEMA_V2: &str = r#"
CREATE TABLE IF NOT EXISTS redaction_entries (
    redaction_id INTEGER PRIMARY KEY,
    original     TEXT NOT NULL,
    fake         TEXT NOT NULL,
    FOREIGN KEY (redaction_id) REFERENCES redactions(id) ON DELETE CASCADE
);

-- composite indexes that match the drill-down query shape (filter then sort DESC by ts).
-- the v1 idx_redactions_category is a strict prefix of idx_redactions_category_ts,
-- but we keep both: v1 covers COUNT GROUP BY, v2 covers ORDER BY ts DESC scans.
CREATE INDEX IF NOT EXISTS idx_redactions_category_ts ON redactions(category, subcategory, ts DESC);
CREATE INDEX IF NOT EXISTS idx_redactions_rule_id_ts  ON redactions(rule_id, ts DESC);
"#;

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();

/// Direction of a redaction (which side of the proxy it occurred on).
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

// HTTP response shapes live in the shared bleep-events crate so the
// menu-bar GUI gets ts-rs-generated TS types via `@bleep-events/*`.
// Re-exported here so existing internal callers don't need to change imports.
pub use bleep_events::{CategoryCount, RuleCount, Summary};

/// Default database location: `~/.bleep/bleep-stats.db`.
/// Falls back to the current directory if `$HOME` is unset.
pub fn default_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".bleep").join("bleep-stats.db"),
        None => PathBuf::from("bleep-stats.db"),
    }
}

/// Initialize the global DB at the given path. Idempotent.
/// Creates the file if it does not exist; runs migrations to bring schema to current version.
pub fn init(path: &PathBuf) -> Result<(), rusqlite::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA_V1)?;
    conn.execute_batch(SCHEMA_V2)?;
    // FK enforcement is per-connection on SQLite — keep cascade working.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;

    // record schema version (insert-or-ignore — first run only).
    // bump on upgrade so future migrations can branch off the stored version.
    conn.execute(
        "INSERT OR REPLACE INTO schema_version (version) VALUES (?1)",
        params![SCHEMA_VERSION],
    )?;

    // pragma tuning for our write pattern (small inserts, occasional reads)
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;",
    )?;

    let _ = DB.set(Mutex::new(conn));
    Ok(())
}

/// Record a batch of redactions for one request/response. No-op if init() was not called.
pub fn record_redactions(direction: Direction, request_id: &str, redactions: &[Redaction]) {
    if redactions.is_empty() {
        return;
    }
    let _g = crate::perf::span("stats.record_redactions");
    let Some(db) = DB.get() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dir = direction.as_str();

    let t_lock = std::time::Instant::now();
    let mut conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    crate::perf::record("stats.db_lock_wait", t_lock.elapsed());

    let t_tx = std::time::Instant::now();
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[stats] begin tx failed: {e}");
            return;
        }
    };
    crate::perf::record("stats.tx_begin", t_tx.elapsed());

    debug!(
        "[stats] recording {} redactions for request_id={}",
        redactions.len(),
        request_id
    );
    let t_inserts = std::time::Instant::now();
    for r in redactions {
        // 1) metadata row — drives summary counters and bar charts.
        if let Err(e) = tx.execute(
            "INSERT INTO redactions (ts, rule_id, category, subcategory, severity, direction, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts, r.rule_id, r.category, r.subcategory, r.severity, dir, request_id],
        ) {
            eprintln!("[stats] insert (redactions) failed: {e}");
            continue;
        }
        let rid = tx.last_insert_rowid();
        // 2) sibling row carrying the secret half — drives the drill-down view.
        if let Err(e) = tx.execute(
            "INSERT INTO redaction_entries (redaction_id, original, fake) VALUES (?1, ?2, ?3)",
            params![rid, r.original, r.fake],
        ) {
            eprintln!("[stats] insert (redaction_entries) failed: {e}");
        }
    }
    crate::perf::record("stats.inserts", t_inserts.elapsed());
    let t_commit = std::time::Instant::now();
    if let Err(e) = tx.commit() {
        eprintln!("[stats] commit failed: {e}");
    }
    crate::perf::record("stats.tx_commit", t_commit.elapsed());
}

/// Wipe all redaction history. Returns number of metadata rows deleted.
/// FK cascade clears redaction_entries; perf counters are NOT touched.
pub fn reset_all() -> u64 {
    let Some(db) = DB.get() else {
        return 0;
    };
    let mut conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[stats] reset begin tx failed: {e}");
            return 0;
        }
    };
    let deleted = tx.execute("DELETE FROM redactions", []).unwrap_or(0) as u64;
    // entries gets cascade-deleted via FK, but be explicit for clarity / older rows.
    let _ = tx.execute("DELETE FROM redaction_entries", []);
    if let Err(e) = tx.commit() {
        eprintln!("[stats] reset commit failed: {e}");
        return 0;
    }
    // reclaim disk so the dashboard "all-time" counter and file size match.
    if let Err(e) = conn.execute_batch("VACUUM;") {
        eprintln!("[stats] vacuum after reset failed: {e}");
    }
    deleted
}

/// Total counts by time window. Returns zeros if init() was not called.
pub fn summary() -> Summary {
    let Some(db) = DB.get() else {
        return Summary::default();
    };
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return Summary::default(),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let one_day = 86_400;

    let count_since = |since: i64| -> u64 {
        conn.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM redactions WHERE ts >= ?1",
            params![since],
            |row| row.get(0),
        )
        .unwrap_or(0) as u64
    };
    let total = conn
        .query_row::<i64, _, _>("SELECT COUNT(*) FROM redactions", [], |row| row.get(0))
        .unwrap_or(0) as u64;

    Summary {
        total,
        last_24h: count_since(now - one_day),
        last_7d: count_since(now - 7 * one_day),
        last_30d: count_since(now - 30 * one_day),
    }
}

/// (category, subcategory) breakdown. Returns empty if init() was not called.
pub fn by_category() -> Vec<CategoryCount> {
    let Some(db) = DB.get() else {
        return vec![];
    };
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut stmt = match conn.prepare(
        "SELECT category, subcategory, COUNT(*) AS c
         FROM redactions
         GROUP BY category, subcategory
         ORDER BY c DESC",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let rows = stmt.query_map([], |row| {
        Ok(CategoryCount {
            category: row.get(0)?,
            subcategory: row.get(1)?,
            count: row.get::<_, i64>(2)? as u64,
        })
    });
    match rows {
        Ok(it) => it.filter_map(Result::ok).collect(),
        Err(_) => vec![],
    }
}

/// Top-N rules by count.
pub fn top_rules(limit: usize) -> Vec<RuleCount> {
    let Some(db) = DB.get() else {
        return vec![];
    };
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return vec![],
    };
    let mut stmt = match conn.prepare(
        "SELECT rule_id, COUNT(*) AS c
         FROM redactions
         GROUP BY rule_id
         ORDER BY c DESC
         LIMIT ?1",
    ) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(RuleCount {
            rule_id: row.get(0)?,
            count: row.get::<_, i64>(1)? as u64,
        })
    });
    match rows {
        Ok(it) => it.filter_map(Result::ok).collect(),
        Err(_) => vec![],
    }
}

// ── drill-down query (v2) ────────────────────────────────────────────────────

/// Filters for the drill-down query. All fields optional; any combination is
/// supported. Empty filter returns the most recent rows up to `limit`.
#[derive(Debug, Default, Clone)]
pub struct RedactionFilter {
    pub category: Option<String>,
    pub subcategory: Option<String>,
    pub rule_id: Option<String>,
    pub request_id: Option<String>,
    /// substring match against original OR fake_value (case-insensitive)
    pub q: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
}

/// Cursor encoding for stable pagination. Format: `"<ts>:<id>"`. Pages are
/// served newest-first, so the next page is "everything strictly older than
/// (ts, id)". Encoding `ts` first keeps the comparison index-friendly.
fn encode_cursor(ts: i64, id: i64) -> String {
    format!("{ts}:{id}")
}
fn decode_cursor(s: &str) -> Option<(i64, i64)> {
    let (a, b) = s.split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Fetch a page of redacted rows joined with originals/fakes. Sorted by
/// `(ts DESC, id DESC)`. Returns `(rows, next_cursor)` where `next_cursor`
/// is `None` if the result is smaller than `limit` (end of stream).
pub fn query_redactions(
    f: &RedactionFilter,
    limit: usize,
    cursor: Option<&str>,
) -> (Vec<bleep_events::RedactedRow>, Option<String>) {
    let Some(db) = DB.get() else {
        return (vec![], None);
    };
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return (vec![], None),
    };

    // build WHERE clause + params in tandem so we don't double-bind anything.
    let mut wheres: Vec<&'static str> = Vec::new();
    let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(v) = &f.category {
        wheres.push("r.category = ?");
        binds.push(Box::new(v.clone()));
    }
    if let Some(v) = &f.subcategory {
        wheres.push("r.subcategory = ?");
        binds.push(Box::new(v.clone()));
    }
    if let Some(v) = &f.rule_id {
        wheres.push("r.rule_id = ?");
        binds.push(Box::new(v.clone()));
    }
    if let Some(v) = &f.request_id {
        wheres.push("r.request_id = ?");
        binds.push(Box::new(v.clone()));
    }
    if let Some(v) = &f.since {
        wheres.push("r.ts >= ?");
        binds.push(Box::new(*v));
    }
    if let Some(v) = &f.until {
        wheres.push("r.ts <= ?");
        binds.push(Box::new(*v));
    }
    if let Some(v) = &f.q {
        wheres.push("(e.original LIKE ? OR e.fake LIKE ?)");
        let like = format!("%{v}%");
        binds.push(Box::new(like.clone()));
        binds.push(Box::new(like));
    }
    if let Some((ts, id)) = cursor.and_then(decode_cursor) {
        // newest-first, so "next page" = strictly older
        wheres.push("(r.ts < ? OR (r.ts = ? AND r.id < ?))");
        binds.push(Box::new(ts));
        binds.push(Box::new(ts));
        binds.push(Box::new(id));
    }

    let where_clause = if wheres.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", wheres.join(" AND "))
    };
    let sql = format!(
        "SELECT r.id, r.ts, r.rule_id, r.category, r.subcategory, r.severity,
                r.direction, r.request_id, e.original, e.fake
         FROM redactions r
         LEFT JOIN redaction_entries e ON e.redaction_id = r.id
         {where_clause}
         ORDER BY r.ts DESC, r.id DESC
         LIMIT ?"
    );
    binds.push(Box::new(limit as i64));

    let bind_refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[stats] prepare query_redactions failed: {e}");
            return (vec![], None);
        }
    };

    let rows_it = stmt.query_map(rusqlite::params_from_iter(bind_refs), |row| {
        Ok(bleep_events::RedactedRow {
            id: row.get(0)?,
            ts: row.get(1)?,
            rule_id: row.get(2)?,
            category: row.get(3)?,
            subcategory: row.get(4)?,
            severity: row.get(5)?,
            direction: row.get(6)?,
            request_id: row.get(7)?,
            // LEFT JOIN: e.original / e.fake are NULL for pre-v2-migration rows.
            // Surface a placeholder so the UI shows the metadata row anyway —
            // before this they were silently filtered out by an INNER JOIN.
            original: row.get::<_, Option<String>>(8)?.unwrap_or_else(|| "(not recorded)".to_string()),
            fake_value: row.get::<_, Option<String>>(9)?.unwrap_or_else(|| "(not recorded)".to_string()),
        })
    });
    let rows: Vec<bleep_events::RedactedRow> = match rows_it {
        Ok(it) => it.filter_map(Result::ok).collect(),
        Err(e) => {
            eprintln!("[stats] query_redactions iter failed: {e}");
            return (vec![], None);
        }
    };

    // next_cursor = the last row's (ts, id), unless we got a short page.
    let next_cursor = if rows.len() < limit {
        None
    } else {
        rows.last().map(|r| encode_cursor(r.ts, r.id))
    };
    (rows, next_cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;

    fn make_redaction(rule_id: &str, category: &str, subcategory: &str) -> Redaction {
        Redaction {
            rule_id: rule_id.to_string(),
            category: category.to_string(),
            subcategory: subcategory.to_string(),
            severity: "medium".to_string(),
            original: "x".to_string(),
            fake: "y".to_string(),
            span: Range { start: 0, end: 1 },
        }
    }

    fn fresh_db() -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        // open + schema, but bypass the global OnceLock by using a fresh Connection
        let conn = Connection::open(f.path()).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        f
    }

    #[test]
    fn schema_v1_is_idempotent() {
        let f = fresh_db();
        let conn = Connection::open(f.path()).unwrap();
        // running twice must not error
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
    }

    #[test]
    fn insert_and_count() {
        let f = fresh_db();
        let conn = Connection::open(f.path()).unwrap();
        conn.execute(
            "INSERT INTO redactions (ts, rule_id, category, subcategory, severity, direction, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![100i64, "gl.aws-key", "secret", "aws", "high", "request", "req-1"],
        ).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM redactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn category_breakdown_query_shape() {
        let f = fresh_db();
        let conn = Connection::open(f.path()).unwrap();
        for (rule, cat, sub) in &[
            ("gl.aws-1", "secret", "aws"),
            ("gl.aws-2", "secret", "aws"),
            ("gl.gh-1", "secret", "github"),
            ("ha.email", "pii", "email"),
        ] {
            conn.execute(
                "INSERT INTO redactions (ts, rule_id, category, subcategory, severity, direction, request_id)
                 VALUES (?1, ?2, ?3, ?4, 'high', 'request', 'r')",
                params![100i64, rule, cat, sub],
            ).unwrap();
        }
        let mut stmt = conn
            .prepare(
                "SELECT category, subcategory, COUNT(*) FROM redactions GROUP BY category, subcategory ORDER BY COUNT(*) DESC",
            )
            .unwrap();
        let rows: Vec<(String, String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(rows[0], ("secret".into(), "aws".into(), 2));
    }

    #[test]
    fn record_redactions_no_init_is_noop() {
        // before init() is called, record_redactions should not panic
        let r = make_redaction("gl.aws-1", "secret", "aws");
        record_redactions(Direction::Request, "req-1", &[r]);
        // summary returns zeros
        let s = summary();
        // (note: this may pick up state from a prior test if init was called globally;
        // best we can assert is "doesn't panic")
        let _ = s;
    }
}
