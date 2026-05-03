//! SQLite-backed redaction history for the menu-bar dashboard.
//!
//! Stores aggregatable metadata only (rule id, category, subcategory, severity,
//! direction, timestamp). The original matched bytes never reach this DB —
//! they stay in the JSONL audit log on disk per the existing security
//! invariant. The DB is for "how many secrets / what kind / when" queries.
//!
//! Single global connection guarded by a Mutex (SQLite is single-writer; our
//! write rate is small enough that contention is invisible in profiling).

use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::replacement::Redaction;

const SCHEMA_VERSION: i64 = 1;

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

/// Aggregated counts for the dashboard summary card.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct Summary {
    pub total: u64,
    pub last_24h: u64,
    pub last_7d: u64,
    pub last_30d: u64,
}

/// One row of the (category, subcategory) breakdown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CategoryCount {
    pub category: String,
    pub subcategory: String,
    pub count: u64,
}

/// One row of the rule-level breakdown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: u64,
}

/// Default database location alongside the proxy's audit log.
pub fn default_path() -> PathBuf {
    PathBuf::from("bleep-stats.db")
}

/// Initialize the global DB at the given path. Idempotent.
/// Creates the file if it does not exist; runs migrations to bring schema to current version.
pub fn init(path: &PathBuf) -> Result<(), rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA_V1)?;

    // record schema version (insert-or-ignore — first run only)
    conn.execute(
        "INSERT OR IGNORE INTO schema_version (version) VALUES (?1)",
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
    let Some(db) = DB.get() else {
        return;
    };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dir = direction.as_str();

    let mut conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[stats] begin tx failed: {e}");
            return;
        }
    };
    {
        let mut stmt = match tx.prepare_cached(
            "INSERT INTO redactions (ts, rule_id, category, subcategory, severity, direction, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[stats] prepare failed: {e}");
                return;
            }
        };
        for r in redactions {
            if let Err(e) = stmt.execute(params![
                ts,
                r.rule_id,
                r.category,
                r.subcategory,
                r.severity,
                dir,
                request_id
            ]) {
                eprintln!("[stats] insert failed: {e}");
            }
        }
    }
    if let Err(e) = tx.commit() {
        eprintln!("[stats] commit failed: {e}");
    }
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
