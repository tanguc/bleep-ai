// dictionary — persistent fake↔original mapping.
//
// Bleep's request-side anonymization mints a random fake for each detected
// PII value. The model echoes that fake in its reply, and the response-side
// deanonymize step swaps it back using the redactions from the *current*
// request. That works for one round trip but breaks the moment a fake
// escapes the in-memory map — most commonly when:
//
//   1. The model's reply gets written to disk (Edit tool, file output).
//      The file now contains the fake. Reading it later sends the fake back
//      through the proxy; with no mapping in the new request, the user sees
//      the fake forever.
//   2. The gateway restarts. Every in-flight mapping is gone.
//
// This module persists every (fake, original) pair the gateway ever mints
// into a dedicated SQLite file and keeps a hot in-memory copy. The response
// handler combines the request's in-flight redactions with the dictionary's
// snapshot, so any fake the model emits — whether from the current request
// or a years-old session — is restored to its original.
//
// Storage layout:
//   ~/.bleep/bleep-dictionary.db          dedicated file, never co-mingled
//                                         with stats (stats explicitly never
//                                         records originals for privacy).
//   table dictionary(fake PK, original, created_at, updated_at)
//   in-memory HashMap<fake, original>, loaded fully at startup.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use tracing::warn;

use crate::replacement::Redaction;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS dictionary (
    fake       TEXT PRIMARY KEY,
    original   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dictionary_updated ON dictionary(updated_at DESC);
"#;

static DB: OnceLock<Mutex<Connection>> = OnceLock::new();
// fake → original (used by deanonymize on the response side)
static MAP: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
// original → fake (used by anonymize on the request side so the same real
// value always maps to the same fake forever, no matter how many requests pass)
static REVERSE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

/// Default location for the dictionary database.
pub fn default_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".bleep").join("bleep-dictionary.db"),
        None => PathBuf::from("bleep-dictionary.db"),
    }
}

/// Open the DB at `path`, run schema, and warm the in-memory map from disk.
/// Idempotent: subsequent calls are no-ops.
pub fn init(path: &PathBuf) -> Result<(), rusqlite::Error> {
    if DB.get().is_some() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous  = NORMAL;
         PRAGMA temp_store   = MEMORY;",
    )?;

    // warm in-memory snapshot.
    let mut forward: HashMap<String, String> = HashMap::new();
    let mut reverse: HashMap<String, String> = HashMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT fake, original FROM dictionary ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows.flatten() {
            // first-writer wins for reverse so the oldest fake for an original
            // stays canonical even if the DB has multiple from legacy data.
            reverse.entry(row.1.clone()).or_insert_with(|| row.0.clone());
            forward.insert(row.0, row.1);
        }
    }
    let count = forward.len();

    let _ = MAP.set(RwLock::new(forward));
    let _ = REVERSE.set(RwLock::new(reverse));
    let _ = DB.set(Mutex::new(conn));
    println!("[dictionary] loaded {count} fake→original mappings from {}", path.display());
    Ok(())
}

/// Reverse lookup: given a real value, return the canonical fake we minted
/// for it in a past request, if any. Used by the request-side anonymizer to
/// keep fakes stable across requests.
pub fn lookup_by_original(original: &str) -> Option<String> {
    let map = REVERSE.get()?;
    map.read().ok()?.get(original).cloned()
}

/// Persist a batch of redactions: write to DB and update the in-memory map.
/// Conflicts on `fake` keep the existing `original` (first-writer wins) — the
/// fake is supposed to be globally unique, so a collision means we reused a
/// fake for two different originals, which would be a generation bug, not
/// something to silently overwrite.
pub fn record_batch(redactions: &[Redaction]) {
    if redactions.is_empty() {
        return;
    }
    let Some(db) = DB.get() else {
        return;
    };
    let Some(map) = MAP.get() else {
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // memory update first (cheap, immediate) — readers see new mappings
    // before the disk write commits.
    {
        let Ok(mut m) = map.write() else {
            return;
        };
        for r in redactions {
            m.entry(r.fake.clone()).or_insert_with(|| r.original.clone());
        }
    }
    if let Some(rev) = REVERSE.get() {
        if let Ok(mut m) = rev.write() {
            for r in redactions {
                // first-writer wins so once we've picked a canonical fake for
                // an original, that pairing is permanent.
                m.entry(r.original.clone()).or_insert_with(|| r.fake.clone());
            }
        }
    }

    // persist
    let mut conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return,
    };
    let tx = match conn.transaction() {
        Ok(t) => t,
        Err(e) => {
            warn!("[dictionary] begin tx failed: {e}");
            return;
        }
    };
    for r in redactions {
        if let Err(e) = tx.execute(
            "INSERT INTO dictionary (fake, original, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(fake) DO UPDATE SET updated_at = excluded.updated_at",
            params![r.fake, r.original, now],
        ) {
            warn!("[dictionary] insert failed for fake {:?}: {e}", r.fake);
        }
    }
    if let Err(e) = tx.commit() {
        warn!("[dictionary] commit failed: {e}");
    }
}

/// Snapshot the full in-memory map as `(fake, original)` pairs. Cloned so the
/// caller can hold it without keeping a read lock across an await point.
pub fn snapshot_pairs() -> Vec<(String, String)> {
    let Some(map) = MAP.get() else {
        return Vec::new();
    };
    let Ok(m) = map.read() else {
        return Vec::new();
    };
    m.iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Number of entries currently held in memory (for diagnostics).
pub fn len() -> usize {
    MAP.get().and_then(|m| m.read().ok()).map(|m| m.len()).unwrap_or(0)
}
