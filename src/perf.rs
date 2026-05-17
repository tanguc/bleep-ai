//! Lightweight global perf registry for the proxy hot path.
//!
//! Records nanosecond timings per named span using atomic counters. Lock-free
//! on the hot path: every span update is 4 atomic adds. A snapshot is taken
//! on demand for the `/perf` HTTP endpoint.
//!
//! Usage:
//! ```ignore
//! let _g = perf::span("hudsucker.request.total");
//! // … work …
//! // recorded on drop
//!
//! perf::record("rule.scan", duration);
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;

// per-span atomic counters. RwLock for the map (only contended on cold-path
// span registration, never on the hot-path increments).
fn registry() -> &'static RwLock<HashMap<&'static str, Box<SpanStat>>> {
    static R: OnceLock<RwLock<HashMap<&'static str, Box<SpanStat>>>> = OnceLock::new();
    R.get_or_init(|| RwLock::new(HashMap::new()))
}

// dynamic spans (rule-id keyed, etc) — keys allocated at runtime. Separate
// map so we don't leak &'static when the caller has a String.
fn dynamic() -> &'static RwLock<HashMap<String, Box<SpanStat>>> {
    static D: OnceLock<RwLock<HashMap<String, Box<SpanStat>>>> = OnceLock::new();
    D.get_or_init(|| RwLock::new(HashMap::new()))
}

struct SpanStat {
    count: AtomicU64,
    total_ns: AtomicU64,
    min_ns: AtomicU64, // u64::MAX = unset
    max_ns: AtomicU64,
    // log-spaced histogram: bucket i covers [2^i ns, 2^(i+1) ns).
    // 40 buckets covers 1ns .. ~18 minutes, more than enough for span timings.
    // Lossy but allocation-free and lock-free.
    buckets: [AtomicU64; HIST_BUCKETS],
}

const HIST_BUCKETS: usize = 40;

impl SpanStat {
    fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            total_ns: AtomicU64::new(0),
            min_ns: AtomicU64::new(u64::MAX),
            max_ns: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    fn add(&self, ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(ns, Ordering::Relaxed);
        // atomic min/max with CAS loops
        let mut cur = self.min_ns.load(Ordering::Relaxed);
        while ns < cur {
            match self
                .min_ns
                .compare_exchange_weak(cur, ns, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        let mut cur = self.max_ns.load(Ordering::Relaxed);
        while ns > cur {
            match self
                .max_ns
                .compare_exchange_weak(cur, ns, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        // bucket index = floor(log2(ns)) clamped to [0, HIST_BUCKETS-1]
        let bucket = if ns == 0 {
            0
        } else {
            let lg = 63 - ns.leading_zeros() as usize;
            lg.min(HIST_BUCKETS - 1)
        };
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
    /// Return (p50, p95, p99) in nanoseconds. Approximate — uses the upper
    /// edge of the bucket containing the percentile rank as the estimate.
    fn percentiles(&self) -> (u64, u64, u64) {
        let total: u64 = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum();
        if total == 0 {
            return (0, 0, 0);
        }
        let target = |p: f64| ((total as f64) * p).ceil() as u64;
        let t50 = target(0.50);
        let t95 = target(0.95);
        let t99 = target(0.99);
        let mut acc: u64 = 0;
        let mut p50 = 0u64;
        let mut p95 = 0u64;
        let mut p99 = 0u64;
        for (i, b) in self.buckets.iter().enumerate() {
            acc += b.load(Ordering::Relaxed);
            // upper edge of bucket i is 2^(i+1) ns
            let upper = 1u64.checked_shl(i as u32 + 1).unwrap_or(u64::MAX);
            if p50 == 0 && acc >= t50 {
                p50 = upper;
            }
            if p95 == 0 && acc >= t95 {
                p95 = upper;
            }
            if p99 == 0 && acc >= t99 {
                p99 = upper;
                break;
            }
        }
        (p50, p95, p99)
    }
}

/// Record a duration against a static span name. Use for hot-path call sites
/// where the name is a literal — zero allocation, no map lookup after the
/// first call.
pub fn record(name: &'static str, dur: Duration) {
    let ns = dur.as_nanos() as u64;
    // fast path — read lock
    if let Some(s) = registry().read().unwrap().get(name) {
        s.add(ns);
        return;
    }
    // cold path — insert. Re-check inside the write lock to avoid races.
    let mut w = registry().write().unwrap();
    w.entry(name)
        .or_insert_with(|| Box::new(SpanStat::new()))
        .add(ns);
}

/// Record a duration against a dynamic span name (e.g. per-rule_id). Slower
/// than `record()` because it allocates / hashes a String — use sparingly.
pub fn record_dyn(name: &str, dur: Duration) {
    let ns = dur.as_nanos() as u64;
    if let Some(s) = dynamic().read().unwrap().get(name) {
        s.add(ns);
        return;
    }
    let mut w = dynamic().write().unwrap();
    w.entry(name.to_string())
        .or_insert_with(|| Box::new(SpanStat::new()))
        .add(ns);
}

/// RAII guard — records the elapsed wall time against `name` when dropped.
pub struct Span {
    name: &'static str,
    start: Instant,
}

impl Span {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            start: Instant::now(),
        }
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        record(self.name, self.start.elapsed());
    }
}

/// Helper: `let _g = perf::span("name");` — recorded on drop.
pub fn span(name: &'static str) -> Span {
    Span::new(name)
}

/// JSON-ready snapshot row for one span.
#[derive(Serialize, Clone, Debug)]
pub struct SpanReport {
    pub name: String,
    pub count: u64,
    pub total_ms: f64,
    pub avg_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
}

/// Take a snapshot of all spans. Sorted by total_ms descending so the biggest
/// time sinks float to the top.
pub fn snapshot() -> Vec<SpanReport> {
    let mut out: Vec<SpanReport> = Vec::new();
    for (name, s) in registry().read().unwrap().iter() {
        out.push(to_report((*name).to_string(), s));
    }
    for (name, s) in dynamic().read().unwrap().iter() {
        out.push(to_report(name.clone(), s));
    }
    out.sort_by(|a, b| {
        b.total_ms
            .partial_cmp(&a.total_ms)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

fn to_report(name: String, s: &SpanStat) -> SpanReport {
    let count = s.count.load(Ordering::Relaxed);
    let total_ns = s.total_ns.load(Ordering::Relaxed);
    let min_ns = s.min_ns.load(Ordering::Relaxed);
    let max_ns = s.max_ns.load(Ordering::Relaxed);
    let to_ms = |ns: u64| (ns as f64) / 1_000_000.0;
    SpanReport {
        name,
        count,
        total_ms: to_ms(total_ns),
        avg_ms: if count == 0 {
            0.0
        } else {
            to_ms(total_ns / count)
        },
        min_ms: if min_ns == u64::MAX {
            0.0
        } else {
            to_ms(min_ns)
        },
        max_ms: to_ms(max_ns),
        p50_ms: to_ms(s.percentiles().0),
        p95_ms: to_ms(s.percentiles().1),
        p99_ms: to_ms(s.percentiles().2),
    }
}

/// Reset all counters. Useful for benchmarks; the /perf?reset=1 endpoint
/// calls this to start a fresh sample.
pub fn reset() {
    registry().write().unwrap().clear();
    dynamic().write().unwrap().clear();
}

/// Spawn a background task that periodically dumps the perf snapshot to disk.
/// - `/tmp/bleep-perf.json` — pretty JSON of the latest snapshot (overwritten).
/// - `/tmp/bleep-perf.jsonl` — one compact line per tick `{ts, snapshot}` for trend.
/// Interval is `BLEEP_PERF_DUMP_MS` env var, default 5000 ms. Set to 0 to disable.
pub fn start_dump_task() {
    let interval_ms: u64 = std::env::var("BLEEP_PERF_DUMP_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000);
    if interval_ms == 0 {
        eprintln!("[perf] disk dump disabled (BLEEP_PERF_DUMP_MS=0)");
        return;
    }
    tokio::spawn(async move {
        let json_path = "/tmp/bleep-perf.json";
        let jsonl_path = "/tmp/bleep-perf.jsonl";
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval_ms));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            let snap = snapshot();
            if snap.is_empty() {
                continue;
            }
            // pretty current snapshot (overwrite)
            if let Ok(s) = serde_json::to_string_pretty(&snap) {
                let _ = std::fs::write(json_path, s);
            }
            // appending trend line — keep small: just timestamp + top-20
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let top: Vec<&SpanReport> = snap.iter().take(20).collect();
            let line = serde_json::json!({ "ts": ts, "top": top });
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(jsonl_path)
            {
                use std::io::Write;
                let _ = writeln!(f, "{}", line);
            }
        }
    });
    eprintln!("[perf] dumping snapshot every {interval_ms} ms to /tmp/bleep-perf.{{json,jsonl}}");
}
