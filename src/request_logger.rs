use std::{
    path::PathBuf,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use tempfile::tempdir;

// set BLEEP_LOG_REQUESTS=1 to enable request logging to disk
static LOG_DIR: OnceLock<Mutex<PathBuf>> = OnceLock::new();
static LOG_FILE: &str = "bleep-requests.jsonl";
static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    if std::env::var("BLEEP_LOG_REQUESTS").as_deref() != Ok("1") {
        return;
    }
    let dir = std::env::var("BLEEP_LOG_PATH").unwrap_or_else(|_| {
        tempdir()
            .unwrap()
            .path()
            .as_os_str()
            .to_string_lossy()
            .to_string()
    });
    let path = PathBuf::from(&dir);
    if let Err(e) = std::fs::create_dir_all(&path) {
        eprintln!("[logger] failed to create log dir {}: {}", dir, e);
        return;
    }
    LOG_DIR.set(Mutex::new(path)).ok();
    println!("[logger] writing requests to {}/", dir);
}

pub fn log(entry: &serde_json::Value) {
    let Some(dir) = LOG_DIR.get() else { return };
    let dir = dir.lock().unwrap();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    let pretty = serde_json::to_string_pretty(entry).unwrap();
    let filename = format!("{:04}.json", seq);
    let path = dir.join(&filename);

    let all_in_one_path = dir.join(LOG_FILE);
    if let Err(e) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&all_in_one_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(pretty.as_bytes())
                .and_then(|_| f.write_all(b"\n"))
        })
    {
        eprintln!(
            "[logger] failed to append to {}: {}",
            all_in_one_path.display(),
            e
        );
    }

    if let Err(e) = std::fs::write(&path, &pretty) {
        eprintln!("[logger] failed to write {}: {}", path.display(), e);
    }
}
