use std::{env::temp_dir, path::PathBuf};

use bytes::Bytes;
use fs_extra::file::write_all;
use serde_jsonlines::write_json_lines as write_jsonl;

/// writes a LogEntry as a single JSONL line to the log file
pub async fn log_entry(content: &Bytes) {
    let tmp_path: PathBuf = "/tmp".into();

    let log_path = tmp_path.join("bleep-log.jsonl");

    let str = String::from_utf8(content.to_vec()).unwrap();

    // let json_str = serde_json::to_string(&str).unwrap();

    write_jsonl(&log_path, &[str]).unwrap();

    // TODO: serialize LogEntry to JSON
    // TODO: append line to log file
}
