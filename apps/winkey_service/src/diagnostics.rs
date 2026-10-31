use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex;

static LOG_LOCK: Mutex<()> = Mutex::new(());

// Accept stable stage/code metadata only, never a request body or credential.
pub fn stage(data_dir: &Path, stage: &str, code: &str) {
    let Ok(_guard) = LOG_LOCK.lock() else { return; };
    let folder = data_dir.join("logs");
    if fs::create_dir_all(&folder).is_err() { return; }
    let file = folder.join("worker_stages.log");
    if fs::metadata(&file).map(|m| m.len() > 2_000_000).unwrap_or(false) {
        let previous = folder.join("worker_stages.previous.log");
        let _ = fs::remove_file(&previous);
        let _ = fs::rename(&file, previous);
    }
    let clean: String = code.chars().filter(|c| c.is_ascii_alphanumeric() || "_-=:,. ".contains(*c)).take(160).collect();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if let Ok(mut out) = OpenOptions::new().create(true).append(true).open(file) {
        let _ = writeln!(out, "{} pid={} stage={} code={}", ts, std::process::id(), stage, clean);
    }
}
