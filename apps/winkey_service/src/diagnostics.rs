// WinKey Pro — Service Diagnostics & Asynchronous Background Telemetry Engine
// Host and Worker inter-process synchronization with fine-grained Windows Named Mutex.
use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static LOG_LOCK: Mutex<()> = Mutex::new(());
static OUTBOX_LOCK: Mutex<()> = Mutex::new(());
static EVENT_SEQ: AtomicU64 = AtomicU64::new(1);
const BATCH_LIMIT: usize = 25;

/// Windows Named Mutex üçün proseslərarası (Host və Worker) avtomatik Drop qoruyucusu
struct IpcOutboxGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

impl Drop for IpcOutboxGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            unsafe {
                windows_sys::Win32::System::Threading::ReleaseMutex(self.handle);
                windows_sys::Win32::Foundation::CloseHandle(self.handle);
            }
        }
    }
}

/// data_dir üzrə unikal Local Named Mutex adı yaradır
fn get_outbox_mutex_name(data_dir: &Path) -> Vec<u16> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data_dir.to_string_lossy().as_bytes());
    let hash_hex = format!("{:x}", hasher.finalize());
    let name = format!("Local\\WinKey_Telemetry_Outbox_{}\0", &hash_hex[..16]);
    name.encode_utf16().collect()
}

/// Host və Worker arasında növbə faylını qoruyan proseslərarası kilidi əldə edir
fn acquire_ipc_outbox_lock(data_dir: &Path, timeout_ms: u32) -> Result<IpcOutboxGuard, String> {
    let wide_name = get_outbox_mutex_name(data_dir);
    unsafe {
        let handle = windows_sys::Win32::System::Threading::CreateMutexW(
            std::ptr::null(),
            0, // initially not owned
            wide_name.as_ptr(),
        );
        if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err("CreateMutexW failed".to_string());
        }

        let wait_res = windows_sys::Win32::System::Threading::WaitForSingleObject(handle, timeout_ms);
        if wait_res == windows_sys::Win32::Foundation::WAIT_OBJECT_0
            || wait_res == windows_sys::Win32::Foundation::WAIT_ABANDONED
        {
            Ok(IpcOutboxGuard { handle })
        } else {
            windows_sys::Win32::Foundation::CloseHandle(handle);
            Err(format!("WaitForSingleObject failed: 0x{:X}", wait_res))
        }
    }
}

struct WorkerHandle {
    sender: SyncSender<()>,
    stop: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
}

static WORKERS: Mutex<Option<HashMap<PathBuf, WorkerHandle>>> = Mutex::new(None);

#[derive(Debug, Default, Clone)]
struct ParsedMetadata {
    install_run_id: Option<String>,
    version: Option<String>,
    duration_ms: Option<u64>,
    error_code: Option<String>,
}

#[derive(Debug, Clone)]
struct OutboxItem {
    event_id: String,
    payload: serde_json::Value,
}

fn parse_code_metadata(code: &str) -> ParsedMetadata {
    let mut meta = ParsedMetadata::default();
    for token in code.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            match k {
                "rel_id" => meta.install_run_id = Some(v.to_string()),
                "ver" => meta.version = Some(v.to_string()),
                "dur_ms" => meta.duration_ms = v.parse::<u64>().ok(),
                "err" => meta.error_code = Some(v.to_string()),
                _ => {}
            }
        }
    }
    meta
}

/// Accept stable stage/code metadata only, never a request body or credential.
/// Writes immediately to local worker_stages.log and enqueues telemetry to the
/// background worker without blocking the main caller flow.
pub fn stage(data_dir: &Path, stage_name: &str, code: &str) {
    let folder = data_dir.join("logs");
    let _ = fs::create_dir_all(&folder);

    let clean: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || "_-=:,. ".contains(*c))
        .take(160)
        .collect();

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1. Synchronous, fast local stage log append (< 0.5ms)
    if let Ok(_guard) = LOG_LOCK.lock() {
        let file = folder.join("worker_stages.log");
        if fs::metadata(&file).map(|m| m.len() > 2_000_000).unwrap_or(false) {
            let previous = folder.join("worker_stages.previous.log");
            let _ = fs::remove_file(&previous);
            let _ = fs::rename(&file, previous);
        }
        if let Ok(mut out) = OpenOptions::new().create(true).append(true).open(&file) {
            let _ = writeln!(out, "{} pid={} stage={} code={}", ts, std::process::id(), stage_name, clean);
        }
    }

    // 2. Non-blocking telemetry background dispatch
    enqueue_and_notify(data_dir, stage_name, &clean, ts);
}

/// Xidmət başlayan zaman çağırılır: diskdə qalan növbəni yeni hadisə gözləmədən göndərməyə başlayır
pub fn init_telemetry(data_dir: &Path) {
    ensure_worker_active(data_dir);
}

/// Xidmət və ya test bağlananda telemetriya worker-ini təmiz dayandırır
pub fn shutdown_telemetry_worker(data_dir: &Path) {
    let mut map_guard = match WORKERS.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(ref mut map) = *map_guard {
        if let Some(mut handle) = map.remove(data_dir) {
            handle.stop.store(true, Ordering::SeqCst);
            let _ = handle.sender.try_send(());
            if let Some(jh) = handle.join_handle.take() {
                let _ = jh.join();
            }
        }
    }
}

fn enqueue_and_notify(data_dir: &Path, stage_name: &str, code: &str, ts: u64) {
    let cfg_file = data_dir.join("config.json");
    if !cfg_file.exists() {
        return;
    }

    let cfg_val: serde_json::Value = match fs::read_to_string(&cfg_file).ok().and_then(|s| serde_json::from_str(&s).ok()) {
        Some(v) => v,
        None => return,
    };

    let device_id = match cfg_val.get("device_id").and_then(|v| v.as_str()) {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => return,
    };

    let meta = parse_code_metadata(code);
    let severity = if stage_name.contains("FAIL") || stage_name.contains("ERR") {
        "ERROR"
    } else {
        "INFO"
    };

    let event_type = if stage_name.starts_with("UPDATE_") {
        "update_stage"
    } else {
        "lifecycle_stage"
    };

    let seq = EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let event_id = format!("ev_{}_{}_{}_{}", stage_name.to_lowercase(), ts, pid, seq);
    let version = meta.version.unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    let payload = serde_json::json!({
        "event_id": event_id,
        "install_run_id": meta.install_run_id,
        "device_id": device_id,
        "component": "winkey_service",
        "version": version,
        "stage": stage_name,
        "event_type": event_type,
        "severity": severity,
        "error_code": meta.error_code,
        "duration_ms": meta.duration_ms,
        "local_time": ts as f64
    });

    // Write to durable local outbox under Inter-Process Named Mutex lock
    let outbox_path = data_dir.join("logs").join("telemetry_outbox.jsonl");
    {
        let _ipc = match acquire_ipc_outbox_lock(data_dir, 50)
            .or_else(|_| acquire_ipc_outbox_lock(data_dir, 50))
        {
            Ok(guard) => guard,
            Err(error) => {
                eprintln!("[TELEMETRY_OUTBOX_LOCK_FAILED] Hadisə növbəyə yazılmadı: {error}");
                return;
            }
        };
        let _guard = OUTBOX_LOCK.lock().ok();
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&outbox_path) {
            if let Ok(serialized) = serde_json::to_string(&payload) {
                let _ = writeln!(f, "{}", serialized);
                let _ = f.flush();
            }
        }
    }

    // Ensure background telemetry worker is active for this data_dir
    ensure_worker_active(data_dir);
}

fn ensure_worker_active(data_dir: &Path) {
    let mut map_guard = match WORKERS.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let map = map_guard.get_or_insert_with(HashMap::new);

    let path_buf = data_dir.to_path_buf();
    if let Some(handle) = map.get(&path_buf) {
        let _ = handle.sender.try_send(());
        return;
    }

    let (tx, rx) = sync_channel::<()>(8);
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_flag.clone();
    let thread_data_dir = path_buf.clone();

    let jh = thread::Builder::new()
        .name(format!("telemetry-bg-{}", thread_data_dir.file_name().and_then(|n| n.to_str()).unwrap_or("worker")))
        .spawn(move || {
            background_telemetry_loop(thread_data_dir, rx, stop_clone);
        })
        .ok();

    let _ = tx.try_send(());
    map.insert(path_buf, WorkerHandle { sender: tx, stop: stop_flag, join_handle: jh });
}

fn background_telemetry_loop(
    data_dir: PathBuf,
    rx: std::sync::mpsc::Receiver<()>,
    stop_flag: Arc<AtomicBool>,
) {
    let outbox_path = data_dir.join("logs").join("telemetry_outbox.jsonl");
    let cfg_path = data_dir.join("config.json");

    while !stop_flag.load(Ordering::SeqCst) {
        // Startup and loop flush: process outbox entries
        if let Some((origin, secret)) = load_config_credentials(&cfg_path, &data_dir) {
            let endpoint = format!("{}/agent/telemetry", origin.trim_end_matches('/'));
            process_outbox_queue(&data_dir, &endpoint, &secret, &outbox_path);
        }

        // Wait for incoming trigger or periodic polling (200ms) to detect network recovery without waiting for new events
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn load_config_credentials(cfg_path: &Path, data_dir: &Path) -> Option<(String, String)> {
    let raw = fs::read_to_string(cfg_path).ok()?;
    let val: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let origin = val.get("gateway_origin").and_then(|v| v.as_str())?.to_string();
    if origin.is_empty() {
        return None;
    }

    let secret = crate::storage::load_device_secret_dpapi(data_dir)
        .ok()
        .or_else(|| val.get("device_secret").and_then(|v| v.as_str()).map(|s| s.to_string()))?;

    if secret.is_empty() {
        return None;
    }
    Some((origin, secret))
}

/// Növbədən məhdud sayda hadisəni proseslərarası kilid altında oxuyur, HTTP sorğusundan əvvəl kilidi buraxır,
/// cavab gələndə yalnız təsdiqlənmiş event_id-ləri çıxarır və bu arada digər proseslərin əlavə etdiyi qeydləri qoruyur.
fn process_outbox_queue(data_dir: &Path, endpoint: &str, secret: &str, outbox_path: &Path) {
    // 1. Məhdud sayda qeydi PROSESLƏRARASI KİLİD ALTINDA oxuyuruq
    let batch = fetch_batch_under_lock(data_dir, outbox_path, BATCH_LIMIT);
    if batch.is_empty() {
        return;
    }

    // 2. KİLİD ARTIQ BURAXILIB!
    // HTTP sorğuları zamanı kilid tutulmur; digər proseslər (məs. Child worker) sərbəst yeni hadisə yaza bilər!
    let mut confirmed_ids = HashSet::new();

    for item in batch {
        match post_telemetry_http(endpoint, secret, &item.payload) {
            Ok(()) => {
                if !item.event_id.is_empty() {
                    confirmed_ids.insert(item.event_id);
                }
            }
            Err(_) => {
                // Şəbəkə kəsildi və ya server təsdiqləmədi: batch-in qalanı saxlanılır
                break;
            }
        }
    }

    // 3. YALNIZ təsdiqlənmiş event_id-lər növbədən çıxarılır, bu arada digər proseslərin əlavə etdikləri QORUNUR!
    if !confirmed_ids.is_empty() {
        remove_confirmed_under_lock(data_dir, outbox_path, &confirmed_ids);
    }
}

fn fetch_batch_under_lock(data_dir: &Path, outbox_path: &Path, limit: usize) -> Vec<OutboxItem> {
    let Ok(_ipc) = acquire_ipc_outbox_lock(data_dir, 5000) else {
        return Vec::new();
    };
    let _guard = match OUTBOX_LOCK.lock() {
        Ok(g) => g,
        Err(_) => return Vec::new(),
    };

    if !outbox_path.exists() {
        return Vec::new();
    }

    let file = match fs::File::open(outbox_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);
    let mut batch = Vec::new();

    for l in reader.lines().map_while(Result::ok) {
        let trimmed = l.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&trimmed) {
            let event_id = val.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            batch.push(OutboxItem {
                event_id,
                payload: val,
            });
            if batch.len() >= limit {
                break;
            }
        }
    }
    batch
    // _guard və _ipc burada drop olur (proseslərarası kilid buraxılır)
}

fn remove_confirmed_under_lock(data_dir: &Path, outbox_path: &Path, confirmed_ids: &HashSet<String>) {
    let Ok(_ipc) = acquire_ipc_outbox_lock(data_dir, 5000) else {
        return;
    };
    let _guard = match OUTBOX_LOCK.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    if !outbox_path.exists() {
        return;
    }

    let file = match fs::File::open(outbox_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let reader = BufReader::new(file);
    let mut remaining = Vec::new();

    for l in reader.lines().map_while(Result::ok) {
        let trimmed = l.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&trimmed) {
            if let Some(eid) = val.get("event_id").and_then(|v| v.as_str()) {
                if confirmed_ids.contains(eid) {
                    // Yalnız təsdiqlənmiş hadisə çıxarılır
                    continue;
                }
            }
        }
        // Digər proses tərəfindən əlavə olunan YENİ qeydlər və təsdiqlənməyənlər QORUNUR!
        remaining.push(trimmed);
    }

    if remaining.is_empty() {
        let _ = fs::remove_file(outbox_path);
    } else {
        let tmp_path = outbox_path.with_extension("tmp");
        if let Ok(mut out) = fs::File::create(&tmp_path) {
            for line in remaining {
                let _ = writeln!(out, "{}", line);
            }
            let _ = out.flush();
            let _ = fs::rename(&tmp_path, outbox_path);
        }
    }
}

fn post_telemetry_http(endpoint: &str, secret: &str, payload: &serde_json::Value) -> Result<(), String> {
    let res = ureq::post(endpoint)
        .timeout(Duration::from_millis(1500))
        .set("Authorization", &format!("Bearer {}", secret))
        .set("Content-Type", "application/json")
        .send_json(payload);

    match res {
        Ok(resp) => {
            if resp.status() == 200 {
                Ok(())
            } else {
                Err(format!("HTTP_{}", resp.status()))
            }
        }
        Err(e) => Err(format!("UREQ_ERR: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::net::TcpListener;
    use std::process::Command;

    #[test]
    fn test_diagnostics_parse_code_metadata() {
        let code = "rel_id=rel_0.2.9 slot=slot_b ver=0.2.9 dur_ms=18";
        let meta = parse_code_metadata(code);
        assert_eq!(meta.install_run_id.as_deref(), Some("rel_0.2.9"));
        assert_eq!(meta.version.as_deref(), Some("0.2.9"));
        assert_eq!(meta.duration_ms, Some(18));
        assert_eq!(meta.error_code, None);
    }

    #[test]
    fn child_process_worker_entrypoint() {
        if std::env::var("WINKEY_IPC_CHILD_TEST").as_deref() != Ok("1") {
            return;
        }
        let data_dir_str = std::env::var("WINKEY_IPC_DATA_DIR").expect("WINKEY_IPC_DATA_DIR lazımdır");
        let stage_name = std::env::var("WINKEY_IPC_STAGE").unwrap_or_else(|_| "UPDATE_COMMIT_DONE_FROM_CHILD_PROC".to_string());
        let code = std::env::var("WINKEY_IPC_CODE").unwrap_or_else(|_| "rel_id=rel_0.2.9 slot=slot_b ver=0.2.9 dur_ms=35".to_string());
        let data_dir = PathBuf::from(data_dir_str);
        stage(&data_dir, &stage_name, &code);
        std::process::exit(0);
    }

    #[test]
    fn test_background_telemetry_offline_and_recovery() {
        let unique_dir = std::env::temp_dir().join(format!("winkey_diag_offline_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&unique_dir);
        fs::create_dir_all(&unique_dir).unwrap();

        let dummy = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = dummy.local_addr().unwrap().port();
        drop(dummy);

        let origin = format!("http://127.0.0.1:{}", port);
        let device_id = "test_dev_offline_01";
        let token = "test_secret_offline_token";

        let cfg = serde_json::json!({
            "device_id": device_id,
            "gateway_origin": origin,
            "device_secret": token,
            "server_confirmed": true
        });
        fs::write(unique_dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let t_start = Instant::now();
        stage(&unique_dir, "UPDATE_COMMIT_DONE", "rel_id=rel_0.2.9 slot=slot_b ver=0.2.9 dur_ms=22");
        let elapsed = t_start.elapsed();

        assert!(
            elapsed < Duration::from_millis(30),
            "stage() əsas axını bloklamamalıdır! Gecikmə: {:?}",
            elapsed
        );

        let outbox_path = unique_dir.join("logs").join("telemetry_outbox.jsonl");
        let mut outbox_found = false;
        for _ in 0..10 {
            if outbox_path.exists() {
                let content = fs::read_to_string(&outbox_path).unwrap_or_default();
                if content.contains("UPDATE_COMMIT_DONE") {
                    outbox_found = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(outbox_found, "Təsdiqlənməyən hadisə outbox-da saxlanmalıdır");

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).expect("Test öz serverini başladır");
        listener.set_nonblocking(true).unwrap();

        let received_events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let events_clone = received_events.clone();
        let server_running = Arc::new(AtomicBool::new(true));
        let server_running_clone = server_running.clone();

        let server_thread = thread::spawn(move || {
            while server_running_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut request_line = String::new();
                        let _ = reader.read_line(&mut request_line);

                        let mut content_length = 0usize;
                        loop {
                            let mut header = String::new();
                            if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                                break;
                            }
                            if let Some(val) = header.to_lowercase().strip_prefix("content-length:") {
                                content_length = val.trim().parse().unwrap_or(0);
                            }
                        }

                        let mut body = vec![0u8; content_length];
                        let _ = reader.read_exact(&mut body);

                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                            events_clone.lock().unwrap().push(json);
                        }

                        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"status\":\"RECORDED\"}";
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        let wait_timeout = Instant::now();
        let mut delivered = false;
        while wait_timeout.elapsed() < Duration::from_secs(4) {
            let count = received_events.lock().unwrap().len();
            if count >= 1 {
                delivered = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        assert!(delivered, "Bağlantı bərpa olunanda yeni hadisə gözləmədən növbə göndərilməli idi!");

        thread::sleep(Duration::from_millis(400));
        server_running.store(false, Ordering::SeqCst);
        let _ = server_thread.join();

        let events = received_events.lock().unwrap();
        assert_eq!(
            events.len(),
            1,
            "Hadisə yalnız 1 dəfə qəbul edilməli idi: {:?}",
            *events
        );

        let event = &events[0];
        assert_eq!(event.get("stage").and_then(|v| v.as_str()), Some("UPDATE_COMMIT_DONE"));
        assert_eq!(event.get("device_id").and_then(|v| v.as_str()), Some("test_dev_offline_01"));
        assert_eq!(event.get("duration_ms").and_then(|v| v.as_u64()), Some(22));

        thread::sleep(Duration::from_millis(150));
        let outbox_remaining = fs::read_to_string(&outbox_path).unwrap_or_default();
        assert!(
            !outbox_path.exists() || outbox_remaining.trim().is_empty(),
            "Server təsdiq etdikdən sonra outbox təmizlənməli idi"
        );

        shutdown_telemetry_worker(&unique_dir);
        let _ = fs::remove_dir_all(&unique_dir);
    }

    #[test]
    fn test_unconfirmed_events_retained_in_outbox() {
        let unique_dir = std::env::temp_dir().join(format!("winkey_diag_unconf_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&unique_dir);
        fs::create_dir_all(&unique_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let origin = format!("http://127.0.0.1:{}", port);
        let device_id = "test_dev_unconfirmed";
        let token = "test_secret_token";

        let cfg = serde_json::json!({
            "device_id": device_id,
            "gateway_origin": origin,
            "device_secret": token,
            "server_confirmed": true
        });
        fs::write(unique_dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let server_running = Arc::new(AtomicBool::new(true));
        let server_running_clone = server_running.clone();

        let server_thread = thread::spawn(move || {
            while server_running_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        stage(&unique_dir, "UPDATE_COMMIT_DONE", "rel_id=rel_0.2.9 slot=slot_b ver=0.2.9 dur_ms=15");

        thread::sleep(Duration::from_millis(500));

        let outbox_path = unique_dir.join("logs").join("telemetry_outbox.jsonl");
        assert!(outbox_path.exists(), "Təsdiqlənməyən qeyd üçün outbox faylı mövcud olmalıdır");
        let content = fs::read_to_string(&outbox_path).unwrap_or_default();
        assert!(
            content.contains("UPDATE_COMMIT_DONE"),
            "Server təsdiqləmədiyi halda qeyd outbox-da qalmalıdır: {}",
            content
        );

        server_running.store(false, Ordering::SeqCst);
        let _ = server_thread.join();
        shutdown_telemetry_worker(&unique_dir);
        let _ = fs::remove_dir_all(&unique_dir);
    }

    #[test]
    fn test_delayed_server_nonblocking_stage_and_restart_flush() {
        let unique_dir = std::env::temp_dir().join(format!("winkey_diag_delay_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&unique_dir);
        fs::create_dir_all(&unique_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let origin = format!("http://127.0.0.1:{}", port);
        let device_id = "test_dev_delayed";
        let token = "test_secret_delay_token";

        let cfg = serde_json::json!({
            "device_id": device_id,
            "gateway_origin": origin,
            "device_secret": token,
            "server_confirmed": true
        });
        fs::write(unique_dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let should_delay = Arc::new(AtomicBool::new(true));
        let should_delay_clone = should_delay.clone();
        let received_events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let received_clone = received_events.clone();
        let server_running = Arc::new(AtomicBool::new(true));
        let server_running_clone = server_running.clone();

        let server_thread = thread::spawn(move || {
            while server_running_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut request_line = String::new();
                        let _ = reader.read_line(&mut request_line);

                        let mut content_length = 0usize;
                        loop {
                            let mut header = String::new();
                            if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                                break;
                            }
                            if let Some(val) = header.to_lowercase().strip_prefix("content-length:") {
                                content_length = val.trim().parse().unwrap_or(0);
                            }
                        }

                        let mut body = vec![0u8; content_length];
                        let _ = reader.read_exact(&mut body);

                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                            let eid = json.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let mut list = received_clone.lock().unwrap();
                            if let Some(pos) = list.iter().position(|e| e.get("event_id").and_then(|v| v.as_str()) == Some(&eid)) {
                                list[pos] = json;
                            } else {
                                list.push(json);
                            }
                        }

                        if should_delay_clone.load(Ordering::SeqCst) {
                            thread::sleep(Duration::from_millis(1500));
                        }

                        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"status\":\"RECORDED\"}";
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });

        stage(&unique_dir, "UPDATE_DOWNLOAD_DONE", "rel_id=rel_0.2.9 ver=0.2.9 dur_ms=10");
        thread::sleep(Duration::from_millis(50));

        let t_stage2 = Instant::now();
        stage(&unique_dir, "UPDATE_COMMIT_DONE", "rel_id=rel_0.2.9 slot=slot_b ver=0.2.9 dur_ms=18");
        let elapsed2 = t_stage2.elapsed();

        assert!(
            elapsed2 < Duration::from_millis(30),
            "stage() server cavabını gözləməməlidir! Gecikmə: {:?}",
            elapsed2
        );

        thread::sleep(Duration::from_millis(100));
        shutdown_telemetry_worker(&unique_dir);
        should_delay.store(false, Ordering::SeqCst);

        let outbox_path = unique_dir.join("logs").join("telemetry_outbox.jsonl");
        assert!(outbox_path.exists(), "İkinci hadisə outbox-da qorunmalı idi!");
        let outbox_content = fs::read_to_string(&outbox_path).unwrap_or_default();
        assert!(
            outbox_content.contains("UPDATE_COMMIT_DONE"),
            "İkinci hadisə outbox-da qalmalı idi: {}",
            outbox_content
        );

        init_telemetry(&unique_dir);

        let wait_restart = Instant::now();
        let mut both_delivered = false;
        while wait_restart.elapsed() < Duration::from_secs(3) {
            let count = received_events.lock().unwrap().len();
            if count >= 2 {
                both_delivered = true;
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }

        assert!(both_delivered, "Xidmət yenidən başlayanda qalan hadisələr serverə çatmalı idi!");

        server_running.store(false, Ordering::SeqCst);
        let _ = server_thread.join();

        let events = received_events.lock().unwrap();
        assert_eq!(events.len(), 2, "Hər iki hadisə çatmalı idi: {:?}", *events);

        thread::sleep(Duration::from_millis(150));
        let outbox_final = fs::read_to_string(&outbox_path).unwrap_or_default();
        assert!(
            !outbox_path.exists() || outbox_final.trim().is_empty(),
            "Bütün hadisələr çatdıqdan sonra outbox təmizlənməlidir"
        );

        shutdown_telemetry_worker(&unique_dir);
        let _ = fs::remove_dir_all(&unique_dir);
    }

    #[test]
    fn test_inter_process_outbox_concurrency_and_restart() {
        let unique_dir = std::env::temp_dir().join(format!("winkey_diag_ipc_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&unique_dir);
        fs::create_dir_all(&unique_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let origin = format!("http://127.0.0.1:{}", port);
        let device_id = "test_dev_ipc_concurrency";
        let token = "test_secret_ipc_token";

        let cfg = serde_json::json!({
            "device_id": device_id,
            "gateway_origin": origin,
            "device_secret": token,
            "server_confirmed": true
        });
        fs::write(unique_dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let received_events = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let received_clone = received_events.clone();
        let server_running = Arc::new(AtomicBool::new(true));
        let server_running_clone = server_running.clone();

        let server_thread = thread::spawn(move || {
            while server_running_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut request_line = String::new();
                        let _ = reader.read_line(&mut request_line);

                        let mut content_length = 0usize;
                        loop {
                            let mut header = String::new();
                            if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                                break;
                            }
                            if let Some(val) = header.to_lowercase().strip_prefix("content-length:") {
                                content_length = val.trim().parse().unwrap_or(0);
                            }
                        }

                        let mut body = vec![0u8; content_length];
                        let _ = reader.read_exact(&mut body);

                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                            let eid = json.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let mut list = received_clone.lock().unwrap();
                            if let Some(pos) = list.iter().position(|e| e.get("event_id").and_then(|v| v.as_str()) == Some(&eid)) {
                                list[pos] = json;
                            } else {
                                list.push(json);
                            }
                        }

                        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"status\":\"RECORDED\"}";
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });

        stage(&unique_dir, "UPDATE_DOWNLOAD_DONE", "rel_id=rel_0.2.9 ver=0.2.9 dur_ms=12");

        let current_exe = std::env::current_exe().expect("Cari binary yolu tapılmadı");
        let mut child_proc = Command::new(current_exe)
            .env("WINKEY_IPC_CHILD_TEST", "1")
            .env("WINKEY_IPC_DATA_DIR", unique_dir.to_str().unwrap())
            .env("WINKEY_IPC_STAGE", "UPDATE_COMMIT_DONE_FROM_CHILD_PROC")
            .args(&["diagnostics::tests::child_process_worker_entrypoint", "--exact", "--nocapture"])
            .spawn()
            .expect("İkinci proses spawn edilə bilmədi");

        let exit_status = child_proc.wait().expect("Child proses wait uğursuz oldu");
        assert!(exit_status.success(), "İkinci proses uğurla tamamlanmalı idi");

        shutdown_telemetry_worker(&unique_dir);

        let outbox_path = unique_dir.join("logs").join("telemetry_outbox.jsonl");
        let outbox_content = fs::read_to_string(&outbox_path).unwrap_or_default();
        assert!(
            outbox_content.contains("UPDATE_COMMIT_DONE_FROM_CHILD_PROC"),
            "İkinci prosesin yazdığı hadisə proseslərarası kilidlə qorunmalı idi: {}",
            outbox_content
        );

        init_telemetry(&unique_dir);

        let wait_ipc = Instant::now();
        let mut both_received = false;
        while wait_ipc.elapsed() < Duration::from_secs(3) {
            let count = received_events.lock().unwrap().len();
            if count >= 2 {
                both_received = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        assert!(both_received, "Restart edildikdən sonra ikinci prosesin qorunmuş hadisəsi çatmalı idi!");

        server_running.store(false, Ordering::SeqCst);
        let _ = server_thread.join();

        let events = received_events.lock().unwrap();
        assert_eq!(events.len(), 2, "Hər iki prosesin hadisəsi serverə çatmalı idi: {:?}", *events);
        let has_child_event = events.iter().any(|e| {
            e.get("stage").and_then(|v| v.as_str()) == Some("UPDATE_COMMIT_DONE_FROM_CHILD_PROC")
        });
        assert!(has_child_event, "İkinci prosesin hadisəsi serverdə tapılmadı!");

        thread::sleep(Duration::from_millis(150));
        let outbox_final = fs::read_to_string(&outbox_path).unwrap_or_default();
        assert!(
            !outbox_path.exists() || outbox_final.trim().is_empty(),
            "Bütün hadisələr çatdıqdan sonra outbox təmizlənməlidir"
        );

        shutdown_telemetry_worker(&unique_dir);
        let _ = fs::remove_dir_all(&unique_dir);
    }

    #[test]
    fn test_mutex_timeout_blocks_write_and_preserves_file() {
        let unique_dir = std::env::temp_dir().join(format!("winkey_diag_timeout_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&unique_dir);
        fs::create_dir_all(unique_dir.join("logs")).unwrap();

        let outbox_path = unique_dir.join("logs").join("telemetry_outbox.jsonl");
        fs::write(&outbox_path, "{\"event_id\":\"ev_original\"}\n").unwrap();

        let cfg = serde_json::json!({
            "device_id": "test_dev_timeout",
            "gateway_origin": "http://127.0.0.1:9999",
            "device_secret": "sec",
            "server_confirmed": true
        });
        fs::write(unique_dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        // Mutex süni olaraq ayrı bir thread tərəfindən tutulur
        let (tx, rx) = std::sync::mpsc::channel();
        let thread_dir = unique_dir.clone();
        let blocker_thread = thread::spawn(move || {
            let _held = acquire_ipc_outbox_lock(&thread_dir, 2000).expect("Mutex əldə edilməli idi");
            tx.send(()).unwrap();
            thread::sleep(Duration::from_millis(800));
        });
        rx.recv().unwrap();

        stage(&unique_dir, "UPDATE_COMMIT_DONE", "rel_id=rel_0.2.9 ver=0.2.9 dur_ms=10");

        let content = fs::read_to_string(&outbox_path).unwrap();
        assert_eq!(
            content.trim(),
            "{\"event_id\":\"ev_original\"}",
            "Mutex timeout zamanı fayl dəyişdirilməməlidir!"
        );

        let _ = blocker_thread.join();
        shutdown_telemetry_worker(&unique_dir);
        let _ = fs::remove_dir_all(&unique_dir);
    }

    #[test]
    fn test_server_drop_response_retried_with_same_event_id_deduped_in_db() {
        let unique_dir = std::env::temp_dir().join(format!("winkey_diag_dedup_test_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let _ = fs::remove_dir_all(&unique_dir);
        fs::create_dir_all(&unique_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let origin = format!("http://127.0.0.1:{}", port);
        let device_id = "test_dev_dedup_01";
        let token = "test_secret_dedup";

        let cfg = serde_json::json!({
            "device_id": device_id,
            "gateway_origin": origin,
            "device_secret": token,
            "server_confirmed": true
        });
        fs::write(unique_dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

        let drop_first = Arc::new(AtomicBool::new(true));
        let drop_first_clone = drop_first.clone();
        let db_records = Arc::new(Mutex::new(HashMap::<String, serde_json::Value>::new()));
        let db_clone = db_records.clone();
        let server_running = Arc::new(AtomicBool::new(true));
        let server_running_clone = server_running.clone();

        let server_thread = thread::spawn(move || {
            while server_running_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut request_line = String::new();
                        let _ = reader.read_line(&mut request_line);

                        let mut content_length = 0usize;
                        loop {
                            let mut header = String::new();
                            if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                                break;
                            }
                            if let Some(val) = header.to_lowercase().strip_prefix("content-length:") {
                                content_length = val.trim().parse().unwrap_or(0);
                            }
                        }

                        let mut body = vec![0u8; content_length];
                        let _ = reader.read_exact(&mut body);

                        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body) {
                            let eid = json.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                            db_clone.lock().unwrap().insert(eid, json);
                        }

                        if drop_first_clone.swap(false, Ordering::SeqCst) {
                            drop(stream);
                            continue;
                        }

                        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"status\":\"RECORDED\"}";
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => break,
                }
            }
        });

        stage(&unique_dir, "UPDATE_COMMIT_DONE", "rel_id=rel_0.2.9 slot=slot_b ver=0.2.9 dur_ms=19");

        let wait_start = Instant::now();
        let mut confirmed = false;
        while wait_start.elapsed() < Duration::from_secs(4) {
            let outbox_path = unique_dir.join("logs").join("telemetry_outbox.jsonl");
            let empty_outbox = !outbox_path.exists() || fs::read_to_string(&outbox_path).unwrap_or_default().trim().is_empty();
            if empty_outbox && db_records.lock().unwrap().len() == 1 {
                confirmed = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }

        assert!(confirmed, "Təkrar cəhddən sonra növbə boşalmalı və server DB-də qeyd təsdiqlənməli idi!");

        server_running.store(false, Ordering::SeqCst);
        let _ = server_thread.join();

        let db = db_records.lock().unwrap();
        assert_eq!(db.len(), 1, "DB-də təkrar qeyd yaranmamalıdır: {:?}", *db);

        shutdown_telemetry_worker(&unique_dir);
        let _ = fs::remove_dir_all(&unique_dir);
    }
}
