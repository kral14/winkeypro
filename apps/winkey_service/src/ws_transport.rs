// WinKey Pro — Native WebSocket Transport & Resilient Execution Engine
// Spesifikasiya: plan/GEMINI_WEBSOCKET_BATCH.md & plan/GEMINI_WEBSOCKET_REVISION_2.md (R2-02, R2-03)

use std::collections::{HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{TcpStream, SocketAddr, ToSocketAddrs, Shutdown};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};
use tungstenite::client::IntoClientRequest;

use crate::diagnostics;
use crate::lock_engine;
use crate::storage;

static OUTBOX_MUTEX: Mutex<()> = Mutex::new(());
const MAX_DEDUP_LOG_ENTRIES: usize = 1000;
const MAX_QUEUE_CAPACITY: usize = 32;

pub fn worker_release_version() -> String {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| std::env::current_exe().ok()
        .and_then(|p|p.parent().map(|p|p.join("manifest.json")))
        .and_then(|p|fs::read(p).ok())
        .and_then(|raw|serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|v|v.get("version").and_then(|v|v.as_str()).map(String::from))
        .unwrap_or_else(||env!("CARGO_PKG_VERSION").to_string())).clone()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DurableResult {
    pub command_id: String,
    pub device_id: String,
    pub success: bool,
    pub status: String,
    pub attempt_id: String,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InFlightTask {
    pub command_id: String,
    pub action: String,
    pub device_id: String,
    pub started_at: u64,
}

#[derive(Clone, Debug)]
pub struct CommandTask {
    pub command_id: String,
    pub action: String,
    pub device_id: String,
}

fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// --- WINDOWS ATOMIC DURABLE REPLACE (R2-02) ---

fn atomic_replace_file(tmp_path: &Path, target_path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let tmp_w: Vec<u16> = tmp_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target_w: Vec<u16> = target_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // MOVEFILE_REPLACE_EXISTING = 0x00000001, MOVEFILE_WRITE_THROUGH = 0x00000008
        const MOVEFILE_REPLACE_EXISTING: u32 = 0x00000001;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x00000008;

        unsafe {
            let ret = windows_sys::Win32::Storage::FileSystem::MoveFileExW(
                tmp_w.as_ptr(),
                target_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            );
            if ret != 0 {
                Ok(())
            } else {
                let err = windows_sys::Win32::Foundation::GetLastError();
                Err(format!("MoveFileExW atomic replace failed: Win32 error {}", err))
            }
        }
    }
    #[cfg(not(windows))]
    {
        fs::rename(tmp_path, target_path).map_err(|e| format!("Atomic rename failed: {}", e))
    }
}

fn read_journal<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, String> {
    match fs::read(path) {
        Ok(raw) => serde_json::from_slice(&raw).map_err(|_| "E_JOURNAL_CORRUPT".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err("E_JOURNAL_READ".to_string()),
    }
}

// --- CRASH-SAFE DURABLE OUTBOX MANAGEMENT (R2-02) ---

fn get_outbox_path(data_dir: &Path) -> PathBuf {
    let outbox_dir = data_dir.join("outbox");
    let _ = fs::create_dir_all(&outbox_dir);
    outbox_dir.join("results.json")
}

fn atomic_write_outbox(data_dir: &Path, list: &[DurableResult]) -> Result<(), String> {
    let outbox_dir = data_dir.join("outbox");
    let _ = fs::create_dir_all(&outbox_dir);
    let target_path = outbox_dir.join("results.json");
    let tmp_path = outbox_dir.join(format!(
        "results.json.tmp.{}_{}",
        std::process::id(),
        current_timestamp_secs()
    ));

    let json_bytes = serde_json::to_vec_pretty(list)
        .map_err(|e| format!("JSON serialization error: {}", e))?;

    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create temp outbox file: {}", e))?;

        file.write_all(&json_bytes)
            .map_err(|e| format!("Failed to write to temp outbox file: {}", e))?;

        file.sync_all()
            .map_err(|e| format!("Failed to sync temp outbox file to disk: {}", e))?;
    }

    atomic_replace_file(&tmp_path, &target_path)
}

pub fn load_pending_results(data_dir: &Path) -> Vec<DurableResult> {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_outbox_path(data_dir);
    if !path.exists() {
        return Vec::new();
    }
    match fs::read_to_string(&path) {
        Ok(raw) => {
            if raw.trim().is_empty() {
                return Vec::new();
            }
            match serde_json::from_str::<Vec<DurableResult>>(&raw) {
                Ok(list) => list,
                Err(err) => {
                    eprintln!(
                        "[OUTBOX_CORRUPT] results.json korlanıb: {}. Ehtiyat nüsxə çıxarılır.",
                        err
                    );
                    let corrupt_path =
                        path.with_extension(format!("corrupt.{}", current_timestamp_secs()));
                    let _ = fs::copy(&path, &corrupt_path);
                    Vec::new()
                }
            }
        }
        Err(err) => {
            eprintln!("[OUTBOX_READ_ERR] results.json oxuna bilmədi: {}", err);
            Vec::new()
        }
    }
}

pub fn save_pending_result(data_dir: &Path, result: &DurableResult) -> Result<(), String> {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_outbox_path(data_dir);
    let mut list = read_journal::<DurableResult>(&path)?;
    list.retain(|r| r.command_id != result.command_id);
    list.push(result.clone());
    atomic_write_outbox(data_dir, &list)
}

pub fn remove_pending_result(data_dir: &Path, command_id: &str) -> Result<(), String> {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_outbox_path(data_dir);
    if !path.exists() {
        return Ok(());
    }
    let mut list = read_journal::<DurableResult>(&path)?;
    let orig_len = list.len();
    list.retain(|r| r.command_id != command_id);
    if list.len() != orig_len {
        atomic_write_outbox(data_dir, &list)?;
    }
    Ok(())
}

// --- IN-FLIGHT JOURNAL & CRASH RECOVERY (R2-02) ---

fn get_in_flight_path(data_dir: &Path) -> PathBuf {
    let outbox_dir = data_dir.join("outbox");
    let _ = fs::create_dir_all(&outbox_dir);
    outbox_dir.join("in_flight.json")
}

pub fn load_in_flight_tasks(data_dir: &Path) -> Vec<InFlightTask> {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_in_flight_path(data_dir);
    if !path.exists() {
        return Vec::new();
    }
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn record_in_flight(data_dir: &Path, task: &CommandTask) -> Result<(), String> {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_in_flight_path(data_dir);
    // Validate both journals before accepting any new side-effect.
    let _ = read_journal::<DurableResult>(&get_outbox_path(data_dir))?;
    let mut list = read_journal::<InFlightTask>(&path)?;
    list.retain(|t| t.command_id != task.command_id);
    list.push(InFlightTask {
        command_id: task.command_id.clone(),
        action: task.action.clone(),
        device_id: task.device_id.clone(),
        started_at: current_timestamp_secs(),
    });

    let tmp_path = path.with_extension(format!(
        "tmp.{}_{}",
        std::process::id(),
        current_timestamp_secs()
    ));
    let bytes = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| e.to_string())?;
        f.write_all(&bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    atomic_replace_file(&tmp_path, &path)
}

pub fn remove_in_flight(data_dir: &Path, command_id: &str) -> Result<(), String> {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_in_flight_path(data_dir);
    if !path.exists() {
        return Ok(());
    }
    let mut list = read_journal::<InFlightTask>(&path)?;
    let orig_len = list.len();
    list.retain(|t| t.command_id != command_id);
    if list.len() != orig_len {
        let tmp_path = path.with_extension(format!(
            "tmp.{}_{}",
            std::process::id(),
            current_timestamp_secs()
        ));
        let bytes = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| e.to_string())?;
            f.write_all(&bytes).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        atomic_replace_file(&tmp_path, &path)?;
    }
    Ok(())
}

pub fn recover_in_flight_tasks_on_startup(data_dir: &Path) {
    let in_flight = load_in_flight_tasks(data_dir);
    if in_flight.is_empty() {
        return;
    }
    println!(
        "[STARTUP_RECOVERY] {} yarımçıq qalmış in-flight tapşırıq aşkarlandı.",
        in_flight.len()
    );
    for task in in_flight {
        let cmd_id = &task.command_id;
        let action = &task.action;
        let did = &task.device_id;

        // A crash after durable result save but before inbox removal must not
        // replace a proven outcome with an indeterminate recovery result.
        match read_journal::<DurableResult>(&get_outbox_path(data_dir)) {
            Ok(results) if results.iter().any(|r| r.command_id == *cmd_id) => {
                let _ = remove_in_flight(data_dir, cmd_id);
                continue;
            }
            Err(_) => { eprintln!("[RECOVERY_BLOCKED] E_JOURNAL_READ"); return; }
            _ => {}
        }

        let (success, status_str) = if action == "lock" || action == "unlock" {
            // Do NOT blind replay physical unlock! Explicit recovery state (R2-02)
            println!("[CRASH_RECOVERY] Fiziki əmr ({}) qəza zamanı yarımçıq qalıb. Kor təkrarlama edilmir: INDETERMINATE_CRASH_RECOVERY.", action);
            (false, "INDETERMINATE_CRASH_RECOVERY".to_string())
        } else {
            // No durable proof of execution, even for a harmless mock action.
            (false, "INDETERMINATE_CRASH_RECOVERY".to_string())
        };

        let res = DurableResult {
            command_id: cmd_id.clone(),
            device_id: did.clone(),
            success,
            status: status_str,
            attempt_id: "recovery_boot".to_string(),
            created_at: current_timestamp_secs(),
        };
        if save_pending_result(data_dir, &res).is_ok() {
            let _ = remove_in_flight(data_dir, cmd_id);
        } else {
            eprintln!("[RECOVERY_BLOCKED] E_JOURNAL_WRITE; original inbox retained");
        }
    }
}

// --- PERSISTENT BOUNDED DEDUP LOG (R2-02) ---

fn get_handled_log_path(data_dir: &Path) -> PathBuf {
    let outbox_dir = data_dir.join("outbox");
    let _ = fs::create_dir_all(&outbox_dir);
    outbox_dir.join("handled.log")
}

pub fn load_handled_commands(data_dir: &Path) -> (HashSet<String>, VecDeque<String>) {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let path = get_handled_log_path(data_dir);
    let mut set = HashSet::new();
    let mut order = VecDeque::new();
    if path.exists() {
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                let id = line.trim();
                if !id.is_empty() {
                    if set.insert(id.to_string()) {
                        order.push_back(id.to_string());
                    }
                }
            }
        }
    }
    while order.len() > MAX_DEDUP_LOG_ENTRIES {
        if let Some(old) = order.pop_front() {
            set.remove(&old);
        }
    }
    // Unfinished receipts and unacknowledged results are never evicted by the
    // bounded historical log. They remain authoritative across restarts.
    for id in load_in_flight_ids_unlocked(data_dir) {
        set.insert(id);
    }
    (set, order)
}

fn load_in_flight_ids_unlocked(data_dir: &Path) -> Vec<String> {
    let mut ids: Vec<String> = read_journal::<InFlightTask>(&get_in_flight_path(data_dir))
        .unwrap_or_default().into_iter().map(|t| t.command_id).collect();
    ids.extend(read_journal::<DurableResult>(&get_outbox_path(data_dir))
        .unwrap_or_default().into_iter().map(|r| r.command_id));
    ids
}

pub fn record_handled_command(
    data_dir: &Path,
    set: &mut HashSet<String>,
    order: &mut VecDeque<String>,
    command_id: &str,
) {
    let _lock = OUTBOX_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    if set.insert(command_id.to_string()) {
        order.push_back(command_id.to_string());
    }
    let path = get_handled_log_path(data_dir);

    if order.len() > MAX_DEDUP_LOG_ENTRIES {
        while order.len() > (MAX_DEDUP_LOG_ENTRIES - 200) {
            if let Some(old) = order.pop_front() {
                set.remove(&old);
            }
        }
        let mut text = String::new();
        for id in order.iter() {
            text.push_str(id);
            text.push('\n');
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
        {
            let _ = f.write_all(text.as_bytes());
            let _ = f.sync_all();
            let _ = atomic_replace_file(&tmp, &path);
        }
    } else {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let line = format!("{}\n", command_id);
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}

// --- BOUNDED COALESCING EXECUTION QUEUE (R2-01, R2-02) ---

pub struct ExecutionQueue {
    tasks: VecDeque<CommandTask>,
    max_capacity: usize,
}

impl ExecutionQueue {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            tasks: VecDeque::new(),
            max_capacity,
        }
    }

    pub fn enqueue_coalesced(
        &mut self,
        new_task: CommandTask,
        data_dir: &Path,
        result_tx: Option<&SyncSender<DurableResult>>,
    ) {
        let mut superseded_ids = Vec::new();

        self.tasks.retain(|existing| {
            if existing.device_id == new_task.device_id {
                if existing.action == new_task.action
                    || new_task.action == "lock"
                    || new_task.action == "unlock"
                {
                    superseded_ids.push(existing.command_id.clone());
                    return false;
                }
            }
            true
        });

        for sup_id in superseded_ids {
            println!(
                "[QUEUE_COALESCE] Başlamamış köhnə əmr (ID={}) yeni əmr (ID={}) ilə coalesce olundu.",
                sup_id, new_task.command_id
            );
            let sup_res = DurableResult {
                command_id: sup_id.clone(),
                device_id: new_task.device_id.clone(),
                success: false,
                status: "SUPERSEDED".to_string(),
                attempt_id: String::new(),
                created_at: current_timestamp_secs(),
            };
            if save_pending_result(data_dir, &sup_res).is_err() {
                eprintln!("[SUPERSEDED_SAVE_BLOCKED] original inbox retained");
                continue;
            }
            let _ = remove_in_flight(data_dir, &sup_id);
            // Immediately dispatch SUPERSEDED result frame on active connection (R2-02)
            if let Some(tx) = result_tx {
                let _ = tx.try_send(sup_res);
            }
        }

        if self.tasks.len() >= self.max_capacity {
            if let Some(dropped) = self.tasks.pop_front() {
                println!(
                    "[QUEUE_FULL] Növbə doludur (limit={}), ən köhnə başlamamış əmr (ID={}) atıldı.",
                    self.max_capacity, dropped.command_id
                );
                let drop_res = DurableResult {
                    command_id: dropped.command_id.clone(),
                    device_id: dropped.device_id,
                    success: false,
                    status: "DROPPED_QUEUE_OVERFLOW".to_string(),
                    attempt_id: String::new(),
                    created_at: current_timestamp_secs(),
                };
                if save_pending_result(data_dir, &drop_res).is_ok() {
                    let _ = remove_in_flight(data_dir, &dropped.command_id);
                }
                if let Some(tx) = result_tx {
                    let _ = tx.try_send(drop_res);
                }
            }
        }

        self.tasks.push_back(new_task);
    }

    pub fn pop_next(&mut self) -> Option<CommandTask> {
        self.tasks.pop_front()
    }
}

// --- DEADLINE-BOUNDED CONNECT & STREAM TIMEOUT (R2-03) ---

fn set_stream_timeout(stream: &mut MaybeTlsStream<TcpStream>, timeout: Option<Duration>) {
    match stream {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(timeout);
            let _ = s.set_write_timeout(timeout);
        }
        MaybeTlsStream::NativeTls(s) => {
            let _ = s.get_mut().set_read_timeout(timeout);
            let _ = s.get_mut().set_write_timeout(timeout);
        }
        _ => {}
    }
}

// DNS alone may block in the OS. Keep at most ONE outstanding resolver globally;
// a timed-out attempt never creates another thread until that resolver finishes.
type DnsReply = Result<Vec<SocketAddr>, String>;
static DNS_PENDING: Mutex<Option<(String, Receiver<DnsReply>)>> = Mutex::new(None);

fn connection_cancelled(stop: &Arc<AtomicBool>) -> bool {
    !stop.load(Ordering::SeqCst) || !crate::RUNNING.load(Ordering::SeqCst)
        || crate::REMOTE_PAUSED.load(Ordering::SeqCst)
}

fn bounded_resolve(host: &str, port: u16, until: Instant, stop: &Arc<AtomicBool>) -> DnsReply {
    if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let key = format!("{}:{}", host, port);
    let mut slot = DNS_PENDING.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if connection_cancelled(stop) || Instant::now() >= until { return Err("E_DNS_DEADLINE".into()); }
        if slot.is_none() {
            let (tx, rx) = std::sync::mpsc::channel();
            let address = key.clone();
            thread::spawn(move || {
                let answer = address.to_socket_addrs().map(|a| a.collect()).map_err(|_| "E_DNS".into());
                let _ = tx.send(answer);
            });
            *slot = Some((key.clone(), rx));
        }
        let (pending_key, rx) = slot.as_ref().unwrap();
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(answer) => {
                let matches = pending_key == &key;
                *slot = None;
                if matches { return answer; }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => { *slot = None; }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn bounded_ws_connect(
    ws_url: &str,
    deadline: Duration,
    stop_signal: &Arc<AtomicBool>,
) -> Result<(WebSocket<MaybeTlsStream<TcpStream>>, tungstenite::handshake::client::Response), String> {
    let until = Instant::now() + deadline;
    let request = ws_url.into_client_request().map_err(|_| "E_WS_URL")?;
    let host = request.uri().host().ok_or("E_WS_HOST")?;
    let port = request.uri().port_u16().unwrap_or(if request.uri().scheme_str() == Some("wss") {443} else {80});
    let addresses = bounded_resolve(host, port, until, stop_signal)?;
    let mut connected = None;
    for address in addresses {
        if connection_cancelled(stop_signal) || Instant::now() >= until { return Err("E_CONNECT_CANCELLED_OR_DEADLINE".into()); }
        let remaining = until.saturating_duration_since(Instant::now());
        if let Ok(stream) = TcpStream::connect_timeout(&address, remaining.min(Duration::from_millis(250))) {
            connected = Some(stream);
            break;
        }
    }
    let stream = connected.ok_or("E_TCP_CONNECT")?;
    let remaining = until.saturating_duration_since(Instant::now());
    if remaining.is_zero() { return Err("E_CONNECT_DEADLINE".into()); }
    stream.set_read_timeout(Some(remaining)).map_err(|_| "E_SOCKET_TIMEOUT")?;
    stream.set_write_timeout(Some(remaining)).map_err(|_| "E_SOCKET_TIMEOUT")?;
    let _ = stream.set_nodelay(true);
    let cancel_socket = stream.try_clone().map_err(|_| "E_SOCKET_CLONE")?;
    let finished = Arc::new(AtomicBool::new(false));
    let done = finished.clone();
    let stop = stop_signal.clone();
    // This joined watchdog owns a clone of the SAME socket. It interrupts TLS and
    // HTTP upgrade on cancellation/deadline; there is no detached connect thread.
    let watchdog = thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            if connection_cancelled(&stop) || Instant::now() >= until {
                let _ = cancel_socket.shutdown(Shutdown::Both);
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
    });
    let config = tungstenite::protocol::WebSocketConfig {
        max_message_size: Some(65536), max_frame_size: Some(65536), ..Default::default()
    };
    let result = tungstenite::client_tls_with_config(request, stream, Some(config), None)
        .map_err(|_| "E_WS_HANDSHAKE".to_string());
    finished.store(true, Ordering::SeqCst);
    let _ = watchdog.join();
    if connection_cancelled(stop_signal) || Instant::now() >= until { return Err("E_CONNECT_CANCELLED_OR_DEADLINE".into()); }
    result
}

fn interruptible_sleep(duration: Duration, stop_signal: &Arc<AtomicBool>) {
    let start = Instant::now();
    while start.elapsed() < duration
        && stop_signal.load(Ordering::SeqCst)
        && crate::RUNNING.load(Ordering::SeqCst)
    {
        thread::sleep(Duration::from_millis(100));
    }
}

// --- DEDICATED EXECUTION WORKER (R2-02) ---

fn run_execution_worker(
    queue: Arc<Mutex<ExecutionQueue>>,
    result_tx: SyncSender<DurableResult>,
    is_mock: bool,
    data_dir: PathBuf,
    stop_signal: Arc<AtomicBool>,
) {
    println!("[EXECUTION_WORKER] Başladı: tək ardıcıl icraçı aktivdir.");
    while stop_signal.load(Ordering::SeqCst) && crate::RUNNING.load(Ordering::SeqCst) {
        if crate::REMOTE_PAUSED.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200));
            continue;
        }

        let next_task = {
            let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
            q.pop_next()
        };

        match next_task {
            Some(task) => {
                let cmd_id = task.command_id;
                let action = task.action;
                let did = task.device_id;

                // Do not start stale physical input after waiting behind a slow
                // operation. Server marks an uncertain attempt terminal at 60s.
                let expired = match read_journal::<InFlightTask>(&get_in_flight_path(&data_dir)) {
                    Ok(entries) => entries.iter().find(|t| t.command_id == cmd_id)
                        .map(|t| current_timestamp_secs().saturating_sub(t.started_at) >= 55).unwrap_or(false),
                    Err(_) => { stop_signal.store(false, Ordering::SeqCst); break; }
                };
                if expired {
                    let result = DurableResult { command_id: cmd_id.clone(), device_id: did,
                        success:false, status:"EXPIRED_BEFORE_EXECUTION".into(), attempt_id:String::new(),
                        created_at:current_timestamp_secs() };
                    if save_pending_result(&data_dir, &result).is_ok() {
                        let _ = remove_in_flight(&data_dir, &cmd_id);
                        let _ = result_tx.try_send(result);
                    } else { stop_signal.store(false, Ordering::SeqCst); break; }
                    continue;
                }

                // Record in-flight before starting execution! (R2-02)
                if record_in_flight(
                    &data_dir,
                    &CommandTask {
                        command_id: cmd_id.clone(),
                        action: action.clone(),
                        device_id: did.clone(),
                    },
                ).is_err() {
                    eprintln!("[EXECUTION_BLOCKED] E_JOURNAL_WRITE; no input attempted");
                    stop_signal.store(false, Ordering::SeqCst);
                    break;
                }

                diagnostics::stage(&data_dir, "COMMAND_RECEIVED", &action);
                println!(
                    "[EXECUTION_WORKER] Əmr icraya verildi: ID={}, Əməliyyat={}",
                    cmd_id, action
                );

                let (success, status_str) = if is_mock
                    || action == "mock"
                    || action == "ping"
                    || action == "status"
                {
                    println!("[HANDLER] Açıq nonphysical mock action icrası: {}", action);
                    (
                        true,
                        format!("SUCCESS_{} DEMO_MOCK_ACTION", action.to_uppercase()),
                    )
                } else if action == "lock" {
                    println!("[HANDLER] Real Win32 LockWorkStation çağırılır...");
                    match lock_engine::lock_workstation() {
                        Ok(_) => (true, "SUCCESS_LOCKED".to_string()),
                        Err(e) => (false, e),
                    }
                } else if action == "unlock" {
                    println!(
                        "[HANDLER] Real Win32 Unlock Adapter çağırılır (Lokal DPAPI vault-dan)..."
                    );
                    match storage::load_user_credential_dpapi(&data_dir) {
                        Ok(local_pin) => {
                            match lock_engine::execute_system_unlock(Some(&local_pin), &data_dir) {
                                Ok(res) => (true, res),
                                Err(e) => {
                                    println!("[HANDLER_BORDER] {}", e);
                                    (false, e)
                                }
                            }
                        }
                        Err(e) => {
                            println!("[HANDLER_BORDER] Lokal PIN tapılmadı: {}", e);
                            (false, format!("E_NO_LOCAL_CREDENTIAL: {}", e))
                        }
                    }
                } else {
                    (false, "UNKNOWN_ACTION".to_string())
                };

                diagnostics::stage(
                    &data_dir,
                    "COMMAND_FINISHED",
                    status_str.split_whitespace().next().unwrap_or("UNKNOWN"),
                );

                let dur_res = DurableResult {
                    command_id: cmd_id.clone(),
                    device_id: did,
                    success,
                    status: status_str,
                    attempt_id: String::new(),
                    created_at: current_timestamp_secs(),
                };

                // 1. Save to local durable outbox first (fail-closed, sync_all)
                match save_pending_result(&data_dir, &dur_res) {
                    Ok(_) => {
                        // Successfully committed to disk: remove from in_flight journal!
                        let _ = remove_in_flight(&data_dir, &cmd_id);
                        // 2. Send to network transport via bounded sync_channel
                        let _ = result_tx.try_send(dur_res);
                    }
                    Err(e) => {
                        eprintln!("[OUTBOX_SAVE_ERR] Nəticə disk outbox-a yazıla bilmədi: {}. Şəbəkəyə ötürülmür.", e);
                        // Stop this executor rather than performing more physical
                        // side-effects while its proven outcome cannot be saved.
                        stop_signal.store(false, Ordering::SeqCst);
                        break;
                    }
                }
            }
            None => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    println!("[EXECUTION_WORKER] Dayandırıldı.");
}

// --- MAIN WEBSOCKET NETWORK TRANSPORT LOOP (R2-02, R2-03) ---

pub fn run_gateway_transport_loop(
    stop_signal: Arc<AtomicBool>,
    is_mock: bool,
    data_dir: PathBuf,
) {
    // 0. Recover any interrupted tasks from in-flight crash journal on startup! (R2-02)
    if read_journal::<InFlightTask>(&get_in_flight_path(&data_dir)).is_err()
        || read_journal::<DurableResult>(&get_outbox_path(&data_dir)).is_err() {
        eprintln!("[TRANSPORT_BLOCKED] E_JOURNAL_CORRUPT_OR_UNREADABLE; repair required");
        return;
    }
    recover_in_flight_tasks_on_startup(&data_dir);

    let queue = Arc::new(Mutex::new(ExecutionQueue::new(MAX_QUEUE_CAPACITY)));
    let (result_tx, result_rx) = sync_channel::<DurableResult>(MAX_QUEUE_CAPACITY);

    // Start dedicated execution worker thread
    let worker_stop = stop_signal.clone();
    let worker_data_dir = data_dir.clone();
    let worker_queue = queue.clone();
    let worker_tx = result_tx.clone();
    let worker_handle = thread::spawn(move || {
        run_execution_worker(
            worker_queue,
            worker_tx,
            is_mock,
            worker_data_dir,
            worker_stop,
        );
    });

    let cfg_file = data_dir.join("config.json");
    let mut backoff_delay = Duration::from_secs(1);
    let mut consecutive_ws_fails = 0;

    // Load persistent bounded dedup log from disk
    let (mut handled_set, mut handled_order) = load_handled_commands(&data_dir);

    println!(
        "[WS_TRANSPORT_START] WinKey Native WebSocket Transport aktivləşdirildi (dedup entries={}).",
        handled_set.len()
    );

    while stop_signal.load(Ordering::SeqCst) && crate::RUNNING.load(Ordering::SeqCst) {
        if crate::REMOTE_PAUSED.load(Ordering::SeqCst) {
            interruptible_sleep(Duration::from_millis(800), &stop_signal);
            continue;
        }

        if !cfg_file.exists() {
            interruptible_sleep(Duration::from_secs(2), &stop_signal);
            continue;
        }

        let raw = match fs::read_to_string(&cfg_file) {
            Ok(r) => r,
            Err(_) => {
                interruptible_sleep(Duration::from_secs(2), &stop_signal);
                continue;
            }
        };

        let cfg: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(c) => c,
            Err(_) => {
                interruptible_sleep(Duration::from_secs(2), &stop_signal);
                continue;
            }
        };

        let origin = cfg.get("gateway_origin").and_then(|v| v.as_str());
        let device_id = cfg.get("device_id").and_then(|v| v.as_str());
        let secret_opt = storage::load_device_secret_dpapi(&data_dir).ok();
        let secret = secret_opt
            .as_deref()
            .or_else(|| cfg.get("device_secret").and_then(|v| v.as_str()));
        let server_confirmed = cfg
            .get("server_confirmed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let (orig, did, sec) = match (origin, device_id, secret) {
            (Some(o), Some(d), Some(s)) if server_confirmed => {
                (o.to_string(), d.to_string(), s.to_string())
            }
            _ => {
                interruptible_sleep(Duration::from_secs(2), &stop_signal);
                continue;
            }
        };

        let clean_orig = orig.trim_end_matches('/');
        let ws_url = if clean_orig.starts_with("https://") {
            format!("wss://{}/ws", &clean_orig[8..])
        } else if clean_orig.starts_with("http://") {
            format!("ws://{}/ws", &clean_orig[7..])
        } else {
            format!("ws://{}/ws", clean_orig)
        };

        println!("[WS_CONNECT] Konfiqurasiya edilmiş gateway-ə qoşulma cəhdi");
        diagnostics::stage(&data_dir, "WS_CONNECT_START", "");

        // Deadline-bounded connection attempt (5 seconds strict deadline, R2-03)
        match bounded_ws_connect(&ws_url, Duration::from_secs(5), &stop_signal) {
            Ok((mut socket, _response)) => {
                println!(
                    "[WS_CONNECTED] WebSocket əlaqəsi quruldu. Agent autentifikasiyası göndərilir..."
                );
                diagnostics::stage(&data_dir, "WS_CONNECTED", "");
                backoff_delay = Duration::from_secs(1);
                consecutive_ws_fails = 0;

                // 1. Initial Auth Frame (token redacted from public console output)
                let auth_payload = serde_json::json!({
                    "type": "auth",
                    "role": "agent",
                    "device_id": did,
                    "token": sec,
                    "version": worker_release_version()
                });
                if let Err(e) = socket.send(Message::Text(auth_payload.to_string())) {
                    eprintln!("[WS_AUTH_SEND_ERROR] {}", e);
                    continue;
                }

                // Set 5-second timeout for auth response
                set_stream_timeout(socket.get_mut(), Some(Duration::from_secs(5)));
                let mut authenticated = false;
                match socket.read() {
                    Ok(Message::Text(resp_text)) => {
                        if let Ok(resp_json) =
                            serde_json::from_str::<serde_json::Value>(&resp_text)
                        {
                            if resp_json.get("type").and_then(|v| v.as_str()) == Some("auth_ok") {
                                authenticated = true;
                                println!("[WS_AUTH_OK] Server agent autentifikasiyasını təsdiqlədi.");
                                diagnostics::stage(&data_dir, "WS_AUTH_OK", "");
                            } else {
                                eprintln!("[WS_AUTH_REJECTED] Server cavabı qeyri-kafi oldu.");
                            }
                        }
                    }
                    Ok(_) => {
                        eprintln!("[WS_AUTH_UNEXPECTED_FRAME] E_UNEXPECTED_FRAME");
                    }
                    Err(e) => {
                        eprintln!("[WS_AUTH_READ_ERROR] {}", e);
                    }
                }

                if !authenticated {
                    let _ = socket.close(None);
                    interruptible_sleep(Duration::from_secs(2), &stop_signal);
                    continue;
                }

                // 2. Set stream timeout to 200ms for responsive polling loop
                set_stream_timeout(socket.get_mut(), Some(Duration::from_millis(200)));

                // 3. Flush any pending results from local durable outbox immediately
                for pending_res in load_pending_results(&data_dir) {
                    if pending_res.device_id == did {
                        let res_frame = serde_json::json!({
                            "type": "result",
                            "command_id": pending_res.command_id,
                            "device_id": did,
                            "success": pending_res.success,
                            "status": pending_res.status,
                            "attempt_id": pending_res.attempt_id
                        });
                        let _ = socket.send(Message::Text(res_frame.to_string()));
                    }
                }

                // 4. Active Session Loop
                let mut last_heartbeat = Instant::now() - Duration::from_secs(30);
                let mut last_activity = Instant::now();
                let mut last_cfg_check = Instant::now();
                let mut last_outbox_retry = Instant::now();
                let mut last_locked_state = lock_engine::is_workstation_locked();

                while stop_signal.load(Ordering::SeqCst) && crate::RUNNING.load(Ordering::SeqCst) {
                    if crate::REMOTE_PAUSED.load(Ordering::SeqCst) {
                        break;
                    }

                    // A. Heartbeat / Pong dead-connection timeout (60s)
                    if last_activity.elapsed() >= Duration::from_secs(60) {
                        eprintln!("[WS_HEARTBEAT_TIMEOUT] 60 saniyə ərzində serverdən fəaliyyət qeydə alınmadı, bağlantı ləğv edilir.");
                        let _ = socket.close(None);
                        break;
                    }

                    // B. Hot-reload config / credential check (every 2 seconds)
                    if last_cfg_check.elapsed() >= Duration::from_secs(2) {
                        last_cfg_check = Instant::now();
                        if let Ok(cur_raw) = fs::read_to_string(&cfg_file) {
                            if let Ok(cur_cfg) =
                                serde_json::from_str::<serde_json::Value>(&cur_raw)
                            {
                                let cur_orig = cur_cfg
                                    .get("gateway_origin")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let cur_did = cur_cfg
                                    .get("device_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let cur_sec_opt =
                                    storage::load_device_secret_dpapi(&data_dir).ok();
                                let cur_sec = cur_sec_opt
                                    .as_deref()
                                    .or_else(|| {
                                        cur_cfg.get("device_secret").and_then(|v| v.as_str())
                                    })
                                    .unwrap_or("");

                                if cur_orig != orig || cur_did != did || cur_sec != sec {
                                    println!("[WS_CONFIG_CHANGED] Konfiqurasiya dəyişdi! Aktiv socket bağlanır və yenilənir...");
                                    let _ = socket.close(None);
                                    break;
                                }
                            }
                        }
                    }

                    // C. Check for finished execution results to send
                    while let Ok(res) = result_rx.try_recv() {
                        let res_frame = serde_json::json!({
                            "type": "result",
                            "command_id": res.command_id,
                            "device_id": did,
                            "success": res.success,
                            "status": res.status,
                            "attempt_id": res.attempt_id
                        });
                        println!(
                            "[WS_SEND_RESULT] Nəticə serverə göndərilir: ID={}",
                            res.command_id
                        );
                        if let Err(e) = socket.send(Message::Text(res_frame.to_string())) {
                            eprintln!("[WS_SEND_RESULT_ERROR] {}", e);
                            break;
                        }
                    }

                    if last_outbox_retry.elapsed() >= Duration::from_secs(2) {
                        last_outbox_retry = Instant::now();
                        for res in load_pending_results(&data_dir).into_iter().filter(|r| r.device_id == did) {
                            let frame = serde_json::json!({"type":"result", "command_id":res.command_id,
                                "success":res.success, "status":res.status, "attempt_id":res.attempt_id});
                            if socket.send(Message::Text(frame.to_string())).is_err() { break; }
                        }
                    }

                    // D. Periodic Heartbeat / State Update (every 25 seconds or on locked state change)
                    let current_locked = lock_engine::is_workstation_locked();
                    if last_heartbeat.elapsed() >= Duration::from_secs(25)
                        || current_locked != last_locked_state
                    {
                        last_locked_state = current_locked;
                        last_heartbeat = Instant::now();
                        let state_frame = serde_json::json!({
                            "type": "state",
                            "worker_version": worker_release_version(),
                            "locked": current_locked,
                            "pin_ready": storage::credential_ready(&data_dir)
                        });
                        if let Err(e) = socket.send(Message::Text(state_frame.to_string())) {
                            eprintln!("[WS_HEARTBEAT_SEND_ERROR] {}", e);
                            break;
                        }
                    }

                    // E. Receive incoming frames
                    match socket.read() {
                        Ok(Message::Text(txt)) => {
                            last_activity = Instant::now();
                            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&txt) {
                                match msg.get("type").and_then(|v| v.as_str()) {
                                    Some("update_available") => {
                                        let version = msg.get("version").and_then(|v| v.as_str()).unwrap_or("");
                                        let release = msg.get("release_id").and_then(|v| v.as_str()).unwrap_or("");
                                        let active = fs::read(data_dir.join("update_journal.json")).ok()
                                            .and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok())
                                            .and_then(|v| v.get("active_version").and_then(|v| v.as_str()).map(String::from))
                                            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
                                        if release.len() == 64 && release.bytes().all(|c| c.is_ascii_hexdigit())
                                            && crate::recovery_engine::compare_semver(version, &active) == std::cmp::Ordering::Greater {
                                            // Notification is only a wake-up hint, never executable content.
                                            // The SYSTEM host re-fetches from its configured origin and verifies signatures.
                                            let temporary = data_dir.join("update_requested.tmp");
                                            if fs::write(&temporary, release.as_bytes()).is_ok() {
                                                let _ = atomic_replace_file(&temporary, &data_dir.join("update_requested"));
                                                println!("[UPDATE_NOTICE] Yeni imzalı buraxılışın yoxlanması istəndi");
                                            }
                                        }
                                    }
                                    Some("command") => {
                                        let cmd_id = msg
                                            .get("command_id")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        let action = msg
                                            .get("action")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("");
                                        if !cmd_id.is_empty() && !action.is_empty() {
                                            if handled_set.contains(cmd_id) {
                                                println!(
                                                    "[WS_COMMAND_DEDUP] Təkrar əmr aşkarlandı (ID={}), icra edilmir.",
                                                    cmd_id
                                                );
                                            } else {
                                                if let Err(_) = record_in_flight(&data_dir, &CommandTask {
                                                    command_id: cmd_id.to_string(), action: action.to_string(), device_id: did.clone()
                                                }) {
                                                    eprintln!("[COMMAND_ACCEPT_BLOCKED] E_JOURNAL_WRITE");
                                                    continue;
                                                }
                                                record_handled_command(
                                                    &data_dir,
                                                    &mut handled_set,
                                                    &mut handled_order,
                                                    cmd_id,
                                                );
                                                println!(
                                                    "[WS_COMMAND_DISPATCH] Yeni əmr qəbul edildi: ID={}, Action={}",
                                                    cmd_id, action
                                                );
                                                let mut q = queue
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner());
                                                q.enqueue_coalesced(
                                                    CommandTask {
                                                        command_id: cmd_id.to_string(),
                                                        action: action.to_string(),
                                                        device_id: did.clone(),
                                                    },
                                                    &data_dir,
                                                    Some(&result_tx),
                                                );
                                            }
                                        }
                                    }
                                    Some("result_ack") => {
                                        if let Some(acked_cmd) =
                                            msg.get("command_id").and_then(|v| v.as_str())
                                        {
                                            println!(
                                                "[WS_RESULT_ACK] Server əmrin nəticəsini təsdiqlədi: {}",
                                                acked_cmd
                                            );
                                            let _ = remove_pending_result(&data_dir, acked_cmd);
                                        }
                                    }
                                    Some("ping") => {
                                        let _ = socket
                                            .send(Message::Text(r#"{"type":"pong"}"#.to_string()));
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(Message::Ping(payload)) => {
                            last_activity = Instant::now();
                            let _ = socket.send(Message::Pong(payload));
                        }
                        Ok(Message::Pong(_)) => {
                            last_activity = Instant::now();
                        }
                        Ok(Message::Close(cf)) => {
                            let _ = cf;
                            println!("[WS_CLOSED_BY_SERVER] Bağlantı bağlandı");
                            break;
                        }
                        Err(tungstenite::Error::Io(e))
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            // Timeout, continue loop
                        }
                        Err(e) => {
                            eprintln!("[WS_READ_ERROR] {}", e);
                            break;
                        }
                        _ => {}
                    }
                }

                let _ = socket.close(None);
                println!("[WS_SESSION_END] WebSocket sessiyası başa çatdı.");
            }
            Err(e) => {
                consecutive_ws_fails += 1;
                diagnostics::stage(&data_dir, "WS_CONNECT_FAILED", &format!("{}", e));
                eprintln!("[WS_CONNECT_FAILED] Cəhd {}: {}", consecutive_ws_fails, e);

                // If consecutive WS connection fails, perform limited, bounded HTTP poll and result flush (Section C.5)
                if consecutive_ws_fails >= 2 {
                    diagnostics::stage(&data_dir, "TRANSPORT_FALLBACK_HTTP", "");
                    println!(
                        "[TRANSPORT_FALLBACK_HTTP] Bounded HTTP poll icra edilir (fails={})",
                        consecutive_ws_fails
                    );

                    // Flush any pending results over HTTP
                    for pending_res in load_pending_results(&data_dir) {
                        let result_url = format!("{}/agent/result", orig.trim_end_matches('/'));
                        if let Ok(resp) = ureq::post(&result_url)
                            .timeout(Duration::from_secs(4))
                            .set("Authorization", &format!("Bearer {}", sec))
                            .send_json(serde_json::json!({
                                "command_id": pending_res.command_id,
                                "device_id": did,
                                "success": pending_res.success,
                                "status": pending_res.status,
                                "attempt_id": pending_res.attempt_id
                            }))
                        {
                            if resp.status() == 200 {
                                let _ = remove_pending_result(&data_dir, &pending_res.command_id);
                            }
                        }
                    }

                    // Poll for commands
                    let locked_state = lock_engine::is_workstation_locked();
                    let poll_url = format!("{}/agent/poll", orig.trim_end_matches('/'));
                    let poll_body = serde_json::json!({
                        "device_id": did,
                        "locked": locked_state,
                        "pin_ready": storage::credential_ready(&data_dir)
                    });

                    if let Ok(resp) = ureq::post(&poll_url)
                        .timeout(Duration::from_secs(4))
                        .set("Authorization", &format!("Bearer {}", sec))
                        .send_json(poll_body)
                    {
                        if let Ok(resp_json) = resp.into_json::<serde_json::Value>() {
                            if let Some(cmd) = resp_json.get("command").filter(|c| !c.is_null()) {
                                let cmd_id =
                                    cmd.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                let action =
                                    cmd.get("action").and_then(|v| v.as_str()).unwrap_or("");
                                if !cmd_id.is_empty()
                                    && !action.is_empty()
                                    && !handled_set.contains(cmd_id)
                                {
                                    if let Err(_) = record_in_flight(&data_dir, &CommandTask {
                                                    command_id: cmd_id.to_string(), action: action.to_string(), device_id: did.clone()
                                                }) {
                                                    eprintln!("[COMMAND_ACCEPT_BLOCKED] E_JOURNAL_WRITE");
                                                    continue;
                                                }
                                                record_handled_command(
                                        &data_dir,
                                        &mut handled_set,
                                        &mut handled_order,
                                        cmd_id,
                                    );
                                    let mut q = queue
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    q.enqueue_coalesced(
                                        CommandTask {
                                            command_id: cmd_id.to_string(),
                                            action: action.to_string(),
                                            device_id: did.clone(),
                                        },
                                        &data_dir,
                                        Some(&result_tx),
                                    );
                                }
                            }
                        }
                    }
                }

                // Exponential backoff + jitter (1s .. 30s)
                let jitter_ms = (current_timestamp_secs() % 700) as u64;
                interruptible_sleep(backoff_delay + Duration::from_millis(jitter_ms), &stop_signal);
                backoff_delay = std::cmp::min(backoff_delay * 2, Duration::from_secs(30));
            }
        }
    }

    let _ = worker_handle.join();
    println!("[WS_TRANSPORT_EXIT] WebSocket Transport təmiz başa çatdı.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_child_hook() {
        let Ok(root) = std::env::var("WINKEY_CRASH_TEST_DIR") else { return; };
        let root = PathBuf::from(root);
        let task = CommandTask {command_id: "crash-command".into(), device_id: "mock-device".into(), action: "unlock".into()};
        record_in_flight(&root, &task).unwrap();
        if std::env::var("WINKEY_CRASH_PHASE").unwrap() == "result" {
            save_pending_result(&root, &DurableResult { command_id: task.command_id,
                device_id: task.device_id, success: true, status: "PROVEN_MOCK_SUCCESS".into(),
                attempt_id: String::new(), created_at: 1 }).unwrap();
        }
        // Abrupt child exit: no Drop, no recovery. Absolutely no physical input.
        std::process::exit(73);
    }

    #[test]
    fn durable_receipt_survives_child_exit_and_preserves_proven_result() {
        for phase in ["receipt", "result"] {
            let root = std::env::temp_dir().join(format!("winkey-crash-{}", uuid::Uuid::new_v4()));
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "ws_transport::tests::crash_child_hook"])
                .env("WINKEY_CRASH_TEST_DIR", &root).env("WINKEY_CRASH_PHASE", phase)
                .status().unwrap();
            assert_eq!(status.code(), Some(73));
            assert_eq!(load_in_flight_tasks(&root).len(), 1);
            recover_in_flight_tasks_on_startup(&root);
            let results = load_pending_results(&root);
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].status, if phase == "result" {"PROVEN_MOCK_SUCCESS"} else {"INDETERMINATE_CRASH_RECOVERY"});
            assert!(load_in_flight_tasks(&root).is_empty());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn journal_corruption_blocks_new_receipts_and_preserves_recovery() {
        let root = std::env::temp_dir().join(format!("winkey-fault-{}", uuid::Uuid::new_v4()));
        let task = CommandTask {command_id: "fault".into(), device_id: "mock".into(), action: "unlock".into()};
        record_in_flight(&root, &task).unwrap();
        let path = get_outbox_path(&root);
        fs::write(&path, b"corrupt evidence").unwrap();
        assert!(record_in_flight(&root, &task).is_err());
        recover_in_flight_tasks_on_startup(&root);
        assert_eq!(load_in_flight_tasks(&root).len(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"corrupt evidence");
        assert!(remove_pending_result(&root, "fault").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn failed_atomic_replace_preserves_previous_result() {
        use std::os::windows::fs::OpenOptionsExt;
        let root = std::env::temp_dir().join(format!("winkey-replace-fault-{}", uuid::Uuid::new_v4()));
        let mut result = DurableResult {command_id:"first".into(), device_id:"mock".into(),
            success:true, status:"MOCK_OK".into(), attempt_id:String::new(), created_at:1};
        save_pending_result(&root, &result).unwrap();
        let path = get_outbox_path(&root);
        let before = fs::read(&path).unwrap();
        // A real Windows sharing violation prevents replacement, not a model stub.
        let held = OpenOptions::new().read(true).share_mode(1 | 2).open(&path).unwrap();
        result.command_id = "second".into();
        assert!(save_pending_result(&root, &result).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(held);
        save_pending_result(&root, &result).unwrap();
        assert_eq!(load_pending_results(&root).len(), 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_queue_receipt_never_reaches_mock_execution() {
        let root = std::env::temp_dir().join(format!("winkey-expired-{}", uuid::Uuid::new_v4()));
        let task = CommandTask {command_id:"stale".into(), device_id:"mock".into(), action:"mock".into()};
        record_in_flight(&root,&task).unwrap();
        let mut receipts = load_in_flight_tasks(&root);
        receipts[0].started_at = current_timestamp_secs()-60;
        fs::write(get_in_flight_path(&root),serde_json::to_vec(&receipts).unwrap()).unwrap();
        let queue = Arc::new(Mutex::new(ExecutionQueue::new(4)));
        queue.lock().unwrap().enqueue_coalesced(task,&root,None);
        let stop = Arc::new(AtomicBool::new(true));
        let (tx,rx)=sync_channel(4);
        let worker_root=root.clone(); let worker_stop=stop.clone();
        let worker=thread::spawn(move || run_execution_worker(queue,tx,true,worker_root,worker_stop));
        let result=rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.status,"EXPIRED_BEFORE_EXECUTION");
        assert!(!result.success);
        stop.store(false,Ordering::SeqCst);
        worker.join().unwrap();
        assert!(load_in_flight_tasks(&root).is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn silent_upgrade_deadline_closes_socket_repeatedly() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut buffer = [0u8; 4096];
                loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => {},
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                        Err(e) => panic!("Client leaked silent-upgrade socket: {}", e),
                    }
                }
            }
        });
        let stop = Arc::new(AtomicBool::new(true));
        for attempt in 0..4 {
            let start = Instant::now();
            let scheme = if attempt % 2 == 0 { "ws" } else { "wss" };
            assert!(bounded_ws_connect(&format!("{}://{}/ws", scheme, address), Duration::from_millis(150), &stop).is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
        }
        server.join().unwrap();
    }

    #[test]
    fn stop_interrupts_silent_upgrade_without_detached_connect_thread() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(true));
        let cancel = stop.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(100));
            cancel.store(false, Ordering::SeqCst);
            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut buffer = [0;4096];
            while let Ok(count) = stream.read(&mut buffer) { if count == 0 { return; } }
        });
        let start = Instant::now();
        assert!(bounded_ws_connect(&format!("ws://{}/ws", address), Duration::from_secs(5), &stop).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn test_outbox_atomic_durable_save_and_remove() {
        let tmp = std::env::temp_dir()
            .join(format!("winkey_test_outbox_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&tmp);

        let res1 = DurableResult {
            command_id: "cmd_01".to_string(),
            device_id: "dev_01".to_string(),
            success: true,
            status: "SUCCESS".to_string(),
            attempt_id: "att_1".to_string(),
            created_at: current_timestamp_secs(),
        };
        let res2 = DurableResult {
            command_id: "cmd_02".to_string(),
            device_id: "dev_01".to_string(),
            success: false,
            status: "FAILED".to_string(),
            attempt_id: "att_2".to_string(),
            created_at: current_timestamp_secs(),
        };

        // Save
        assert!(save_pending_result(&tmp, &res1).is_ok());
        assert!(save_pending_result(&tmp, &res2).is_ok());

        let loaded = load_pending_results(&tmp);
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&res1));
        assert!(loaded.contains(&res2));

        // Remove 1
        assert!(remove_pending_result(&tmp, "cmd_01").is_ok());
        let loaded2 = load_pending_results(&tmp);
        assert_eq!(loaded2.len(), 1);
        assert_eq!(loaded2[0].command_id, "cmd_02");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_outbox_corruption_backup_recovery() {
        let tmp = std::env::temp_dir()
            .join(format!("winkey_test_corrupt_{}", uuid::Uuid::new_v4()));
        let outbox_dir = tmp.join("outbox");
        let _ = fs::create_dir_all(&outbox_dir);

        // Write garbage
        let file_path = outbox_dir.join("results.json");
        fs::write(&file_path, "MALFORMED_JSON_CORRUPTED_BYTES{{{").unwrap();

        // Loading should not panic, return empty vec, and create backup
        let loaded = load_pending_results(&tmp);
        assert_eq!(loaded.len(), 0);

        // Verify backup exists
        let entries = fs::read_dir(&outbox_dir).unwrap();
        let backup_exists = entries.into_iter().any(|e| {
            let name = e.unwrap().file_name().to_string_lossy().to_string();
            name.starts_with("results.corrupt.")
        });
        assert!(backup_exists, "Corrupt backup file was not created!");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_persistent_bounded_dedup_log() {
        let tmp = std::env::temp_dir()
            .join(format!("winkey_test_dedup_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&tmp);

        let (mut set, mut order) = load_handled_commands(&tmp);
        assert_eq!(set.len(), 0);

        for i in 0..1050 {
            let id = format!("cmd_dedup_{}", i);
            record_handled_command(&tmp, &mut set, &mut order, &id);
        }

        // Must be bounded
        assert!(set.len() <= MAX_DEDUP_LOG_ENTRIES);
        assert!(order.len() <= MAX_DEDUP_LOG_ENTRIES);

        // Reload from disk to verify persistence
        let (re_set, re_order) = load_handled_commands(&tmp);
        assert_eq!(re_set.len(), set.len());
        assert_eq!(re_order.len(), order.len());
        assert!(re_set.contains("cmd_dedup_1049"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_coalescing_execution_queue_supersedes_unstarted() {
        let tmp = std::env::temp_dir()
            .join(format!("winkey_test_queue_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&tmp);

        let mut q = ExecutionQueue::new(4);
        let task1 = CommandTask {
            command_id: "c1".to_string(),
            action: "lock".to_string(),
            device_id: "dev_a".to_string(),
        };
        let task2 = CommandTask {
            command_id: "c2".to_string(),
            action: "unlock".to_string(),
            device_id: "dev_a".to_string(),
        };

        q.enqueue_coalesced(task1, &tmp, None);
        assert_eq!(q.tasks.len(), 1);

        // Enqueueing task2 should coalesce/supersede unstarted task1 for same device
        q.enqueue_coalesced(task2, &tmp, None);
        assert_eq!(q.tasks.len(), 1);
        assert_eq!(q.tasks[0].command_id, "c2");

        // Verify outbox has SUPERSEDED record for c1
        let outbox = load_pending_results(&tmp);
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].command_id, "c1");
        assert_eq!(outbox[0].status, "SUPERSEDED");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_in_flight_journal_and_crash_recovery() {
        let tmp = std::env::temp_dir()
            .join(format!("winkey_test_inflight_{}", uuid::Uuid::new_v4()));
        let _ = fs::create_dir_all(&tmp);

        let task1 = CommandTask {
            command_id: "cmd_phys".to_string(),
            action: "lock".to_string(),
            device_id: "dev_crash".to_string(),
        };
        let task2 = CommandTask {
            command_id: "cmd_mock".to_string(),
            action: "mock".to_string(),
            device_id: "dev_crash".to_string(),
        };

        // Record in-flight
        assert!(record_in_flight(&tmp, &task1).is_ok());
        assert!(record_in_flight(&tmp, &task2).is_ok());

        let in_flight = load_in_flight_tasks(&tmp);
        assert_eq!(in_flight.len(), 2);

        // Simulate crash recovery
        recover_in_flight_tasks_on_startup(&tmp);

        // In-flight should be cleared
        let in_flight_after = load_in_flight_tasks(&tmp);
        assert_eq!(in_flight_after.len(), 0);

        // Results should contain recovery records
        let results = load_pending_results(&tmp);
        assert_eq!(results.len(), 2);

        let phys_res = results.iter().find(|r| r.command_id == "cmd_phys").unwrap();
        assert_eq!(phys_res.status, "INDETERMINATE_CRASH_RECOVERY");
        assert!(!phys_res.success);

        let mock_res = results.iter().find(|r| r.command_id == "cmd_mock").unwrap();
        assert_eq!(mock_res.status, "INDETERMINATE_CRASH_RECOVERY");
        assert!(!mock_res.success);

        let _ = fs::remove_dir_all(&tmp);
    }
}
