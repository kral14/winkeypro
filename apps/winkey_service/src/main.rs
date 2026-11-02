// WinKey Pro — Windows Service, SCM Dispatcher & Secure IPC Engine
#![allow(unsafe_op_in_unsafe_fn, unused_imports, dead_code)]

pub use recovery_engine::HOST_PROTOCOL_VERSION;

mod embedded_gateway;
mod ipc_engine;
mod lock_engine;
mod recovery_engine;
mod storage;
mod diagnostics;
mod helper_peer;
mod ws_transport;

use std::ffi::c_void;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT,
    INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_PAUSE_CONTINUE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PAUSE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_PAUSED, SERVICE_PAUSE_PENDING,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
};

use ipc_engine::{
    build_narrow_user_channel_sddl, create_secure_overlapped_pipe, extract_os_client_identity,
    get_current_user_sid, win32, IpcCommand, IpcPeerIdentity, IpcResponse, IpcSecurityPolicy,
    ScopedHandle, MAX_IPC_FRAME_PAYLOAD,
};

static RUNNING: AtomicBool = AtomicBool::new(true);
static REMOTE_PAUSED: AtomicBool = AtomicBool::new(false);
static mut SERVICE_STATUS_H: SERVICE_STATUS_HANDLE = null_mut();
static mut CURRENT_SERVICE_STATUS: SERVICE_STATUS = SERVICE_STATUS {
    dwServiceType: 0x00000010, // SERVICE_WIN32_OWN_PROCESS
    dwCurrentState: SERVICE_STOPPED,
    dwControlsAccepted: 0,
    dwWin32ExitCode: NO_ERROR,
    dwServiceSpecificExitCode: 0,
    dwCheckPoint: 0,
    dwWaitHint: 0,
};

const SERVICE_NAME: &str = "WinKeyService";
const PIPE_NAME: &str = "\\\\.\\pipe\\WinKey_Service_IPC";

fn get_app_data_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("WINKEY_DATA_DIR") {
        let p = PathBuf::from(custom);
        let _ = fs::create_dir_all(&p);
        return p;
    }
    let base = std::env::var("ProgramData")
        .or_else(|_| std::env::var("LOCALAPPDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
    let winkey_dir = base.join("WinKey");
    let _ = fs::create_dir_all(&winkey_dir);
    winkey_dir
}

unsafe fn update_status(state: u32, wait_hint: u32) {
    if SERVICE_STATUS_H.is_null() {
        return;
    }
    CURRENT_SERVICE_STATUS.dwCurrentState = state;
    CURRENT_SERVICE_STATUS.dwWaitHint = wait_hint;
    if state == SERVICE_RUNNING || state == SERVICE_PAUSED {
        CURRENT_SERVICE_STATUS.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PAUSE_CONTINUE;
    } else {
        CURRENT_SERVICE_STATUS.dwControlsAccepted = 0;
    }
    SetServiceStatus(SERVICE_STATUS_H, std::ptr::addr_of_mut!(CURRENT_SERVICE_STATUS));
}

extern "system" {
    fn GetNamedPipeServerProcessId(Pipe: *mut c_void, ServerProcessId: *mut u32) -> i32;
    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
}

const WAIT_OBJECT_0: u32 = 0x00000000;
const WAIT_TIMEOUT: u32 = 0x00000102;

static SCM_DESIRED_STATE: AtomicU32 = AtomicU32::new(0); // 0=None, 1=Pause, 2=Resume, 3=Stop

/// Native Bounded Overlapped Pipe Client Açılışı və Fail-Closed Server PID Trust Binding
fn open_secure_overlapped_pipe_client(expected_pid: Option<u32>) -> Result<*mut c_void, String> {
    let pipe_w: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h_pipe = win32::CreateFileW(
            pipe_w.as_ptr(),
            win32::PIPE_MIN_USER_CHANNEL_MASK,
            0,
            null_mut(),
            3, // OPEN_EXISTING
            0x40000000 | 0x00110000, // FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION
            null_mut(),
        );
        if h_pipe.is_null() || h_pipe == INVALID_HANDLE_VALUE {
            return Err("E_PIPE_OPEN_FAILED".to_string());
        }

        // Server Process ID Trust Binding (Fail-Closed)
        let mut server_pid = 0u32;
        if GetNamedPipeServerProcessId(h_pipe, &mut server_pid) == 0 {
            win32::CloseHandle(h_pipe);
            return Err("E_GET_SERVER_PID_FAILED_FAIL_CLOSED".to_string());
        }

        if let Some(exp_pid) = expected_pid {
            if server_pid != exp_pid {
                eprintln!("[TRUST_BINDING_REJECT] Rogue pipe server aşkarlandı! exp_pid={}, actual_server_pid={}", exp_pid, server_pid);
                // Rogue pipe-a sıfır bayt payload ötürülməsi zəmanəti: dərhal bağlanır
                win32::CloseHandle(h_pipe);
                return Err(format!("E_SERVER_PID_MISMATCH_ROGUE_PIPE: exp={}, act={}", exp_pid, server_pid));
            }
        }

        Ok(h_pipe)
    }
}

/// Native Bounded Overlapped Write və Read Əməliyyatı (Single Deadline & CancelIoEx Terminal Drain)
fn ipc_overlapped_write_and_read(h_pipe: *mut c_void, request: &[u8], timeout_ms: u32) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    let remaining_ms = || deadline.saturating_duration_since(Instant::now()).as_millis().min(u32::MAX as u128) as u32;
    unsafe {
        // 1. Bounded Overlapped Write
        let h_write_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
        if h_write_event.is_null() {
            return Err("E_CREATE_EVENT_FAILED".to_string());
        }
        let mut ov_w: win32::OVERLAPPED = std::mem::zeroed();
        ov_w.h_event = h_write_event;

        let mut written = 0u32;
        let w_res = win32::WriteFile(h_pipe, request.as_ptr(), request.len() as u32, &mut written, &mut ov_w);
        if w_res == 0 {
            let err = win32::GetLastError();
            if err == win32::ERROR_IO_PENDING {
                let wait = WaitForSingleObject(h_write_event, remaining_ms());
                if wait != WAIT_OBJECT_0 {
                    win32::CancelIoEx(h_pipe, &mut ov_w);
                    let mut dummy = 0u32;
                    let _ = win32::GetOverlappedResult(h_pipe, &mut ov_w, &mut dummy, 1);
                    win32::CloseHandle(h_write_event);
                    return Err("E_WRITE_TIMEOUT".to_string());
                }
                if win32::GetOverlappedResult(h_pipe, &mut ov_w, &mut written, 0) == 0 {
                    let err = win32::GetLastError();
                    win32::CloseHandle(h_write_event);
                    return Err(format!("E_WRITE_COMPLETION_FAILED: {}", err));
                }
            } else {
                win32::CloseHandle(h_write_event);
                return Err(format!("E_WRITE_FAILED: {}", err));
            }
        }
        win32::CloseHandle(h_write_event);
        if written as usize != request.len() {
            return Err("E_PARTIAL_WRITE".to_string());
        }

        // 2. Bounded Overlapped Read
        let h_read_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
        if h_read_event.is_null() {
            return Err("E_CREATE_EVENT_FAILED".to_string());
        }
        let mut ov_r: win32::OVERLAPPED = std::mem::zeroed();
        ov_r.h_event = h_read_event;

        let mut buf = [0u8; 1024];
        let mut read_bytes = 0u32;
        let r_res = win32::ReadFile(h_pipe, buf.as_mut_ptr(), buf.len() as u32, &mut read_bytes, &mut ov_r);
        if r_res == 0 {
            let err = win32::GetLastError();
            if err == win32::ERROR_IO_PENDING {
                let wait = WaitForSingleObject(h_read_event, remaining_ms());
                if wait != WAIT_OBJECT_0 {
                    win32::CancelIoEx(h_pipe, &mut ov_r);
                    let mut dummy = 0u32;
                    let _ = win32::GetOverlappedResult(h_pipe, &mut ov_r, &mut dummy, 1);
                    win32::CloseHandle(h_read_event);
                    return Err("E_READ_TIMEOUT".to_string());
                }
                let mut trans = 0u32;
                if win32::GetOverlappedResult(h_pipe, &mut ov_r, &mut trans, 0) != 0 {
                    read_bytes = trans;
                } else {
                    let err = win32::GetLastError();
                    win32::CloseHandle(h_read_event);
                    return Err(format!("E_READ_COMPLETION_FAILED: {}", err));
                }
            } else {
                win32::CloseHandle(h_read_event);
                return Err(format!("E_READ_FAILED: {}", err));
            }
        }
        win32::CloseHandle(h_read_event);

        if read_bytes > 0 {
            Ok(String::from_utf8_lossy(&buf[..read_bytes as usize]).to_string())
        } else {
            Err("E_EMPTY_RESPONSE".to_string())
        }
    }
}

fn send_control_command_to_worker(expected_pid: Option<u32>, cmd: &str) -> bool {
    let h_pipe = match open_secure_overlapped_pipe_client(expected_pid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[CONTROL_SEND_ERR] Boru açıla bilmədi və ya server PID rədd edildi: {}", e);
            return false;
        }
    };

    let req_line = format!("{}\n", cmd);
    let res = ipc_overlapped_write_and_read(h_pipe, req_line.as_bytes(), 800);
    unsafe { win32::CloseHandle(h_pipe); }

    match res {
        Ok(resp) => {
            // Strict typed ACK validation (IpcResponse::Ack)
            match serde_json::from_str::<crate::ipc_engine::IpcResponse>(resp.trim()) {
                Ok(crate::ipc_engine::IpcResponse::Ack) => {
                    println!("[CONTROL_STRICT_ACK] Worker əmri üçün dəqiq typed ACK təsdiqləndi: {}", cmd);
                    true
                }
                Ok(other) => {
                    eprintln!("[CONTROL_TYPED_FAIL] Worker ACK yerinə fərqli cavab qaytardı: {:?}", other);
                    false
                }
                Err(e) => {
                    eprintln!("[CONTROL_PARSE_FAIL] Worker cavabı typed IpcResponse deyil: {} (xəta: {})", resp, e);
                    false
                }
            }
        }
        Err(e) => {
            eprintln!("[CONTROL_TIMEOUT_OR_ERR] Worker əmrə cavab vermədi: {}", e);
            false
        }
    }
}

fn probe_worker_health(expected_pid: Option<u32>) -> bool {
    let h_pipe = match open_secure_overlapped_pipe_client(expected_pid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[HEALTH_PROBE_FAIL] {}", e);
            return false;
        }
    };

    let req = b"STATUS\n";
    let res = ipc_overlapped_write_and_read(h_pipe, req, 800);
    unsafe { win32::CloseHandle(h_pipe); }

    match res {
        Ok(resp) => {
            // Strict typed validation: IpcResponse::Status { state == "RUNNING", .. }
            match serde_json::from_str::<crate::ipc_engine::IpcResponse>(resp.trim()) {
                Ok(crate::ipc_engine::IpcResponse::Status { state, .. }) if state == "RUNNING" => true,
                Ok(other) => {
                    eprintln!("[HEALTH_PROBE_STRICT_FAIL] Worker Status cavabı RUNNING deyil: {:?}", other);
                    false
                }
                Err(e) => {
                    // Fallback JSON nested parsing
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp) {
                        let state = json.get("state")
                            .or_else(|| json.get("Status").and_then(|s| s.get("state")))
                            .and_then(|v| v.as_str());
                        if state == Some("RUNNING") {
                            return true;
                        }
                    }
                    eprintln!("[HEALTH_PROBE_PARSE_FAIL] Cavab parse edilmədi: {} (xəta: {})", resp, e);
                    false
                }
            }
        }
        Err(e) => {
            eprintln!("[HEALTH_PROBE_ERR] Health probe cavab vermədi: {}", e);
            false
        }
    }
}

unsafe extern "system" fn service_ctrl_handler(
    dw_control: u32,
    _dw_event_type: u32,
    _lp_event_data: *mut c_void,
    _lp_context: *mut c_void,
) -> u32 {
    match dw_control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            update_status(SERVICE_STOP_PENDING, 3000);
            RUNNING.store(false, Ordering::SeqCst);
            SCM_DESIRED_STATE.store(3, Ordering::SeqCst);
            NO_ERROR
        }
        SERVICE_CONTROL_PAUSE => {
            update_status(SERVICE_PAUSE_PENDING, 2000);
            SCM_DESIRED_STATE.store(1, Ordering::SeqCst);
            NO_ERROR
        }
        SERVICE_CONTROL_CONTINUE => {
            update_status(SERVICE_START_PENDING, 2000);
            SCM_DESIRED_STATE.store(2, Ordering::SeqCst);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            SetServiceStatus(SERVICE_STATUS_H, std::ptr::addr_of_mut!(CURRENT_SERVICE_STATUS));
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

// REM-025: Qeydiyyatdan keçmiş sahib istifadəçi SID-sinin qorunan şəkildə həlli (Zero IU fallback)
fn resolve_enrolled_owner_sid(data_dir: &std::path::Path) -> Option<String> {
    // 1. data_dir/owner.sid faylından
    let sid_file = data_dir.join("owner.sid");
    if let Ok(content) = fs::read_to_string(&sid_file) {
        let trimmed = content.trim_start_matches('\u{feff}').trim();
        if trimmed.starts_with("S-1-5-21-") {
            return Some(trimmed.to_string());
        }
    }
    // 2. data_dir/config.json daxilindən
    let cfg_file = data_dir.join("config.json");
    if let Ok(content) = fs::read_to_string(&cfg_file) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(s) = json.get("owner_sid").and_then(|v| v.as_str()) {
                if s.starts_with("S-1-5-21-") {
                    return Some(s.to_string());
                }
            }
        }
    }
    // 3. Aktiv konsol sessiyası interaktiv istifadəçi tokenindən
    if let Some(sess_id) = lock_engine::get_active_console_session() {
        if let Ok(tok) = lock_engine::get_target_session_user_token(sess_id) {
            if let Ok(sid_str) = lock_engine::get_token_sid_string(tok.raw()) {
                if sid_str.starts_with("S-1-5-21-") {
                    let _ = fs::write(&sid_file, &sid_str);
                    return Some(sid_str);
                }
            }
        }
    }
    // 4. Standalone / test rejimində cari proses istifadəçi SID-si
    if let Ok(sid_str) = get_current_user_sid() {
        if sid_str.starts_with("S-1-5-21-") {
            return Some(sid_str);
        }
    }
    None
}

// Bounded Overlapped I/O və Təhlükəsiz IPC Dinləyicisi (data_dir parametrli)
fn run_ipc_worker_loop(stop_signal: Arc<AtomicBool>, is_mock: bool, data_dir: PathBuf) {
    println!("[IPC_WORKER] WinKey B.2 Təhlükəsiz IPC Dinləyicisi başladılır...");

    // REM-028: Bootstrap və ya clean-machine first-run zamanı owner hələ yazılmayıbsa, UNENROLLED_IDLE vəziyyətində gözlənilir
    let mut resolved_owner: Option<String> = None;
    while stop_signal.load(Ordering::SeqCst) && RUNNING.load(Ordering::SeqCst) {
        if let Some(sid) = resolve_enrolled_owner_sid(&data_dir) {
            resolved_owner = Some(sid);
            break;
        }
        println!("[IPC_BOOTSTRAP] Qeydiyyatdan keçmiş owner SID tapılmadı (UNENROLLED_IDLE). Quraşdırıcı və ya Desktop qeydiyyatı gözlənilir...");
        thread::sleep(Duration::from_millis(1000));
    }

    let owner_sid = match resolved_owner {
        Some(sid) => sid,
        None => {
            println!("[IPC_WORKER] Dayandırılma siqnalı səbəbilə IPC dinləyicisi sonlandı.");
            return;
        }
    };

    let sddl = match build_narrow_user_channel_sddl(&owner_sid) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[IPC_SECURITY_FATAL] Dar DACL qurula bilmədi: {e}. Fail-closed dayandırılır.");
            return;
        }
    };
    println!("[IPC_SECURITY] Dar DACL tətbiq edildi: {sddl}");

    let target_session = lock_engine::get_active_console_session();
    let policy = IpcSecurityPolicy::new(Some(owner_sid), target_session);

    unsafe {
        let h_stop_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
        let _stop_guard = ScopedHandle::new(h_stop_event);

        while stop_signal.load(Ordering::SeqCst) && RUNNING.load(Ordering::SeqCst) {
            let h_pipe = match create_secure_overlapped_pipe(PIPE_NAME, &sddl) {
                Ok(h) => h,
                Err(e) => {
                    if e.contains("os error 5") || e.contains("Erişim engellendi") || e.contains("Access is denied") {
                        eprintln!("[IPC_CONFLICT] Named Pipe artıq aktiv sistem xidməti (WinKeyService) tərəfindən idarə olunur. Təkrar IPC dinləməsi gözlədilir.");
                        thread::sleep(Duration::from_secs(5));
                    } else {
                        eprintln!("[IPC_ERROR] Pipe yaradıla bilmədi: {e}");
                        thread::sleep(Duration::from_millis(500));
                    }
                    continue;
                }
            };

            let h_connect_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
            let mut ov_connect: win32::OVERLAPPED = std::mem::zeroed();
            ov_connect.h_event = h_connect_event;

            let conn_res = win32::ConnectNamedPipe(h_pipe, &mut ov_connect);
            let mut is_connected = false;

            if conn_res != 0 {
                is_connected = true;
            } else {
                let err = win32::GetLastError();
                if err == win32::ERROR_PIPE_CONNECTED {
                    is_connected = true;
                } else if err == win32::ERROR_IO_PENDING {
                    // Bounded connect wait (500ms intervals to honor stop_signal)
                    let start_wait = Instant::now();
                    while start_wait.elapsed() < Duration::from_secs(3) {
                        if !stop_signal.load(Ordering::SeqCst) || !RUNNING.load(Ordering::SeqCst) {
                            win32::CancelIoEx(h_pipe, &mut ov_connect);
                            break;
                        }
                        let wait_res = win32::WaitForSingleObject(h_connect_event, 250);
                        if wait_res == win32::WAIT_OBJECT_0 {
                            let mut transferred = 0u32;
                            if win32::GetOverlappedResult(h_pipe, &mut ov_connect, &mut transferred, 0) != 0 {
                                is_connected = true;
                            }
                            break;
                        }
                    }
                }
            }

            win32::CloseHandle(h_connect_event);

            if !stop_signal.load(Ordering::SeqCst) || !RUNNING.load(Ordering::SeqCst) {
                win32::DisconnectNamedPipe(h_pipe);
                win32::CloseHandle(h_pipe);
                break;
            }

            if is_connected {
                // Exact Client Identity Yoxlanışı
                let client_ident = extract_os_client_identity(h_pipe);
                let is_authorized = match client_ident {
                    Ok(ref id) => {
                        println!("[IPC_AUTH] Müştəri təsdiqləndi: PID={}, Sessiya={}, SID={}", id.os_client_pid, id.os_client_session_id, id.os_client_sid);
                        policy.validate_os_peer_identity(id).is_ok()
                    }
                    Err(ref err) => {
                        eprintln!("[IPC_AUTH_REJECT] Müştəri kimliyi alına bilmədi: {err}");
                        false
                    }
                };

                if is_authorized {
                    // Bounded ReadFile (maksimum 3000 ms deadline — silent client qoruması)
                    let h_read_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
                    let mut ov_read: win32::OVERLAPPED = std::mem::zeroed();
                    ov_read.h_event = h_read_event;

                    let mut buf = [0u8; MAX_IPC_FRAME_PAYLOAD];
                    let mut read_bytes = 0u32;
                    let read_res = win32::ReadFile(h_pipe, buf.as_mut_ptr(), buf.len() as u32, &mut read_bytes, &mut ov_read);

                    let mut read_success = false;
                    if read_res != 0 {
                        read_success = true;
                    } else if win32::GetLastError() == win32::ERROR_IO_PENDING {
                        let wait_res = win32::WaitForSingleObject(h_read_event, 3000);
                        if wait_res == win32::WAIT_OBJECT_0 {
                            if win32::GetOverlappedResult(h_pipe, &mut ov_read, &mut read_bytes, 0) != 0 {
                                read_success = true;
                            }
                        } else {
                            println!("[IPC_TIMEOUT] Müştəri susdu (Silent Client Timeout 3s) -> I/O ləğv edilir.");
                            win32::CancelIoEx(h_pipe, &mut ov_read);
                        }
                    }
                    win32::CloseHandle(h_read_event);

                    if read_success && read_bytes > 0 {
                        let req_str = String::from_utf8_lossy(&buf[..read_bytes as usize]);
                        let response_dto = if req_str.contains("PING") {
                            serde_json::to_string(&IpcResponse::Ack).unwrap()
                        } else if req_str.trim() == "CREDENTIAL_READY" {
                            serde_json::json!({"credential_ready": storage::credential_ready(&data_dir)}).to_string()
                        } else if req_str.trim() == "CHECK_UPDATE" {
                            match fs::write(data_dir.join("update_requested"), b"manual") {
                                Ok(_) => serde_json::to_string(&IpcResponse::Ack).unwrap(),
                                Err(_) => serde_json::json!({"error":"E_UPDATE_REQUEST_WRITE"}).to_string(),
                            }
                        } else if req_str.trim() == "UPDATE_STATUS" {
                            let journal=fs::read(data_dir.join("update_journal.json")).ok()
                                .and_then(|raw|serde_json::from_slice::<serde_json::Value>(&raw).ok());
                            serde_json::json!({"worker_version":ws_transport::worker_release_version(),
                                "active_version":journal.as_ref().and_then(|j|j.get("active_version")),
                                "phase":journal.as_ref().and_then(|j|j.get("state"))}).to_string()
                        } else if req_str.contains("STATUS") {
                            serde_json::to_string(&IpcResponse::Status {
                                service: "WinKeyService".to_string(),
                                state: "RUNNING".to_string(),
                                session_id: client_ident.as_ref().map(|i| i.os_client_session_id).unwrap_or(0),
                            }).unwrap()
                        } else if req_str.contains("PAUSE") {
                            println!("[IPC_CMD] PAUSE əmri qəbul edildi. Uzaqdan idarə dayandırıldı.");
                            REMOTE_PAUSED.store(true, Ordering::SeqCst);
                            serde_json::to_string(&IpcResponse::Ack).unwrap()
                        } else if req_str.contains("RESUME") {
                            println!("[IPC_CMD] RESUME əmri qəbul edildi. Uzaqdan idarə bərpa edildi.");
                            REMOTE_PAUSED.store(false, Ordering::SeqCst);
                            serde_json::to_string(&IpcResponse::Ack).unwrap()
                        } else if req_str.contains("STOP") {
                            println!("[IPC_CMD] STOP əmri qəbul edildi. Xidmət sonlandırılır...");
                            stop_signal.store(false, Ordering::SeqCst);
                            RUNNING.store(false, Ordering::SeqCst);
                            serde_json::to_string(&IpcResponse::Ack).unwrap()
                        } else if serde_json::from_str::<IpcCommand>(&req_str).map(|command| matches!(command,IpcCommand::RequestPairing {..})).unwrap_or(false) {
                            let outcome = (|| -> Result<serde_json::Value,String> {
                                let IpcCommand::RequestPairing {device_id,gateway_origin}=serde_json::from_str(&req_str).map_err(|_|"E_PAIR_REQUEST_FORMAT")? else {
                                    return Err("E_PAIR_REQUEST_FORMAT".into());
                                };
                                request_pair_code_for_enrolled_device(&data_dir,&device_id,&gateway_origin)
                            })();
                            match outcome {Ok(pair)=>pair.to_string(),Err(code)=>serde_json::json!({"error":code}).to_string()}
                        } else if req_str.contains("ProvisionDevice") {
                            println!("[IPC_PROVISION] Autentifikasiya olunmuş interaktiv istifadəçidən cihaz təminatı qəbul edildi.");
                            if let Ok(IpcCommand::ProvisionDevice { device_id, device_secret, gateway_origin }) = serde_json::from_str::<IpcCommand>(&req_str) {
                                match storage::save_device_secret_dpapi(&data_dir, &device_secret) {
                                    Ok(_) => {
                                        let cfg_file = data_dir.join("config.json");
                                        let mut cfg_val = if cfg_file.exists() {
                                            fs::read_to_string(&cfg_file)
                                                .ok()
                                                .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
                                                .unwrap_or_else(|| serde_json::json!({}))
                                        } else {
                                            serde_json::json!({})
                                        };
                                        cfg_val["device_id"] = serde_json::json!(device_id);
                                        if let Some(origin) = gateway_origin {
                                            cfg_val["gateway_origin"] = serde_json::json!(origin);
                                        }
                                        cfg_val["server_confirmed"] = serde_json::json!(true);
                                        if let Some(obj) = cfg_val.as_object_mut() {
                                            obj.remove("device_secret");
                                        }
                                        let _ = fs::write(&cfg_file, cfg_val.to_string());
                                        serde_json::to_string(&IpcResponse::Ack).unwrap()
                                    }
                                    Err(e) => {
                                        serde_json::to_string(&IpcResponse::Error {
                                            code: "E_DPAPI_PROVISION_FAILED".to_string(),
                                            message: e,
                                        }).unwrap()
                                    }
                                }
                            } else {
                                serde_json::to_string(&IpcResponse::Error {
                                    code: "E_PROVISION_PARSE_ERROR".to_string(),
                                    message: "Provision parametrləri oxunmadı".to_string(),
                                    }).unwrap()
                            }
                        } else if req_str.contains("StoreUserCredential") {
                            println!("[IPC_CREDENTIAL] Autentifikasiya olunmuş istifadəçidən yerli PIN saxlanması qəbul edildi.");
                            if let Ok(IpcCommand::StoreUserCredential { pin }) = serde_json::from_str::<IpcCommand>(&req_str) {
                                match storage::save_user_credential_dpapi(&data_dir, &pin) {
                                    Ok(_) => serde_json::to_string(&IpcResponse::Ack).unwrap(),
                                    Err(e) => serde_json::to_string(&IpcResponse::Error {
                                        code: "E_DPAPI_PIN_FAILED".to_string(),
                                        message: e,
                                    }).unwrap(),
                                }
                            } else {
                                serde_json::to_string(&IpcResponse::Error {
                                    code: "E_PIN_PARSE_ERROR".to_string(),
                                    message: "PIN parametrləri oxunmadı".to_string(),
                                }).unwrap()
                            }
                        } else if req_str.contains("MOCK_UNLOCK") || is_mock {
                            serde_json::to_string(&IpcResponse::ActionExecuted {
                                status: "DEMO_MOCK_ACTION".to_string(),
                                result: "MOCK_UNLOCK əmri demo mühitində uğurla icra olundu".to_string(),
                            }).unwrap()
                        } else {
                            serde_json::to_string(&IpcResponse::Error {
                                code: "E_UNKNOWN_COMMAND".to_string(),
                                message: "Əmr tanınmadı".to_string(),
                            }).unwrap()
                        };

                        let resp_data = format!("{}\n", response_dto);
                        let mut written = 0u32;
                        let mut ov_write: win32::OVERLAPPED = std::mem::zeroed();
                        win32::WriteFile(h_pipe, resp_data.as_ptr(), resp_data.len() as u32, &mut written, &mut ov_write);
                        win32::FlushFileBuffers(h_pipe);
                    }
                } else {
                    // Unauthorized peer: dərhal xəta bildirişi və əlaqənin kəsilməsi
                    let err_resp = "{\"error\":\"E_UNAUTHORIZED_PEER_SID\"}\n";
                    let mut written = 0u32;
                    let mut ov_err: win32::OVERLAPPED = std::mem::zeroed();
                    win32::WriteFile(h_pipe, err_resp.as_ptr(), err_resp.len() as u32, &mut written, &mut ov_err);
                    win32::FlushFileBuffers(h_pipe);
                }

                win32::DisconnectNamedPipe(h_pipe);
            }

            win32::CloseHandle(h_pipe);
        }
    }
    println!("[IPC_WORKER] WinKey IPC Worker təmiz sonlandı.");
}

// Gateway Polling və Real Command Execution Handler
fn request_pair_code_for_enrolled_device(data_dir:&std::path::Path, device_id:&str, gateway_origin:&str) -> Result<serde_json::Value,String> {
    let mut config:serde_json::Value=serde_json::from_slice(&fs::read(data_dir.join("config.json")).map_err(|_|"E_SERVICE_NOT_ENROLLED")?).map_err(|_|"E_SERVICE_NOT_ENROLLED")?;
    let stored_origin=config.get("gateway_origin").and_then(|v|v.as_str()).unwrap_or("").trim_end_matches('/');
    let cloud_origin=config.get("cloud_gateway_origin").and_then(|v|v.as_str()).unwrap_or("").trim_end_matches('/');
    let incoming_origin = gateway_origin.trim_end_matches('/');

    let origin_matches = (stored_origin == incoming_origin) || (!cloud_origin.is_empty() && cloud_origin == incoming_origin);
    if config.get("device_id").and_then(|v|v.as_str())!=Some(device_id) || (!origin_matches && !stored_origin.is_empty()) {
        return Err("E_PAIR_SERVICE_CONTEXT_MISMATCH".into());
    }

    let secret=storage::load_device_secret_dpapi(data_dir).map_err(|_|"E_SERVICE_CREDENTIAL_UNAVAILABLE")?;
    let target_origin = if !stored_origin.is_empty() && stored_origin == incoming_origin { stored_origin } else { incoming_origin };
    let response=ureq::post(&format!("{}/devices/pair-request",target_origin))
        .timeout(Duration::from_secs(5)).set("Authorization",&format!("Bearer {}",secret))
        .send_json(serde_json::json!({"device_id":device_id})).map_err(|_|"E_SERVICE_PAIR_REQUEST_FAILED")?;
    let pair:serde_json::Value=response.into_json().map_err(|_|"E_SERVICE_PAIR_RESPONSE")?;

    if stored_origin != target_origin {
        config["gateway_origin"] = serde_json::json!(target_origin);
        let _ = fs::write(data_dir.join("config.json"), config.to_string());
    }

    // Never return the SYSTEM device secret to the renderer/user process.
    Ok(serde_json::json!({"device_id":device_id,"pair_code":pair.get("pair_code"),"expires_at":pair.get("expires_at")}))
}

#[cfg(test)]
mod pairing_broker_tests {
    use super::*;
    #[test]
    fn broker_uses_enrolled_credential_without_registration_or_secret_response() {
        use std::io::{Read,Write};
        let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin=format!("http://{}",listener.local_addr().unwrap());
        let root=std::env::temp_dir().join(format!("winkey-broker-{}",uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("config.json"),serde_json::to_vec(&serde_json::json!({"device_id":"test-device","gateway_origin":origin})).unwrap()).unwrap();
        storage::save_device_secret_dpapi(&root,"FAKE_TEST_AGENT_SECRET").unwrap();
        assert!(request_pair_code_for_enrolled_device(&root,"other-device",&origin).unwrap_err().contains("CONTEXT_MISMATCH"));
        assert!(request_pair_code_for_enrolled_device(&root,"test-device","http://invalid.example").unwrap_err().contains("CONTEXT_MISMATCH"));
        let server=std::thread::spawn(move || {
            let (mut stream,_)=listener.accept().unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut bytes=Vec::new();
            let mut buffer=[0;4096];
            loop {
                let count=stream.read(&mut buffer).unwrap();
                assert!(count>0); bytes.extend_from_slice(&buffer[..count]);
                if let Some(end)=bytes.windows(4).position(|v|v==b"\r\n\r\n") {
                    let headers=String::from_utf8_lossy(&bytes[..end]);
                    let length=headers.lines().find_map(|line|line.to_lowercase().strip_prefix("content-length:").and_then(|v|v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if bytes.len()>=end+4+length {break;}
                }
            }
            let request=String::from_utf8_lossy(&bytes);
            assert!(request.starts_with("POST /devices/pair-request "));
            assert!(request.to_lowercase().contains("authorization: bearer fake_test_agent_secret"));
            let body=r#"{"pair_code":"ABCD-EFGH-JKLM","expires_at":9999999999,"device_secret":"MUST_NOT_LEAVE_BROKER"}"#;
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        });
        let pair=request_pair_code_for_enrolled_device(&root,"test-device",&origin).unwrap();
        assert_eq!(pair["pair_code"],"ABCD-EFGH-JKLM");
        assert_eq!(pair["device_id"],"test-device");
        assert!(pair.get("device_secret").is_none());
        server.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

fn update_input_idle(data_dir: &std::path::Path) -> bool {
    match fs::read(data_dir.join("outbox").join("in_flight.json")) {
        Ok(raw) => serde_json::from_slice::<Vec<serde_json::Value>>(&raw).map(|v|v.is_empty()).unwrap_or(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

fn check_and_apply_native_gateway_update(origin: &str, data_dir: &std::path::Path) -> Result<String, String> {
    let clean_orig = origin.trim_end_matches('/');
    let latest_url = format!("{}/updates/latest", clean_orig);

    let resp = match ureq::get(&latest_url).timeout(Duration::from_secs(5)).call() {
        Ok(r) => r,
        Err(e) => return Err(format!("E_GATEWAY_UPDATE_REQUEST_FAILED: {}", e)),
    };

    let body_json: serde_json::Value = match resp.into_json() {
        Ok(j) => j,
        Err(e) => return Err(format!("E_GATEWAY_UPDATE_JSON_PARSE: {}", e)),
    };

    let manifest_val = body_json.get("manifest").ok_or("E_MISSING_MANIFEST_FIELD")?;
    let sig_hex = body_json.get("manifest_sig_hex").and_then(|v| v.as_str()).ok_or("E_MISSING_SIG_FIELD")?;
    let dl_prefix = body_json.get("download_url_prefix").and_then(|v| v.as_str()).unwrap_or("/updates/download");

    let manifest_bytes = if let Some(raw_str) = body_json.get("manifest_raw").and_then(|v| v.as_str()) {
        raw_str.as_bytes().to_vec()
    } else {
        serde_json::to_vec_pretty(manifest_val).map_err(|e| format!("E_SERIALIZE_MANIFEST: {}", e))?
    };
    let mut sig_bytes = Vec::new();
    let trimmed_sig = sig_hex.trim();
    if trimmed_sig.len() == 128 {
        for i in 0..64 {
            let b = u8::from_str_radix(&trimmed_sig[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("E_SIG_HEX_PARSE: {}", e))?;
            sig_bytes.push(b);
        }
    } else {
        return Err("E_INVALID_SIG_HEX_LEN".to_string());
    }

    let files_arr = manifest_val.get("files").and_then(|v| v.as_array()).ok_or("E_MISSING_FILES_LIST")?;
    // Validate authenticity, version and resource limits BEFORE downloading binaries.
    let key = ed25519_dalek::VerifyingKey::from_bytes(&recovery_engine::get_pinned_public_key_bytes()?)
        .map_err(|_| "E_RELEASE_KEY")?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|_| "E_RELEASE_SIGNATURE")?;
    key.verify_strict(&manifest_bytes, &signature).map_err(|_| "E_RELEASE_SIGNATURE")?;
    let verified: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|_| "E_RELEASE_JSON")?;
    if verified != *manifest_val { return Err("E_MANIFEST_MISMATCH".into()); }
    let version = verified.get("version").and_then(|v| v.as_str()).ok_or("E_RELEASE_VERSION")?;
    let journal = fs::read(data_dir.join("update_journal.json")).ok()
        .and_then(|v| serde_json::from_slice::<serde_json::Value>(&v).ok());

    if let Some(state) = journal.as_ref().and_then(|j| j.get("state")).and_then(|v| v.as_str()) {
        if state == "PROBATION" || state == "STAGING" || state == "PENDING_ACTIVATION" {
            diagnostics::stage(data_dir, "UPDATE_DEFERRED", &format!("state={}", state));
            return Err(format!("E_UPDATE_IN_PROGRESS: Cari yenilənmə hələ təsdiqlənməyib (vəziyyət: {}).", state));
        }
    }

    if let Some(proto_val) = verified.get("min_host_protocol_version") {
        let min_proto = match proto_val.as_u64() {
            Some(p) => p,
            None => {
                diagnostics::stage(data_dir, "UPDATE_REJECTED", "E_INVALID_PROTOCOL_VERSION_TYPE");
                return Err("E_INVALID_PROTOCOL_VERSION_TYPE: min_host_protocol_version müsbət tam ədəd olmalıdır".to_string());
            }
        };
        if min_proto > HOST_PROTOCOL_VERSION {
            let err = format!("E_HOST_UPGRADE_REQUIRED: Yeni buraxılış üçün proqram quraşdırıcısının (WinKeySetup.exe) yenilənməsi tələb olunur (tələb: {}, cari: {})", min_proto, HOST_PROTOCOL_VERSION);
            diagnostics::stage(data_dir, "UPDATE_REJECTED", "E_HOST_UPGRADE_REQUIRED");
            let (mut j, _) = recovery_engine::read_or_recover_journal(data_dir, None);
            {
                j.state = "SETUP_REQUIRED".to_string();
                let _ = recovery_engine::save_journal_atomic(data_dir, &j);
            }
            return Err(err);
        }
    }
    if let Some(active) = journal.as_ref().and_then(|j| j.get("active_version")).and_then(|v| v.as_str()) {
        if recovery_engine::compare_semver(version,active) != std::cmp::Ordering::Greater {
            return Err("E_NO_NEWER_RELEASE".into());
        }
    }
    if files_arr.len() > 4096 || files_arr.iter().try_fold(0u64, |sum,f| sum.checked_add(f.get("size")?.as_u64()?)).unwrap_or(u64::MAX) > 256*1024*1024 {
        return Err("E_RELEASE_LIMIT".into());
    }
    let rel_id = format!("rel_{}", version);
    let active_ver = journal.as_ref().and_then(|j| j.get("active_version")).and_then(|v| v.as_str()).unwrap_or("none");
    let mut payload_files = Vec::new();
    let t_dl = Instant::now();

    for f_entry in files_arr {
        let fname = f_entry.get("path").and_then(|v| v.as_str()).ok_or("E_MISSING_FILE_PATH")?;
        if fname.contains("..") || fname.contains('\\') || fname.contains(':') || fname.starts_with('/') {
            return Err("E_RELEASE_PATH".into());
        }
        let dl_url = format!("{}{}/{}", clean_orig, dl_prefix, fname);

        let f_resp = match ureq::get(&dl_url).timeout(Duration::from_secs(10)).call() {
            Ok(r) => r,
            Err(e) => return Err(format!("E_DOWNLOAD_FILE_FAILED_{}: {}", fname, e)),
        };

        let mut content = Vec::new();
        f_resp.into_reader().take(f_entry.get("size").and_then(|v|v.as_u64()).unwrap_or(0)+1).read_to_end(&mut content)
            .map_err(|e| format!("E_READ_DOWNLOAD_STREAM_{}: {}", fname, e))?;

        payload_files.push((fname.to_string(), content));
    }

    let dl_dur = t_dl.elapsed().as_millis() as u64;
    diagnostics::stage(data_dir, "UPDATE_DOWNLOAD_DONE", &format!("rel_id={} prev_ver={} new_ver={} dur_ms={}", rel_id, active_ver, version, dl_dur));

    let t_stage = Instant::now();
    let res = recovery_engine::stage_native_update_bundle(data_dir, &manifest_bytes, &sig_bytes, &payload_files, None);
    let stage_dur = t_stage.elapsed().as_millis() as u64;
    if res.is_ok() {
        diagnostics::stage(data_dir, "UPDATE_STAGE_DONE", &format!("rel_id={} prev_ver={} new_ver={} dur_ms={}", rel_id, active_ver, version, stage_dur));
    } else if let Err(ref e) = res {
        if e.starts_with("E_TARGET_SLOT_IN_USE") || e.starts_with("E_TARGET_SLOT_LOCKED") {
            diagnostics::stage(data_dir, "UPDATE_DEFERRED", &format!("rel_id={} prev_ver={} new_ver={} reason={}", rel_id, active_ver, version, e));
            eprintln!("[HOST_UPDATE_DEFERRED] Hədəf slot istifadədədir və ya kilidlidir, yeniləmə sonrakı dövrə təxirə salındı: {}", e);
        } else {
            diagnostics::stage(data_dir, "UPDATE_STAGE_FAILED", &format!("rel_id={} prev_ver={} new_ver={} err={}", rel_id, active_ver, version, e));
        }
    }
    res
}

fn run_gateway_poller_loop(stop_signal: Arc<AtomicBool>, is_mock: bool, data_dir: PathBuf) {
    let cfg_file = data_dir.join("config.json");
    while stop_signal.load(Ordering::SeqCst) && RUNNING.load(Ordering::SeqCst) {
        if REMOTE_PAUSED.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(800));
            continue;
        }
        if cfg_file.exists() {
            if let Ok(raw) = fs::read_to_string(&cfg_file) {
                if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let origin = cfg.get("gateway_origin").and_then(|v| v.as_str());
                    let device_id = cfg.get("device_id").and_then(|v| v.as_str());
                    let secret_opt = storage::load_device_secret_dpapi(&data_dir).ok();
                    let secret = secret_opt.as_deref().or_else(|| cfg.get("device_secret").and_then(|v| v.as_str()));
                    let server_confirmed = cfg.get("server_confirmed").and_then(|v| v.as_bool()).unwrap_or(false);

                    if let (Some(orig), Some(did), Some(sec)) = (origin, device_id, secret) {
                        if server_confirmed {
                            // Dinamik Win32 Lock statusu (locked=true sabit deyil!)
                            let locked_state = lock_engine::is_workstation_locked();
                            let poll_url = format!("{}/agent/poll", orig.trim_end_matches('/'));
                            let poll_body = serde_json::json!({
                                "device_id": did,
                                "locked": locked_state,
                                "pin_ready": storage::credential_ready(&data_dir)
                            });

                            diagnostics::stage(&data_dir, "POLL_START", "");
                            let poll_result = ureq::post(&poll_url)
                                .timeout(Duration::from_secs(4))
                                .set("Authorization", &format!("Bearer {}", sec))
                                .send_json(poll_body);
                            if let Ok(resp) = poll_result {
                                diagnostics::stage(&data_dir, "POLL_OK", "");
                                if let Ok(resp_json) = resp.into_json::<serde_json::Value>() {
                                    if let Some(cmd) = resp_json.get("command").filter(|c| !c.is_null()) {
                                        let cmd_id = cmd.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                        let action = cmd.get("action").and_then(|v| v.as_str()).unwrap_or("");
                                        diagnostics::stage(&data_dir, "COMMAND_RECEIVED", action);
                                        println!("[GATEWAY_COMMAND] Gələn əmr: ID={}, Əməliyyat={}", cmd_id, action);

                                        // Səlahiyyətli Handler və Real Lock/Unlock Adapteri
                                        let (success, status_str) = if is_mock || action == "mock" || action == "ping" || action == "status" {
                                            println!("[HANDLER] Açıq nonphysical mock action icrası: {}", action);
                                            (true, format!("SUCCESS_{} DEMO_MOCK_ACTION", action.to_uppercase()))
                                        } else if action == "lock" {
                                            println!("[HANDLER] Real Win32 LockWorkStation çağırılır...");
                                            match lock_engine::lock_workstation() {
                                                Ok(_) => (true, "SUCCESS_LOCKED".to_string()),
                                                Err(e) => (false, e),
                                            }
                                        } else if action == "unlock" {
                                            println!("[HANDLER] Real Win32 Unlock Adapter çağırılır (Lokal DPAPI vault-dan)...");
                                            // REM-020: Server və ya şəbəkədən PIN qəbul edilmir! PIN yalnız lokal xidmət DPAPI vault-undan oxunur:
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

                                        // Nəticəni Gateway-ə çatdırırıq
                                        diagnostics::stage(&data_dir, "COMMAND_FINISHED", status_str.split_whitespace().next().unwrap_or("UNKNOWN"));
                                        let res_url = format!("{}/agent/result", orig.trim_end_matches('/'));
                                        let res_body = serde_json::json!({
                                            "device_id": did,
                                            "command_id": cmd_id,
                                            "success": success,
                                            "status": status_str
                                        });

                                        let result_delivery = ureq::post(&res_url)
                                            .timeout(Duration::from_secs(3))
                                            .set("Authorization", &format!("Bearer {}", sec))
                                            .send_json(res_body);
                                        diagnostics::stage(&data_dir, "RESULT_DELIVERY", if result_delivery.is_ok() { "OK" } else { "FAILED" });
                                    }
                                }
                            } else {
                                let code = match poll_result.err().unwrap() {
                                    ureq::Error::Status(status, _) => format!("HTTP={}", status),
                                    _ => "TRANSPORT_OR_TIMEOUT".to_string(),
                                };
                                diagnostics::stage(&data_dir, "POLL_FAILED", &code);
                            }
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(600));
    }
}

fn run_host_lifecycle(data_dir: PathBuf, is_scm: bool, timeout_sec: Option<u64>) {
    if is_scm {
        unsafe { update_status(SERVICE_START_PENDING, 3000); }
    }
    RUNNING.store(true, Ordering::SeqCst);

    println!("[HOST_LIFECYCLE_START] WinKey Host Lifecycle Manager başladı: data_dir={:?}", data_dir);

    // 0. Əgər arxa planda saxlanılmış PENDING_ACTIVATION varsa, aktivləşdiririk
    let (pending_j, _) = recovery_engine::read_or_recover_journal(&data_dir, None);
    if pending_j.state == "PENDING_ACTIVATION" {
        println!("[NATIVE_RECOVERY] PENDING_ACTIVATION aşkarlandı. Namizəd slot aktivləşdirilir...");
        let _ = recovery_engine::activate_pending_update(&data_dir, None);
    }

    // 1. Native Boot & Recovery Lifecycle Evaluation (Fail-Closed)
    let (journal, _action) = match recovery_engine::evaluate_and_prepare_active_slot(&data_dir, None) {
        Ok((j, act)) => {
            println!("[NATIVE_RECOVERY] Boot qiymətləndirildi: slot={} action={:?}", j.current_slot, act);
            (j, act)
        }
        Err(e) => {
            eprintln!("[NATIVE_RECOVERY_FATAL] Boot qiymətləndirmə xətası: {}. Fail-closed çıxılır.", e);
            if is_scm { unsafe { update_status(SERVICE_STOPPED, 0); } }
            return;
        }
    };

    if is_scm {
        unsafe { update_status(SERVICE_RUNNING, 0); }
    }

    // 2. Aktiv slot binarını tap və spawn et
    let current_slot_name = journal.current_slot.clone();
    let slot_bin = recovery_engine::get_slot_executable_path(&data_dir, &current_slot_name);

    println!("[NATIVE_LAUNCHER] Aktiv slot ({}) binarı seçildi: {:?}", current_slot_name, slot_bin);

    let mut active_child: Option<std::process::Child> = if slot_bin.exists() {
        std::process::Command::new(&slot_bin)
            .arg("--worker")
            .arg("--data-dir")
            .arg(&data_dir)
            .spawn()
            .ok()
    } else {
        eprintln!("[NATIVE_LAUNCHER_WARN] Slot binarı tapılmadı: {:?}", slot_bin);
        None
    };

    let host_start_instant = Instant::now();
    let mut start_instant = Instant::now();
    let mut committed = false;
    let mut switched_to_lkg = false;

    let update_interval_secs: u64 = std::env::var("WINKEY_UPDATE_CHECK_SEC")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(3600);
    let mut last_update_check = Instant::now() - Duration::from_secs(update_interval_secs);

    while RUNNING.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(150));

        // Avtomatik Arxa Plan Auto-Update Yoxlaması və Runtime Keçidi (Timer və ya trigger)
        let update_notice = data_dir.join("update_requested");
        let input_idle = update_input_idle(&data_dir);
        let should_check_update = (last_update_check.elapsed() >= Duration::from_secs(update_interval_secs)
            || (update_notice.is_file() && last_update_check.elapsed() >= Duration::from_secs(10))
            || std::env::var("WINKEY_TRIGGER_UPDATE").map(|v| v == "1" || v == "true").unwrap_or(false))
            && committed && input_idle;

        if should_check_update {
            last_update_check = Instant::now();
            let _ = fs::remove_file(&update_notice);
            let cfg_file = data_dir.join("config.json");
            let origin_opt = std::env::var("WINKEY_GATEWAY_ORIGIN").ok().or_else(|| {
                if cfg_file.exists() {
                    fs::read_to_string(&cfg_file).ok()
                        .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
                        .and_then(|cfg| cfg.get("gateway_origin").and_then(|v| v.as_str()).map(String::from))
                } else {
                    None
                }
            });

            if let Some(orig) = origin_opt {
                println!("[HOST_AUTO_UPDATE_POLL] Gateway yenilənmələri yoxlanılır: {}", orig);
                match check_and_apply_native_gateway_update(&orig, &data_dir) {
                    Ok(msg) => {
                        println!("[HOST_AUTO_UPDATE_SUCCESS] {}", msg);
                        let old_pid = active_child.as_ref().map(|c| c.id());
                        // Pause new input first, then recheck receipts: commands may
                        // have arrived while the release was downloading.
                        let paused = send_control_command_to_worker(old_pid, "PAUSE");
                        let idle = update_input_idle(&data_dir);
                        if !paused || !idle {
                            if paused { let _ = send_control_command_to_worker(old_pid, "RESUME"); }
                            let _ = fs::write(&update_notice,b"deferred");
                            println!("[HOST_UPDATE_DEFERRED] Cari emeliyyat bitdikden sonra yeniden yoxlanacaq");
                            continue;
                        }
                        let t_act = Instant::now();
                        match recovery_engine::activate_pending_update(&data_dir, None) {
                            Ok((j, new_slot)) => {
                                let act_dur = t_act.elapsed().as_millis() as u64;
                                let cand_v = j.candidate_version.as_deref().unwrap_or("unknown");
                                let rel_id = format!("rel_{}", cand_v);
                                diagnostics::stage(&data_dir, "UPDATE_ACTIVATE_DONE", &format!("rel_id={} slot={} ver={} dur_ms={}", rel_id, new_slot, cand_v, act_dur));
                                println!("[HOST_AUTO_UPDATE_ACTIVATED] Yeni slot aktivləşdirildi: {} (ver={:?}). Köhnə worker dayandırılır...", new_slot, j.candidate_version);
                                let old_pid = active_child.as_ref().map(|c| c.id());
                                let _ = send_control_command_to_worker(old_pid, "STOP");
                                thread::sleep(Duration::from_millis(300));
                                if let Some(ref mut c) = active_child {
                                    let _ = c.kill();
                                    let _ = c.wait();
                                }
                                active_child = None;

                                let new_bin = recovery_engine::get_slot_executable_path(&data_dir, &new_slot);
                                if new_bin.exists() {
                                    match std::process::Command::new(&new_bin)
                                        .arg("--worker")
                                        .arg("--data-dir")
                                        .arg(&data_dir)
                                        .spawn()
                                    {
                                        Ok(child) => {
                                            let new_pid = child.id();
                                            active_child = Some(child);
                                            start_instant = Instant::now();
                                            committed = false;
                                            switched_to_lkg = false;
                                            println!("[HOST_UPDATE_WORKER_SWITCH] Yeni namizəd worker binarı işə salındı: PID={}, slot={}, binar={:?}", new_pid, new_slot, new_bin);
                                        }
                                        Err(e) => {
                                            eprintln!("[HOST_FATAL] Yeni namizəd binarı spawn edilə bilmədi: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = send_control_command_to_worker(old_pid, "RESUME");
                                eprintln!("[HOST_AUTO_UPDATE_ACTIVATE_ERR] {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("[HOST_AUTO_UPDATE_SKIP] Yenilənmə tətbiq edilmədi: {}", e);
                    }
                }
            }
        }

        // SCM Handler idarəetmə siqnallarının worker-ə yönləndirilməsi (Non-blocking bounded queue)
        let desired = SCM_DESIRED_STATE.swap(0, Ordering::SeqCst);
        let child_pid = active_child.as_ref().map(|c| c.id());
        if desired == 1 {
            // PAUSE
            println!("[SCM_FORWARD] PAUSE siqnalı worker-ə ötürülür (PID: {:?})...", child_pid);
            if send_control_command_to_worker(child_pid, "PAUSE") {
                REMOTE_PAUSED.store(true, Ordering::SeqCst);
                if is_scm { unsafe { update_status(SERVICE_PAUSED, 0); } }
                println!("[SCM_FORWARD] Worker PAUSE təsdiqləndi (SERVICE_PAUSED).");
            } else {
                eprintln!("[SCM_FORWARD_FAIL] Worker PAUSE ACK vermədi! SERVICE_PAUSED qeydiyyata ALINMADI.");
                if is_scm { unsafe { update_status(SERVICE_RUNNING, 0); } }
            }
        } else if desired == 2 {
            // RESUME
            println!("[SCM_FORWARD] RESUME siqnalı worker-ə ötürülür (PID: {:?})...", child_pid);
            if send_control_command_to_worker(child_pid, "RESUME") {
                REMOTE_PAUSED.store(false, Ordering::SeqCst);
                if is_scm { unsafe { update_status(SERVICE_RUNNING, 0); } }
                println!("[SCM_FORWARD] Worker RESUME təsdiqləndi (SERVICE_RUNNING).");
            } else {
                eprintln!("[SCM_FORWARD_FAIL] Worker RESUME ACK vermədi!");
            }
        } else if desired == 3 {
            // STOP
            println!("[SCM_FORWARD] STOP siqnalı qəbul edildi. Bounded sonlanma başlanır...");
            break;
        }

        if let Some(limit) = timeout_sec {
            if host_start_instant.elapsed() >= Duration::from_secs(limit) {
                println!("[HOST_LIFECYCLE] Test timeout çatdı ({}s). Bounded sonlanma...", limit);
                break;
            }
        }

        // Child vəziyyətini yoxla
        let mut child_exited = false;
        let mut exit_status_code = None;

        if let Some(ref mut child) = active_child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    child_exited = true;
                    exit_status_code = status.code();
                }
                Ok(None) => {
                    // Child canlıdır və işləyir
                }
                Err(e) => {
                    eprintln!("[HOST_MONITOR_ERR] try_wait xətası: {}", e);
                }
            }
        } else {
            child_exited = true;
        }

        if child_exited {
            eprintln!("[HOST_CHILD_CRASH] Child worker qəzaya uğradı və ya dayandı! Exit: {:?}", exit_status_code);
            active_child = None;

            if !switched_to_lkg {
                println!("[HOST_RECOVERY_TRIGGER] Qəza aşkarlandı. Rollback və LKG bərpası qiymətləndirilir...");
                let t_roll = Instant::now();
                match recovery_engine::record_candidate_crash_and_rollback(
                    &data_dir,
                    None,
                    "Namizəd slot worker prosesi sınaq müddətində qəzaya uğradı",
                ) {
                    Ok((rec_journal, rec_action)) => {
                        let roll_dur = t_roll.elapsed().as_millis() as u64;
                        let q_ver = rec_journal.quarantined_versions.last().map(|s| s.as_str()).unwrap_or("unknown");
                        let rel_id = format!("rel_{}", q_ver);
                        diagnostics::stage(&data_dir, "UPDATE_ROLLBACK_DONE", &format!("rel_id={} restored_slot={} dur_ms={}", rel_id, rec_journal.current_slot, roll_dur));
                        println!("[HOST_RECOVERY_RESULT] Nəticə: {:?}, LKG slot: {}", rec_action, rec_journal.last_known_good_slot);
                        let lkg_slot = rec_journal.last_known_good_slot.clone();
                        let lkg_bin = recovery_engine::get_slot_executable_path(&data_dir, &lkg_slot);
                        if lkg_bin.exists() {
                            let child_res = std::process::Command::new(&lkg_bin)
                                .arg("--worker")
                                .arg("--data-dir")
                                .arg(&data_dir)
                                .spawn();
                            match child_res {
                                Ok(c) => {
                                    let pid = c.id();
                                    active_child = Some(c);
                                    switched_to_lkg = true;
                                    println!("[HOST_LKG_SPAWN] Validated LKG ({}) worker binarı işə salındı: PID={}, binar={:?}", lkg_slot, pid, lkg_bin);
                                }
                                Err(e) => {
                                    eprintln!("[HOST_FATAL] LKG binarı spawn edilə bilmədi: {}", e);
                                    break;
                                }
                            }
                        } else {
                            eprintln!("[HOST_FATAL] LKG binarı mövcud deyil: {:?}", lkg_bin);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[HOST_FATAL] evaluate_and_prepare_active_slot xətası: {}", e);
                        break;
                    }
                }
            } else {
                eprintln!("[HOST_FATAL] LKG worker prosesi də dayandı. Təkrar işə salınmır.");
                break;
            }
        } else {
            // Child hələ canlıdır
            if !committed && !switched_to_lkg {
                let probation_seconds = start_instant.elapsed().as_secs();
                if probation_seconds >= 5 {
                    // YALNIZ child canlı olduqda VƏ actual health probe təsdiqləndikdə commit edilir!
                    let child_pid = active_child.as_ref().map(|c| c.id());
                    if probe_worker_health(child_pid) {
                        let t_commit = Instant::now();
                        match recovery_engine::mark_boot_healthy(&data_dir, None) {
                            Ok(new_j) => {
                                committed = true;
                                let commit_dur = t_commit.elapsed().as_millis() as u64;
                                let prob_dur = start_instant.elapsed().as_millis() as u64;
                                let act_v = new_j.active_version.as_deref().unwrap_or("unknown");
                                let rel_id = format!("rel_{}", act_v);
                                diagnostics::stage(&data_dir, "UPDATE_PROBATION_PASSED", &format!("rel_id={} ver={} dur_ms={}", rel_id, act_v, prob_dur));
                                diagnostics::stage(&data_dir, "UPDATE_COMMIT_DONE", &format!("rel_id={} slot={} ver={} dur_ms={}", rel_id, new_j.last_known_good_slot, act_v, commit_dur));
                                println!("[HOST_PROBATION_PASSED] 5 saniyəlik child probation və actual health check təsdiqləndi. LKG commit edildi: slot={}", new_j.last_known_good_slot);
                            }
                            Err(e) => {
                                diagnostics::stage(&data_dir, "UPDATE_COMMIT_FAILED", &format!("err={}", e));
                                eprintln!("[HOST_COMMIT_ERR] mark_boot_healthy xətası: {}", e);
                            }
                        }
                    } else {
                        eprintln!("[HOST_PROBATION_WARN] Child proses canlıdır, lakin IPC Health/Status cavab vermədi. Commit saxlanılır.");
                    }
                }
            }
        }
    }

    // Təmiz bağlanış: Child worker prosesinə IPC STOP ötürülür və bounded cleanup aparılır
    if let Some(ref mut child) = active_child {
        let child_pid = Some(child.id());
        println!("[HOST_SHUTDOWN] Child worker prosesinə IPC STOP siqnalı verilir (PID: {:?})...", child_pid);
        let _ = send_control_command_to_worker(child_pid, "STOP");
        thread::sleep(Duration::from_millis(300));
        if let Ok(None) = child.try_wait() {
            println!("[HOST_SHUTDOWN] Child proses hələ aktivdir, kill edilir...");
            let _ = child.kill();
        }
        let _ = child.wait();
        println!("[HOST_SHUTDOWN] Child worker prosesi tamamilə təmizləndi.");
    }

    if is_scm {
        unsafe { update_status(SERVICE_STOPPED, 0); }
    }
    println!("[HOST_LIFECYCLE_DONE] Host proses təmiz bağlandı.");
}

unsafe extern "system" fn service_main(_dw_num_services_args: u32, _lp_service_arg_vectors: *mut *mut u16) {
    let service_name_u16: Vec<u16> = format!("{}\0", SERVICE_NAME).encode_utf16().collect();
    SERVICE_STATUS_H = RegisterServiceCtrlHandlerExW(
        service_name_u16.as_ptr(),
        Some(service_ctrl_handler),
        null_mut(),
    );

    if SERVICE_STATUS_H.is_null() {
        return;
    }

    let data_dir = get_app_data_dir();
    run_host_lifecycle(data_dir, true, None);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--probe-helper-peer") {
        let explicit = args.iter().position(|a| a == "--helper-path")
            .and_then(|pos| args.get(pos + 1)).map(std::path::Path::new);
        match helper_peer::probe_packaged_helper(explicit) {
            Ok(()) => std::process::exit(0),
            Err(error) => { eprintln!("{}", error); std::process::exit(1); }
        }
    }

    // REM-029: Child Worker Proses Entrypoint (Slot daxilində real worker icrası)
    if args.iter().any(|a| a == "--worker") {
        let version_marker = if let Some(pos) = args.iter().position(|a| a == "--version-marker") {
            args.get(pos + 1).map(|s| s.as_str()).unwrap_or("0.1.0")
        } else {
            "0.1.0"
        };

        let cur_exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf()));
        let should_crash = args.iter().any(|a| a == "--crash-on-start")
            || cur_exe_dir.as_ref().map(|p| p.join("crash.marker").exists()).unwrap_or(false);

        if should_crash {
            eprintln!("[WORKER_SIMULATED_CRASH] Namizəd sınaq qəzası təqlid edilir! Marker: {}", version_marker);
            std::process::exit(216);
        }

        if let Some(pos) = args.iter().position(|a| a == "--crash-after-ms") {
            let delay_ms = args.get(pos + 1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(500);
            let marker_copy = version_marker.to_string();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(delay_ms));
                eprintln!("[WORKER_DELAYED_CRASH] Gecikdirilmiş sınaq qəzası baş verdi ({} ms sonra)! Marker: {}", delay_ms, marker_copy);
                std::process::exit(217);
            });
        }

        let data_dir = if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(get_app_data_dir)
        } else {
            get_app_data_dir()
        };

        std::env::set_var("WINKEY_DATA_DIR", &data_dir);
        println!("[WORKER_START] WinKey Pro Native Worker aktivdir. Marker: {} PID: {}", version_marker, std::process::id());

        let stop_signal = Arc::new(AtomicBool::new(true));
        let stop_ipc = stop_signal.clone();
        let stop_poll = stop_signal.clone();
        let stop_gw = stop_signal.clone();
        let data_ipc = data_dir.clone();
        let data_poll = data_dir.clone();
        let data_gw = data_dir.clone();
        let is_mock = args.iter().any(|a| a == "--mock");

        let t_ipc = thread::spawn(move || run_ipc_worker_loop(stop_ipc, is_mock, data_ipc));
        let t_poll = thread::spawn(move || ws_transport::run_gateway_transport_loop(stop_poll, is_mock, data_poll));
        let t_gw = thread::spawn(move || embedded_gateway::run_embedded_gateway(stop_gw, is_mock, data_gw, 8788));

        while RUNNING.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }

        stop_signal.store(false, Ordering::SeqCst);
        let _ = t_ipc.join();
        let _ = t_poll.join();
        let _ = t_gw.join();
        println!("[WORKER_EXIT] Worker təmiz başa çatdı.");
        std::process::exit(0);
    }

    // REM-020: Native Boot Recovery CLI Sorğuları (Python-suz müstəqil yoxlama)
    if args.iter().any(|a| a == "--evaluate-recovery") {
        let data_dir = if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(get_app_data_dir)
        } else {
            get_app_data_dir()
        };

        match recovery_engine::evaluate_and_prepare_active_slot(&data_dir, None) {
            Ok((journal, action)) => {
                let action_str = match &action {
                    recovery_engine::RecoveryAction::NormalBoot { slot, version } => {
                        format!("NORMAL_BOOT slot={} ver={}", slot, version)
                    }
                    recovery_engine::RecoveryAction::RolledBackToLkg { from_slot, to_slot, quarantined_version, reason } => {
                        format!("ROLLED_BACK {}->{} quarantined={:?} reason={}", from_slot, to_slot, quarantined_version, reason)
                    }
                    recovery_engine::RecoveryAction::RecoveredCorruptedJournal { chosen_slot, reason } => {
                        format!("RECOVERED_JOURNAL slot={} reason={}", chosen_slot, reason)
                    }
                    recovery_engine::RecoveryAction::FatalNoValidSlot { reason } => {
                        format!("FATAL_NO_VALID_SLOT reason={}", reason)
                    }
                };
                println!("RECOVERY_OUTCOME: {}", action_str);
                println!("JOURNAL_STATE: {}", serde_json::to_string(&journal).unwrap_or_default());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("RECOVERY_ERROR: {}", e);
                std::process::exit(1);
            }
        }
    }

        if let Some(pos) = args.iter().position(|a| a == "--clean-slot") {
        if let Some(target) = args.get(pos + 1) {
            match recovery_engine::clean_lingering_slot_processes(&PathBuf::from(target), None, None) {
                Ok(()) => {
                    println!("PASS_SLOT_CLEANED");
                    println!("PASS_SLOT_IDLE");
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("FAIL_SLOT_CLEAN: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    if args.iter().any(|a| a == "--record-crash") {
        let data_dir = if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(get_app_data_dir)
        } else {
            get_app_data_dir()
        };
        match recovery_engine::record_candidate_crash_and_rollback(&data_dir, None, "Sınaq qəzası təqlidi") {
            Ok((j, _action)) => {
                println!("PASS_CRASH_RECORDED: to_slot={} state={}", j.current_slot, j.state);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("FAIL_CRASH_RECORD: {}", e);
                std::process::exit(1);
            }
        }
    }
    if args.iter().any(|a| a == "--mark-healthy") {
        let data_dir = if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(get_app_data_dir)
        } else {
            get_app_data_dir()
        };

        match recovery_engine::mark_boot_healthy(&data_dir, None) {
            Ok(journal) => {
                println!("COMMITTED_HEALTHY: {}", serde_json::to_string(&journal).unwrap_or_default());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("MARK_HEALTHY_ERROR: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|a| a == "--validate-slot") {
        let slot_path = if let Some(pos) = args.iter().position(|a| a == "--validate-slot") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(".")
        };

        let res = recovery_engine::validate_slot(&slot_path, None);
        if res.is_valid {
            println!("VALID_SLOT: ver={:?}", res.version);
            std::process::exit(0);
        } else {
            eprintln!("INVALID_SLOT: {:?}", res.error);
            std::process::exit(1);
        }
    }

    if args.iter().any(|a| a == "--validate-helper") {
        let helper_path = if let Some(pos) = args.iter().position(|a| a == "--validate-helper") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
        } else {
            PathBuf::from(".")
        };

        if lock_engine::validate_helper_binary(&helper_path) {
            println!("VALID_HELPER: {:?}", helper_path);
            std::process::exit(0);
        } else {
            eprintln!("INVALID_HELPER: {:?}", helper_path);
            std::process::exit(1);
        }
    }

    // Native IPC Probe və Control CLI Test İnterfeysi
    if args.iter().any(|a| a == "--test-native-ipc-probe") {
        let expected_pid = if let Some(pos) = args.iter().position(|a| a == "--expected-pid") {
            args.get(pos + 1).and_then(|v| v.parse::<u32>().ok())
        } else {
            None
        };

        if probe_worker_health(expected_pid) {
            println!("PASS_NATIVE_PROBE");
            std::process::exit(0);
        } else {
            eprintln!("FAIL_NATIVE_PROBE");
            std::process::exit(1);
        }
    }

    if let Some(pos) = args.iter().position(|a| a == "--test-native-ipc-control") {
        let cmd = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("PAUSE");
        let expected_pid = if let Some(p_pos) = args.iter().position(|a| a == "--expected-pid") {
            args.get(p_pos + 1).and_then(|v| v.parse::<u32>().ok())
        } else {
            None
        };

        if send_control_command_to_worker(expected_pid, cmd) {
            println!("PASS_NATIVE_CONTROL: {}", cmd);
            std::process::exit(0);
        } else {
            eprintln!("FAIL_NATIVE_CONTROL: {}", cmd);
            std::process::exit(1);
        }
    }

    // Native Auto-Update Staging CLI Testi
    if args.iter().any(|a| a == "--test-native-update-stage") {
        let data_dir = args.iter().position(|a| a == "--data-dir")
            .and_then(|p| args.get(p + 1)).map(PathBuf::from).unwrap_or_else(get_app_data_dir);
        let manifest_path = args.iter().position(|a| a == "--manifest")
            .and_then(|p| args.get(p + 1)).map(PathBuf::from);
        let sig_path = args.iter().position(|a| a == "--sig")
            .and_then(|p| args.get(p + 1)).map(PathBuf::from);
        let payload_dir = args.iter().position(|a| a == "--payload-dir")
            .and_then(|p| args.get(p + 1)).map(PathBuf::from);

        if manifest_path.is_none() || sig_path.is_none() || payload_dir.is_none() {
            eprintln!("FAIL_NATIVE_UPDATE_STAGE: Missing args");
            std::process::exit(1);
        }

        let m_bytes = match fs::read(manifest_path.unwrap()) {
            Ok(b) => b,
            Err(e) => { eprintln!("FAIL_READ_MANIFEST: {}", e); std::process::exit(1); }
        };
        let s_bytes = match fs::read(sig_path.unwrap()) {
            Ok(b) => b,
            Err(e) => { eprintln!("FAIL_READ_SIG: {}", e); std::process::exit(1); }
        };

        let p_dir = payload_dir.unwrap();
        let mut payloads = Vec::new();
        if let Ok(entries) = fs::read_dir(&p_dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_file() {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if let Ok(c) = fs::read(entry.path()) {
                            payloads.push((fname, c));
                        }
                    }
                }
            }
        }

        match recovery_engine::stage_native_update_bundle(&data_dir, &m_bytes, &s_bytes, &payloads, None) {
            Ok(msg) => {
                println!("PASS_NATIVE_UPDATE_STAGE: {}", msg);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("FAIL_NATIVE_UPDATE_STAGE: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Native Gateway Auto-Update Fetch, Stage & Activate CLI
    if let Some(pos) = args.iter().position(|a| a == "--check-update") {
        let gateway_origin = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("http://127.0.0.1:8089");
        let data_dir = args.iter().position(|a| a == "--data-dir")
            .and_then(|p| args.get(p + 1)).map(PathBuf::from).unwrap_or_else(get_app_data_dir);
        let no_activate = args.iter().any(|a| a == "--no-activate");

        match check_and_apply_native_gateway_update(gateway_origin, &data_dir) {
            Ok(msg) => {
                println!("PASS_NATIVE_GATEWAY_UPDATE_STAGED: {}", msg);
                if no_activate {
                    println!("PASS_NATIVE_GATEWAY_UPDATE: {}", msg);
                    std::process::exit(0);
                }
                match recovery_engine::activate_pending_update(&data_dir, None) {
                    Ok((j, new_slot)) => {
                        println!("PASS_NATIVE_UPDATE_ACTIVATED: slot={} ver={:?}", new_slot, j.candidate_version.as_deref().or(j.active_version.as_deref()));
                        println!("PASS_NATIVE_GATEWAY_UPDATE: {} (ACTIVATED to {})", msg, new_slot);
                        // Əgər arxa planda işləyən worker varsa, ona STOP/SWITCH siqnalı veririk
                        let _ = send_control_command_to_worker(None, "STOP");
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("FAIL_NATIVE_UPDATE_ACTIVATION: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("FAIL_NATIVE_GATEWAY_UPDATE: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|a| a == "--activate-update") {
        let data_dir = args.iter().position(|a| a == "--data-dir")
            .and_then(|p| args.get(p + 1)).map(PathBuf::from).unwrap_or_else(get_app_data_dir);
        match recovery_engine::activate_pending_update(&data_dir, None) {
            Ok((j, target_slot)) => {
                println!("PASS_ACTIVATE_UPDATE: slot={} ver={:?}", target_slot, j.candidate_version);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("FAIL_ACTIVATE_UPDATE: {}", e);
                std::process::exit(1);
            }
        }
    }
    let args: Vec<String> = std::env::args().collect();

    // REM-019: Token Rejection Testi
    if args.iter().any(|a| a == "--test-token-rejection") {
        let mut h_token: *mut c_void = null_mut();
        unsafe {
            if win32::OpenProcessToken(win32::GetCurrentProcess(), 0x0008, &mut h_token) != 0 {
                let dummy_path = std::path::Path::new("dummy.exe");
                let res = lock_engine::spawn_helper_in_session(dummy_path, &[], "winlogon", 1, Some(h_token));
                win32::CloseHandle(h_token);
                match res {
                    Err(e) if e.contains("E_STANDARD_USER_TOKEN_REJECTED_FOR_WINLOGON") => {
                        println!("PASS_STANDARD_USER_TOKEN_REJECTED: {}", e);
                        std::process::exit(0);
                    }
                    Err(e) => {
                        eprintln!("FAIL: Expected E_STANDARD_USER_TOKEN_REJECTED_FOR_WINLOGON, got error: {}", e);
                        std::process::exit(1);
                    }
                    Ok(_) => {
                        eprintln!("FAIL: Unexpected success with standard user token on winlogon!");
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("FAIL: OpenProcessToken failed");
                std::process::exit(1);
            }
        }
    }

    // REM-029: Host Lifecycle Runner (Non-SCM rejimində slot child binarının idarəsi və rollback testi)
    if args.iter().any(|a| a == "--run-host" || a == "--host-mode") {
        let timeout_sec = if let Some(pos) = args.iter().position(|a| a == "--timeout-sec") {
            args.get(pos + 1).and_then(|v| v.parse::<u64>().ok())
        } else {
            Some(30)
        };
        let data_dir = if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(get_app_data_dir)
        } else {
            get_app_data_dir()
        };

        run_host_lifecycle(data_dir, false, timeout_sec);
        std::process::exit(0);
    }

    // 1. Standalone / Test Rejimi
    if args.iter().any(|a| a == "--standalone" || a == "--test") {
        println!("==========================================================");
        println!("   WinKey Pro - Service Standalone / Test Rejimi          ");
        println!("==========================================================");
        println!("[INFO] B.2 Təhlükəsiz IPC və Gateway Worker aktivdir.");

        let is_mock = args.iter().any(|a| a == "--mock");
        let timeout_sec = if let Some(pos) = args.iter().position(|a| a == "--timeout-sec") {
            args.get(pos + 1).and_then(|v| v.parse::<u64>().ok()).unwrap_or(30)
        } else {
            30
        };

        let data_dir = if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            args.get(pos + 1).map(PathBuf::from).unwrap_or_else(get_app_data_dir)
        } else {
            get_app_data_dir()
        };

        let stop_signal = Arc::new(AtomicBool::new(true));
        let stop_ipc = stop_signal.clone();
        let stop_poll = stop_signal.clone();
        let stop_gw = stop_signal.clone();

        let data_for_ipc = data_dir.clone();
        let data_for_poll = data_dir.clone();
        let data_for_gw = data_dir.clone();

        let t_ipc = thread::spawn(move || {
            run_ipc_worker_loop(stop_ipc, is_mock, data_for_ipc);
        });

        let t_poll = thread::spawn(move || {
            ws_transport::run_gateway_transport_loop(stop_poll, is_mock, data_for_poll);
        });

        let t_gw = thread::spawn(move || {
            embedded_gateway::run_embedded_gateway(stop_gw, is_mock, data_for_gw, 8788);
        });

        let start_time = Instant::now();
        while start_time.elapsed() < Duration::from_secs(timeout_sec) && RUNNING.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200));
        }

        println!("[INFO] Standalone timeout çatdı ({timeout_sec}s). Bounded sonlanma başlanır...");
        stop_signal.store(false, Ordering::SeqCst);
        RUNNING.store(false, Ordering::SeqCst);

        // Dummy client connect to unblock any waiting connect pipe safely
        unsafe {
            let pipe_w: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
            let _ = win32::CloseHandle(win32::CreateNamedPipeW(pipe_w.as_ptr(), win32::PIPE_ACCESS_DUPLEX, 0, 1, 64, 64, 50, null_mut()));
        }

        let _ = t_ipc.join();
        let _ = t_poll.join();
        let _ = t_gw.join();

        println!("[PASS] Standalone xidmət testi təmiz və bounded başa çatdı.");
        std::process::exit(0);
    }

    // 2. Rəsmi SCM Dispatcher Başlatma
    if args.iter().any(|a| a == "--run-service") {
        let service_name_u16: Vec<u16> = format!("{}\0", SERVICE_NAME).encode_utf16().collect();
        let service_table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name_u16.as_ptr() as *mut u16,
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];

        unsafe {
            if StartServiceCtrlDispatcherW(service_table.as_ptr()) == 0 {
                let err = GetLastError();
                if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                    eprintln!("[ERROR] SCM əlaqəsi qurula bilmədi. Bu binary Windows SCM tərəfindən işə salınmalıdır.");
                    eprintln!("Konsol testi üçün '--standalone' arqumentindən istifadə edin.");
                    std::process::exit(1);
                } else {
                    eprintln!("[ERROR] StartServiceCtrlDispatcherW xətası: {}", err);
                    std::process::exit(err as i32);
                }
            }
        }
        return;
    }

    println!("WinKey Service Binary v0.1.0");
    println!("İstifadə:");
    println!("  winkey_service.exe --run-service                 Windows SCM altında işə salınma");
    println!("  winkey_service.exe --standalone [--timeout-sec N] [--mock]  Konsol test və sazlama");
    std::process::exit(0);
}
