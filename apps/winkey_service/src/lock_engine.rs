// WinKey Pro — Real Cross-Session Helper Launch & Authenticated Bounded Pipe (Revision 8)
#![allow(unsafe_op_in_unsafe_fn, dead_code)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use crate::ipc_engine::{get_current_user_sid, win32, ScopedHandle};
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;

pub mod win32_ui {
    use std::ffi::c_void;

    pub const HWND_BROADCAST: usize = 0xFFFF;
    pub const WM_SYSCOMMAND: u32 = 0x0112;
    pub const SC_MONITORPOWER: usize = 0xF170;
    pub const MONITOR_ON: isize = -1;
    pub const MOUSEEVENTF_MOVE: u32 = 0x0001;

    extern "system" {
        pub fn LockWorkStation() -> i32;
        pub fn OpenInputDesktop(dwFlags: u32, fInherit: i32, dwDesiredAccess: u32) -> *mut c_void;
        pub fn CloseDesktop(hDesktop: *mut c_void) -> i32;
        pub fn GetUserObjectInformationW(
            hObj: *mut c_void,
            nIndex: i32,
            pvInfo: *mut c_void,
            nLength: u32,
            lpnLengthNeeded: *mut u32,
        ) -> i32;
        pub fn SendMessageW(
            hWnd: *mut c_void,
            Msg: u32,
            wParam: usize,
            lParam: isize,
        ) -> isize;
        pub fn SendMessageTimeoutW(hWnd: *mut c_void, Msg: u32, wParam: usize, lParam: isize,
            fuFlags: u32, uTimeout: u32, lpdwResult: *mut usize) -> isize;
        pub fn mouse_event(
            dwFlags: u32,
            dx: u32,
            dy: u32,
            dwData: u32,
            dwExtraInfo: usize,
        );
    }
}

pub mod win32_process {
    use std::ffi::c_void;

    pub const CREATE_NO_WINDOW: u32 = 0x08000000;
    pub const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;
    pub const TOKEN_DUPLICATE: u32 = 0x0002;
    pub const TOKEN_QUERY: u32 = 0x0008;
    pub const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    pub const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
    pub const TOKEN_SESSION_ID: u32 = 12;

    #[repr(C)]
    pub struct STARTUPINFOW {
        pub cb: u32,
        pub lp_reserved: *mut u16,
        pub lp_desktop: *mut u16,
        pub lp_title: *mut u16,
        pub dw_x: u32,
        pub dw_y: u32,
        pub dw_x_size: u32,
        pub dw_y_size: u32,
        pub dw_x_count_chars: u32,
        pub dw_y_count_chars: u32,
        pub dw_fill_attribute: u32,
        pub dw_flags: u32,
        pub w_show_window: u16,
        pub cb_reserved2: u16,
        pub lp_reserved2: *mut u8,
        pub h_std_input: *mut c_void,
        pub h_std_output: *mut c_void,
        pub h_std_error: *mut c_void,
    }

    #[repr(C)]
    pub struct PROCESS_INFORMATION {
        pub h_process: *mut c_void,
        pub h_thread: *mut c_void,
        pub dw_process_id: u32,
        pub dw_thread_id: u32,
    }

    extern "system" {
        pub fn WTSQueryUserToken(SessionId: u32, phToken: *mut *mut c_void) -> i32;
        pub fn DuplicateTokenEx(
            hExistingToken: *mut c_void,
            dwDesiredAccess: u32,
            lpTokenAttributes: *mut c_void,
            ImpersonationLevel: u32,
            TokenType: u32,
            phNewToken: *mut *mut c_void,
        ) -> i32;
        pub fn SetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: u32,
            TokenInformation: *const c_void,
            TokenInformationLength: u32,
        ) -> i32;
        pub fn CreateProcessAsUserW(
            hToken: *mut c_void,
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *mut c_void,
            lpThreadAttributes: *mut c_void,
            bInheritHandles: i32,
            dwCreationFlags: u32,
            lpEnvironment: *mut c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *mut STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> i32;
        pub fn CreateProcessW(
            lpApplicationName: *const u16,
            lpCommandLine: *mut u16,
            lpProcessAttributes: *mut c_void,
            lpThreadAttributes: *mut c_void,
            bInheritHandles: i32,
            dwCreationFlags: u32,
            lpEnvironment: *mut c_void,
            lpCurrentDirectory: *const u16,
            lpStartupInfo: *mut STARTUPINFOW,
            lpProcessInformation: *mut PROCESS_INFORMATION,
        ) -> i32;
        pub fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> i32;
        pub fn TerminateProcess(hProcess: *mut c_void, uExitCode: u32) -> i32;
        pub fn GetExitCodeProcess(hProcess: *mut c_void, lpExitCode: *mut u32) -> i32;
        pub fn GetCurrentProcessId() -> u32;
    }
}

pub struct ChildProcessInfo {
    pub pid: u32,
    pub handle: ScopedHandle,
}

/// Win32 aktiv konsol sessiyasının mövcudluğunu yoxlayır
pub fn get_active_console_session() -> Option<u32> {
    unsafe {
        let sid = WTSGetActiveConsoleSessionId();
        if sid == 0xFFFFFFFF {
            None
        } else {
            Some(sid)
        }
    }
}

/// Helper binarının reparse point / symlink, signed bundle və SHA-256 manifest bütövlüyünü yoxlayır (Fail-Closed)
pub fn validate_helper_binary(path: &std::path::Path) -> bool {
    if !path.is_file() {
        eprintln!("[HELPER_REJECT] Helper faylı mövcud deyil və ya normal fayl deyil: {:?}", path);
        return false;
    }

    // 1. Ancestor və fayl üçün Symlink / Reparse Point yoxlanışı (TOCTOU qoruması)
    for ancestor in path.ancestors() {
        if let Ok(meta) = std::fs::symlink_metadata(ancestor) {
            if meta.file_type().is_symlink() {
                eprintln!("[HELPER_REJECT] Reparse point / Symlink aşkarlandı: {:?}", ancestor);
                return false;
            }
        } else {
            eprintln!("[HELPER_REJECT] Metadata oxuna bilmədi: {:?}", ancestor);
            return false;
        }
    }

    // 2. Məcburi İmzalı Paket Tələbi: manifest.json və manifest.sig mövcud olmalıdır
    let parent = match path.parent() {
        Some(p) => p,
        None => {
            eprintln!("[HELPER_REJECT] Valideyn qovluq tapılmadı: {:?}", path);
            return false;
        }
    };

    let manifest_path = parent.join("manifest.json");
    let sig_path = parent.join("manifest.sig");

    if !manifest_path.is_file() || !sig_path.is_file() {
        eprintln!("[HELPER_REJECT] E_HELPER_MISSING_MANIFEST_OR_SIG: manifest.json və ya manifest.sig tapılmadı: {:?}", parent);
        return false;
    }

    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[HELPER_REJECT] manifest.json oxunmadı: {}", e);
            return false;
        }
    };

    let sig_bytes = match std::fs::read(&sig_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[HELPER_REJECT] manifest.sig oxunmadı: {}", e);
            return false;
        }
    };

    if sig_bytes.len() != 64 {
        eprintln!("[HELPER_REJECT] E_HELPER_INVALID_SIG_LEN: imza uzunluğu 64 bayt deyil: {}", sig_bytes.len());
        return false;
    }

    // 3. Ed25519 İmza Yoxlanışı (Pinned Public Key ilə)
    let pubkey_bytes = match crate::recovery_engine::get_pinned_public_key_bytes() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[HELPER_REJECT] Pinned public key oxunmadı: {}", e);
            return false;
        }
    };

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let verifying_key = match VerifyingKey::from_bytes(&pubkey_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[HELPER_REJECT] VerifyingKey parse xətası: {}", e);
            return false;
        }
    };

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    if let Err(e) = verifying_key.verify(&manifest_bytes, &signature) {
        eprintln!("[HELPER_REJECT] E_HELPER_INVALID_SIGNATURE: manifest imzası etibarsızdır: {}", e);
        return false;
    }

    // 4. Manifest JSON Parsing
    let json: serde_json::Value = match serde_json::from_slice(&manifest_bytes) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[HELPER_REJECT] E_HELPER_MANIFEST_PARSE_ERROR: {}", e);
            return false;
        }
    };

    // 5. winkey_helper.exe qeydinin və faktiki hash/ölçü uyğunluğunun tapılması
    let files = match json.get("files").and_then(|f| f.as_array()) {
        Some(arr) => arr,
        None => {
            eprintln!("[HELPER_REJECT] E_HELPER_NO_FILES_ARRAY");
            return false;
        }
    };

    let helper_file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("winkey_helper.exe");
    let mut found_entry = false;
    let mut expected_sha256 = String::new();
    let mut expected_size: Option<u64> = None;

    for f in files {
        let p = f.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if p == "winkey_helper.exe" || p == helper_file_name {
            found_entry = true;
            if let Some(s) = f.get("sha256").and_then(|v| v.as_str()) {
                expected_sha256 = s.to_string();
            }
            expected_size = f.get("size").and_then(|v| v.as_u64());
            break;
        }
    }

    if !found_entry || expected_sha256.is_empty() {
        eprintln!("[HELPER_REJECT] E_HELPER_NOT_IN_MANIFEST: helper manifestdə qeydiyyatda deyil: {:?}", path);
        return false;
    }

    // Faktiki ölçü yoxlanışı
    if let Ok(meta) = std::fs::metadata(path) {
        if let Some(exp_sz) = expected_size {
            if meta.len() != exp_sz {
                eprintln!("[HELPER_REJECT] E_HELPER_SIZE_MISMATCH: exp={}, act={}", exp_sz, meta.len());
                return false;
            }
        }
    } else {
        eprintln!("[HELPER_REJECT] Helper fayl metadata oxunmadı");
        return false;
    }

    // Faktiki SHA-256 hash yoxlanışı
    let helper_bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[HELPER_REJECT] Helper faylı oxuna bilmədi: {}", e);
            return false;
        }
    };

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&helper_bytes);
    let actual_sha = format!("{:x}", hasher.finalize());

    if !actual_sha.eq_ignore_ascii_case(&expected_sha256) {
        eprintln!("[HELPER_HASH_MISMATCH] Helper binarı tampered aşkarlandı! exp={}, act={}", expected_sha256, actual_sha);
        return false;
    }

    println!("[HELPER_VALID] Helper binarı və imzalı paketi tam təsdiqləndi: {:?}", path);
    true
}

/// Helper executable axtarışı (yalnız absolute kanonik yollar və bütöv fayllar qəbul edilir)
pub fn find_helper_exe() -> Option<PathBuf> {
    // 1. Qorunan Program Files qovluğu (SYSTEM-Only Tree üstünlüyü)
    let pf_dir = std::env::var("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\Program Files"));
    let pf_helper = pf_dir.join("WinKey Pro").join("winkey_helper.exe");
    if pf_helper.is_file() && validate_helper_binary(&pf_helper) {
        return pf_helper.canonicalize().ok().or(Some(pf_helper));
    }

    // 2. Mövcud prosesin yanındakı qovluq (Validated slot)
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            let candidate = dir.join("winkey_helper.exe");
            if candidate.is_file() && validate_helper_binary(&candidate) {
                return candidate.canonicalize().ok().or(Some(candidate));
            }
        }
    }
    // 3. apps/winkey_service/target/release
    let c2 = PathBuf::from("apps/winkey_service/target/release/winkey_helper.exe");
    if c2.is_file() && validate_helper_binary(&c2) {
        return c2.canonicalize().ok().or(Some(c2));
    }
    let c3 = PathBuf::from("target/release/winkey_helper.exe");
    if c3.is_file() && validate_helper_binary(&c3) {
        return c3.canonicalize().ok().or(Some(c3));
    }
    None
}

/// Token-dən istifadəçi SID string-ni çıxarır
pub fn get_token_sid_string(token: *mut c_void) -> Result<String, String> {
    unsafe {
        let mut return_length: u32 = 0;
        let _ = win32::GetTokenInformation(token, 1, null_mut(), 0, &mut return_length);
        if return_length == 0 {
            return Err("GetTokenInformation uzunluq ala bilmədi".to_string());
        }
        let mut buf = vec![0u8; return_length as usize];
        if win32::GetTokenInformation(token, 1, buf.as_mut_ptr() as *mut c_void, return_length, &mut return_length) == 0 {
            return Err("GetTokenInformation uğursuz oldu".to_string());
        }
        let p_sid = *(buf.as_ptr() as *const *mut c_void);
        let mut p_string_sid: *mut u16 = null_mut();
        if win32::ConvertSidToStringSidW(p_sid, &mut p_string_sid) == 0 || p_string_sid.is_null() {
            return Err("ConvertSidToStringSidW uğursuz oldu".to_string());
        }
        let mut len = 0;
        while *p_string_sid.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p_string_sid, len as usize);
        let sid_str = String::from_utf16_lossy(slice);
        win32::LocalFree(p_string_sid as *mut c_void);
        Ok(sid_str)
    }
}

/// REM-019: Hədəf sessiyanın interaktiv istifadəçi tokenini əldə edir (yalnız istifadəçi SID və sessiya authorization üçündür)
pub fn get_target_session_user_token(session_id: u32) -> Result<ScopedHandle, String> {
    unsafe {
        let mut h_token: *mut c_void = null_mut();
        if win32_process::WTSQueryUserToken(session_id, &mut h_token) == 0 {
            let err = win32::GetLastError();
            return Err(format!(
                "E_WTS_QUERY_USER_TOKEN_FAILED: WinError={} (Requires SE_TCB_NAME LocalSystem privilege)",
                err
            ));
        }
        let mut h_primary: *mut c_void = null_mut();
        let dup_res = win32_process::DuplicateTokenEx(
            h_token,
            0x02000000, // MAXIMUM_ALLOWED
            null_mut(),
            2,          // SecurityImpersonation
            1,          // TokenPrimary
            &mut h_primary,
        );
        win32::CloseHandle(h_token);
        if dup_res == 0 || h_primary.is_null() {
            let err = win32::GetLastError();
            return Err(format!("E_DUPLICATE_TOKEN_FAILED: WinError={}", err));
        }
        Ok(ScopedHandle::new(h_primary))
    }
}

/// REM-019: Hədəf sessiyaya bağlanmış etibarlı SYSTEM Primary Tokenini əldə edir (Winlogon helper üçün)
pub fn get_session_trusted_system_token(session_id: u32) -> Result<ScopedHandle, String> {
    unsafe {
        // 1. Cari prosesin (LocalSystem xidməti) tokenini açırıq
        let mut h_proc_token: *mut c_void = null_mut();
        let desired_access = win32_process::TOKEN_DUPLICATE
            | win32_process::TOKEN_QUERY
            | win32_process::TOKEN_ADJUST_DEFAULT
            | win32_process::TOKEN_ADJUST_SESSIONID;

        if win32::OpenProcessToken(win32::GetCurrentProcess(), desired_access, &mut h_proc_token) == 0 {
            let err = win32::GetLastError();
            return Err(format!("E_OPEN_SERVICE_TOKEN_FAILED: WinError={}", err));
        }
        let proc_guard = ScopedHandle::new(h_proc_token);

        // 2. Token-in həqiqətən LocalSystem olduğunu yoxlayırıq
        let service_sid = get_token_sid_string(proc_guard.raw())?;
        if service_sid != "S-1-5-18" {
            // Unprivileged proses rejimində
            return Err(format!("E_NOT_LOCALSYSTEM: Xidmət LocalSystem (S-1-5-18) altında deyil: '{}'", service_sid));
        }

        // 3. Primary Token duplicate edirik
        let mut h_primary: *mut c_void = null_mut();
        let dup_res = win32_process::DuplicateTokenEx(
            proc_guard.raw(),
            0x02000000, // MAXIMUM_ALLOWED
            null_mut(),
            2,          // SecurityImpersonation
            1,          // TokenPrimary
            &mut h_primary,
        );
        if dup_res == 0 || h_primary.is_null() {
            let err = win32::GetLastError();
            return Err(format!("E_DUPLICATE_SYSTEM_TOKEN_FAILED: WinError={}", err));
        }
        let primary_guard = ScopedHandle::new(h_primary);

        // 4. Token-i hədəf interaktiv sessiya ID-sinə bağlayırıq (SetTokenInformation -> TokenSessionId)
        let sess_val = session_id;
        let set_res = win32_process::SetTokenInformation(
            primary_guard.raw(),
            win32_process::TOKEN_SESSION_ID,
            &sess_val as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        );
        if set_res == 0 {
            let err = win32::GetLastError();
            return Err(format!("E_SET_TOKEN_SESSION_FAILED: WinError={}", err));
        }

        Ok(primary_guard)
    }
}

/// REM-016 & REM-019: Hədəf Sessiyada Helper Prosesini Başladır
pub fn spawn_helper_in_session(
    helper_exe: &Path,
    args: &[&str],
    desktop: &str,
    target_session: u32,
    primary_token: Option<*mut c_void>,
) -> Result<ChildProcessInfo, String> {
    // REM-019: Winlogon masaüstü üçün Standard User Token-in qəti qadağan edilməsi (Fail-Closed)
    if desktop == "winlogon" {
        if let Some(tok) = primary_token {
            if let Ok(tok_sid) = get_token_sid_string(tok) {
                if tok_sid.starts_with("S-1-5-21-") {
                    return Err(format!(
                        "E_STANDARD_USER_TOKEN_REJECTED_FOR_WINLOGON: winsta0\\winlogon desktopu üçün yalnız SYSTEM (S-1-5-18) tokeni qəbul edilir, istifadəçi SID: '{}'",
                        tok_sid
                    ));
                }
            }
        }
    }

    let canonical = helper_exe
        .canonicalize()
        .map_err(|e| format!("E_HELPER_PATH_CANONICALIZE_FAILED: {}", e))?;

    let cmd_line = format!("\"{}\" {}", canonical.display(), args.join(" "));
    let mut cmd_w: Vec<u16> = cmd_line.encode_utf16().chain(std::iter::once(0)).collect();

    let desktop_str = format!("winsta0\\{}\0", desktop);
    let mut desktop_w: Vec<u16> = desktop_str.encode_utf16().collect();

    unsafe {
        let mut si: win32_process::STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<win32_process::STARTUPINFOW>() as u32;
        si.lp_desktop = desktop_w.as_mut_ptr();

        let mut pi: win32_process::PROCESS_INFORMATION = std::mem::zeroed();

        let success = match primary_token {
            Some(tok) => win32_process::CreateProcessAsUserW(
                tok,
                null(),
                cmd_w.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                win32_process::CREATE_NO_WINDOW | win32_process::CREATE_UNICODE_ENVIRONMENT,
                null_mut(),
                null(),
                &mut si,
                &mut pi,
            ),
            None => win32_process::CreateProcessW(
                null(),
                cmd_w.as_mut_ptr(),
                null_mut(),
                null_mut(),
                0,
                win32_process::CREATE_NO_WINDOW,
                null_mut(),
                null(),
                &mut si,
                &mut pi,
            ),
        };

        if success == 0 {
            let err = win32::GetLastError();
            return Err(format!("E_HELPER_SPAWN_FAILED: CreateProcess xətası {}", err));
        }

        // Thread handle-ını bağlayırıq (yalnız process handle saxlanılır)
        win32::CloseHandle(pi.h_thread);

        // REM-016: Faktiki Child Process Sessiyasının Yoxlanılması
        let mut actual_session = 0u32;
        if win32_process::ProcessIdToSessionId(pi.dw_process_id, &mut actual_session) != 0 {
            if actual_session != target_session {
                // Sessiya uyğunsuzluğu: dərhal child kill edilir!
                win32_process::TerminateProcess(pi.h_process, 99);
                win32::CloseHandle(pi.h_process);
                return Err(format!(
                    "E_CHILD_SESSION_MISMATCH: Child PID {} in session {}, expected target {}",
                    pi.dw_process_id, actual_session, target_session
                ));
            }
        }

        Ok(ChildProcessInfo {
            pid: pi.dw_process_id,
            handle: ScopedHandle::new(pi.h_process),
        })
    }
}

/// Masaüstünün kilidli olub-olmadığını yoxlayır
pub fn is_workstation_locked() -> bool {
    let session = get_active_console_session().unwrap_or(1);
    if let Some(helper) = find_helper_exe() {
        if let Ok(child) = spawn_helper_in_session(&helper, &["--mode", "status", "--session", &session.to_string()], "default", session, None) {
            unsafe {
                win32::WaitForSingleObject(child.handle.raw(), 3000);
            }
        }
    }

    // Direct desktop check
    unsafe {
        let h_desktop = win32_ui::OpenInputDesktop(0, 0, 0x0001);
        if h_desktop.is_null() {
            return true;
        }

        let mut needed = 0u32;
        let mut name_buf = [0u16; 256];
        let res = win32_ui::GetUserObjectInformationW(
            h_desktop,
            2,
            name_buf.as_mut_ptr() as *mut c_void,
            (name_buf.len() * 2) as u32,
            &mut needed,
        );

        win32_ui::CloseDesktop(h_desktop);

        if res == 0 {
            return true;
        }

        let len = (needed as usize / 2).saturating_sub(1);
        let name = String::from_utf16_lossy(&name_buf[..len]);
        name.to_lowercase() != "default"
    }
}

/// Win32 LockWorkStation çağırışı (Hədəf interaktiv sessiya üzərindən)
pub fn lock_workstation() -> Result<(), String> {
    let session = get_active_console_session().ok_or("E_NO_ACTIVE_CONSOLE_SESSION")?;
    let helper = find_helper_exe().ok_or("E_LOCK_HELPER_UNAVAILABLE")?;
    let mut current_session = 0;
    unsafe {
        if win32_process::ProcessIdToSessionId(win32_process::GetCurrentProcessId(), &mut current_session) == 0 {
            return Err(format!("E_LOCK_SESSION_QUERY: WinError={}", win32::GetLastError()));
        }
    }
    // Session 0 must launch with the interactive USER token on Default desktop.
    // Never fall back to LockWorkStation in the service's own session.
    let token = if current_session != session { Some(get_target_session_user_token(session)?) } else { None };
    let child = spawn_helper_in_session(&helper, &["--mode", "lock", "--session", &session.to_string()],
        "default", session, token.as_ref().map(|t| t.raw()))?;
    println!("[LOCK_HELPER] service_session={} target_session={} child_pid={}", current_session, session, child.pid);
    unsafe {
        let wait = win32::WaitForSingleObject(child.handle.raw(), 4000);
        if wait != win32::WAIT_OBJECT_0 {
            win32_process::TerminateProcess(child.handle.raw(), 99);
            win32::WaitForSingleObject(child.handle.raw(), 1000);
            return Err(format!("E_LOCK_HELPER_WAIT: wait={}", wait));
        }
        let mut exit_code = 0u32;
        if win32_process::GetExitCodeProcess(child.handle.raw(), &mut exit_code) == 0 {
            return Err(format!("E_LOCK_HELPER_EXIT_QUERY: WinError={}", win32::GetLastError()));
        }
        if exit_code != 0 { return Err(format!("E_LOCK_HELPER_EXIT: code={}", exit_code)); }
    }
    Ok(())
}

/// Ekranı və Winlogon masaüstünü oyatma siqnalı
pub fn wake_screen() {
    unsafe {
        let mut result = 0usize;
        win32_ui::SendMessageTimeoutW(
            win32_ui::HWND_BROADCAST as *mut c_void,
            win32_ui::WM_SYSCOMMAND,
            win32_ui::SC_MONITORPOWER,
            win32_ui::MONITOR_ON,
            0x0002, // SMTO_ABORTIFHUNG
            500,
            &mut result,
        );
        win32_ui::mouse_event(win32_ui::MOUSEEVENTF_MOVE, 1, 0, 0, 0);
        win32_ui::mouse_event(win32_ui::MOUSEEVENTF_MOVE, (-1i32) as u32, 0, 0, 0);
    }
}

/// REM-016, REM-017, REM-018, REM-019 & REM-020: Real Cross-Session Helper Launch & Local Credential IPC
pub fn execute_system_unlock(credential: Option<&str>, data_dir: &Path) -> Result<String, String> {
    crate::diagnostics::stage(data_dir, "UNLOCK_START", "");
    // 1. Aktiv konsol sessiyası yoxlanılır
    let active_session = get_active_console_session()
        .ok_or_else(|| "E_NO_ACTIVE_CONSOLE_SESSION: Aktiv istifadəçi konsol sessiyası mövcud deyil".to_string())?;

    // 2. Boş credential dərhal fail-closed rədd edilir
    let cred = match credential {
        Some(c) if !c.trim().is_empty() => c.trim(),
        _ => return Err("E_EMPTY_CREDENTIAL: Parol və ya PIN təqdim edilməyib".to_string()),
    };

    // 3. Helper binary kanonik yolu axtarılır
    let helper_exe = find_helper_exe()
        .ok_or_else(|| "NOT_IMPLEMENTED: winkey_helper.exe köməkçi binary-si tapılmadı".to_string())?;

    // Fail before any input: a normal dev worker cannot inject on Winlogon.
    // Never hide the LocalSystem/token failure behind a later pipe timeout.
    let system_token = get_session_trusted_system_token(active_session).map_err(|err| {
        eprintln!("[UNLOCK_STAGE] SYSTEM_TOKEN_FAILED session={} error={}", active_session, err);
        format!("E_UNLOCK_SYSTEM_SERVICE_REQUIRED: Kilidi açmaq üçün SYSTEM Windows xidməti lazımdır. {}", err)
    })?;
    eprintln!("[UNLOCK_STAGE] SYSTEM_TOKEN_OK session={}", active_session);
    crate::diagnostics::stage(data_dir, "SYSTEM_TOKEN_OK", "");

    // 4. Ekran oyadılır
    crate::diagnostics::stage(data_dir, "WAKE_START", "");
    wake_screen();
    crate::diagnostics::stage(data_dir, "WAKE_DONE", "");

    // 5. REM-019: Token Ayrımı:
    // a) User Token: WTSQueryUserToken yalnız user SID təsdiqi və IPC DACL üçündür
    let user_token_opt = get_target_session_user_token(active_session).ok();
    let target_user_sid = user_token_opt
        .as_ref()
        .and_then(|tok| get_token_sid_string(tok.raw()).ok());

    // b) SYSTEM Token: Winlogon masaüstü üçün etibarlı SYSTEM Primary Token
    let system_token_ptr = Some(system_token.raw());

    // 6. Default lock curtain aradan qaldırılması (əgər Default masaüstündədirsə)
    if is_workstation_locked() {
        // Curtain Default desktop-dadır, istifadəçi tokeni və ya standalone rejim kifayətdir
        let curtain_token_ptr = user_token_opt.as_ref().map(|t| t.raw());
        let curtain_child = spawn_helper_in_session(
            &helper_exe,
            &["--mode", "curtain", "--session", &active_session.to_string()],
            "default",
            active_session,
            curtain_token_ptr,
        );
        if let Ok(child) = curtain_child {
            unsafe {
                win32::WaitForSingleObject(child.handle.raw(), 5000);
            }
            thread::sleep(Duration::from_millis(300));
        }
    }

    crate::diagnostics::stage(data_dir, "CURTAIN_DONE", "");
    // 7. REM-017: Məhdud ömürlü dar DACL-li Ephemeral Named Pipe yaradılması
    let pipe_id = format!("WinKey_Ephemeral_Credential_{}", uuid::Uuid::new_v4().simple());
    let pipe_path = format!("\\\\.\\pipe\\{}", pipe_id);
    let pipe_w: Vec<u16> = pipe_path.encode_utf16().chain(std::iter::once(0)).collect();

    let client_sid = target_user_sid
        .clone()
        .or_else(|| get_current_user_sid().ok())
        .unwrap_or_else(|| "S-1-5-21-0-0-0-1000".to_string());

    let sddl = format!(
        "D:P(A;;0x{:08x};;;SY)(A;;0x{:08x};;;{})",
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        client_sid
    );
    let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut p_sd: *mut c_void = null_mut();
    let mut sd_size = 0u32;
    let res_sd = unsafe {
        win32::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            1,
            &mut p_sd,
            &mut sd_size,
        )
    };
    if res_sd == 0 || p_sd.is_null() {
        return Err("E_IPC_PIPE_SDDL_FAILED: Dar DACL SDDL çevrilmədi".to_string());
    }

    let mut sa = win32::SECURITY_ATTRIBUTES {
        n_length: std::mem::size_of::<win32::SECURITY_ATTRIBUTES>() as u32,
        lp_security_descriptor: p_sd,
        b_inherit_handle: 0,
    };

    // FIRST_PIPE_INSTANCE | OVERLAPPED | PIPE_REJECT_REMOTE_CLIENTS
    let open_mode = win32::PIPE_ACCESS_DUPLEX
        | win32::FILE_FLAG_OVERLAPPED
        | win32::FILE_FLAG_FIRST_PIPE_INSTANCE;
    let pipe_mode = 0x00000000 /* PIPE_TYPE_BYTE */ | win32::PIPE_REJECT_REMOTE_CLIENTS;

    let h_pipe = unsafe {
        win32::CreateNamedPipeW(
            pipe_w.as_ptr(),
            open_mode,
            pipe_mode,
            1,
            512,
            512,
            3000,
            &mut sa,
        )
    };

    unsafe { win32::LocalFree(p_sd) };

    if h_pipe.is_null() || h_pipe as isize == -1 {
        return Err("E_IPC_PIPE_CREATE_FAILED: Ephemeral pipe yaradıla bilmədi".to_string());
    }
    let pipe_guard = ScopedHandle::new(h_pipe);

    // 8. Helper Prosesini Winlogon masaüstündə başladırıq (REM-019: trusted SYSTEM tokeni ilə)
    let current_service_pid = unsafe { win32_process::GetCurrentProcessId() };
    let helper_args = [
        "--mode", "unlock",
        "--session", &active_session.to_string(),
        "--ipc-pipe", &pipe_id,
        "--expected-server-pid", &current_service_pid.to_string(),
    ];
    crate::diagnostics::stage(data_dir, "UNLOCK_HELPER_SPAWN", "");

    let child = spawn_helper_in_session(
        &helper_exe,
        &helper_args,
        "winlogon",
        active_session,
        system_token_ptr,
    )?;

    // 9. REM-017 & REM-022: Bounded Overlapped Connect & Peer Authentication (Deadline 4s)
    unsafe {
        let h_conn_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
        let _conn_event_guard = ScopedHandle::new(h_conn_event);
        let mut ov_conn: win32::OVERLAPPED = std::mem::zeroed();
        ov_conn.h_event = h_conn_event;

        let conn_res = win32::ConnectNamedPipe(pipe_guard.raw(), &mut ov_conn);
        let mut is_connected = false;

        if conn_res != 0 {
            is_connected = true;
        } else {
            let err = win32::GetLastError();
            if err == win32::ERROR_PIPE_CONNECTED {
                is_connected = true;
            } else if err == win32::ERROR_IO_PENDING {
                let wait = win32::WaitForSingleObject(h_conn_event, 4000);
                if wait == win32::WAIT_OBJECT_0 {
                    let mut transferred = 0u32;
                    if win32::GetOverlappedResult(pipe_guard.raw(), &mut ov_conn, &mut transferred, 0) != 0 {
                        is_connected = true;
                    }
                } else {
                    // Connect timeout -> ləğv et və child-ı terminate et
                    win32::CancelIoEx(pipe_guard.raw(), &mut ov_conn);
                    win32_process::TerminateProcess(child.handle.raw(), 1);
                    return Err("E_PIPE_CONNECT_TIMEOUT: Helper vaxtında pipe-a qoşulmadı (4s)".to_string());
                }
            }
        }

        if !is_connected {
            win32_process::TerminateProcess(child.handle.raw(), 1);
            return Err("E_PIPE_CONNECT_FAILED: Named Pipe əlaqəsi qurulmadı".to_string());
        }

        // REM-017: Peer PID və Session Identity Təsdiqi
        let mut client_pid = 0u32;
        let mut client_sess = 0u32;
        if win32::GetNamedPipeClientProcessId(pipe_guard.raw(), &mut client_pid) == 0
            || win32::GetNamedPipeClientSessionId(pipe_guard.raw(), &mut client_sess) == 0 {
            return Err("E_PIPE_PEER_IDENTITY_QUERY".into());
        }
        let _runtime_peer = crate::helper_peer::verify(&child, client_pid, &helper_exe, active_session)?;
        crate::diagnostics::stage(data_dir, "HELPER_PEER_VERIFIED", &format!("bootstrap={} runtime={}", child.pid, client_pid));

        if client_sess != active_session {
            win32::DisconnectNamedPipe(pipe_guard.raw());
            win32_process::TerminateProcess(child.handle.raw(), 3);
            return Err(format!(
                "E_CLIENT_SESSION_MISMATCH: Müştəri sessiyası {} != gözlənilən {}",
                client_sess, active_session
            ));
        }

        // The held runtime process handle was already checked for token SID,
        // image, session, parent and creation time. No thread impersonation is needed.

        // 10. REM-017: Bounded Overlapped Write of Credential (2s Deadline)
        let cred_bytes = format!("{}\n", cred).into_bytes();
        let h_write_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
        let _write_event_guard = ScopedHandle::new(h_write_event);
        let mut ov_write: win32::OVERLAPPED = std::mem::zeroed();
        ov_write.h_event = h_write_event;

        let mut written = 0u32;
        let write_res = win32::WriteFile(
            pipe_guard.raw(),
            cred_bytes.as_ptr(),
            cred_bytes.len() as u32,
            &mut written,
            &mut ov_write,
        );

        let mut write_success = false;
        if write_res != 0 {
            write_success = true;
        } else if win32::GetLastError() == win32::ERROR_IO_PENDING {
            let wait = win32::WaitForSingleObject(h_write_event, 2000);
            if wait == win32::WAIT_OBJECT_0 {
                if win32::GetOverlappedResult(pipe_guard.raw(), &mut ov_write, &mut written, 0) != 0 {
                    write_success = true;
                }
            } else {
                win32::CancelIoEx(pipe_guard.raw(), &mut ov_write);
                win32_process::TerminateProcess(child.handle.raw(), 4);
                return Err("E_PIPE_WRITE_TIMEOUT: Credential ötürülməsi vaxt aşımına uğradı".to_string());
            }
        }

        if !write_success {
            win32_process::TerminateProcess(child.handle.raw(), 4);
            return Err("E_PIPE_WRITE_FAILED: Credential pipe-a yazıla bilmədi".to_string());
        }

        // 11. REM-017: Bounded Overlapped Read of ACK from Helper (2s Deadline)
        let h_read_event = win32::CreateEventW(null_mut(), 1, 0, null_mut());
        let _read_event_guard = ScopedHandle::new(h_read_event);
        let mut ov_read: win32::OVERLAPPED = std::mem::zeroed();
        ov_read.h_event = h_read_event;

        let mut ack_buf = [0u8; 64];
        let mut read_bytes = 0u32;
        let read_res = win32::ReadFile(
            pipe_guard.raw(),
            ack_buf.as_mut_ptr(),
            ack_buf.len() as u32,
            &mut read_bytes,
            &mut ov_read,
        );

        let mut ack_success = false;
        if read_res != 0 {
            ack_success = true;
        } else if win32::GetLastError() == win32::ERROR_IO_PENDING {
            let wait = win32::WaitForSingleObject(h_read_event, 2000);
            if wait == win32::WAIT_OBJECT_0 {
                if win32::GetOverlappedResult(pipe_guard.raw(), &mut ov_read, &mut read_bytes, 0) != 0 {
                    ack_success = true;
                }
            } else {
                win32::CancelIoEx(pipe_guard.raw(), &mut ov_read);
                // Helper silent reader -> terminate
                win32_process::TerminateProcess(child.handle.raw(), 5);
                return Err("E_PIPE_ACK_TIMEOUT: Helper credential ACK göndərmədi (Silent Reader)".to_string());
            }
        }

        if !ack_success || read_bytes == 0 {
            win32_process::TerminateProcess(child.handle.raw(), 5);
            return Err("E_PIPE_ACK_FAILED: Helper-dən təsdiq oxunmadı (Child crash və ya Broken Pipe)".to_string());
        }

        let ack_str = String::from_utf8_lossy(&ack_buf[..read_bytes as usize]);
        if !ack_str.contains("ACK_CREDENTIAL_RECEIVED") {
            win32_process::TerminateProcess(child.handle.raw(), 6);
            return Err("E_INVALID_HELPER_ACK: Helper etibarsız təsdiq göndərdi".to_string());
        }

        // Pipe dərhal bağlanır və yaddaş təmizlənir
        win32::DisconnectNamedPipe(pipe_guard.raw());
    }

    crate::diagnostics::stage(data_dir, "CREDENTIAL_ACK_OK", "");
    // 12. Helper Prosesinin Nəticəsi və Exit Code Gözlənilməsi (15s Timeout)
    unsafe {
        let wait_child = win32::WaitForSingleObject(child.handle.raw(), 15000);
        if wait_child != win32::WAIT_OBJECT_0 {
            win32_process::TerminateProcess(child.handle.raw(), 7);
            return Err("E_HELPER_TIMEOUT: Helper prosesi 15 saniyə ərzində tamamlanmadı".to_string());
        }

        let mut exit_code = 0u32;
        if win32_process::GetExitCodeProcess(child.handle.raw(), &mut exit_code) == 0 {
            return Err("E_GET_EXIT_CODE_FAILED: Helper çıxış kodu alına bilmədi".to_string());
        }

        crate::diagnostics::stage(data_dir, "UNLOCK_HELPER_EXIT", &format!("exit={}", exit_code));
        if exit_code == 0 {
            Ok("SUCCESS_UNLOCKED".to_string())
        } else {
            Err(format!("UNLOCK_FAILED: Helper xəta kodu {}", exit_code))
        }
    }
}
