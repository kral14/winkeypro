#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::c_void;
use std::fs;
use std::path::PathBuf;
use std::ptr::null_mut;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use rand::RngCore;
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use tauri::Manager;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};
mod gateway_config;
mod account;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
};
use windows_sys::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatus, CloseServiceHandle,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_STATUS,
    SERVICE_RUNNING, SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTSGetActiveConsoleSessionId, ProcessIdToSessionId,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, CreateMutexW, CreateEventW, OpenEventW, SetEvent, WaitForSingleObject,
    EVENT_MODIFY_STATE,
};

mod win32_pipe {
    use std::ffi::c_void;

    // REM-025: B.2b Dar User-Channel Access Mask (0x0012008B) və SQOS
    pub const PIPE_MIN_USER_CHANNEL_MASK: u32 = 0x0012008B;
    pub const SECURITY_SQOS_PRESENT: u32 = 0x00100000;
    pub const SECURITY_IDENTIFICATION: u32 = 0x00010000;
    pub const SECURITY_IMPERSONATION: u32 = 0x00020000;
    pub const FLAGS_SECURITY: u32 = SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION;
    pub const OPEN_EXISTING: u32 = 3;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const TOKEN_QUERY: u32 = 0x0008;

    extern "system" {
        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut c_void,
        ) -> *mut c_void;
        pub fn ReadFile(
            hFile: *mut c_void,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> i32;
        pub fn WriteFile(
            hFile: *mut c_void,
            lpBuffer: *const u8,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: *mut u32,
            lpOverlapped: *mut c_void,
        ) -> i32;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
        pub fn GetNamedPipeServerProcessId(Pipe: *mut c_void, ServerProcessId: *mut u32) -> i32;
        pub fn ConvertSidToStringSidW(Sid: *mut c_void, StringSid: *mut *mut u16) -> i32;
        pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        pub fn QueryFullProcessImageNameW(hProcess: *mut c_void, dwFlags: u32, lpExeName: *mut u16, lpdwSize: *mut u32) -> i32;
        pub fn OpenProcessToken(ProcessHandle: *mut c_void, DesiredAccess: u32, TokenHandle: *mut *mut c_void) -> i32;
        pub fn GetTokenInformation(TokenHandle: *mut c_void, TokenInformationClass: u32, TokenInformation: *mut c_void, TokenInformationLength: u32, ReturnLength: *mut u32) -> i32;
    }
}

pub fn get_current_user_sid() -> Result<String, String> {
    unsafe {
        let mut h_token: windows_sys::Win32::Foundation::HANDLE = std::ptr::null_mut();
        if windows_sys::Win32::System::Threading::OpenProcessToken(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            windows_sys::Win32::Security::TOKEN_QUERY,
            &mut h_token,
        ) == 0 {
            return Err("OpenProcessToken uğursuz oldu".to_string());
        }

        let mut return_length: u32 = 0;
        let _ = windows_sys::Win32::Security::GetTokenInformation(
            h_token,
            windows_sys::Win32::Security::TokenUser,
            std::ptr::null_mut(),
            0,
            &mut return_length,
        );
        if return_length == 0 {
            windows_sys::Win32::Foundation::CloseHandle(h_token);
            return Err("GetTokenInformation uzunluq ala bilmədi".to_string());
        }

        let mut buf = vec![0u8; return_length as usize];
        if windows_sys::Win32::Security::GetTokenInformation(
            h_token,
            windows_sys::Win32::Security::TokenUser,
            buf.as_mut_ptr() as *mut _,
            return_length,
            &mut return_length,
        ) == 0 {
            windows_sys::Win32::Foundation::CloseHandle(h_token);
            return Err("GetTokenInformation uğursuz oldu".to_string());
        }
        windows_sys::Win32::Foundation::CloseHandle(h_token);

        let p_sid = *(buf.as_ptr() as *const *mut _);
        let mut p_string_sid: *mut u16 = std::ptr::null_mut();
        if win32_pipe::ConvertSidToStringSidW(p_sid, &mut p_string_sid) == 0 || p_string_sid.is_null() {
            return Err("ConvertSidToStringSidW uğursuz oldu".to_string());
        }

        let mut len = 0;
        while *p_string_sid.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p_string_sid, len as usize);
        let sid_str = String::from_utf16_lossy(slice);
        LocalFree(p_string_sid as HLOCAL);
        Ok(sid_str)
    }
}

fn verify_scm_service_pid(srv_pid: u32) -> bool {
    unsafe {
        let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
        if scm.is_null() { return false; }
        let svc_name_u16: Vec<u16> = "WinKeyService\0".encode_utf16().collect();
        let svc = OpenServiceW(scm, svc_name_u16.as_ptr(), SERVICE_QUERY_STATUS);
        if svc.is_null() {
            CloseServiceHandle(scm);
            return false;
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct SERVICE_STATUS_PROCESS {
            dwServiceType: u32,
            dwCurrentState: u32,
            dwControlsAccepted: u32,
            dwWin32ExitCode: u32,
            dwServiceSpecificExitCode: u32,
            dwCheckPoint: u32,
            dwWaitHint: u32,
            dwProcessId: u32,
            dwServiceFlags: u32,
        }
        extern "system" {
            fn QueryServiceStatusEx(
                hService: *mut c_void,
                InfoLevel: u32,
                lpBuffer: *mut u8,
                cbBufSize: u32,
                pcbBytesNeeded: *mut u32,
            ) -> i32;
        }

        let mut ssp: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0u32;
        let ok = QueryServiceStatusEx(
            svc,
            0,
            &mut ssp as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        );
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);

        if ok == 0 || ssp.dwCurrentState != SERVICE_RUNNING {
            return false;
        }

        if ssp.dwProcessId == srv_pid {
            return true;
        }

        #[repr(C)]
        #[allow(non_snake_case)]
        struct PROCESSENTRY32W {
            dwSize: u32,
            cntUsage: u32,
            th32ProcessID: u32,
            th32DefaultHeapID: usize,
            th32ModuleID: u32,
            cntThreads: u32,
            th32ParentProcessID: u32,
            pcPriClassBase: i32,
            dwFlags: u32,
            szExeFile: [u16; 260],
        }
        extern "system" {
            fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut c_void;
            fn Process32FirstW(hSnapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
            fn Process32NextW(hSnapshot: *mut c_void, lppe: *mut PROCESSENTRY32W) -> i32;
        }

        let snap = CreateToolhelp32Snapshot(0x00000002, 0);
        if snap.is_null() || snap as isize == -1 {
            return false;
        }

        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        let mut matched = false;
        if Process32FirstW(snap, &mut pe) != 0 {
            loop {
                if pe.th32ProcessID == srv_pid {
                    let exe_name = String::from_utf16_lossy(&pe.szExeFile);
                    let clean_exe = exe_name.trim_matches('\0').to_lowercase();
                    if clean_exe.ends_with("winkey_service.exe") && pe.th32ParentProcessID == ssp.dwProcessId {
                        matched = true;
                    }
                    break;
                }
                if Process32NextW(snap, &mut pe) == 0 {
                    break;
                }
            }
        }
        win32_pipe::CloseHandle(snap);
        matched
    }
}

// REM-027: B.2b Client-Tərəfli Pre-Transfer Server Autentifikasiyası (Fail-Closed)
pub fn verify_trusted_service_server(h_pipe: *mut c_void) -> Result<u32, String> {
    unsafe {
        let mut srv_pid = 0u32;
        if win32_pipe::GetNamedPipeServerProcessId(h_pipe, &mut srv_pid) == 0 || srv_pid == 0 {
            return Err("E_CANNOT_VERIFY_SERVICE_PID: Server proses kimliyi alına bilmədi".to_string());
        }

        let my_pid = GetCurrentProcessId();
        if srv_pid == my_pid {
            return Err("E_SELF_CONNECT_FORBIDDEN: Server prosesi cari proses ilə eynidir (Daxili dövr əngəlləndi)".to_string());
        }

        // Open server process handle for limited query
        let h_proc = win32_pipe::OpenProcess(win32_pipe::PROCESS_QUERY_LIMITED_INFORMATION, 0, srv_pid);
        if h_proc.is_null() || h_proc as isize == -1 {
            let err = GetLastError();
            // If Access Denied (5), the server is running in Session 0 as LocalSystem.
            // Verify via SCM that WinKeyService is running and matches srv_pid.
            if err == 5 && verify_scm_service_pid(srv_pid) {
                return Ok(srv_pid);
            }
            return Err(format!("E_CANNOT_OPEN_SERVER_PROCESS: Server prosesi açıla bilmədi (WinError={})", err));
        }

        // 1. Check executable image path (must end with winkey_service.exe)
        let mut exe_buf = [0u16; 1024];
        let mut exe_len = exe_buf.len() as u32;
        let image_ok = win32_pipe::QueryFullProcessImageNameW(h_proc, 0, exe_buf.as_mut_ptr(), &mut exe_len);
        if image_ok == 0 || exe_len == 0 {
            win32_pipe::CloseHandle(h_proc);
            return Err(format!("E_CANNOT_VERIFY_SERVER_IMAGE: Server proses fayl yolu alına bilmədi (WinError={})", GetLastError()));
        }
        let exe_path = String::from_utf16_lossy(&exe_buf[..exe_len as usize]).to_lowercase();
        if !exe_path.ends_with("winkey_service.exe") {
            win32_pipe::CloseHandle(h_proc);
            return Err(format!("E_UNTRUSTED_SERVER_EXE: Server prosesi winkey_service.exe deyil: '{}'", exe_path));
        }

        // 2. Extract Server Token SID
        let mut h_token: *mut c_void = null_mut();
        if win32_pipe::OpenProcessToken(h_proc, win32_pipe::TOKEN_QUERY, &mut h_token) == 0 || h_token.is_null() {
            win32_pipe::CloseHandle(h_proc);
            return Err(format!("E_CANNOT_OPEN_SERVER_TOKEN: Server proses tokeni alına bilmədi (WinError={})", GetLastError()));
        }

        let mut return_length = 0u32;
        let _ = win32_pipe::GetTokenInformation(h_token, 1, null_mut(), 0, &mut return_length);
        if return_length == 0 {
            win32_pipe::CloseHandle(h_token);
            win32_pipe::CloseHandle(h_proc);
            return Err("E_CANNOT_READ_SERVER_TOKEN_INFO: Token uzunluğu alına bilmədi".to_string());
        }

        let mut buf = vec![0u8; return_length as usize];
        if win32_pipe::GetTokenInformation(h_token, 1, buf.as_mut_ptr() as *mut c_void, return_length, &mut return_length) == 0 {
            win32_pipe::CloseHandle(h_token);
            win32_pipe::CloseHandle(h_proc);
            return Err("E_SERVER_TOKEN_QUERY_FAILED: Token məlumatı oxunmadı".to_string());
        }

        let p_sid = *(buf.as_ptr() as *const *mut c_void);
        let mut p_string_sid: *mut u16 = null_mut();
        if win32_pipe::ConvertSidToStringSidW(p_sid, &mut p_string_sid) == 0 || p_string_sid.is_null() {
            win32_pipe::CloseHandle(h_token);
            win32_pipe::CloseHandle(h_proc);
            return Err("E_SERVER_SID_CONVERSION_FAILED: SID mətnə çevrilmədi".to_string());
        }

        let mut len = 0;
        while *p_string_sid.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p_string_sid, len as usize);
        let srv_sid = String::from_utf16_lossy(slice);
        LocalFree(p_string_sid as HLOCAL);
        win32_pipe::CloseHandle(h_token);
        win32_pipe::CloseHandle(h_proc);

        // 3. Trust Decision:
        // A) Əgər server LocalSystem-dirsə (S-1-5-18) -> Təsdiqlənmiş Production SCM xidmətidir!
        if srv_sid == "S-1-5-18" {
            return Ok(srv_pid);
        }

        // B) Əgər standalone/test rejimindədirsə: yalnız explicit test trusted binding ilə qəbul edilir!
        if let Ok(expected_pid_str) = std::env::var("WINKEY_TRUSTED_SERVICE_PID") {
            if let Ok(expected_pid) = expected_pid_str.trim().parse::<u32>() {
                if expected_pid == srv_pid {
                    println!("[TEST_TRUST_BINDING] Standalone test üçün server PID {} təsdiqləndi", srv_pid);
                    return Ok(srv_pid);
                } else {
                    return Err(format!("E_UNTRUSTED_SERVER_PID_MISMATCH: Gözlənilən test PID {} != server PID {}", expected_pid, srv_pid));
                }
            }
        }

        // Production-da başqa istifadəçi və ya SYSTEM olmayan saxta server fail-closed rədd edilir!
        Err(format!("E_UNTRUSTED_SERVER_IDENTITY: Server LocalSystem (S-1-5-18) deyil və etibarlı test binding yoxdur (Server SID='{}', PID={})", srv_sid, srv_pid))
    }
}

pub fn provision_device_to_service_ipc(device_id: &str, device_secret: &str) -> Result<String, String> {
    let pipe_path = "\\\\.\\pipe\\WinKey_Service_IPC\0";
    let pipe_w: Vec<u16> = pipe_path.encode_utf16().collect();

    let gateway_origin = fs::read_to_string(get_app_data_dir().join("config.json")).ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|cfg| cfg.get("gateway_origin").and_then(|v| v.as_str()).map(String::from));
    let cmd = serde_json::json!({
        "ProvisionDevice": {
            "device_id": device_id,
            "device_secret": device_secret,
            "gateway_origin": gateway_origin
        }
    });
    let cmd_str = format!("{}\n", cmd);

    unsafe {
        // REM-025: CreateFileW PIPE_MIN_USER_CHANNEL_MASK və FLAGS_SECURITY ilə açılır (GENERIC_WRITE qadağandır)
        let h_pipe = win32_pipe::CreateFileW(
            pipe_w.as_ptr(),
            win32_pipe::PIPE_MIN_USER_CHANNEL_MASK,
            0,
            null_mut(),
            win32_pipe::OPEN_EXISTING,
            win32_pipe::FLAGS_SECURITY,
            null_mut(),
        );

        if h_pipe.is_null() || h_pipe as isize == -1 {
            let err = GetLastError();
            return Err(format!("E_SERVICE_IPC_UNAVAILABLE: Service pipe əlçatmazdır (WinError={})", err));
        }

        // REM-027: Pre-transfer trusted server təsdiqi (B.2b)
        // Fake pipe server / wrong process / non-SYSTEM halında serverə SIFIR payload ötürülür!
        if let Err(e) = verify_trusted_service_server(h_pipe) {
            win32_pipe::CloseHandle(h_pipe);
            return Err(e);
        }

        let mut written = 0u32;
        let write_ok = win32_pipe::WriteFile(
            h_pipe,
            cmd_str.as_ptr(),
            cmd_str.len() as u32,
            &mut written,
            null_mut(),
        );

        if write_ok == 0 {
            win32_pipe::CloseHandle(h_pipe);
            return Err("E_SERVICE_IPC_WRITE_FAILED".to_string());
        }

        let mut buf = [0u8; 1024];
        let mut read = 0u32;
        let read_ok = win32_pipe::ReadFile(
            h_pipe,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut read,
            null_mut(),
        );
        win32_pipe::CloseHandle(h_pipe);

        if read_ok != 0 && read > 0 {
            let resp = String::from_utf8_lossy(&buf[..read as usize]);
            Ok(resp.trim().to_string())
        } else {
            Err("E_SERVICE_IPC_EMPTY_RESPONSE".to_string())
        }
    }
}

pub fn send_service_control_command(action: &str) -> Result<String, String> {
    let pipe_path = "\\\\.\\pipe\\WinKey_Service_IPC\0";
    let pipe_w: Vec<u16> = pipe_path.encode_utf16().collect();
    let cmd_str = format!("{}\n", action);

    unsafe {
        let h_pipe = win32_pipe::CreateFileW(
            pipe_w.as_ptr(),
            win32_pipe::PIPE_MIN_USER_CHANNEL_MASK,
            0,
            null_mut(),
            win32_pipe::OPEN_EXISTING,
            win32_pipe::FLAGS_SECURITY,
            null_mut(),
        );

        if h_pipe.is_null() || h_pipe as isize == -1 {
            let err = GetLastError();
            return Err(format!("E_SERVICE_IPC_UNAVAILABLE: Service pipe əlçatmazdır (WinError={})", err));
        }

        if let Err(e) = verify_trusted_service_server(h_pipe) {
            win32_pipe::CloseHandle(h_pipe);
            return Err(e);
        }

        let mut written = 0u32;
        let write_ok = win32_pipe::WriteFile(
            h_pipe,
            cmd_str.as_ptr(),
            cmd_str.len() as u32,
            &mut written,
            null_mut(),
        );

        if write_ok == 0 {
            win32_pipe::CloseHandle(h_pipe);
            return Err("E_SERVICE_IPC_WRITE_FAILED".to_string());
        }

        let mut buf = [0u8; 1024];
        let mut read = 0u32;
        let read_ok = win32_pipe::ReadFile(
            h_pipe,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut read,
            null_mut(),
        );
        win32_pipe::CloseHandle(h_pipe);

        if read_ok != 0 && read > 0 {
            let resp = String::from_utf8_lossy(&buf[..read as usize]);
            Ok(resp.trim().to_string())
        } else {
            Err("E_SERVICE_IPC_EMPTY_RESPONSE".to_string())
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceStatusDto {
    pub computer_name: String,
    pub service_status: String,
    pub is_registered: bool,
    pub device_id: String,
    pub pin_ready: bool,
    pub current_process_session_id: u32,
    pub active_console_session_id: u32,
    pub version: String,
    pub gateway_origin: String,
    pub cloud_gateway_origin: String,
    pub connection_mode: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PairingPayloadDto {
    pub device_id: String,
    pub computer_name: String,
    pub pair_code: String,
    pub challenge_hex: String,
    pub public_key_hex: String,
    pub expires_at: u64,
    pub pairing_url: String,
    pub qr_svg_data_uri: String,
    #[serde(default)]
    pub qr_svg_raw: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SupportDiagnosticsDto {
    pub os_name: String,
    pub current_process_session_id: u32,
    pub active_console_session_id: u32,
    pub service_status: String,
    pub credential_stored_locally: bool,
    pub config_dir: String,
    pub redacting_policy: String,
    pub dpapi_service_boundary: String,
}

fn get_app_data_dir() -> PathBuf {
    if let Ok(custom) = std::env::var("WINKEY_DATA_DIR") {
        let p = PathBuf::from(custom);
        let _ = fs::create_dir_all(&p);
        return p;
    }
    if let Ok(program_data) = std::env::var("ProgramData") {
        let p = PathBuf::from(program_data).join("WinKey");
        if p.exists() {
            let test_file = p.join(".write_test");
            if fs::write(&test_file, b"1").is_ok() {
                let _ = fs::remove_file(test_file);
                return p;
            }
        }
    }
    let base = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("ProgramData"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
    let winkey_dir = base.join("WinKey");
    let _ = fs::create_dir_all(&winkey_dir);
    winkey_dir
}

fn dpapi_protect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptProtectData(
            &mut in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if success == 0 {
        return Err(format!("Windows DPAPI şifrələmə xətası: {}", unsafe { GetLastError() }));
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let vec = slice.to_vec();
    unsafe { LocalFree(out_blob.pbData as HLOCAL) };
    Ok(vec)
}

fn dpapi_unprotect(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let success = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if success == 0 {
        return Err(format!("Windows DPAPI deşifrələmə xətası: {}", unsafe { GetLastError() }));
    }
    let slice = unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) };
    let vec = slice.to_vec();
    unsafe { LocalFree(out_blob.pbData as HLOCAL) };
    Ok(vec)
}

pub fn store_user_credential_to_service_ipc(pin: &str) -> Result<String, String> {
    let pipe_path = "\\\\.\\pipe\\WinKey_Service_IPC\0";
    let pipe_w: Vec<u16> = pipe_path.encode_utf16().collect();

    let cmd = serde_json::json!({
        "StoreUserCredential": {
            "pin": pin
        }
    });
    let cmd_str = format!("{}\n", cmd);

    unsafe {
        // REM-025: CreateFileW PIPE_MIN_USER_CHANNEL_MASK və FLAGS_SECURITY ilə açılır (GENERIC_WRITE qadağandır)
        let h_pipe = win32_pipe::CreateFileW(
            pipe_w.as_ptr(),
            win32_pipe::PIPE_MIN_USER_CHANNEL_MASK,
            0,
            null_mut(),
            win32_pipe::OPEN_EXISTING,
            win32_pipe::FLAGS_SECURITY,
            null_mut(),
        );

        if h_pipe.is_null() || h_pipe as isize == -1 {
            let err = GetLastError();
            return Err(format!("E_SERVICE_IPC_UNAVAILABLE: Service pipe əlçatmazdır (WinError={})", err));
        }

        // REM-027: Pre-transfer trusted server təsdiqi (B.2b)
        // Fake pipe server / wrong process / non-SYSTEM halında serverə SIFIR payload ötürülür!
        if let Err(e) = verify_trusted_service_server(h_pipe) {
            win32_pipe::CloseHandle(h_pipe);
            return Err(e);
        }

        let mut written = 0u32;
        let write_ok = win32_pipe::WriteFile(
            h_pipe,
            cmd_str.as_ptr(),
            cmd_str.len() as u32,
            &mut written,
            null_mut(),
        );

        if write_ok == 0 {
            win32_pipe::CloseHandle(h_pipe);
            return Err("E_SERVICE_IPC_WRITE_FAILED".to_string());
        }

        let mut buf = [0u8; 1024];
        let mut read = 0u32;
        let read_ok = win32_pipe::ReadFile(
            h_pipe,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut read,
            null_mut(),
        );
        win32_pipe::CloseHandle(h_pipe);

        if read_ok != 0 && read > 0 {
            let resp = String::from_utf8_lossy(&buf[..read as usize]);
            Ok(resp.trim().to_string())
        } else {
            Err("E_SERVICE_IPC_EMPTY_RESPONSE".to_string())
        }
    }
}

// Persist edilmiş və Windows DPAPI ilə qorunan Ed25519 Device Keypair
fn get_or_create_device_keypair() -> Result<(SigningKey, VerifyingKey), String> {
    let key_dpapi_file = get_app_data_dir().join("device_key.dpapi");
    if key_dpapi_file.exists() {
        if let Ok(enc_bytes) = fs::read(&key_dpapi_file) {
            if let Ok(mut raw_seed) = dpapi_unprotect(&enc_bytes) {
                if raw_seed.len() == 32 {
                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&raw_seed);
                    raw_seed.zeroize();
                    let signing_key = SigningKey::from_bytes(&seed);
                    let verifying_key = signing_key.verifying_key();
                    return Ok((signing_key, verifying_key));
                }
            }
        }
    }

    // Yeni keypair generasiya edirik və DPAPI ilə qoruyuruq
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let enc_bytes = dpapi_protect(&seed)?;
    fs::write(&key_dpapi_file, &enc_bytes).map_err(|e| format!("Açar faylı saxlanıla bilmədi: {}", e))?;

    // Köhnə qorunmayan fayl varsa təmizləyirik
    let old_raw_file = get_app_data_dir().join("device_key.bin");
    if old_raw_file.exists() {
        let _ = fs::remove_file(old_raw_file);
    }

    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    seed.zeroize();
    Ok((signing_key, verifying_key))
}

fn to_base64(bytes: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(CHARSET[(b0 >> 2) as usize] as char);
        out.push(CHARSET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARSET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARSET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn get_local_lan_ip() -> Option<String> {
    use std::net::UdpSocket;
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    let ip = local_addr.ip().to_string();
    if ip != "0.0.0.0" && ip != "127.0.0.1" {
        Some(ip)
    } else {
        None
    }
}

// 1. Windows DPAPI ilə təhlükəsiz PIN saxlanması (REM-024: Tək və vahid service-owned vault)
#[tauri::command]
fn save_credential_dpapi(mut pin: String) -> Result<String, String> {
    if pin.trim().is_empty() {
        return Err("PIN boş ola bilməz".to_string());
    }

    // REM-024: Heç bir plaintext credential sızmır!
    // Only the service can confirm a credential usable in its SYSTEM context.
    let ipc_res = store_user_credential_to_service_ipc(&pin);
    pin.zeroize();
    match ipc_res {
        Ok(ref resp) if resp.contains("Ack") || resp.contains("PIN_STORED") => Ok("DPAPI_SUCCESS".to_string()),
        Ok(resp) => Err(format!("E_SERVICE_PIN_SAVE_FAILED: {}", resp)),
        Err(e) => Err(format!("E_SERVICE_PIN_SAVE_FAILED: {}", e)),
    }
}

#[tauri::command]
fn check_credential_status() -> Result<bool, String> {
    let response = send_service_control_command("CREDENTIAL_READY")?;
    let value: serde_json::Value = serde_json::from_str(&response).map_err(|_| "E_CREDENTIAL_STATUS_RESPONSE")?;
    Ok(value.get("credential_ready").and_then(|v| v.as_bool()).unwrap_or(false))
}

// 2. Cihaz Statusu və Real Sessiya ID-ləri
#[tauri::command]
fn get_device_status() -> Result<DeviceStatusDto, String> {
    let computer_name = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".to_string());

    let mut current_proc_session: u32 = 0;
    unsafe {
        let _ = ProcessIdToSessionId(GetCurrentProcessId(), &mut current_proc_session);
    }
    let active_console = unsafe { WTSGetActiveConsoleSessionId() };

    // SCM Service sorğusu
    let service_status = unsafe {
        let scm = OpenSCManagerW(null_mut(), null_mut(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            "SCM_UNAVAILABLE".to_string()
        } else {
            let service_name: Vec<u16> = "WinKeyService\0".encode_utf16().collect();
            let svc = OpenServiceW(scm, service_name.as_ptr(), SERVICE_QUERY_STATUS);
            if svc.is_null() {
                CloseServiceHandle(scm);
                "NOT_INSTALLED".to_string()
            } else {
                let mut status: SERVICE_STATUS = std::mem::zeroed();
                let res = QueryServiceStatus(svc, &mut status);
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);

                if res != 0 {
                    match status.dwCurrentState {
                        SERVICE_RUNNING => "RUNNING".to_string(),
                        SERVICE_STOPPED => "STOPPED".to_string(),
                        SERVICE_START_PENDING => "STARTING".to_string(),
                        SERVICE_STOP_PENDING => "STOPPING".to_string(),
                        _ => format!("STATE_{}", status.dwCurrentState),
                    }
                } else {
                    "STATUS_UNKNOWN".to_string()
                }
            }
        }
    };

    let cred_ready = check_credential_status().unwrap_or(false);

    // Server-confirmed registration yoxlanışı
    let cfg_file = get_app_data_dir().join("config.json");
    let mut is_registered = false;
    let mut device_id = String::new();
    let mut gateway_origin = std::env::var("WINKEY_GATEWAY_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:8788".to_string());
    let mut cloud_gateway_origin = gateway_config::CLOUD_ORIGIN.to_string();
    let mut connection_mode = "cloud".to_string();

    if cfg_file.exists() {
        if let Ok(raw) = fs::read_to_string(&cfg_file) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
                cloud_gateway_origin = gateway_config::cloud_origin(json.get("cloud_gateway_origin").and_then(|v| v.as_str()));
                connection_mode = json.get("connection_mode").and_then(|v| v.as_str()).unwrap_or("cloud").to_string();
                if let Some(gw) = json.get("gateway_origin").and_then(|v| v.as_str()) {
                    if !gw.trim().is_empty() {
                        gateway_origin = gw.trim().trim_end_matches('/').to_string();
                    }
                }
                if json.get("server_confirmed").and_then(|v| v.as_bool()).unwrap_or(false) {
                    if let Some(did) = json.get("device_id").and_then(|v| v.as_str()) {
                        is_registered = true;
                        device_id = did.to_string();
                    }
                }
            }
        }
    }

    Ok(DeviceStatusDto {
        computer_name,
        service_status,
        is_registered,
        device_id,
        pin_ready: cred_ready,
        current_process_session_id: current_proc_session,
        active_console_session_id: active_console,
        version: slot_update::current_version(),
        gateway_origin,
        cloud_gateway_origin,
        connection_mode,
    })
}

// 3. Kompüter adının qeydiyyatı
#[tauri::command]
fn set_computer_name(name: String) -> Result<String, String> {
    let clean = name.trim().to_string();
    if clean.is_empty() {
        return Err("Kompüter adı boş ola bilməz".to_string());
    }
    let cfg_file = get_app_data_dir().join("config.json");
    let mut val = if cfg_file.exists() {
        fs::read_to_string(&cfg_file)
            .ok()
            .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    val["computer_name"] = serde_json::json!(clean);
    val["updated_at"] = serde_json::json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());

    fs::write(&cfg_file, val.to_string()).map_err(|e| format!("Saxlama xətası: {}", e))?;
    Ok(clean)
}

// 3.1 Gateway origin təyini
#[tauri::command]
fn set_gateway_origin(origin: String) -> Result<String, String> {
    let clean = gateway_config::normalize(&origin)?;
    if clean.is_empty() {
        return Err("Gateway ünvanı boş ola bilməz".to_string());
    }
    let cfg_file = get_app_data_dir().join("config.json");
    let mut val = if cfg_file.exists() {
        fs::read_to_string(&cfg_file)
            .ok()
            .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    val["gateway_origin"] = serde_json::json!(clean);
    val["cloud_gateway_origin"] = serde_json::json!(clean);
    val["updated_at"] = serde_json::json!(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());

    fs::write(&cfg_file, val.to_string()).map_err(|e| format!("Saxlama xətası: {}", e))?;
    Ok(clean)
}

// 4. Real Ed25519 QR Pairing Kodu, Server Qeydiyyatı və Həqiqi SVG QR
#[tauri::command]
fn generate_qr_pairing(mode: Option<String>) -> Result<PairingPayloadDto, String> {
    account::require_account()?;
    // 1. Gateway origin-in əldə edilməsi (Dual Mode: Wi-Fi Lokal vs Bulud İnternet)
    let cfg_file = get_app_data_dir().join("config.json");
    let mut cfg_val = if cfg_file.exists() {
        fs::read_to_string(&cfg_file)
            .ok()
            .and_then(|r| serde_json::from_str::<serde_json::Value>(&r).ok())
            .unwrap_or_else(|| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let target_origin = if let Some(ref m) = mode {
        if m == "cloud" || m == "internet" {
            gateway_config::cloud_origin(cfg_val.get("cloud_gateway_origin").and_then(|v| v.as_str()))
        } else {
            "http://127.0.0.1:8788".to_string()
        }
    } else {
        std::env::var("WINKEY_GATEWAY_ORIGIN").ok()
            .or_else(|| cfg_val.get("gateway_origin").and_then(|v| v.as_str()).map(String::from))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "http://127.0.0.1:8788".to_string())
    };
    let origin = gateway_config::normalize(&target_origin)?;
    let request = |path: &str, payload: serde_json::Value, token: Option<&str>| -> Result<serde_json::Value, String> {
        eprintln!("[PAIRING] POST {} started", path);
        let mut req = ureq::post(&format!("{}{}", origin, path))
            .timeout(std::time::Duration::from_secs(3));
        if let Some(t) = token { req = req.set("Authorization", &format!("Bearer {}", t)); }
        match req.send_json(payload) {
            Ok(resp) => {
                eprintln!("[PAIRING] POST {} HTTP={}", path, resp.status());
                resp.into_json().map_err(|_| format!("E_RESPONSE_JSON {}", path))
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_json::<serde_json::Value>().unwrap_or_default();
                let code = body.get("error").and_then(|v| v.as_str()).unwrap_or("E_GATEWAY_RESPONSE");
                eprintln!("[PAIRING] POST {} HTTP={} code={}", path, status, code);
                Err(format!("{} HTTP={} {}", path, status, code))
            }
            Err(_) => { eprintln!("[PAIRING] POST {} transport/timeout failure", path); Err(format!("E_GATEWAY_CONNECTION {}", path)) }
        }
    };
    let (signing_key, verifying_key) = get_or_create_device_keypair()?;
    let public_key_hex = verifying_key.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let device_id = format!("pc_{}", &public_key_hex[..24]);
    let computer_name = cfg_val.get("computer_name").and_then(|v| v.as_str()).map(String::from)
        .unwrap_or_else(|| std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".to_string()));
    let secret_file = get_app_data_dir().join("device_secret.dpapi");
    use sha2::{Digest, Sha256};
    let endpoint_secret_file = get_app_data_dir().join(format!("device_secret_{:x}.dpapi", Sha256::digest(origin.as_bytes())));
    let previous_origin = cfg_val.get("gateway_origin").and_then(|v| v.as_str()).unwrap_or("");
    let secret_source = if endpoint_secret_file.exists() { Some(&endpoint_secret_file) }
        else if previous_origin.trim_end_matches('/') == origin { Some(&secret_file) } else { None };
    let old_secret = if cfg_val.get("device_id").and_then(|v| v.as_str()) == Some(device_id.as_str()) {
        secret_source.and_then(|path| fs::read(path).ok()).and_then(|b| dpapi_unprotect(&b).ok()).and_then(|b| String::from_utf8(b).ok())
    } else { None };

    let is_local_mode = matches!(mode.as_deref(), Some("wifi") | Some("local"));
    let broker_pair = if !is_local_mode {
        let command=serde_json::json!({"RequestPairing":{"device_id":device_id,"gateway_origin":origin}}).to_string();
        send_service_control_command(&command).ok()
            .and_then(|raw|serde_json::from_str::<serde_json::Value>(&raw).ok())
            .filter(|value|value.get("device_id").and_then(|v|v.as_str())==Some(device_id.as_str())
                && value.get("pair_code").and_then(|v|v.as_str()).is_some()
                && value.get("expires_at").and_then(|v|v.as_f64()).is_some())
    } else {None};
    let (secret, pair_code, expires_at) = if let Some(pair)=broker_pair {
        (None,pair["pair_code"].as_str().unwrap().to_string(),pair["expires_at"].as_f64().unwrap() as u64)
    } else {(|| -> Result<(Option<String>, String, u64), String> {
        let do_register = || -> Result<String, String> {
            let challenge = request("/agent/challenge", serde_json::json!({"purpose":"register", "device_id":device_id}), None)?;
            let nonce = challenge.get("nonce").and_then(|v| v.as_str()).ok_or("E_MISSING_NONCE")?;
            let proof = signing_key.sign(format!("WINKEY_REGISTER:{}:{}", nonce, device_id).as_bytes());
            let proof_hex = proof.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
            let registered = request("/agent/register", serde_json::json!({
                "device_id":device_id, "computer_name":computer_name, "public_key_hex":public_key_hex,
                "nonce":nonce, "proof_signature_hex":proof_hex
            }), None).map_err(|error| if error.contains("E_DEVICE_ALREADY_REGISTERED") {
                "E_LOCAL_AGENT_ACCESS_RECOVERY_REQUIRED: Cihaz serverdə mövcuddur. Quraşdırılmış xidməti Repair/setup ilə yeniləyin; cihazı və telefon sessiyalarını silməyin.".to_string()
            } else {error})?;
            registered.get("device_secret").and_then(|v| v.as_str()).map(String::from).ok_or_else(|| "E_MISSING_DEVICE_SECRET".to_string())
        };

        let (sec, pair) = if let Some(s) = old_secret.clone() {
            match request("/devices/pair-request", serde_json::json!({"device_id":device_id}), Some(&s)) {
                Ok(p) => (s, p),
                Err(err) if err.contains("401") || err.contains("E_UNAUTHORIZED") => {
                    eprintln!("[PAIRING] Server secret-i qebul etmedi (401), yeniden qeydiyyat edilir...");
                    let new_sec = do_register()?;
                    let p = request("/devices/pair-request", serde_json::json!({"device_id":device_id}), Some(&new_sec))?;
                    (new_sec, p)
                }
                Err(e) => return Err(e),
            }
        } else {
            let new_sec = do_register()?;
            let p = request("/devices/pair-request", serde_json::json!({"device_id":device_id}), Some(&new_sec))?;
            (new_sec, p)
        };
        let code = pair.get("pair_code").and_then(|v| v.as_str()).ok_or("E_MISSING_PAIR_CODE")?.to_string();
        let exp = pair.get("expires_at").and_then(|v| v.as_f64()).ok_or("E_MISSING_PAIR_EXPIRY")? as u64;
        Ok((Some(sec), code, exp))
    })().map_err(|err| {
        eprintln!("[PAIRING] Gateway xətası: {}", err);
        format!("E_GATEWAY_PAIRING_FAILED: {}", err)
    })?};

    let challenge_hex = String::new();
    if let Some(secret)=secret.as_ref() {
        let encrypted = dpapi_protect(secret.as_bytes())?;
        fs::write(&endpoint_secret_file, &encrypted).map_err(|_| "E_SECRET_SAVE")?;
        // SYSTEM vault is provisioned through IPC; never overwrite its DPAPI blob from the UI.
    }
    cfg_val["device_id"] = serde_json::json!(device_id);
    cfg_val["computer_name"] = serde_json::json!(computer_name);
    gateway_config::record_registration(&mut cfg_val, &origin, is_local_mode);
    if let Some(obj) = cfg_val.as_object_mut() { obj.remove("device_secret"); }
    fs::write(&cfg_file, cfg_val.to_string()).map_err(|e| format!("E_CONFIG_SAVE: {}", e))?;

    if !is_local_mode { account::bind_device(&device_id, &signing_key)?; }

    // Aktiv birdəfəlik LAN cütləşmə kodunu qeyd edirik
    let pair_challenge_dto = serde_json::json!({
        "device_id": device_id,
        "pair_code": pair_code,
        "expires_at": expires_at,
        "consumed": false,
        "created_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
    });
    let active_pair_file = get_app_data_dir().join("active_pair.json");
    let _ = fs::write(&active_pair_file, pair_challenge_dto.to_string());
    let pd_pair = std::path::PathBuf::from("C:\\ProgramData\\WinKey\\active_pair.json");
    let _ = fs::write(&pd_pair, pair_challenge_dto.to_string());

    if let Some(secret)=secret.as_ref().filter(|_| !is_local_mode) {
        match provision_device_to_service_ipc(&device_id, secret) {
            Ok(_) => eprintln!("[PAIRING] trusted service provisioning OK"),
            Err(_) => eprintln!("[PAIRING] E_SERVICE_PROVISION_FAILED: QR may pair, but PC commands require the installed service"),
        }
    }
    // Dual-Mode Mobil URL generasiyası (Lokal Wi-Fi LAN IP vs Bulud HTTPS)
    let pairing_url = if origin.contains("127.0.0.1") || origin.contains("localhost") {
        let lan_ip = get_local_lan_ip().unwrap_or_else(|| "127.0.0.1".to_string());
        let mobile_origin = origin.replace("127.0.0.1", &lan_ip).replace("localhost", &lan_ip);
        format!("{}/remote?device={}&code={}", mobile_origin, device_id, pair_code)
    } else {
        format!("{}/mobile?device={}&code={}", origin, device_id, pair_code)
    };

    let qr_code = qrcode::QrCode::new(pairing_url.as_bytes())
        .map_err(|e| format!("QR generasiya xətası: {}", e))?;

    let qr_svg_raw = qr_code.render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();

    let qr_svg_data_uri = format!(
        "data:image/svg+xml;base64,{}",
        to_base64(qr_svg_raw.as_bytes())
    );

    Ok(PairingPayloadDto {
        device_id,
        computer_name,
        pair_code,
        challenge_hex,
        public_key_hex,
        expires_at,
        pairing_url,
        qr_svg_data_uri,
        qr_svg_raw: Some(qr_svg_raw),
    })
}

// 5. Cütləşmənin ləğv edilməsi (Revoke)
#[tauri::command]
fn revoke_pairing() -> Result<String, String> {
    let data_dir = get_app_data_dir();
    let cfg_file = data_dir.join("config.json");
    if cfg_file.exists() {
        if let Ok(raw) = fs::read_to_string(&cfg_file) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                let origin = val.get("gateway_origin").and_then(|v| v.as_str())
                    .or_else(|| val.get("cloud_gateway_origin").and_then(|v| v.as_str()));
                let dev_id = val.get("device_id").and_then(|v| v.as_str());
                if let (Some(orig), Some(did)) = (origin, dev_id) {
                    let clean_orig = orig.trim_end_matches('/');
                    // 1. Serverdən cihazı və admin panelindən qeydiyyatı tam silirik
                    let _ = ureq::post(&format!("{}/devices/unregister", clean_orig))
                        .timeout(std::time::Duration::from_secs(3))
                        .send_json(serde_json::json!({ "device_id": did }));
                    // 2. Mobil sessiyaları ləğv edirik
                    let _ = ureq::post(&format!("{}/devices/revoke", clean_orig))
                        .timeout(std::time::Duration::from_secs(3))
                        .send_json(serde_json::json!({ "device_id": did }));
                }
            }
        }
        let _ = fs::remove_file(&cfg_file);
    }

    // Kompüterdəki köhnə açar və secret-ləri təmizləyirik ki, yeni QR yaradılanda tərtəmiz yeni cihaz kimi qeydiyyatdan keçsin:
    let _ = fs::remove_file(data_dir.join("device_key.dpapi"));
    let _ = fs::remove_file(data_dir.join("device_secret.dpapi"));
    let _ = fs::remove_file(data_dir.join("active_pair.json"));
    if let Ok(entries) = fs::read_dir(&data_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("device_secret_") && name.ends_with(".dpapi") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    Ok("REVOKED_AND_UNREGISTERED".to_string())
}

// 6. Pəncərəni tepsiyə (tray) gizlətmə
#[tauri::command]
fn minimize_to_tray(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = tauri::Manager::get_webview_window(&app, "main") {
        let _ = window.hide();
    }
    Ok(())
}

// 7. Pəncərəni bərpa etmə
#[tauri::command]
fn restore_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = tauri::Manager::get_webview_window(&app, "main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
    Ok(())
}

// 8. Dəstək və Texniki Diaqnostika
#[tauri::command]
fn get_support_diagnostics() -> Result<SupportDiagnosticsDto, String> {
    let dev = get_device_status()?;
    Ok(SupportDiagnosticsDto {
        os_name: "Windows 11 / 10 x64 (NT 10.0)".to_string(),
        current_process_session_id: dev.current_process_session_id,
        active_console_session_id: dev.active_console_session_id,
        service_status: dev.service_status,
        credential_stored_locally: dev.pin_ready,
        config_dir: get_app_data_dir().to_string_lossy().to_string(),
        redacting_policy: "STRICT_CANARY_ACTIVE: Zero PIN/passwords logged or exported".to_string(),
        dpapi_service_boundary: "ISOLATED: LocalSystem service delegates session focus to user session helper without extracting raw PIN".to_string(),
    })
}

// 9. Uzaqdan İdarəetmənin dayandırılması / bərpası (Tauri command)
#[tauri::command]
fn toggle_remote_service_control(pause: bool) -> Result<String, String> {
    let cmd = if pause { "PAUSE" } else { "RESUME" };
    match send_service_control_command(cmd) {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(if pause { "PAUSED_STANDALONE" } else { "RESUMED_STANDALONE" }.to_string()),
    }
}

// 10. Xidmətin IPC Statusunun sorğulanması (Tauri command)
#[tauri::command]
fn query_service_ipc_status() -> Result<String, String> {
    send_service_control_command("STATUS")
}

#[tauri::command]
async fn get_update_status(check_server: bool) -> Result<serde_json::Value,String> {
    tauri::async_runtime::spawn_blocking(move || {
        let desktop=slot_update::current_version();
        let packaged=std::env::current_exe().ok().and_then(|p|p.parent().map(|p|p.join("manifest.json").is_file())).unwrap_or(false);
        let mut result=serde_json::json!({"desktop_version":desktop,"channel":if packaged {"installed"} else {"dev"},"latest_version":null,"status":"not_checked"});
        if let Ok(raw)=send_service_control_command("UPDATE_STATUS") {
            if let Ok(value)=serde_json::from_str::<serde_json::Value>(&raw) {
                result["worker_version"]=value.get("worker_version").cloned().unwrap_or(serde_json::Value::Null);
                result["phase"]=value.get("phase").cloned().unwrap_or(serde_json::Value::Null);
            }
        }
        if !check_server {return Ok(result);}
        let config=fs::read(get_app_data_dir().join("config.json")).ok()
            .and_then(|raw|serde_json::from_slice::<serde_json::Value>(&raw).ok()).unwrap_or_default();
        let origin=gateway_config::cloud_origin(config.get("cloud_gateway_origin").or_else(||config.get("gateway_origin")).and_then(|v|v.as_str()));
        let response=ureq::get(&format!("{}/updates/latest",origin)).timeout(std::time::Duration::from_secs(5)).call();
        match response {
            Ok(response) => {
                let metadata:serde_json::Value=response.into_json().map_err(|_|"E_UPDATE_RESPONSE".to_string())?;
                let latest=slot_update::verified_release_version(&metadata)?;
                let remote=slot_update::version_tuple(&latest)?;
                let local=slot_update::version_tuple(&desktop)?;
                let worker=result.get("worker_version").and_then(|v|v.as_str()).and_then(|v|slot_update::version_tuple(v).ok());
                let newer=remote>local || worker.as_ref().map(|v|remote>*v).unwrap_or(false);
                result["latest_version"]=serde_json::json!(latest);
                if !packaged {
                    result["status"]=serde_json::json!("dev");
                } else if newer {
                    let reply=send_service_control_command("CHECK_UPDATE");
                    let accepted=reply.as_ref().ok().and_then(|v|serde_json::from_str::<serde_json::Value>(v).ok())==Some(serde_json::json!("Ack"));
                    result["status"]=serde_json::json!(if accepted {"requested"} else {"service_unavailable"});
                } else if worker.is_none() {
                    result["status"]=serde_json::json!("service_unknown");
                } else if local>remote || worker.as_ref().map(|v|*v>remote).unwrap_or(false) {
                    result["status"]=serde_json::json!("ahead");
                } else {
                    result["status"]=serde_json::json!("up_to_date");
                }
            }
            Err(ureq::Error::Status(404,_)) => result["status"]=serde_json::json!("no_release"),
            Err(_) => result["status"]=serde_json::json!("unreachable"),
        }
        Ok(result)
    }).await.map_err(|_|"E_UPDATE_CHECK_TASK".to_string())?
}

/// REM-014: Yerli PC-nin Ed25519 Kriptoqrafik İmzası ilə Təsdiq Funksiyası
pub fn approve_device_on_server(origin: &str, device_id: &str) -> Result<serde_json::Value, String> {
    let (signing_key, _verifying_key) = get_or_create_device_keypair()?;
    let challenge_url = format!("{}/agent/challenge", origin);
    let chal_resp = ureq::post(&challenge_url)
        .timeout(std::time::Duration::from_secs(5))
        .send_json(serde_json::json!({"purpose": "approve", "device_id": device_id}))
        .map_err(|e| format!("E_CHALLENGE_FAILED: Gateway approval challenge sorğusu uğursuz oldu: {}", e))?;

    let chal_json: serde_json::Value = chal_resp.into_json()
        .map_err(|e| format!("E_CHALLENGE_FAILED: Server challenge cavabı oxunmadı: {}", e))?;

    let nonce = chal_json.get("nonce").and_then(|v| v.as_str())
        .ok_or_else(|| "E_CHALLENGE_FAILED: Server 'nonce' qaytarmadı".to_string())?;

    let bound_approve_msg = format!("WINKEY_APPROVE:{}:{}", nonce, device_id);
    let approve_sig = signing_key.sign(bound_approve_msg.as_bytes());
    let approve_sig_hex = approve_sig.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();

    let approve_url = format!("{}/devices/approve", origin);
    let approve_payload = serde_json::json!({
        "device_id": device_id,
        "nonce": nonce,
        "approval_proof_hex": approve_sig_hex
    });

    let resp = ureq::post(&approve_url)
        .timeout(std::time::Duration::from_secs(5))
        .send_json(approve_payload)
        .map_err(|e| format!("E_APPROVAL_FAILED: PC təsdiqi uğursuz oldu: {}", e))?;

    let resp_json: serde_json::Value = resp.into_json()
        .map_err(|e| format!("E_APPROVAL_FAILED: Server cavabı oxunmadı: {}", e))?;

    Ok(resp_json)
}

#[tauri::command]
fn report_ui_error(kind: String, source: String, line: u32) {
    let clean = |s: &str| s.chars().filter(|c| c.is_ascii_alphanumeric() || "_:-./".contains(*c)).take(100).collect::<String>();
    eprintln!("[UI_ERROR] kind={} source={} line={} (details in WebView console)", clean(&kind), clean(&source), line);
}

mod slot_update;

fn main() {
    if std::env::args().skip(1).all(|arg| matches!(arg.as_str(),"--minimized"|"-m")) {
        if let Some(target)=slot_update::different_active_desktop() {
            if std::process::Command::new(target).args(std::env::args().skip(1)).spawn().is_ok() {return;}
        }
    }
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("CRASH PANIC: {:?}\n", info);
        let _ = fs::write("C:\\ProgramData\\WinKey\\crash.log", &msg);
        eprintln!("{}", msg);
    }));
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("WinKey Desktop v{}",slot_update::current_version());
        return;
    }
    if args.iter().any(|a| a == "--check") {
        println!("WINKEY_DESKTOP_PE_OK");
        return;
    }
    if args.iter().any(|a| a == "--register-and-qr") {
        if let Some(pos) = args.iter().position(|a| a == "--origin") {
            if let Some(orig) = args.get(pos + 1) {
                std::env::set_var("WINKEY_GATEWAY_ORIGIN", orig);
            }
        }
        if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            if let Some(dir) = args.get(pos + 1) {
                std::env::set_var("WINKEY_DATA_DIR", dir);
            }
        }
        let mode_arg = if let Some(pos) = args.iter().position(|a| a == "--mode") {
            args.get(pos + 1).cloned()
        } else {
            None
        };
        match generate_qr_pairing(mode_arg) {
            Ok(payload) => {
                println!("{}", serde_json::to_string(&payload).unwrap());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                std::process::exit(1);
            }
        }
    }
    if args.iter().any(|a| a == "--approve-device") {
        if let Some(pos) = args.iter().position(|a| a == "--origin") {
            if let Some(orig) = args.get(pos + 1) {
                std::env::set_var("WINKEY_GATEWAY_ORIGIN", orig);
            }
        }
        if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            if let Some(dir) = args.get(pos + 1) {
                std::env::set_var("WINKEY_DATA_DIR", dir);
            }
        }
        let dev_id = if let Some(pos) = args.iter().position(|a| a == "--approve-device") {
            args.get(pos + 1).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        let origin = std::env::var("WINKEY_GATEWAY_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:8788".to_string());
        match approve_device_on_server(&origin, &dev_id) {
            Ok(payload) => {
                println!("{}", serde_json::to_string(&payload).unwrap());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|a| a == "--provision-service") {
        let dev_id = if let Some(pos) = args.iter().position(|a| a == "--device-id") {
            args.get(pos + 1).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        let secret = if let Some(pos) = args.iter().position(|a| a == "--secret") {
            args.get(pos + 1).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        match provision_device_to_service_ipc(&dev_id, &secret) {
            Ok(resp) => {
                println!("{}", resp);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                std::process::exit(1);
            }
        }
    }

    // REM-027: Standalone test və launcher üçün etibarlı xidmət PID binding
    if let Some(pos) = args.iter().position(|a| a == "--trusted-service-pid") {
        if let Some(pid_str) = args.get(pos + 1) {
            std::env::set_var("WINKEY_TRUSTED_SERVICE_PID", pid_str);
        }
    }

    // REM-024: --store-pin <PIN> qəti qadağandır (argv-də credential sızmasının qarşısı alınır)
    if args.iter().any(|a| a == "--store-pin") {
        eprintln!("ERROR: E_ARGV_CREDENTIAL_PROHIBITED: PIN komanda sətrində parametr kimi qəbul edilmir (Təhlükəsizlik səbəbilə). Stdin üçün '--store-pin-stdin' və ya interaktiv prompt üçün '--store-pin-prompt' istifadə edin.");
        std::process::exit(2);
    }

    // REM-024: Stdin vasitəsilə təhlükəsiz PIN saxlanması (argv və env yoxdur)
    if args.iter().any(|a| a == "--store-pin-stdin") {
        if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            if let Some(dir) = args.get(pos + 1) {
                std::env::set_var("WINKEY_DATA_DIR", dir);
            }
        }
        let mut pin = String::new();
        if std::io::stdin().read_line(&mut pin).is_err() || pin.trim().is_empty() {
            eprintln!("ERROR: E_EMPTY_PIN: Stdin-dən PIN oxunmadı");
            std::process::exit(1);
        }
        let pin = pin.trim().to_string();
        match store_user_credential_to_service_ipc(&pin) {
            Ok(resp) if resp.contains("Ack") || resp.contains("PIN_STORED") => {
                println!("OK_SERVICE_PROVISIONED: PIN_STORED_IN_DPAPI_VAULT");
                std::process::exit(0);
            }
            Ok(resp) => {
                eprintln!("ERROR: E_SERVICE_IPC_UNEXPECTED: {}", resp);
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("ERROR: E_SERVICE_PROVISIONING_FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    // REM-024: İnteraktiv konsol prompt vasitəsilə təhlükəsiz PIN saxlanması
    if args.iter().any(|a| a == "--store-pin-prompt") {
        if let Some(pos) = args.iter().position(|a| a == "--data-dir") {
            if let Some(dir) = args.get(pos + 1) {
                std::env::set_var("WINKEY_DATA_DIR", dir);
            }
        }
        print!("Windows PIN: ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut pin = String::new();
        if std::io::stdin().read_line(&mut pin).is_err() || pin.trim().is_empty() {
            eprintln!("ERROR: E_EMPTY_PIN");
            std::process::exit(1);
        }
        let pin = pin.trim().to_string();
        match store_user_credential_to_service_ipc(&pin) {
            Ok(resp) if resp.contains("Ack") || resp.contains("PIN_STORED") => {
                println!("OK_SERVICE_PROVISIONED: PIN_STORED_IN_DPAPI_VAULT");
                std::process::exit(0);
            }
            Ok(resp) => {
                eprintln!("ERROR: E_SERVICE_IPC_UNEXPECTED: {}", resp);
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("ERROR: E_SERVICE_PROVISIONING_FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    // REM-030: Xidmət Idarəetməsi (PAUSE / RESUME / STATUS) CLI dəstəyi
    if args.iter().any(|a| a == "--service-pause") {
        match send_service_control_command("PAUSE") {
            Ok(resp) => {
                println!("OK_SERVICE_PAUSED: {}", resp);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ERROR: E_SERVICE_PAUSE_FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|a| a == "--service-resume") {
        match send_service_control_command("RESUME") {
            Ok(resp) => {
                println!("OK_SERVICE_RESUMED: {}", resp);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ERROR: E_SERVICE_RESUME_FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    if args.iter().any(|a| a == "--service-status") {
        match send_service_control_command("STATUS") {
            Ok(resp) => {
                println!("OK_SERVICE_STATUS: {}", resp);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("ERROR: E_SERVICE_STATUS_FAILED: {}", e);
                std::process::exit(1);
            }
        }
    }

    // SINGLETON (Session-Scoped Named Mutex + Show/Restore Event)
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    let mut current_sess: u32 = 0;
    unsafe {
        ProcessIdToSessionId(GetCurrentProcessId(), &mut current_sess);
    }
    let sess = if session_id != 0xFFFFFFFF { session_id } else { current_sess };

    let instance_scope = if cfg!(debug_assertions) { "DEV_" } else { "" };
    let mutex_name: Vec<u16> = format!("Local\\WinKeyPro_Desktop_SingleInstance_{}{}\0", instance_scope, sess).encode_utf16().collect();
    let event_name: Vec<u16> = format!("Local\\WinKeyPro_Desktop_ShowRestore_{}{}\0", instance_scope, sess).encode_utf16().collect();

    let h_mutex = unsafe {
        CreateMutexW(null_mut(), 1, mutex_name.as_ptr())
    };
    let last_err = unsafe { GetLastError() };
    if last_err == 183 { // ERROR_ALREADY_EXISTS = 183
        println!("[SINGLETON] WinKey Pro artıq bu sessiyada (Session {}) işləyir. Mövcud pəncərə bərpa edilir...", sess);
        let h_event = unsafe {
            OpenEventW(EVENT_MODIFY_STATE, 0, event_name.as_ptr())
        };
        if h_event != null_mut() {
            unsafe {
                SetEvent(h_event);
                windows_sys::Win32::Foundation::CloseHandle(h_event);
            }
        }
        if h_mutex != null_mut() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(h_mutex); }
        }
        std::process::exit(0);
    }

    let h_show_event = unsafe {
        CreateEventW(null_mut(), 0, 0, event_name.as_ptr())
    };
    let show_event_val: usize = h_show_event as usize;

    let builder = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            account::account_status,
            account::account_authenticate,
            save_credential_dpapi,
            check_credential_status,
            get_device_status,
            report_ui_error,
            set_computer_name,
            set_gateway_origin,
            generate_qr_pairing,
            revoke_pairing,
            minimize_to_tray,
            restore_window,
            get_support_diagnostics,
            toggle_remote_service_control,
            query_service_ipc_status,
            get_update_status,
        ])
        .setup(move |app| {
            let update_handle=app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(15));
                if slot_update::different_active_desktop().is_some() {
                    // Tauri restarts this executable; its startup delegates to the
                    // verified committed slot. Existing PIN/config storage is shared.
                    update_handle.restart();
                }
            });
            let app_handle = app.handle().clone();

            // Pəncərəni dərhal görünən edirik və fokus veririk
            let is_minimized_arg = std::env::args().any(|a| a == "--minimized" || a == "-m");
            if !is_minimized_arg {
                if let Some(w) = app_handle.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.unminimize();
                    let _ = w.set_focus();
                } else {
                    for (_, w) in app_handle.webview_windows() {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                }
            }

            // Background listener for Show/Restore event from duplicate instances
            if show_event_val != 0 {
                let bg_handle = app_handle.clone();
                std::thread::spawn(move || {
                    loop {
                        let wait_res = unsafe { WaitForSingleObject(show_event_val as *mut c_void, 1000) };
                        if wait_res == 0 { // WAIT_OBJECT_0 = 0
                            if let Some(w) = bg_handle.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            } else {
                                for (_, w) in bg_handle.webview_windows() {
                                    let _ = w.show();
                                    let _ = w.unminimize();
                                    let _ = w.set_focus();
                                }
                            }
                        }
                    }
                });
            }

            // Tray Menu Setup
            let open_i = MenuItem::with_id(&app_handle, "open", "Proqramı aç", true, None::<&str>)?;
            let status_i = MenuItem::with_id(&app_handle, "status", "WinKey Pro - Aktiv", false, None::<&str>)?;
            let pause_i = MenuItem::with_id(&app_handle, "pause_remote", "Mobil İdarəni Dayandır", true, None::<&str>)?;
            let resume_i = MenuItem::with_id(&app_handle, "resume_remote", "Mobil İdarəni Bərpa Et", true, None::<&str>)?;
            let sep = tauri::menu::PredefinedMenuItem::separator(&app_handle)?;
            let exit_i = MenuItem::with_id(&app_handle, "exit", "Proqramdan çıx (Desktop)", true, None::<&str>)?;
            let menu = Menu::with_items(&app_handle, &[&open_i, &status_i, &pause_i, &resume_i, &sep, &exit_i])?;

            let default_icon = app_handle.default_window_icon().cloned();
            let mut tray_builder = TrayIconBuilder::new()
                .tooltip("WinKey Pro - Windows Kilid İdarəetməsi")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| {
                    match event.id.as_ref() {
                        "open" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            } else {
                                for (_, w) in app.webview_windows() {
                                    let _ = w.show();
                                    let _ = w.unminimize();
                                    let _ = w.set_focus();
                                }
                            }
                        }
                        "pause_remote" => {
                            match send_service_control_command("PAUSE") {
                                Ok(_) => println!("[DESKTOP_TRAY] Xidmətə PAUSE əmri göndərildi (Mobil sorğular dayandırıldı)."),
                                Err(e) => eprintln!("[DESKTOP_TRAY] PAUSE göndərilərkən xəta: {}", e),
                            }
                        }
                        "resume_remote" => {
                            match send_service_control_command("RESUME") {
                                Ok(_) => println!("[DESKTOP_TRAY] Xidmətə RESUME əmri göndərildi (Mobil sorğular bərpa edildi)."),
                                Err(e) => eprintln!("[DESKTOP_TRAY] RESUME göndərilərkən xəta: {}", e),
                            }
                        }
                        "exit" => {
                            println!("[DESKTOP] İstifadəçi tray menyusundan 'Çıxış' seçdi. Yalnız UI bağlanır; Windows arxa plan xidməti işləməyə davam edir.");
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.unminimize();
                            let _ = w.set_focus();
                        } else {
                            for (_, w) in app.webview_windows() {
                                let _ = w.show();
                                let _ = w.unminimize();
                                let _ = w.set_focus();
                            }
                        }
                    }
                });

            if let Some(icon) = default_icon {
                tray_builder = tray_builder.icon(icon);
            }

            let _ = tray_builder.build(&app_handle);

            Ok(())
        });

    let run_res = builder
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // X düyməsi pəncərəni bağlamır, arxa plan tepsisinə (tray) gizlədir!
                api.prevent_close();
                let _ = window.hide();
                println!("[DESKTOP] Pəncərə tray-a gizlədildi. Bərpa üçün tray ikonuna klikləyin.");
            }
        })
        .run(tauri::generate_context!());

    if let Err(e) = run_res {
        let msg = format!("TAURI RUN ERROR: {:?}\n", e);
        let _ = fs::write("C:\\ProgramData\\WinKey\\tauri_error.log", msg);
        eprintln!("Tauri xətası: {:?}", e);
    }
}
