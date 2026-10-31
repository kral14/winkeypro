// WinKey Pro — B.2 Qəbul Edilmiş Təhlükəsiz IPC Mühərriki (Xidmət İnteqrasiyası)
#![allow(unsafe_op_in_unsafe_fn, unused_imports, dead_code)]

use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const MAX_IPC_FRAME_PAYLOAD: usize = 4096;
pub const FATAL_REVERT_FAILURE_EXIT_CODE: i32 = 202;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcCommand {
    Ping,
    GetStatus,
    TriggerMockAction { action_name: String },
    InjectPin { dummy_payload: String },
    ProvisionDevice { device_id: String, device_secret: String, #[serde(default)] gateway_origin: Option<String> },
    StoreUserCredential { pin: String },
    StopService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcResponse {
    Ack,
    Status { service: String, state: String, session_id: u32 },
    ActionExecuted { status: String, result: String },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcPeerIdentity {
    pub os_client_pid: u32,
    pub os_client_session_id: u32,
    pub os_client_sid: String,
    pub is_impersonation_successful: bool,
}

pub struct IpcSecurityPolicy {
    pub expected_sid: Option<String>,
    pub expected_session_id: Option<u32>,
}

impl IpcSecurityPolicy {
    pub fn new(expected_sid: Option<String>, expected_session_id: Option<u32>) -> Self {
        Self {
            expected_sid,
            expected_session_id,
        }
    }

    pub fn validate_os_peer_identity(&self, peer: &IpcPeerIdentity) -> Result<(), &'static str> {
        if !peer.is_impersonation_successful {
            return Err("E_IMPERSONATION_FAILED: Client OS tokeni alına bilmədi");
        }
        if peer.os_client_session_id == 0 {
            return Err("E_SESSION_ZERO_ISOLATION: Session 0-dan birbaşa interaktiv IPC qəbul edilmir");
        }
        if let Some(exp_sess) = self.expected_session_id {
            if peer.os_client_session_id != exp_sess {
                return Err("E_SESSION_MISMATCH: Client sessiyası gözlənilən interaktiv sessiya ilə uyğun gəlmir");
            }
        }
        if let Some(ref exp_sid) = self.expected_sid {
            if &peer.os_client_sid != exp_sid {
                return Err("E_UNAUTHORIZED_PEER_SID: Client OS SID-i təsdiqlənmiş istifadəçi ilə uyğun gəlmir");
            }
        }
        Ok(())
    }
}

pub mod win32 {
    use std::ffi::c_void;

    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_TIMEOUT: u32 = 258;
    pub const WAIT_FAILED: u32 = 0xFFFFFFFF;
    pub const ERROR_IO_PENDING: u32 = 997;
    pub const ERROR_PIPE_CONNECTED: u32 = 535;
    pub const ERROR_OPERATION_ABORTED: u32 = 995;
    pub const ERROR_BROKEN_PIPE: u32 = 109;
    pub const ERROR_NOT_FOUND: u32 = 1168;
    pub const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
    pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
    pub const PIPE_ACCESS_DUPLEX: u32 = 0x00000003;
    pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x00000008;

    // B.2b: Minimum Pipe Access Mask: 0x0012008B
    // FILE_CREATE_PIPE_INSTANCE (0x0004), WRITE_DAC, WRITE_OWNER, DELETE İSTİSNA EDİLİR!
    pub const PIPE_MIN_USER_CHANNEL_MASK: u32 = 0x0012008B;
    pub const SECURITY_SQOS_PRESENT: u32 = 0x00100000;
    pub const SECURITY_IDENTIFICATION: u32 = 0x00010000;
    pub const TOKEN_QUERY: u32 = 0x00000008;

    #[repr(C)]
    #[derive(Default)]
    pub struct OVERLAPPED {
        pub internal: usize,
        pub internal_high: usize,
        pub offset: u32,
        pub offset_high: u32,
        pub h_event: *mut c_void,
    }

    #[repr(C)]
    pub struct SECURITY_ATTRIBUTES {
        pub n_length: u32,
        pub lp_security_descriptor: *mut c_void,
        pub b_inherit_handle: i32,
    }

    extern "system" {
        pub fn CreateNamedPipeW(
            lpName: *const u16,
            dwOpenMode: u32,
            dwPipeMode: u32,
            nMaxInstances: u32,
            nOutBufferSize: u32,
            nInBufferSize: u32,
            nDefaultTimeOut: u32,
            lpSecurityAttributes: *mut SECURITY_ATTRIBUTES,
        ) -> *mut c_void;
        pub fn ConnectNamedPipe(hNamedPipe: *mut c_void, lpOverlapped: *mut OVERLAPPED) -> i32;
        pub fn DisconnectNamedPipe(hNamedPipe: *mut c_void) -> i32;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
        pub fn CreateEventW(
            lpEventAttributes: *mut c_void,
            bManualReset: i32,
            bInitialState: i32,
            lpName: *const u16,
        ) -> *mut c_void;
        pub fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
        pub fn SetEvent(hEvent: *mut c_void) -> i32;
        pub fn ResetEvent(hEvent: *mut c_void) -> i32;
        pub fn CancelIoEx(hFile: *mut c_void, lpOverlapped: *mut OVERLAPPED) -> i32;
        pub fn GetOverlappedResult(
            hFile: *mut c_void,
            lpOverlapped: *mut OVERLAPPED,
            lpNumberOfBytesTransferred: *mut u32,
            bWait: i32,
        ) -> i32;
        pub fn ReadFile(
            hFile: *mut c_void,
            lpBuffer: *mut u8,
            nNumberOfBytesToRead: u32,
            lpNumberOfBytesRead: *mut u32,
            lpOverlapped: *mut OVERLAPPED,
        ) -> i32;
        pub fn WriteFile(
            hFile: *mut c_void,
            lpBuffer: *const u8,
            nNumberOfBytesToWrite: u32,
            lpNumberOfBytesWritten: *mut u32,
            lpOverlapped: *mut OVERLAPPED,
        ) -> i32;
        pub fn FlushFileBuffers(hFile: *mut c_void) -> i32;
        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut c_void,
        ) -> *mut c_void;
        pub fn GetLastError() -> u32;
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: *const u16,
            StringSDRevision: u32,
            SecurityDescriptor: *mut *mut c_void,
            SecurityDescriptorSize: *mut u32,
        ) -> i32;
        pub fn GetNamedPipeClientProcessId(Pipe: *mut c_void, ClientProcessId: *mut u32) -> i32;
        pub fn GetNamedPipeClientSessionId(Pipe: *mut c_void, ClientSessionId: *mut u32) -> i32;
        pub fn ImpersonateNamedPipeClient(hNamedPipe: *mut c_void) -> i32;
        pub fn RevertToSelf() -> i32;
        pub fn OpenThreadToken(
            ThreadHandle: *mut c_void,
            DesiredAccess: u32,
            OpenAsSelf: i32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        pub fn GetTokenInformation(
            TokenHandle: *mut c_void,
            TokenInformationClass: u32,
            TokenInformation: *mut c_void,
            TokenInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
        pub fn ConvertSidToStringSidW(Sid: *mut c_void, StringSid: *mut *mut u16) -> i32;
        pub fn GetCurrentThread() -> *mut c_void;
        pub fn OpenProcessToken(ProcessHandle: *mut c_void, DesiredAccess: u32, TokenHandle: *mut *mut c_void) -> i32;
        pub fn GetCurrentProcess() -> *mut c_void;
    }
}

pub struct ScopedHandle(*mut c_void);
impl ScopedHandle {
    pub fn new(h: *mut c_void) -> Self {
        Self(h)
    }
    pub fn raw(&self) -> *mut c_void {
        self.0
    }
}
impl Drop for ScopedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != !0 as *mut c_void {
            unsafe { win32::CloseHandle(self.0) };
        }
    }
}

// B.2b: Dar SDDL Qurucusu (Geniş qruplar yoxdur, yalnız SYSTEM və konkret istifadəçi SID)
pub fn build_narrow_user_channel_sddl(confirmed_user_sid: &str) -> Result<String, String> {
    let trimmed = confirmed_user_sid.trim();
    if trimmed.is_empty() || !trimmed.starts_with("S-1-5-21-") {
        return Err(format!("E_INVALID_USER_CHANNEL_SID: Yalnız S-1-5-21-... qəbul edilir: '{}'", trimmed));
    }
    Ok(format!(
        "D:P(A;;0x{:08x};;;SY)(A;;0x{:08x};;;{})",
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        trimmed
    ))
}

pub fn get_current_user_sid() -> Result<String, String> {
    unsafe {
        let mut h_token: *mut c_void = std::ptr::null_mut();
        if win32::OpenProcessToken(win32::GetCurrentProcess(), win32::TOKEN_QUERY, &mut h_token) == 0 {
            return Err("OpenProcessToken uğursuz oldu".to_string());
        }
        let token_guard = ScopedHandle::new(h_token);

        let mut return_length: u32 = 0;
        let _ = win32::GetTokenInformation(token_guard.raw(), 1, std::ptr::null_mut(), 0, &mut return_length);
        if return_length == 0 {
            return Err("GetTokenInformation uzunluq ala bilmədi".to_string());
        }

        let mut buf = vec![0u8; return_length as usize];
        if win32::GetTokenInformation(token_guard.raw(), 1, buf.as_mut_ptr() as *mut c_void, return_length, &mut return_length) == 0 {
            return Err("GetTokenInformation uğursuz oldu".to_string());
        }

        let p_sid = *(buf.as_ptr() as *const *mut c_void);
        let mut p_string_sid: *mut u16 = std::ptr::null_mut();
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

// B.2b Checked RevertToSelf və Fatal Termination
pub fn fatal_terminate_on_revert_failure(context: &str) -> ! {
    eprintln!("[FATAL SECURITY TERMINATION] RevertToSelf uğursuz oldu ({context}). Çıxış={FATAL_REVERT_FAILURE_EXIT_CODE}");
    std::process::exit(FATAL_REVERT_FAILURE_EXIT_CODE);
}

pub unsafe fn checked_revert_to_self_or_fatal(context: &str) {
    let ok = win32::RevertToSelf();
    if ok == 0 {
        fatal_terminate_on_revert_failure(&format!("{}: OS RevertToSelf error: {}", context, std::io::Error::last_os_error()));
    }
}

pub fn extract_os_client_identity(h_pipe: *mut c_void) -> Result<IpcPeerIdentity, String> {
    unsafe {
        let mut pid = 0u32;
        if win32::GetNamedPipeClientProcessId(h_pipe, &mut pid) == 0 || pid == 0 {
            return Err(format!("GetNamedPipeClientProcessId xətası: {}", std::io::Error::last_os_error()));
        }

        let mut session_id = 0u32;
        if win32::GetNamedPipeClientSessionId(h_pipe, &mut session_id) == 0 {
            return Err(format!("GetNamedPipeClientSessionId xətası: {}", std::io::Error::last_os_error()));
        }

        if win32::ImpersonateNamedPipeClient(h_pipe) == 0 {
            return Err(format!("ImpersonateNamedPipeClient xətası: {}", std::io::Error::last_os_error()));
        }

        let mut h_thread_token: *mut c_void = std::ptr::null_mut();
        let open_tok_ok = win32::OpenThreadToken(
            win32::GetCurrentThread(),
            win32::TOKEN_QUERY,
            1,
            &mut h_thread_token,
        );

        if open_tok_ok == 0 || h_thread_token.is_null() {
            let err = std::io::Error::last_os_error();
            checked_revert_to_self_or_fatal("OpenThreadToken_error");
            return Err(format!("OpenThreadToken xətası: {}", err));
        }

        let token_guard = ScopedHandle::new(h_thread_token);

        // SID çıxarılması
        let mut ret_len = 0u32;
        let _ = win32::GetTokenInformation(token_guard.raw(), 1, std::ptr::null_mut(), 0, &mut ret_len);
        let mut buf = vec![0u8; ret_len as usize];
        if win32::GetTokenInformation(token_guard.raw(), 1, buf.as_mut_ptr() as *mut c_void, ret_len, &mut ret_len) == 0 {
            drop(token_guard);
            checked_revert_to_self_or_fatal("GetTokenInformation_error");
            return Err("GetTokenInformation(TokenUser) xətası".to_string());
        }

        let p_sid = *(buf.as_ptr() as *const *mut c_void);
        let mut p_str_sid: *mut u16 = std::ptr::null_mut();
        if win32::ConvertSidToStringSidW(p_sid, &mut p_str_sid) == 0 || p_str_sid.is_null() {
            drop(token_guard);
            checked_revert_to_self_or_fatal("ConvertSidToStringSidW_error");
            return Err("ConvertSidToStringSidW xətası".to_string());
        }

        let mut len = 0;
        while *p_str_sid.offset(len) != 0 { len += 1; }
        let slice = std::slice::from_raw_parts(p_str_sid, len as usize);
        let sid_str = String::from_utf16_lossy(slice);
        win32::LocalFree(p_str_sid as *mut c_void);

        drop(token_guard);
        checked_revert_to_self_or_fatal("main_impersonation_teardown");

        Ok(IpcPeerIdentity {
            os_client_pid: pid,
            os_client_session_id: session_id,
            os_client_sid: sid_str,
            is_impersonation_successful: true,
        })
    }
}

// B.2a Overlapped Server Yaradılması
pub fn create_secure_overlapped_pipe(pipe_name: &str, sddl: &str) -> Result<*mut c_void, String> {
    let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let mut p_sd: *mut c_void = std::ptr::null_mut();
        if win32::ConvertStringSecurityDescriptorToSecurityDescriptorW(wide_sddl.as_ptr(), 1, &mut p_sd, std::ptr::null_mut()) == 0 {
            return Err(format!("ConvertStringSecurityDescriptor xətası: {}", std::io::Error::last_os_error()));
        }

        let mut sa = win32::SECURITY_ATTRIBUTES {
            n_length: std::mem::size_of::<win32::SECURITY_ATTRIBUTES>() as u32,
            lp_security_descriptor: p_sd,
            b_inherit_handle: 0,
        };

        let open_mode = win32::PIPE_ACCESS_DUPLEX | win32::FILE_FLAG_FIRST_PIPE_INSTANCE | win32::FILE_FLAG_OVERLAPPED;
        let pipe_mode = win32::PIPE_REJECT_REMOTE_CLIENTS;

        let h_pipe = win32::CreateNamedPipeW(
            wide_name.as_ptr(),
            open_mode,
            pipe_mode,
            1,
            MAX_IPC_FRAME_PAYLOAD as u32,
            MAX_IPC_FRAME_PAYLOAD as u32,
            3000,
            &mut sa,
        );

        win32::LocalFree(p_sd);

        if h_pipe == !0 as *mut c_void || h_pipe.is_null() {
            return Err(format!("CreateNamedPipeW xətası: {}", std::io::Error::last_os_error()));
        }

        Ok(h_pipe)
    }
}
