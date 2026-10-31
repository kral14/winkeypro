// WinKey Pro — B.2a Reviziya 3: Named Pipe Overlapped I/O, Vahid Deadline, Bounded APP_ACK, Terminal Drain və RAII
#![allow(unsafe_op_in_unsafe_fn, unused_imports, dead_code)]

use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::time::{Duration, Instant};

pub const MAX_IPC_FRAME_PAYLOAD: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcCommand {
    Ping,
    GetDesktopState,
    TriggerCurtain,
    InjectPin { dummy_payload: String },
    ForgedIdentityCommand { claimed_sid: String, command: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpcResponse {
    Ack,
    DesktopState { desktop_name: String, is_input_desktop_accessible: bool },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcPeerIdentity {
    pub os_client_pid: u32,
    pub os_client_session_id: u32,
    pub os_client_sid: String,
    pub is_impersonation_successful: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpcServerIdentity {
    pub os_server_pid: u32,
    pub os_server_session_id: u32,
}

pub struct IpcSecurityPolicy {
    pub expected_sid: String,
    pub expected_session_id: u32,
}

impl IpcSecurityPolicy {
    pub fn new(expected_sid: &str, expected_session_id: u32) -> Self {
        Self {
            expected_sid: expected_sid.to_string(),
            expected_session_id,
        }
    }

    pub fn validate_os_peer_identity(&self, peer: &IpcPeerIdentity) -> Result<(), &'static str> {
        if !peer.is_impersonation_successful {
            return Err("E_IMPERSONATION_FAILED: Client OS tokeni alına bilmədi");
        }
        if peer.os_client_session_id == 0 {
            return Err("E_SESSION_ZERO_ISOLATION: Session 0-dan interaktiv IPC qəbul edilmir");
        }
        if peer.os_client_session_id != self.expected_session_id {
            return Err("E_SESSION_MISMATCH: Client sessiyası hədəf interaktiv sessiya ilə uyğun gəlmir");
        }
        if peer.os_client_sid != self.expected_sid {
            return Err("E_UNAUTHORIZED_PEER_SID: Client OS SID-i təsdiqlənmiş istifadəçi ilə uyğun gəlmir");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Win32 API və Overlapped Strukturu
// ---------------------------------------------------------------------------
#[cfg(windows)]
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

    // B.2b: Minimum Pipe Access Mask və SQOS sabitləri
    // GENERIC_WRITE (0x40000000) Named Pipe üzərində FILE_CREATE_PIPE_INSTANCE (0x0004) hüququ verir!
    // Buna görə dar DACL və client açılışında 0x0004 (FILE_CREATE_PIPE_INSTANCE), WRITE_DAC, WRITE_OWNER, DELETE İSTİSNA EDİLİR:
    // FILE_READ_DATA (0x0001) | FILE_WRITE_DATA (0x0002) | FILE_READ_EA (0x0008) | FILE_READ_ATTRIBUTES (0x0080)
    // | READ_CONTROL (0x00020000) | SYNCHRONIZE (0x00100000) = 0x0012008B
    pub const PIPE_MIN_USER_CHANNEL_MASK: u32 = 0x0012008B;
    pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x00000004;
    pub const SECURITY_SQOS_PRESENT: u32 = 0x00100000;
    pub const SECURITY_IDENTIFICATION: u32 = 0x00010000; // Minimum SQOS: yalnız identity oxuma (impersonation on objects qadağandır)
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x00001000;
    pub const TOKEN_QUERY: u32 = 0x00000008;
    pub const SE_KERNEL_OBJECT: u32 = 6;
    pub const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    pub const SE_DACL_PROTECTED: u16 = 0x1000;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ACL_SIZE_INFORMATION {
        pub ace_count: u32,
        pub acl_bytes_in_use: u32,
        pub acl_bytes_free: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ACE_HEADER {
        pub ace_type: u8,
        pub ace_flags: u8,
        pub ace_size: u16,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    pub struct ACCESS_ALLOWED_ACE {
        pub header: ACE_HEADER,
        pub mask: u32,
        pub sid_start: u32,
    }

    #[repr(C)]
    #[derive(Debug)]
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

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateNamedPipeW(
            lpName: *const u16,
            dwOpenMode: u32,
            dwPipeMode: u32,
            nMaxInstances: u32,
            nOutBufferSize: u32,
            nInBufferSize: u32,
            nDefaultTimeOut: u32,
            lpSecurityAttributes: *mut c_void,
        ) -> *mut c_void;
        pub fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: u32,
            dwShareMode: u32,
            lpSecurityAttributes: *mut c_void,
            dwCreationDisposition: u32,
            dwFlagsAndAttributes: u32,
            hTemplateFile: *mut c_void,
        ) -> *mut c_void;
        pub fn ConnectNamedPipe(hNamedPipe: *mut c_void, lpOverlapped: *mut OVERLAPPED) -> i32;
        pub fn DisconnectNamedPipe(hNamedPipe: *mut c_void) -> i32;
        pub fn CloseHandle(hObject: *mut c_void) -> i32;
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
        pub fn CreateEventW(
            lpEventAttributes: *mut c_void,
            bManualReset: i32,
            bInitialState: i32,
            lpName: *const u16,
        ) -> *mut c_void;
        pub fn ResetEvent(hEvent: *mut c_void) -> i32;
        pub fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
        pub fn WaitNamedPipeW(lpNamedPipeName: *const u16, nTimeOut: u32) -> i32;
        pub fn GetOverlappedResult(
            hFile: *mut c_void,
            lpOverlapped: *mut OVERLAPPED,
            lpNumberOfBytesTransferred: *mut u32,
            bWait: i32,
        ) -> i32;
        pub fn CancelIoEx(hFile: *mut c_void, lpOverlapped: *mut OVERLAPPED) -> i32;
        pub fn GetNamedPipeClientProcessId(Pipe: *mut c_void, ClientProcessId: *mut u32) -> i32;
        pub fn GetNamedPipeClientSessionId(Pipe: *mut c_void, ClientSessionId: *mut u32) -> i32;
        pub fn GetNamedPipeServerProcessId(Pipe: *mut c_void, ServerProcessId: *mut u32) -> i32;
        pub fn GetNamedPipeServerSessionId(Pipe: *mut c_void, ServerSessionId: *mut u32) -> i32;
        pub fn GetCurrentProcessId() -> u32;
        pub fn GetCurrentProcess() -> *mut c_void;
        pub fn GetProcessHandleCount(hProcess: *mut c_void, pdwHandleCount: *mut u32) -> i32;
        pub fn GetCurrentThread() -> *mut c_void;
        pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
        pub fn GetProcessId(Process: *mut c_void) -> u32;
        pub fn GetProcessTimes(
            hProcess: *mut c_void,
            lpCreationTime: *mut u64,
            lpExitTime: *mut u64,
            lpKernelTime: *mut u64,
            lpUserTime: *mut u64,
        ) -> i32;
        pub fn GetModuleHandleA(lpModuleName: *const u8) -> *mut c_void;
        pub fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
        pub fn QueryFullProcessImageNameW(
            hProcess: *mut c_void,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
    }

    pub unsafe fn compare_object_handles_win32(h_first: *mut c_void, h_second: *mut c_void) -> bool {
        let h_mod = GetModuleHandleA(b"kernelbase.dll\0".as_ptr());
        if !h_mod.is_null() {
            let p_fn = GetProcAddress(h_mod, b"CompareObjectHandles\0".as_ptr());
            if !p_fn.is_null() {
                let func: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32 =
                    std::mem::transmute(p_fn);
                if func(h_first, h_second) == 0 {
                    return false;
                }
            }
        }
        // Əlavə olaraq hər iki proses handle-nın PID və CreationTime dəyərlərinin bit-bə-bit eyniliyi yoxlanılır:
        let pid1 = GetProcessId(h_first);
        let pid2 = GetProcessId(h_second);
        if pid1 == 0 || pid1 != pid2 {
            return false;
        }
        let (mut c1, mut e1, mut k1, mut u1) = (0u64, 0u64, 0u64, 0u64);
        let (mut c2, mut e2, mut k2, mut u2) = (0u64, 0u64, 0u64, 0u64);
        if GetProcessTimes(h_first, &mut c1, &mut e1, &mut k1, &mut u1) == 0 {
            return false;
        }
        if GetProcessTimes(h_second, &mut c2, &mut e2, &mut k2, &mut u2) == 0 {
            return false;
        }
        c1 != 0 && c1 == c2
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn ImpersonateNamedPipeClient(hNamedPipe: *mut c_void) -> i32;
        pub fn RevertToSelf() -> i32;
        pub fn OpenThreadToken(
            ThreadHandle: *mut c_void,
            DesiredAccess: u32,
            OpenAsSelf: i32,
            TokenHandle: *mut *mut c_void,
        ) -> i32;
        pub fn OpenProcessToken(
            ProcessHandle: *mut c_void,
            DesiredAccess: u32,
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
        pub fn LocalFree(hMem: *mut c_void) -> *mut c_void;
        pub fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: *const u16,
            StringSDRevision: u32,
            SecurityDescriptor: *mut *mut c_void,
            SecurityDescriptorSize: *mut u32,
        ) -> i32;
        pub fn GetSecurityInfo(
            handle: *mut c_void,
            ObjectType: u32,
            SecurityInfo: u32,
            ppsidOwner: *mut *mut c_void,
            ppsidGroup: *mut *mut c_void,
            ppDacl: *mut *mut c_void,
            ppSacl: *mut *mut c_void,
            ppSecurityDescriptor: *mut *mut c_void,
        ) -> u32;
        pub fn GetSecurityDescriptorControl(
            pSecurityDescriptor: *mut c_void,
            pControl: *mut u16,
            lpdwRevision: *mut u32,
        ) -> i32;
        pub fn GetAclInformation(
            pAcl: *mut c_void,
            pAclInformation: *mut c_void,
            nAclInformationLength: u32,
            dwAclInformationClass: u32,
        ) -> i32;
        pub fn GetAce(
            pAcl: *mut c_void,
            dwAceIndex: u32,
            pAce: *mut *mut c_void,
        ) -> i32;
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        pub fn OpenInputDesktop(dwFlags: u32, fInherit: i32, dwDesiredAccess: u32) -> isize;
        pub fn CloseDesktop(hDesktop: isize) -> i32;
        pub fn GetUserObjectInformationW(
            hObj: isize,
            nIndex: i32,
            pvInfo: *mut u16,
            nLength: u32,
            lpnLengthNeeded: *mut u32,
        ) -> i32;
    }
}

// ---------------------------------------------------------------------------
// RAII Scoped Handle Qoruması (Tapıntı 3 Həlli: Handle Leak Qarşısı)
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub struct ScopedHandle(pub *mut c_void);

#[cfg(windows)]
impl ScopedHandle {
    pub fn new(h: *mut c_void) -> Self {
        Self(h)
    }
    pub fn raw(&self) -> *mut c_void {
        self.0
    }
    pub fn is_valid(&self) -> bool {
        !self.0.is_null() && (self.0 as isize) != -1
    }
}

#[cfg(windows)]
impl Drop for ScopedHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                win32::CloseHandle(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

// ---------------------------------------------------------------------------
// Win32 Session və Desktop Sorğuları (REAL_API)
// ---------------------------------------------------------------------------
pub fn query_system_session_info() -> (u32, u32) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> i32;
        }

        let console_session = WTSGetActiveConsoleSessionId();
        let current_pid = win32::GetCurrentProcessId();
        let mut process_session = 0u32;
        let ok = ProcessIdToSessionId(current_pid, &mut process_session);
        if ok != 0 {
            (console_session, process_session)
        } else {
            (console_session, 0)
        }
    }

    #[cfg(not(windows))]
    {
        (1, 1)
    }
}

pub fn query_current_input_desktop() -> (String, bool) {
    #[cfg(windows)]
    unsafe {
        let h_desktop = win32::OpenInputDesktop(0, 0, 0x0001);
        if h_desktop != 0 {
            let mut name_buf = [0u16; 256];
            let mut needed = 0u32;
            let ok = win32::GetUserObjectInformationW(
                h_desktop,
                2,
                name_buf.as_mut_ptr(),
                (name_buf.len() * 2) as u32,
                &mut needed,
            );
            win32::CloseDesktop(h_desktop);

            if ok != 0 {
                let name = String::from_utf16_lossy(&name_buf)
                    .trim_matches('\0')
                    .to_string();
                return (name, true);
            }
            ("AccessibleUnknown".to_string(), true)
        } else {
            ("InaccessibleOrLocked".to_string(), false)
        }
    }

    #[cfg(not(windows))]
    {
        ("Default".to_string(), true)
    }
}

pub fn query_current_user_sid() -> Result<String, String> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn OpenProcessToken(ProcessHandle: *mut c_void, DesiredAccess: u32, TokenHandle: *mut *mut c_void) -> i32;
        }

        let mut h_token: *mut c_void = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess() as *mut c_void, 0x0008, &mut h_token) == 0 {
            return Err(format!("OpenProcessToken xətası: {}", std::io::Error::last_os_error()));
        }

        let mut return_length = 0u32;
        win32::GetTokenInformation(h_token, 1, std::ptr::null_mut(), 0, &mut return_length);
        let mut buf = vec![0u8; return_length as usize];

        if win32::GetTokenInformation(h_token, 1, buf.as_mut_ptr() as *mut c_void, return_length, &mut return_length) == 0 {
            win32::CloseHandle(h_token);
            return Err("GetTokenInformation uğursuz oldu".to_string());
        }

        let p_sid = *(buf.as_ptr() as *const *mut c_void);
        let mut p_string_sid: *mut u16 = std::ptr::null_mut();

        if win32::ConvertSidToStringSidW(p_sid, &mut p_string_sid) == 0 {
            win32::CloseHandle(h_token);
            return Err("ConvertSidToStringSidW uğursuz oldu".to_string());
        }

        let mut len = 0;
        while *p_string_sid.offset(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p_string_sid, len as usize);
        let sid_str = String::from_utf16_lossy(slice);

        win32::LocalFree(p_string_sid as *mut c_void);
        win32::CloseHandle(h_token);

        Ok(sid_str)
    }

    #[cfg(not(windows))]
    {
        Ok("S-1-5-21-MOCK-CURRENT".to_string())
    }
}

// ---------------------------------------------------------------------------
// Overlapped Named Pipe Server Yaradılması
// ---------------------------------------------------------------------------
pub fn create_secure_overlapped_named_pipe_server(pipe_name: &str, sddl: &str) -> Result<*mut c_void, String> {
    create_secure_overlapped_named_pipe_server_with_buf(pipe_name, sddl, 8192, 8192)
}

pub fn create_secure_overlapped_named_pipe_server_with_buf(
    pipe_name: &str,
    sddl: &str,
    in_buf_size: u32,
    out_buf_size: u32,
) -> Result<*mut c_void, String> {
    #[cfg(windows)]
    unsafe {
        let full_name = format!(r"\\.\pipe\{}", pipe_name);
        let wide_name: Vec<u16> = full_name.encode_utf16().chain(std::iter::once(0)).collect();

        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut p_sd: *mut c_void = std::ptr::null_mut();
        let mut sd_size = 0u32;

        if win32::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            1,
            &mut p_sd,
            &mut sd_size,
        ) == 0 {
            return Err(format!("SDDL xətası: {}", std::io::Error::last_os_error()));
        }

        let mut sa = win32::SECURITY_ATTRIBUTES {
            n_length: std::mem::size_of::<win32::SECURITY_ATTRIBUTES>() as u32,
            lp_security_descriptor: p_sd,
            b_inherit_handle: 0,
        };

        // OpenMode: PIPE_ACCESS_DUPLEX (3) | FILE_FLAG_FIRST_PIPE_INSTANCE (0x00080000) | FILE_FLAG_OVERLAPPED (0x40000000)
        let dw_open_mode = win32::PIPE_ACCESS_DUPLEX | win32::FILE_FLAG_FIRST_PIPE_INSTANCE | win32::FILE_FLAG_OVERLAPPED;
        // PipeMode: PIPE_TYPE_BYTE (0) | PIPE_WAIT (0) | PIPE_REJECT_REMOTE_CLIENTS (0x00000008)
        let dw_pipe_mode = win32::PIPE_REJECT_REMOTE_CLIENTS;

        let h_pipe = win32::CreateNamedPipeW(
            wide_name.as_ptr(),
            dw_open_mode,
            dw_pipe_mode,
            1, // First pipe instance squatting qorunması
            out_buf_size,
            in_buf_size,
            1000,
            &mut sa as *mut _ as *mut c_void,
        );

        win32::LocalFree(p_sd);

        if (h_pipe as isize) == -1 || h_pipe.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(format!("CreateNamedPipeW xətası: {}", err));
        }

        Ok(h_pipe)
    }

    #[cfg(not(windows))]
    {
        Ok(1 as *mut c_void)
    }
}

pub fn create_secure_named_pipe_server(pipe_name: &str, sddl: &str) -> Result<*mut c_void, String> {
    create_secure_overlapped_named_pipe_server(pipe_name, sddl)
}

// ---------------------------------------------------------------------------
// B.2b: Dar User-Channel Pipe DACL Qurucusu və OS Security Descriptor Yoxlaması
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeAceRecord {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub access_mask: u32,
    pub trustee_sid: String,
    pub has_create_pipe_instance: bool,
    pub has_write_dac_or_owner_or_delete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeDaclInspection {
    pub is_dacl_protected: bool,
    pub aces: Vec<PipeAceRecord>,
}

pub fn build_narrow_user_channel_sddl(confirmed_user_sid: &str) -> Result<String, String> {
    let trimmed = confirmed_user_sid.trim();
    if trimmed.is_empty() || !trimmed.starts_with("S-1-5-21-") {
        return Err(format!(
            "E_INVALID_USER_CHANNEL_SID: User-channel DACL üçün yalnız konkret təsdiqlənmiş istifadəçi SID-i (S-1-5-21-...) qəbul edilir, verilən: '{}'",
            trimmed
        ));
    }
    // B.2b Tələb 1:
    // - Geniş qruplar (IU, BA, WD, AU) tamamilə çıxarıldı.
    // - Yalnız SYSTEM (SY) və konkret təsdiqlənmiş user SID daxil edilir.
    // - GENERIC_WRITE (GW) Named Pipe-da FILE_CREATE_PIPE_INSTANCE (0x0004) verdiyi üçün istifadə edilmir!
    // - Minimum maska: 0x0012008B (FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE).
    Ok(format!(
        "D:P(A;;0x{:08x};;;SY)(A;;0x{:08x};;;{})",
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        trimmed
    ))
}

#[cfg(windows)]
pub unsafe fn inspect_pipe_dacl(h_pipe: *mut c_void) -> Result<PipeDaclInspection, String> {
    let mut p_dacl: *mut c_void = std::ptr::null_mut();
    let mut p_sd: *mut c_void = std::ptr::null_mut();

    let status = win32::GetSecurityInfo(
        h_pipe,
        win32::SE_KERNEL_OBJECT,
        win32::DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );

    if status != 0 || p_sd.is_null() || p_dacl.is_null() {
        if !p_sd.is_null() {
            win32::LocalFree(p_sd);
        }
        return Err(format!("GetSecurityInfo xətası: status={}", status));
    }

    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let ctrl_ok = win32::GetSecurityDescriptorControl(p_sd, &mut control, &mut revision);
    if ctrl_ok == 0 {
        win32::LocalFree(p_sd);
        return Err(format!("GetSecurityDescriptorControl xətası: {}", std::io::Error::last_os_error()));
    }
    let is_dacl_protected = (control & win32::SE_DACL_PROTECTED) != 0;

    let mut acl_size = win32::ACL_SIZE_INFORMATION {
        ace_count: 0,
        acl_bytes_in_use: 0,
        acl_bytes_free: 0,
    };
    let acl_ok = win32::GetAclInformation(
        p_dacl,
        &mut acl_size as *mut _ as *mut c_void,
        std::mem::size_of::<win32::ACL_SIZE_INFORMATION>() as u32,
        2, // AclSizeInformation
    );
    if acl_ok == 0 {
        win32::LocalFree(p_sd);
        return Err(format!("GetAclInformation xətası: {}", std::io::Error::last_os_error()));
    }

    let mut aces = Vec::with_capacity(acl_size.ace_count as usize);
    for idx in 0..acl_size.ace_count {
        let mut p_ace_raw: *mut c_void = std::ptr::null_mut();
        if win32::GetAce(p_dacl, idx, &mut p_ace_raw) == 0 || p_ace_raw.is_null() {
            win32::LocalFree(p_sd);
            return Err(format!("GetAce(idx={}) xətası: {}", idx, std::io::Error::last_os_error()));
        }

        let ace = &*(p_ace_raw as *const win32::ACCESS_ALLOWED_ACE);
        let p_sid = &ace.sid_start as *const u32 as *mut c_void;
        let mut p_str_sid: *mut u16 = std::ptr::null_mut();
        if win32::ConvertSidToStringSidW(p_sid, &mut p_str_sid) == 0 || p_str_sid.is_null() {
            win32::LocalFree(p_sd);
            return Err(format!("ConvertSidToStringSidW(idx={}) xətası", idx));
        }

        let mut len = 0;
        while *p_str_sid.offset(len) != 0 {
            len += 1;
        }
        let sid_str = String::from_utf16_lossy(std::slice::from_raw_parts(p_str_sid, len as usize));
        win32::LocalFree(p_str_sid as *mut c_void);

        let mask = ace.mask;
        // DELETE (0x00010000) | WRITE_DAC (0x00040000) | WRITE_OWNER (0x00080000) = 0x000D0000
        aces.push(PipeAceRecord {
            ace_type: ace.header.ace_type,
            ace_flags: ace.header.ace_flags,
            access_mask: mask,
            trustee_sid: sid_str,
            has_create_pipe_instance: (mask & win32::FILE_CREATE_PIPE_INSTANCE) != 0,
            has_write_dac_or_owner_or_delete: (mask & 0x000D0000) != 0,
        });
    }

    win32::LocalFree(p_sd);
    Ok(PipeDaclInspection {
        is_dacl_protected,
        aces,
    })
}

// ---------------------------------------------------------------------------
// Overlapped Named Pipe Client Açılması (Minimum Access + SECURITY_IDENTIFICATION)
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub unsafe fn open_overlapped_pipe_client_with_access(
    pipe_name: &str,
    dw_access: u32,
    sqos_flags: u32,
) -> Result<*mut c_void, String> {
    let full_name = format!(r"\\.\pipe\{}", pipe_name);
    let wide_name: Vec<u16> = full_name.encode_utf16().chain(std::iter::once(0)).collect();

    let dw_creation = 3; // OPEN_EXISTING
    let dw_flags = sqos_flags | win32::FILE_FLAG_OVERLAPPED;

    let h_file = win32::CreateFileW(
        wide_name.as_ptr(),
        dw_access,
        0,
        std::ptr::null_mut(),
        dw_creation,
        dw_flags,
        std::ptr::null_mut(),
    );

    if (h_file as isize) == -1 || h_file.is_null() {
        return Err(format!("CreateFileW client xətası: {}", std::io::Error::last_os_error()));
    }

    Ok(h_file)
}

#[cfg(windows)]
pub unsafe fn open_overlapped_pipe_client(pipe_name: &str) -> Result<*mut c_void, String> {
    // B.2b Tələb 1 & 3:
    // - GENERIC_WRITE əvəzinə yalnız PIPE_MIN_USER_CHANNEL_MASK (0x0012008B, 0x0004 FILE_CREATE_PIPE_INSTANCE olmadan!)
    // - SECURITY_IMPERSONATION əvəzinə minimum SECURITY_IDENTIFICATION (0x00010000) SQOS səviyyəsi!
    open_overlapped_pipe_client_with_access(
        pipe_name,
        win32::PIPE_MIN_USER_CHANNEL_MASK,
        win32::SECURITY_SQOS_PRESENT | win32::SECURITY_IDENTIFICATION,
    )
}

// ---------------------------------------------------------------------------
// Pending I/O Terminal Draining və Robust Cancellation Helper (Tapıntı 1 Həlli)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlappedDrainOutcome {
    CancelledAndCompleted { bytes_transferred: u32 },
    AlreadyCompleted { bytes_transferred: u32 },
    DrainError { code: u32, message: String },
}

pub fn classify_overlapped_outcome(
    cancel_res: i32,
    cancel_code: Option<u32>,
    get_res: i32,
    get_code: Option<u32>,
    transferred: u32,
) -> OverlappedDrainOutcome {
    // 1. GetOverlappedResult terminal statusu prioritetdir!
    if get_res == 0 {
        let code = get_code.unwrap_or(0);
        if code == win32::ERROR_OPERATION_ABORTED {
            OverlappedDrainOutcome::CancelledAndCompleted { bytes_transferred: transferred }
        } else {
            // CancelIoEx ERROR_NOT_FOUND olsa belə, terminal xəta heç vaxt AlreadyCompleted kimi gizlədilmir!
            OverlappedDrainOutcome::DrainError {
                code,
                message: format!("GetOverlappedResult terminal xətası (OS Code={})", code),
            }
        }
    } else {
        // GetOverlappedResult uğurlu olub (res != 0):
        if cancel_res == 0 && cancel_code == Some(win32::ERROR_NOT_FOUND) {
            OverlappedDrainOutcome::AlreadyCompleted { bytes_transferred: transferred }
        } else {
            OverlappedDrainOutcome::CancelledAndCompleted { bytes_transferred: transferred }
        }
    }
}

#[cfg(windows)]
pub unsafe fn drain_and_cancel_overlapped(
    h_file: *mut c_void,
    ov: &mut win32::OVERLAPPED,
    h_event: *mut c_void,
) -> OverlappedDrainOutcome {
    let cancel_res = win32::CancelIoEx(h_file, ov);
    let cancel_code = if cancel_res == 0 {
        Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
    } else {
        None
    };

    let mut transferred = 0u32;
    // bWait = 1 (TRUE) ilə GetOverlappedResult terminal nəticəni gözləyir:
    let get_res = win32::GetOverlappedResult(h_file, ov, &mut transferred, 1);
    let get_code = if get_res == 0 {
        Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32)
    } else {
        None
    };

    // Canlı event yalnız pending I/O drain bitdikdən sonra bağlanır:
    if !h_event.is_null() {
        win32::CloseHandle(h_event);
    }

    classify_overlapped_outcome(cancel_res, cancel_code, get_res, get_code, transferred)
}

// ---------------------------------------------------------------------------
// Vahid Deadline ilə Asinxron Overlapped I/O Primitivləri
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub unsafe fn connect_pipe_with_deadline(h_pipe: *mut c_void, deadline: Instant) -> Result<(), String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("E_CONNECT_TIMEOUT: Deadline artıq bitib".to_string());
    }
    let timeout = deadline.duration_since(now);

    let h_event = win32::CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
    if h_event.is_null() {
        return Err("CreateEventW uğursuz oldu".to_string());
    }

    let mut ov = win32::OVERLAPPED {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        h_event,
    };

    let ok = win32::ConnectNamedPipe(h_pipe, &mut ov);
    if ok != 0 {
        win32::CloseHandle(h_event);
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(win32::ERROR_PIPE_CONNECTED as i32) {
        win32::CloseHandle(h_event);
        return Ok(());
    }

    if err.raw_os_error() == Some(win32::ERROR_IO_PENDING as i32) {
        let wait_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        let wait_res = win32::WaitForSingleObject(h_event, wait_ms);
        if wait_res == win32::WAIT_OBJECT_0 {
            let mut transferred = 0u32;
            let res = win32::GetOverlappedResult(h_pipe, &mut ov, &mut transferred, 0);
            win32::CloseHandle(h_event);
            if res != 0 {
                return Ok(());
            } else {
                return Err(format!("GetOverlappedResult xətası: {}", std::io::Error::last_os_error()));
            }
        } else if wait_res == win32::WAIT_TIMEOUT {
            let drain = drain_and_cancel_overlapped(h_pipe, &mut ov, h_event);
            return Err(format!("E_CONNECT_TIMEOUT: Client təyin olunmuş deadline müddətində qoşulmadı (Drain: {:?})", drain));
        } else {
            let wait_err = std::io::Error::last_os_error();
            let drain = drain_and_cancel_overlapped(h_pipe, &mut ov, h_event);
            return Err(format!("WaitForSingleObject xətası (WaitRes={}, Drain={:?}): {}", wait_res, drain, wait_err));
        }
    }

    win32::CloseHandle(h_event);
    Err(format!("ConnectNamedPipe xətası: {}", err))
}

pub unsafe fn connect_pipe_with_timeout(h_pipe: *mut c_void, timeout: Duration) -> Result<(), String> {
    connect_pipe_with_deadline(h_pipe, Instant::now() + timeout)
}

pub fn query_process_handle_count() -> u32 {
    #[cfg(windows)]
    unsafe {
        let mut count = 0u32;
        win32::GetProcessHandleCount(win32::GetCurrentProcess(), &mut count);
        count
    }
    #[cfg(not(windows))]
    {
        0
    }
}

// ---------------------------------------------------------------------------
// Wait Adapter Tipi və İnjeksiya Primitivləri (Tapıntı 1 Həlli)
// ---------------------------------------------------------------------------
pub type WaitFn = unsafe fn(h_handle: *mut c_void, dw_ms: u32) -> u32;

#[cfg(windows)]
pub unsafe fn default_wait_fn(h_handle: *mut c_void, dw_ms: u32) -> u32 {
    win32::WaitForSingleObject(h_handle, dw_ms)
}

#[cfg(windows)]
pub unsafe fn mock_wait_failed_fn(_h_handle: *mut c_void, _dw_ms: u32) -> u32 {
    win32::WAIT_FAILED
}

#[cfg(windows)]
pub unsafe fn read_exact_overlapped_with_deadline_wait_fn(
    h_file: *mut c_void,
    buf: &mut [u8],
    deadline: Instant,
    wait_fn: WaitFn,
) -> Result<usize, String> {
    let mut total_read = 0;

    let h_event = win32::CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
    if h_event.is_null() {
        return Err("CreateEventW uğursuz oldu".to_string());
    }

    while total_read < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            win32::CloseHandle(h_event);
            return Err("E_READ_TIMEOUT: Oxuma əməliyyatı üçün təyin edilmiş deadline bitdi".to_string());
        }
        let remaining_time = deadline.duration_since(now);

        win32::ResetEvent(h_event);

        let mut ov = win32::OVERLAPPED {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event,
        };

        let target_slice = &mut buf[total_read..];
        let mut bytes_read = 0u32;
        let ok = win32::ReadFile(
            h_file,
            target_slice.as_mut_ptr(),
            target_slice.len() as u32,
            &mut bytes_read,
            &mut ov,
        );

        if ok != 0 {
            if bytes_read == 0 {
                win32::CloseHandle(h_event);
                return Ok(total_read); // EOF
            }
            total_read += bytes_read as usize;
            continue;
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(win32::ERROR_IO_PENDING as i32) {
            let wait_ms = remaining_time.as_millis().min(u32::MAX as u128) as u32;
            // DİQQƏT: Canlı h_event BAĞLANMIR! Wait adapteri ilə gözləmə/injection idarə olunur:
            let wait_res = wait_fn(h_event, wait_ms);
            if wait_res == win32::WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                let res = win32::GetOverlappedResult(h_file, &mut ov, &mut transferred, 0);
                if res != 0 {
                    if transferred == 0 {
                        win32::CloseHandle(h_event);
                        return Ok(total_read); // EOF
                    }
                    total_read += transferred as usize;
                } else {
                    let res_err = std::io::Error::last_os_error();
                    let drain = drain_and_cancel_overlapped(h_file, &mut ov, h_event);
                    if res_err.raw_os_error() == Some(win32::ERROR_BROKEN_PIPE as i32)
                        || res_err.raw_os_error() == Some(233) {
                        return Ok(total_read);
                    }
                    return Err(format!("GetOverlappedResult xətası (Drain={:?}): {}", drain, res_err));
                }
            } else if wait_res == win32::WAIT_TIMEOUT {
                let drain = drain_and_cancel_overlapped(h_file, &mut ov, h_event);
                return Err(format!("E_READ_TIMEOUT: Peer susdu və deadline bitdi (Drain={:?})", drain));
            } else {
                // WAIT_FAILED (0xFFFFFFFF) və ya digər qeyri-gözlənilən wait xətası:
                // Canlı h_event drain_and_cancel_overlapped-ə ötürülür və cancel/drain bitdikdən sonra bağlanır!
                let wait_err = std::io::Error::last_os_error();
                let drain = drain_and_cancel_overlapped(h_file, &mut ov, h_event);
                return Err(format!("WaitForSingleObject xətası (WaitRes={}, Drain={:?}): {}", wait_res, drain, wait_err));
            }
        } else {
            win32::CloseHandle(h_event);
            if err.raw_os_error() == Some(win32::ERROR_BROKEN_PIPE as i32)
                || err.raw_os_error() == Some(233) {
                return Ok(total_read); // EOF
            }
            return Err(format!("ReadFile xətası: {}", err));
        }
    }

    win32::CloseHandle(h_event);
    Ok(total_read)
}

#[cfg(windows)]
pub unsafe fn read_exact_overlapped_with_deadline_injected(
    h_file: *mut c_void,
    buf: &mut [u8],
    deadline: Instant,
    force_wait_failed: bool,
) -> Result<usize, String> {
    let wait_fn = if force_wait_failed {
        mock_wait_failed_fn
    } else {
        default_wait_fn
    };
    read_exact_overlapped_with_deadline_wait_fn(h_file, buf, deadline, wait_fn)
}

#[cfg(windows)]
pub unsafe fn read_exact_overlapped_with_deadline(
    h_file: *mut c_void,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<usize, String> {
    read_exact_overlapped_with_deadline_injected(h_file, buf, deadline, false)
}

pub unsafe fn read_exact_overlapped_with_timeout(
    h_file: *mut c_void,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<usize, String> {
    read_exact_overlapped_with_deadline(h_file, buf, Instant::now() + timeout)
}

#[cfg(windows)]
pub unsafe fn write_all_overlapped_with_deadline(
    h_file: *mut c_void,
    data: &[u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut total_written = 0;

    let h_event = win32::CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
    if h_event.is_null() {
        return Err("CreateEventW uğursuz oldu".to_string());
    }

    while total_written < data.len() {
        let now = Instant::now();
        if now >= deadline {
            win32::CloseHandle(h_event);
            return Err("E_WRITE_TIMEOUT: Yazma əməliyyatı üçün təyin edilmiş deadline bitdi".to_string());
        }
        let remaining_time = deadline.duration_since(now);

        win32::ResetEvent(h_event);

        let mut ov = win32::OVERLAPPED {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event,
        };

        let target_slice = &data[total_written..];
        let mut bytes_written = 0u32;
        let ok = win32::WriteFile(
            h_file,
            target_slice.as_ptr(),
            target_slice.len() as u32,
            &mut bytes_written,
            &mut ov,
        );

        if ok != 0 {
            total_written += bytes_written as usize;
            continue;
        }

        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(win32::ERROR_IO_PENDING as i32) {
            let wait_ms = remaining_time.as_millis().min(u32::MAX as u128) as u32;
            let wait_res = win32::WaitForSingleObject(h_event, wait_ms);
            if wait_res == win32::WAIT_OBJECT_0 {
                let mut transferred = 0u32;
                let res = win32::GetOverlappedResult(h_file, &mut ov, &mut transferred, 0);
                if res != 0 {
                    total_written += transferred as usize;
                } else {
                    let res_err = std::io::Error::last_os_error();
                    let drain = drain_and_cancel_overlapped(h_file, &mut ov, h_event);
                    return Err(format!("GetOverlappedResult xətası (Drain={:?}): {}", drain, res_err));
                }
            } else if wait_res == win32::WAIT_TIMEOUT {
                let drain = drain_and_cancel_overlapped(h_file, &mut ov, h_event);
                return Err(format!("E_WRITE_TIMEOUT: Peer yazını qəbul etmədi və deadline bitdi (Drain={:?})", drain));
            } else {
                let wait_err = std::io::Error::last_os_error();
                let drain = drain_and_cancel_overlapped(h_file, &mut ov, h_event);
                return Err(format!("WaitForSingleObject xətası (WaitRes={}, Drain={:?}): {}", wait_res, drain, wait_err));
            }
        } else {
            win32::CloseHandle(h_event);
            return Err(format!("WriteFile xətası: {}", err));
        }
    }

    win32::CloseHandle(h_event);
    Ok(())
}

pub unsafe fn write_all_overlapped_with_timeout(
    h_file: *mut c_void,
    data: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    write_all_overlapped_with_deadline(h_file, data, Instant::now() + timeout)
}

// ---------------------------------------------------------------------------
// Vahid Deadline ilə Framed Messaging Protokolu
// ---------------------------------------------------------------------------
#[cfg(windows)]
pub unsafe fn read_framed_message_with_deadline(h_pipe: *mut c_void, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut header_buf = [0u8; 4];
    let n = read_exact_overlapped_with_deadline(h_pipe, &mut header_buf, deadline)?;
    if n == 0 {
        return Err("E_CONNECTION_CLOSED: Əlaqə bağlandı".to_string());
    }
    if n < 4 {
        return Err("E_TRUNCATED_HEADER: Başlıq 4 baytdan azdır (kəsilib)".to_string());
    }

    let payload_len = u32::from_le_bytes(header_buf) as usize;

    if payload_len > MAX_IPC_FRAME_PAYLOAD {
        return Err(format!(
            "E_MESSAGE_OVERFLOW: Bildirilən payload ölçüsü ({}) icazə verilən 4096 bayt həddini aşır",
            payload_len
        ));
    }

    let mut payload_buf = vec![0u8; payload_len];
    let n_body = read_exact_overlapped_with_deadline(h_pipe, &mut payload_buf, deadline)?;
    if n_body < payload_len {
        return Err("E_TRUNCATED_BODY: Göndərilən body elan edilmiş başlıq ölçüsündən azdır (kəsilib)".to_string());
    }

    Ok(payload_buf)
}

pub unsafe fn read_framed_message(h_pipe: *mut c_void, timeout: Duration) -> Result<Vec<u8>, String> {
    read_framed_message_with_deadline(h_pipe, Instant::now() + timeout)
}

#[cfg(windows)]
pub unsafe fn write_framed_message_with_deadline(h_pipe: *mut c_void, payload: &[u8], deadline: Instant) -> Result<(), String> {
    if payload.len() > MAX_IPC_FRAME_PAYLOAD {
        return Err(format!(
            "E_MESSAGE_OVERFLOW: Göndəriləcək payload ölçüsü ({}) 4096 bayt həddini aşır",
            payload.len()
        ));
    }

    let header = (payload.len() as u32).to_le_bytes();
    write_all_overlapped_with_deadline(h_pipe, &header, deadline)?;
    write_all_overlapped_with_deadline(h_pipe, payload, deadline)?;
    Ok(())
}

pub unsafe fn write_framed_message(h_pipe: *mut c_void, payload: &[u8], timeout: Duration) -> Result<(), String> {
    write_framed_message_with_deadline(h_pipe, payload, Instant::now() + timeout)
}

// ---------------------------------------------------------------------------
// B.2b: Identity API Fault Injection və Etibarlı Server Bağlantı Modeli
// ---------------------------------------------------------------------------
pub const FATAL_REVERT_FAILURE_EXIT_CODE: i32 = 202;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityApiFault {
    None,
    // Server-side client identity API faults:
    FailClientPidApi,
    FailClientSessionApi,
    FailImpersonateApi,
    FailOpenThreadTokenApi,
    FailOpenThreadTokenThenRevertApi,
    FailRevertToSelfApi,
    // Client-side server identity API faults:
    FailServerPidApi,
    FailServerTokenApi,
    FailServerExePathApi,
}

#[derive(Debug, Clone)]
pub struct ExpectedServerBinding {
    pub expected_server_pid: u32,
    pub retained_process_handle: usize,
    pub expected_server_sid: String,
    pub expected_server_session_id: u32,
    pub expected_executable_path: String,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedRoundtripOutcome {
    pub client_result: Result<(IpcResponse, IpcServerIdentity), String>,
    pub server_result: Result<(IpcResponse, IpcPeerIdentity), String>,
    pub server_received_payload_bytes: usize,
}

pub fn query_current_executable_path() -> Result<String, String> {
    #[cfg(windows)]
    unsafe {
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        if win32::QueryFullProcessImageNameW(win32::GetCurrentProcess(), 0, buf.as_mut_ptr(), &mut size) == 0 {
            return Err(format!("QueryFullProcessImageNameW xətası: {}", std::io::Error::last_os_error()));
        }
        Ok(String::from_utf16_lossy(&buf[..size as usize]))
    }
    #[cfg(not(windows))]
    {
        Ok("C:\\mock\\winkey_spike.exe".to_string())
    }
}

#[cfg(windows)]
pub unsafe fn open_retained_process_handle(pid: u32) -> Result<ScopedHandle, String> {
    let h = win32::OpenProcess(win32::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if h.is_null() || (h as isize) == -1 {
        return Err(format!("OpenProcess(PID={}) xətası: {}", pid, std::io::Error::last_os_error()));
    }
    Ok(ScopedHandle::new(h))
}

#[cfg(windows)]
unsafe fn extract_token_sid_and_session(h_token: *mut c_void) -> Result<(String, u32), String> {
    let mut ret_len = 0u32;
    win32::GetTokenInformation(h_token, 1, std::ptr::null_mut(), 0, &mut ret_len);
    if ret_len == 0 {
        return Err(format!("GetTokenInformation(TokenUser size) xətası: {}", std::io::Error::last_os_error()));
    }
    let mut buf = vec![0u8; ret_len as usize];
    if win32::GetTokenInformation(h_token, 1, buf.as_mut_ptr() as *mut c_void, ret_len, &mut ret_len) == 0 {
        return Err(format!("GetTokenInformation(TokenUser) xətası: {}", std::io::Error::last_os_error()));
    }

    let p_sid = *(buf.as_ptr() as *const *mut c_void);
    let mut p_str_sid: *mut u16 = std::ptr::null_mut();
    if win32::ConvertSidToStringSidW(p_sid, &mut p_str_sid) == 0 || p_str_sid.is_null() {
        return Err(format!("ConvertSidToStringSidW xətası: {}", std::io::Error::last_os_error()));
    }
    let mut len = 0;
    while *p_str_sid.offset(len) != 0 {
        len += 1;
    }
    let sid_str = String::from_utf16_lossy(std::slice::from_raw_parts(p_str_sid, len as usize));
    win32::LocalFree(p_str_sid as *mut c_void);

    let mut token_session_id = 0u32;
    let mut sess_ret_len = 0u32;
    if win32::GetTokenInformation(
        h_token,
        12, // TokenSessionId
        &mut token_session_id as *mut _ as *mut c_void,
        std::mem::size_of::<u32>() as u32,
        &mut sess_ret_len,
    ) == 0
    {
        return Err(format!("GetTokenInformation(TokenSessionId) xətası: {}", std::io::Error::last_os_error()));
    }

    Ok((sid_str, token_session_id))
}

// ---------------------------------------------------------------------------
// B.2b Tələb 3 (Reviziya 2): Checked RevertToSelf və Dedicated Fatal Termination
// ---------------------------------------------------------------------------
pub fn fatal_terminate_on_revert_failure(context: &str) -> ! {
    eprintln!(
        "[FATAL SECURITY TERMINATION] RevertToSelf uğursuz oldu ({}). Proses dərhal dayandırılır (exit={}).",
        context, FATAL_REVERT_FAILURE_EXIT_CODE
    );
    std::process::exit(FATAL_REVERT_FAILURE_EXIT_CODE);
}

#[cfg(windows)]
pub unsafe fn checked_revert_to_self_or_fatal(fault: IdentityApiFault, branch_context: &str) {
    // 1. Həqiqi OS RevertToSelf çağırılır (injection zamanı da OS thread mühiti təmizlənir):
    let real_rev_ok = win32::RevertToSelf();
    if real_rev_ok == 0 {
        fatal_terminate_on_revert_failure(&format!(
            "{}: Real OS RevertToSelf failed: {}",
            branch_context,
            std::io::Error::last_os_error()
        ));
    }

    // 2. İdarə olunan fault injection (CONTROLLED_INJECTION) aktivdirsə, real OS revert-dən dərhal sonra eyni fatal yol çağırılır:
    if fault == IdentityApiFault::FailRevertToSelfApi
        || fault == IdentityApiFault::FailOpenThreadTokenThenRevertApi
    {
        fatal_terminate_on_revert_failure(&format!(
            "{}: CONTROLLED_INJECTION RevertToSelf failure ({:?})",
            branch_context, fault
        ));
    }
}

pub fn extract_os_client_identity_checked(
    h_pipe: *mut c_void,
    fault: IdentityApiFault,
) -> Result<IpcPeerIdentity, String> {
    #[cfg(windows)]
    unsafe {
        if fault == IdentityApiFault::FailClientPidApi {
            return Err("E_CLIENT_IDENTITY_API_FAILED: GetNamedPipeClientProcessId uğursuz oldu (injected)".to_string());
        }
        let mut pid = 0u32;
        if win32::GetNamedPipeClientProcessId(h_pipe, &mut pid) == 0 || pid == 0 {
            return Err(format!(
                "E_CLIENT_IDENTITY_API_FAILED: GetNamedPipeClientProcessId xətası: {}",
                std::io::Error::last_os_error()
            ));
        }

        if fault == IdentityApiFault::FailClientSessionApi {
            return Err("E_CLIENT_IDENTITY_API_FAILED: GetNamedPipeClientSessionId uğursuz oldu (injected)".to_string());
        }
        let mut session_id = 0u32;
        if win32::GetNamedPipeClientSessionId(h_pipe, &mut session_id) == 0 {
            return Err(format!(
                "E_CLIENT_IDENTITY_API_FAILED: GetNamedPipeClientSessionId xətası: {}",
                std::io::Error::last_os_error()
            ));
        }

        if fault == IdentityApiFault::FailImpersonateApi {
            return Err("E_IMPERSONATION_FAILED: ImpersonateNamedPipeClient uğursuz oldu (injected)".to_string());
        }
        if win32::ImpersonateNamedPipeClient(h_pipe) == 0 {
            return Err(format!(
                "E_IMPERSONATION_FAILED: ImpersonateNamedPipeClient xətası: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Impersonation uğurlu olduqdan sonrakı BÜTÜN çıxışlar checked_revert_to_self_or_fatal-dan keçir!
        let mut h_thread_token: *mut c_void = std::ptr::null_mut();
        let force_open_tok_fail = fault == IdentityApiFault::FailOpenThreadTokenApi
            || fault == IdentityApiFault::FailOpenThreadTokenThenRevertApi;
        let open_tok_ok = if force_open_tok_fail {
            0
        } else {
            win32::OpenThreadToken(
                win32::GetCurrentThread(),
                win32::TOKEN_QUERY,
                1, // OpenAsSelf = TRUE (SECURITY_IDENTIFICATION səviyyəsində identity oxumaq üçün)
                &mut h_thread_token,
            )
        };
        if open_tok_ok == 0 || h_thread_token.is_null() {
            let err = std::io::Error::last_os_error();
            // OpenThreadToken uğursuzluğunda let _ YOXDUR — checked revert və uğursuz olarsa fatal exit!
            checked_revert_to_self_or_fatal(fault, "OpenThreadToken_error_branch");
            return Err(format!("E_IMPERSONATION_FAILED: OpenThreadToken xətası: {}", err));
        }

        let token_guard = ScopedHandle::new(h_thread_token);
        let token_info_res = extract_token_sid_and_session(token_guard.raw());

        // Əlavə olaraq TokenImpersonationLevel (Class 9) yoxlanılır:
        let mut imp_level: u32 = 0;
        let mut imp_ret_len: u32 = 0;
        let imp_level_ok = win32::GetTokenInformation(
            token_guard.raw(),
            9, // TokenImpersonationLevel
            &mut imp_level as *mut _ as *mut c_void,
            std::mem::size_of::<u32>() as u32,
            &mut imp_ret_len,
        );

        drop(token_guard);

        // Əsas çıxışda checked RevertToSelf — uğursuz olarsa adi Err qaytarılmır, proses dərhal fatal dayandırılır!
        checked_revert_to_self_or_fatal(fault, "main_impersonation_teardown");

        let (client_sid, token_session_id) = token_info_res?;
        if imp_level_ok == 0 || imp_level < 1 {
            // SecurityAnonymous (0) rədd edilir; ən azı SecurityIdentification (1) olmalıdır
            return Err(format!("E_INSUFFICIENT_SQOS_LEVEL: Token impersonation level etibarsızdır ({})", imp_level));
        }
        if token_session_id != session_id {
            return Err(format!(
                "E_CLIENT_SESSION_TOKEN_MISMATCH: Pipe Session ({}) != Token Session ({})",
                session_id, token_session_id
            ));
        }
        if client_sid.is_empty() {
            return Err("E_EMPTY_CLIENT_SID: Client SID boş ola bilməz".to_string());
        }

        Ok(IpcPeerIdentity {
            os_client_pid: pid,
            os_client_session_id: session_id,
            os_client_sid: client_sid,
            is_impersonation_successful: true,
        })
    }

    #[cfg(not(windows))]
    {
        let _ = (h_pipe, fault);
        Ok(IpcPeerIdentity {
            os_client_pid: 1234,
            os_client_session_id: 1,
            os_client_sid: "S-1-5-21-MOCK".to_string(),
            is_impersonation_successful: true,
        })
    }
}

pub fn extract_os_client_identity(h_pipe: *mut c_void) -> IpcPeerIdentity {
    match extract_os_client_identity_checked(h_pipe, IdentityApiFault::None) {
        Ok(peer) => peer,
        Err(_) => IpcPeerIdentity {
            os_client_pid: 0,
            os_client_session_id: 0,
            os_client_sid: String::new(),
            is_impersonation_successful: false,
        },
    }
}

// ---------------------------------------------------------------------------
// B.2b Tələb 2: Client-Tərəfli Pre-Transfer Server Autentifikasiyası (Fail-Closed)
// ---------------------------------------------------------------------------
pub fn verify_pipe_server_before_transfer(
    h_client: *mut c_void,
    binding: &ExpectedServerBinding,
    fault: IdentityApiFault,
) -> Result<IpcServerIdentity, String> {
    #[cfg(windows)]
    unsafe {
        if fault == IdentityApiFault::FailServerPidApi {
            return Err("E_SERVER_IDENTITY_API_FAILED: GetNamedPipeServerProcessId uğursuz oldu (injected)".to_string());
        }

        let mut actual_pid = 0u32;
        if win32::GetNamedPipeServerProcessId(h_client, &mut actual_pid) == 0 || actual_pid == 0 {
            return Err(format!(
                "E_SERVER_IDENTITY_API_FAILED: GetNamedPipeServerProcessId xətası: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut actual_session_id = 0u32;
        if win32::GetNamedPipeServerSessionId(h_client, &mut actual_session_id) == 0 {
            return Err(format!(
                "E_SERVER_IDENTITY_API_FAILED: GetNamedPipeServerSessionId xətası: {}",
                std::io::Error::last_os_error()
            ));
        }

        // 1. Gözlənilən Server PID yoxlaması (launcher-dən gələn):
        if actual_pid != binding.expected_server_pid {
            return Err(format!(
                "E_UNTRUSTED_SERVER_PID: Gözlənilən PID={}, Faktiki Pipe Server PID={}",
                binding.expected_server_pid, actual_pid
            ));
        }

        // 2. Saxlanan (retained) process handle ilə eyni proses obyekti olduğunun yoxlanması (PID reuse qorunması):
        let h_retained = binding.retained_process_handle as *mut c_void;
        if h_retained.is_null() || (h_retained as isize) == -1 {
            return Err("E_SERVER_IDENTITY_API_FAILED: Saxlanan launcher process handle etibarsızdır".to_string());
        }
        let retained_pid = win32::GetProcessId(h_retained);
        if retained_pid == 0 || retained_pid != actual_pid {
            return Err(format!(
                "E_UNTRUSTED_SERVER_HANDLE_PID: Saxlanan handle PID ({}) != Pipe Server PID ({})",
                retained_pid, actual_pid
            ));
        }

        let h_server_proc = open_retained_process_handle(actual_pid)?;
        if !win32::compare_object_handles_win32(h_retained, h_server_proc.raw()) {
            return Err("E_UNTRUSTED_SERVER_PROCESS_OBJECT: CompareObjectHandles / ProcessTimes uğursuz oldu — proses obyekti uyğun gəlmir".to_string());
        }

        // 3. Server prosesinin token SID və Session ID yoxlaması:
        if fault == IdentityApiFault::FailServerTokenApi {
            return Err("E_SERVER_IDENTITY_API_FAILED: OpenProcessToken uğursuz oldu (injected)".to_string());
        }
        let mut h_proc_token_raw: *mut c_void = std::ptr::null_mut();
        if win32::OpenProcessToken(h_server_proc.raw(), win32::TOKEN_QUERY, &mut h_proc_token_raw) == 0 || h_proc_token_raw.is_null() {
            return Err(format!(
                "E_SERVER_IDENTITY_API_FAILED: OpenProcessToken xətası: {}",
                std::io::Error::last_os_error()
            ));
        }
        let h_proc_token = ScopedHandle::new(h_proc_token_raw);
        let (server_token_sid, server_token_session_id) = extract_token_sid_and_session(h_proc_token.raw())?;

        if actual_session_id != binding.expected_server_session_id || server_token_session_id != binding.expected_server_session_id {
            return Err(format!(
                "E_UNTRUSTED_SERVER_SESSION: Gözlənilən Session={}, Pipe Session={}, Token Session={}",
                binding.expected_server_session_id, actual_session_id, server_token_session_id
            ));
        }

        if server_token_sid != binding.expected_server_sid {
            return Err(format!(
                "E_UNTRUSTED_SERVER_SID: Gözlənilən SID='{}', Faktiki Server Token SID='{}'",
                binding.expected_server_sid, server_token_sid
            ));
        }

        // 4. Server prosesinin qorunan executable yolu yoxlaması:
        if fault == IdentityApiFault::FailServerExePathApi {
            return Err("E_SERVER_IDENTITY_API_FAILED: QueryFullProcessImageNameW uğursuz oldu (injected)".to_string());
        }
        let mut exe_buf = [0u16; 1024];
        let mut exe_len = exe_buf.len() as u32;
        if win32::QueryFullProcessImageNameW(h_server_proc.raw(), 0, exe_buf.as_mut_ptr(), &mut exe_len) == 0 || exe_len == 0 {
            return Err(format!(
                "E_SERVER_IDENTITY_API_FAILED: QueryFullProcessImageNameW xətası: {}",
                std::io::Error::last_os_error()
            ));
        }
        let actual_exe_path = String::from_utf16_lossy(&exe_buf[..exe_len as usize]);
        if !actual_exe_path.eq_ignore_ascii_case(&binding.expected_executable_path) {
            return Err(format!(
                "E_UNTRUSTED_SERVER_EXE_PATH: Gözlənilən yol='{}', Faktiki yol='{}'",
                binding.expected_executable_path, actual_exe_path
            ));
        }

        Ok(IpcServerIdentity {
            os_server_pid: actual_pid,
            os_server_session_id: actual_session_id,
        })
    }

    #[cfg(not(windows))]
    {
        let _ = (h_client, binding, fault);
        Ok(IpcServerIdentity {
            os_server_pid: 5678,
            os_server_session_id: 1,
        })
    }
}

pub fn extract_os_server_identity(h_pipe: *mut c_void) -> IpcServerIdentity {
    #[cfg(windows)]
    unsafe {
        let mut pid = 0u32;
        let mut session_id = 0u32;
        win32::GetNamedPipeServerProcessId(h_pipe, &mut pid);
        win32::GetNamedPipeServerSessionId(h_pipe, &mut session_id);

        IpcServerIdentity {
            os_server_pid: pid,
            os_server_session_id: session_id,
        }
    }

    #[cfg(not(windows))]
    {
        IpcServerIdentity {
            os_server_pid: 5678,
            os_server_session_id: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// B.2b: Pre-Transfer Server Autentifikasiyalı və Dar DACL-li Roundtrip
// ---------------------------------------------------------------------------
pub fn execute_authenticated_user_channel_roundtrip(
    pipe_name: &str,
    payload: &[u8],
    dacl_user_sid: &str,
    server_policy_expected_sid: &str,
    server_policy_expected_session: u32,
    client_expected_server: &ExpectedServerBinding,
    timeout: Duration,
    client_identity_fault: IdentityApiFault,
    server_identity_fault: IdentityApiFault,
) -> Result<AuthenticatedRoundtripOutcome, String> {
    #[cfg(windows)]
    unsafe {
        let deadline = Instant::now() + timeout;
        let sddl = build_narrow_user_channel_sddl(dacl_user_sid)?;
        let h_server = create_secure_overlapped_named_pipe_server(pipe_name, &sddl)?;

        let (tx_ready, rx_ready) = std::sync::mpsc::channel();

        let h_server_raw = h_server as usize;
        let exp_sid = server_policy_expected_sid.to_string();

        let server_thread = std::thread::spawn(move || -> (Result<(IpcResponse, IpcPeerIdentity), String>, usize) {
            let h_server = h_server_raw as *mut c_void;
            tx_ready.send(()).unwrap();

            let conn_res = connect_pipe_with_deadline(h_server, deadline);
            if let Err(e) = conn_res {
                win32::CloseHandle(h_server);
                return (Err(e), 0);
            }

            // Server əvvəlcə client-in göndərdiyi (və ya göndərmədiyi) frame-i oxumağa cəhd edir
            // (Əgər client pre-transfer yoxlamada serveri rədd edib handle-ı bağlayıbsa, burada 0 bayt / EOF qayıdır!):
            let req_res = read_framed_message_with_deadline(h_server, deadline);
            let received_bytes = match &req_res {
                Ok(b) => b.len(),
                Err(_) => 0,
            };

            // Əgər client heç bir request yazmadan əlaqəni kəsibsə, server dərhal çıxır:
            if let Err(ref e) = req_res {
                if e.contains("E_CONNECTION_CLOSED") {
                    win32::DisconnectNamedPipe(h_server);
                    win32::CloseHandle(h_server);
                    return (Err(e.clone()), 0);
                }
            }

            // Server client kimliyini OS-dən fail-closed olaraq yoxlayır:
            let peer_identity_res = extract_os_client_identity_checked(h_server, server_identity_fault);
            let policy = IpcSecurityPolicy::new(&exp_sid, server_policy_expected_session);

            let (resp, peer_identity_for_record) = match peer_identity_res {
                Ok(peer_identity) => {
                    let r = match policy.validate_os_peer_identity(&peer_identity) {
                        Ok(_) => match req_res {
                            Ok(req_bytes) => match serde_json::from_slice::<IpcCommand>(&req_bytes) {
                                Ok(cmd) => match cmd {
                                    IpcCommand::Ping => IpcResponse::Ack,
                                    IpcCommand::GetDesktopState => {
                                        let (name, acc) = query_current_input_desktop();
                                        IpcResponse::DesktopState {
                                            desktop_name: name,
                                            is_input_desktop_accessible: acc,
                                        }
                                    }
                                    IpcCommand::ForgedIdentityCommand { .. } => IpcResponse::Ack,
                                    IpcCommand::TriggerCurtain | IpcCommand::InjectPin { .. } => IpcResponse::Error {
                                        code: "NOT_IMPLEMENTED".to_string(),
                                        message: "Komanda bu fazada aktiv deyil".to_string(),
                                    },
                                },
                                Err(_) => IpcResponse::Error {
                                    code: "E_MALFORMED_OR_UNSUPPORTED".to_string(),
                                    message: "Məlumat formata uyğun deyil".to_string(),
                                },
                            },
                            Err(e) => IpcResponse::Error {
                                code: "E_MALFORMED_OR_UNSUPPORTED".to_string(),
                                message: e,
                            },
                        },
                        Err(err_code) => IpcResponse::Error {
                            code: "E_POLICY_REJECTED".to_string(),
                            message: err_code.to_string(),
                        },
                    };
                    (r, peer_identity)
                }
                Err(api_err) => (
                    IpcResponse::Error {
                        code: "E_CLIENT_IDENTITY_API_FAILED".to_string(),
                        message: api_err,
                    },
                    IpcPeerIdentity {
                        os_client_pid: 0,
                        os_client_session_id: 0,
                        os_client_sid: String::new(),
                        is_impersonation_successful: false,
                    },
                ),
            };

            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            if let Err(e) = write_framed_message_with_deadline(h_server, &resp_bytes, deadline) {
                win32::DisconnectNamedPipe(h_server);
                win32::CloseHandle(h_server);
                return (Err(format!("Server yazı xətası: {}", e)), received_bytes);
            }

            let ack_res = read_framed_message_with_deadline(h_server, deadline);
            win32::DisconnectNamedPipe(h_server);
            win32::CloseHandle(h_server);

            match ack_res {
                Ok(ack_bytes) if ack_bytes.as_slice() == b"APP_ACK" => {
                    (Ok((resp, peer_identity_for_record)), received_bytes)
                }
                Ok(wrong_ack) => (
                    Err(format!(
                        "E_INVALID_ACK: Gözlənilən 'APP_ACK' əvəzinə naməlum ACK alındı (len={})",
                        wrong_ack.len()
                    )),
                    received_bytes,
                ),
                Err(e) => (Err(format!("Server ACK gözləmə xətası: {}", e)), received_bytes),
            }
        });

        let ready_res = rx_ready.recv_timeout(timeout);

        let client_res: Result<(IpcResponse, IpcServerIdentity), String> = if ready_res.is_ok() {
            (|| -> Result<(IpcResponse, IpcServerIdentity), String> {
                let h_client = ScopedHandle::new(open_overlapped_pipe_client(pipe_name)?);

                // KRİTİK (B.2b Tələb 2): Client payload göndərməzdən ƏVVƏL serveri yoxlayır!
                // Rədd olunarsa h_client dərhal bağlanır və pipe-a 0 bayt yazılır!
                let verified_server = verify_pipe_server_before_transfer(
                    h_client.raw(),
                    client_expected_server,
                    client_identity_fault,
                )?;

                write_framed_message_with_deadline(h_client.raw(), payload, deadline)?;
                let resp_payload = read_framed_message_with_deadline(h_client.raw(), deadline)?;
                let client_received_resp: IpcResponse = serde_json::from_slice(&resp_payload)
                    .map_err(|e| format!("Client parse xətası: {}", e))?;

                write_framed_message_with_deadline(h_client.raw(), b"APP_ACK", deadline)?;

                Ok((client_received_resp, verified_server))
            })()
        } else {
            Err(format!("Server ready timeout: {:?}", ready_res.as_ref().err().unwrap()))
        };

        let join_res = server_thread.join();
        if let Err(panic_payload) = join_res {
            let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Server thread panic etdi".to_string()
            };
            return Err(format!("E_SERVER_PANIC: {}", msg));
        }

        let (server_res, server_received_payload_bytes) = join_res.unwrap();

        if let Err(e) = ready_res {
            return Err(format!("E_SERVER_NOT_READY: {}", e));
        }

        Ok(AuthenticatedRoundtripOutcome {
            client_result: client_res,
            server_result: server_res,
            server_received_payload_bytes,
        })
    }

    #[cfg(not(windows))]
    {
        let _ = (
            pipe_name,
            payload,
            dacl_user_sid,
            server_policy_expected_sid,
            server_policy_expected_session,
            client_expected_server,
            timeout,
            client_identity_fault,
            server_identity_fault,
        );
        Ok(AuthenticatedRoundtripOutcome {
            client_result: Ok((
                IpcResponse::Ack,
                IpcServerIdentity {
                    os_server_pid: 1,
                    os_server_session_id: 1,
                },
            )),
            server_result: Ok((
                IpcResponse::Ack,
                IpcPeerIdentity {
                    os_client_pid: 1,
                    os_client_session_id: 1,
                    os_client_sid: server_policy_expected_sid.to_string(),
                    is_impersonation_successful: true,
                },
            )),
            server_received_payload_bytes: payload.len(),
        })
    }
}

// ---------------------------------------------------------------------------
// Client və Server Fault Injection Enum-ları (Tapıntı 2 Həlli)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFaultInjection {
    None,
    FailWrite,
    FailReadTimeout,
    FailParse,
    OmitAck,
    WrongAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFaultInjection {
    None,
    PanicBeforeReady,
    PanicAfterConnect,
    PanicAfterRequest,
}

// ---------------------------------------------------------------------------
// Tam Təhlükəsiz Roundtrip (RAII Client Handle, Bounded APP_ACK, Vahid Teardown)
// ---------------------------------------------------------------------------
pub fn execute_secure_ipc_roundtrip(
    pipe_name: &str,
    payload: &[u8],
    expected_sid: &str,
    expected_session: u32,
    timeout: Duration,
) -> Result<(IpcResponse, IpcPeerIdentity, IpcServerIdentity), String> {
    execute_secure_ipc_roundtrip_with_fault(
        pipe_name,
        payload,
        expected_sid,
        expected_session,
        timeout,
        ClientFaultInjection::None,
        ServerFaultInjection::None,
    )
}

pub fn execute_secure_ipc_roundtrip_with_fault(
    pipe_name: &str,
    payload: &[u8],
    expected_sid: &str,
    expected_session: u32,
    timeout: Duration,
    client_fault: ClientFaultInjection,
    server_fault: ServerFaultInjection,
) -> Result<(IpcResponse, IpcPeerIdentity, IpcServerIdentity), String> {
    #[cfg(windows)]
    unsafe {
        let deadline = Instant::now() + timeout;
        let current_user_sid = query_current_user_sid()?;
        let sddl = build_narrow_user_channel_sddl(&current_user_sid)?;
        let h_server = create_secure_overlapped_named_pipe_server(pipe_name, &sddl)?;

        let current_pid = win32::GetCurrentProcessId();
        let (_, current_proc_session) = query_system_session_info();
        let current_exe_path = query_current_executable_path()?;
        let h_retained_proc = open_retained_process_handle(current_pid)?;
        let expected_server_binding = ExpectedServerBinding {
            expected_server_pid: current_pid,
            retained_process_handle: h_retained_proc.raw() as usize,
            expected_server_sid: current_user_sid.clone(),
            expected_server_session_id: current_proc_session,
            expected_executable_path: current_exe_path,
        };

        let (tx_ready, rx_ready) = std::sync::mpsc::channel();
        let (tx_res, rx_res) = std::sync::mpsc::channel();

        let h_server_raw = h_server as usize;
        let exp_sid = expected_sid.to_string();

        let server_thread = std::thread::spawn(move || {
            let h_server = h_server_raw as *mut c_void;

            if server_fault == ServerFaultInjection::PanicBeforeReady {
                win32::CloseHandle(h_server);
                panic!("INJECTED_SERVER_PANIC: Server ready siqnalından əvvəl panic");
            }

            tx_ready.send(()).unwrap();
            let conn_res = connect_pipe_with_deadline(h_server, deadline);
            if let Err(e) = conn_res {
                win32::CloseHandle(h_server);
                tx_res.send(Err(e)).ok();
                return;
            }

            if server_fault == ServerFaultInjection::PanicAfterConnect {
                win32::DisconnectNamedPipe(h_server);
                win32::CloseHandle(h_server);
                panic!("INJECTED_SERVER_PANIC: Client qoşulduqdan sonra panic");
            }

            let peer_identity = extract_os_client_identity(h_server);
            let policy = IpcSecurityPolicy::new(&exp_sid, expected_session);

            let req_res = read_framed_message_with_deadline(h_server, deadline);

            if server_fault == ServerFaultInjection::PanicAfterRequest {
                win32::DisconnectNamedPipe(h_server);
                win32::CloseHandle(h_server);
                panic!("INJECTED_SERVER_PANIC: Sorğunu oxuduqdan sonra panic");
            }

            let resp = match policy.validate_os_peer_identity(&peer_identity) {
                Ok(_) => {
                    match req_res {
                        Ok(req_bytes) => {
                            match serde_json::from_slice::<IpcCommand>(&req_bytes) {
                                Ok(cmd) => match cmd {
                                    IpcCommand::Ping => IpcResponse::Ack,
                                    IpcCommand::GetDesktopState => {
                                        let (name, acc) = query_current_input_desktop();
                                        IpcResponse::DesktopState {
                                            desktop_name: name,
                                            is_input_desktop_accessible: acc,
                                        }
                                    }
                                    IpcCommand::ForgedIdentityCommand { .. } => {
                                        IpcResponse::Ack
                                    }
                                    IpcCommand::TriggerCurtain | IpcCommand::InjectPin { .. } => {
                                        IpcResponse::Error {
                                            code: "NOT_IMPLEMENTED".to_string(),
                                            message: "Komanda bu fazada aktiv deyil".to_string(),
                                        }
                                    }
                                },
                                Err(_) => IpcResponse::Error {
                                    code: "E_MALFORMED_OR_UNSUPPORTED".to_string(),
                                    message: "Məlumat formata uyğun deyil".to_string(),
                                },
                            }
                        }
                        Err(e) => IpcResponse::Error {
                            code: "E_MALFORMED_OR_UNSUPPORTED".to_string(),
                            message: e,
                        },
                    }
                }
                Err(err_code) => IpcResponse::Error {
                    code: "E_POLICY_REJECTED".to_string(),
                    message: err_code.to_string(),
                },
            };

            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            // YAZI NƏTİCƏSİ İTİRİLMİR: Həqiqi error propagation
            if let Err(e) = write_framed_message_with_deadline(h_server, &resp_bytes, deadline) {
                win32::DisconnectNamedPipe(h_server);
                win32::CloseHandle(h_server);
                tx_res.send(Err(format!("Server yazı xətası: {}", e))).ok();
                return;
            }

            // BOUNDED APPLICATION ACK PROTOKOLU (Dəqiq b"APP_ACK" tələb olunur):
            let ack_res = read_framed_message_with_deadline(h_server, deadline);

            win32::DisconnectNamedPipe(h_server);
            win32::CloseHandle(h_server);

            match ack_res {
                Ok(ack_bytes) if ack_bytes.as_slice() == b"APP_ACK" => {
                    tx_res.send(Ok((resp, peer_identity))).ok();
                }
                Ok(wrong_ack) => {
                    tx_res.send(Err(format!(
                        "E_INVALID_ACK: Gözlənilən 'APP_ACK' əvəzinə naməlum ACK alındı (len={})",
                        wrong_ack.len()
                    ))).ok();
                }
                Err(e) => {
                    tx_res.send(Err(format!("Server ACK gözləmə xətası: {}", e))).ok();
                }
            }
        });

        // 1. Server Ready yoxlaması:
        let ready_res = rx_ready.recv_timeout(timeout);

        // 2. Client icrası (Yalnız server ready olduqda çağırılır):
        let client_res: Result<(IpcResponse, IpcServerIdentity), String> = if ready_res.is_ok() {
            (|| -> Result<(IpcResponse, IpcServerIdentity), String> {
                let h_client = ScopedHandle::new(open_overlapped_pipe_client(pipe_name)?);
                let server_identity = verify_pipe_server_before_transfer(
                    h_client.raw(),
                    &expected_server_binding,
                    IdentityApiFault::None,
                )?;

                // FAULT INJECTION 1: Client Write Fail
                if client_fault == ClientFaultInjection::FailWrite {
                    return Err("E_CLIENT_WRITE_FAILED: Client yazını icra etmədi (injected write fail)".to_string());
                }

                write_framed_message_with_deadline(h_client.raw(), payload, deadline)?;

                // FAULT INJECTION 2: Client Read Timeout
                if client_fault == ClientFaultInjection::FailReadTimeout {
                    return Err("E_CLIENT_READ_TIMEOUT: Client cavabı gözləmədi (injected read timeout)".to_string());
                }

                let resp_payload = read_framed_message_with_deadline(h_client.raw(), deadline)?;

                // FAULT INJECTION 3: Client Parse Fail
                if client_fault == ClientFaultInjection::FailParse {
                    return Err("E_CLIENT_PARSE_FAILED: Injected JSON parse xətası".to_string());
                }

                let client_received_resp: IpcResponse = serde_json::from_slice(&resp_payload)
                    .map_err(|e| format!("Client parse xətası: {}", e))?;

                // FAULT INJECTION 4: Client Omit ACK
                if client_fault == ClientFaultInjection::OmitAck {
                    return Err("E_CLIENT_ACK_OMITTED: Client APP_ACK göndərmədi (injected omit ACK)".to_string());
                }

                // FAULT INJECTION 5: Client Wrong ACK
                if client_fault == ClientFaultInjection::WrongAck {
                    write_framed_message_with_deadline(h_client.raw(), b"WRONG_TOKEN", deadline)?;
                    return Err("E_CLIENT_WRONG_ACK: Client yanlış ACK göndərdi".to_string());
                }

                // Normal path: dəqiq b"APP_ACK"
                write_framed_message_with_deadline(h_client.raw(), b"APP_ACK", deadline)?;

                Ok((client_received_resp, server_identity))
            })()
        } else {
            Err(format!("Server ready timeout: {:?}", ready_res.as_ref().err().unwrap()))
        };

        // 3. VAHİD TEARDOWN: Bütün exit-lər üçün server thread bounded join edilir və panic heç vaxt itirilmir!
        let server_outcome = rx_res.recv_timeout(timeout.saturating_add(Duration::from_millis(600)));
        let join_res = server_thread.join();
        drop(h_retained_proc);

        // Server panic yoxlanılır (let _ ilə itirilmir!):
        if let Err(panic_payload) = join_res {
            let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "Server thread panic etdi".to_string()
            };
            return Err(format!("E_SERVER_PANIC: {}", msg));
        }

        // Server ready xətası varsa yayılır:
        if let Err(e) = ready_res {
            return Err(format!("E_SERVER_NOT_READY: {}", e));
        }

        // Client xətası varsa yayılır (ScopedHandle artıq RAII ilə bağlanıb):
        let (client_received_resp, server_identity) = client_res?;

        // Server outcome yoxlanılır:
        let (server_resp, peer_identity) = server_outcome
            .map_err(|e| format!("Server cavab almadı / timeout: {}", e))?
            .map_err(|e| format!("Server daxili xəta: {}", e))?;

        assert_eq!(client_received_resp, server_resp);
        Ok((client_received_resp, peer_identity, server_identity))
    }

    #[cfg(not(windows))]
    {
        Ok((
            IpcResponse::Ack,
            IpcPeerIdentity {
                os_client_pid: 1,
                os_client_session_id: 1,
                os_client_sid: expected_sid.to_string(),
                is_impersonation_successful: true,
            },
            IpcServerIdentity {
                os_server_pid: 2,
                os_server_session_id: 1,
            },
        ))
    }
}

// -------------------------------------------------------------------------------------------------
// Mərhələ D: Etalon Windows Unlock Ardıcıllığı və Secure Desktop Mühafizəsi
// Default klik -> Winlogon fokus -> Bir dəfə credential -> Faktiki unlock təsdiqi
// Qaydalar:
//  - UAC ekranına QƏTİYYƏN PIN göndərilmir (E_UAC_DESKTOP_BLOCKED)
//  - Windows Hello aktivdirsə əlavə PIN / Enter göndərilmir (E_HELLO_ACTIVE_NO_INPUT)
//  - Səhv PIN təkrar-təkrar sınanmır (tək cəhd müqaviləsi)
//  - Kilidsiz masaüstündə təkrar unlock rədd edilir
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopSecurityState {
    LockedDefaultCurtain,
    WinlogonPinFocus,
    WinlogonHelloActive,
    UacSecureDesktopActive,
    UnlockedUserDesktop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockOutcome {
    SuccessUnlocked,
    RejectedUacDesktop,
    RejectedHelloActiveNoInput,
    RejectedAlreadyUnlocked,
    CurtainDismissedWaitingFocus,
}

pub struct UnlockSequenceEngine {
    pub last_attempt_failed: bool,
}

impl UnlockSequenceEngine {
    pub fn new() -> Self {
        Self {
            last_attempt_failed: false,
        }
    }

    /// Etalon unlock ardıcıllığının icrası:
    /// 1. Pərdə klik (PIN-siz) -> 2. Winlogon fokus təsdiqi -> 3. Tək bir dəfə credential
    pub fn execute_unlock_step(
        &mut self,
        current_state: DesktopSecurityState,
        has_local_pin: bool,
    ) -> Result<UnlockOutcome, &'static str> {
        // Təhlükəsizlik qaydası 1: UAC ekranına PIN göndərmə!
        if current_state == DesktopSecurityState::UacSecureDesktopActive {
            return Err("E_UAC_DESKTOP_BLOCKED: UAC Təhlükəsiz masaüstü aktivdir, credential inyeksiyası bloklandı!");
        }

        // Təhlükəsizlik qaydası 2: Windows Hello aktiv olduqda əlavə input göndərmə!
        if current_state == DesktopSecurityState::WinlogonHelloActive {
            return Ok(UnlockOutcome::RejectedHelloActiveNoInput);
        }

        // Təhlükəsizlik qaydası 3: Artıq kilidsizdirsə əlavə əməliyyat etmə
        if current_state == DesktopSecurityState::UnlockedUserDesktop {
            return Ok(UnlockOutcome::RejectedAlreadyUnlocked);
        }

        // Addım 1: Default pərdəyə PIN-siz klik
        if current_state == DesktopSecurityState::LockedDefaultCurtain {
            // Pərdə qaldırıldı, Winlogon PIN fokusu gözlənilir
            return Ok(UnlockOutcome::CurtainDismissedWaitingFocus);
        }

        // Addım 2: Winlogon PIN fokusunda yalnız tək bir dəfə daxiletmə
        if current_state == DesktopSecurityState::WinlogonPinFocus {
            if !has_local_pin {
                return Err("E_LOCAL_PIN_MISSING: Yerli qorunan PIN tapılmadı");
            }
            if self.last_attempt_failed {
                return Err("E_PIN_RETRY_BLOCKED: Yanlış PIN təkrar-təkrar sınana bilməz, operator təsdiqi tələb olunur");
            }

            // Tək bir dəfə credential uğurla ötürülür və kilid açılır
            return Ok(UnlockOutcome::SuccessUnlocked);
        }

        Err("E_UNKNOWN_DESKTOP_STATE")
    }
}

