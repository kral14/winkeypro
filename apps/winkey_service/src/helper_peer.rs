use std::ffi::c_void;
use std::path::{Path, PathBuf};
use crate::ipc_engine::{win32, ScopedHandle};
use crate::lock_engine::{ChildProcessInfo, get_token_sid_string};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, GetProcessTimes, PROCESS_QUERY_LIMITED_INFORMATION};
const SYNCHRONIZE: u32 = 0x00100000;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};

pub fn parent_pid(pid: u32) -> Result<u32, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot as isize == -1 { return Err("E_PEER_SNAPSHOT".into()); }
        let snapshot = ScopedHandle::new(snapshot);
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut next = Process32FirstW(snapshot.raw(), &mut entry);
        while next != 0 {
            if entry.th32ProcessID == pid { return Ok(entry.th32ParentProcessID); }
            next = Process32NextW(snapshot.raw(), &mut entry);
        }
    }
    Err("E_PEER_PROCESS_NOT_FOUND".into())
}

pub fn find_child(parent: u32, expected_image: &Path) -> Option<u32> {
    unsafe {
        let handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if handle as isize == -1 { return None; }
        let snapshot = ScopedHandle::new(handle);
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut next = Process32FirstW(snapshot.raw(), &mut entry);
        while next != 0 {
            let end = entry.szExeFile.iter().position(|v| *v == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
            let expected_name = expected_image.file_name()?.to_string_lossy();
            if entry.th32ParentProcessID == parent && name.eq_ignore_ascii_case(&expected_name) { return Some(entry.th32ProcessID); }
            next = Process32NextW(snapshot.raw(), &mut entry);
        }
    }
    None
}

// Read-only identity probe: helper waits on a random pipe that is NEVER created.
// No credential is supplied and no Windows input path can be reached.
pub fn probe_packaged_helper(explicit_path: Option<&Path>) -> Result<(), String> {
    use std::time::{Instant, Duration};
    let helper = if let Some(path) = explicit_path {
        if !crate::lock_engine::validate_helper_binary(path) { return Err("E_HELPER_UNAVAILABLE".into()); }
        path.canonicalize().map_err(|_| "E_HELPER_UNAVAILABLE")?
    } else {
        crate::lock_engine::find_helper_exe().ok_or("E_HELPER_UNAVAILABLE")?
    };
    let mut session = 0;
    unsafe { crate::lock_engine::win32_process::ProcessIdToSessionId(std::process::id(), &mut session); }
    let pipe = format!("WinKey_NoPipe_{}", uuid::Uuid::new_v4().simple());
    let child = crate::lock_engine::spawn_helper_in_session(&helper,
        &["--mode", "unlock", "--session", &session.to_string(), "--ipc-pipe", &pipe,
          "--expected-server-pid", &std::process::id().to_string()], "default", session, None)?;
    let start = Instant::now();
    let result = (|| {
        let runtime = if helper.parent().map(|p| p.join("helper_runtime").is_dir()).unwrap_or(false) {
            child.pid
        } else { loop {
            if let Some(pid) = find_child(child.pid, &helper) { break pid; }
            if start.elapsed() > Duration::from_secs(4) { return Err("E_PROBE_RUNTIME_NOT_FOUND".into()); }
            std::thread::sleep(Duration::from_millis(20));
        }};
        let guard = verify(&child, runtime, &helper, session)?;
        println!("PASS packaged helper identity: bootstrap={} runtime={}", child.pid, runtime);
        assert!(verify(&child, std::process::id(), &helper, session).is_err());
        assert!(verify(&child, runtime, &std::env::current_exe().unwrap(), session).is_err());
        assert!(verify(&child, runtime, &helper, session.wrapping_add(1)).is_err());
        println!("PASS unrelated PID, wrong image and wrong session rejected; no credential or input sent");
        unsafe {
            let terminate_handle = OpenProcess(1, 0, runtime);
            if !terminate_handle.is_null() {
                let terminate_handle = ScopedHandle::new(terminate_handle);
                crate::lock_engine::win32_process::TerminateProcess(terminate_handle.raw(), 0);
            }
        }
        drop(guard);
        Ok(())
    })();
    unsafe {
        if win32::WaitForSingleObject(child.handle.raw(), 5000) == win32::WAIT_TIMEOUT {
            crate::lock_engine::win32_process::TerminateProcess(child.handle.raw(), 0);
        }
    }
    result
}

fn image(process: *mut c_void) -> Result<PathBuf, String> {
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size) } == 0 {
        return Err("E_PEER_IMAGE_QUERY".into());
    }
    PathBuf::from(String::from_utf16_lossy(&buffer[..size as usize])).canonicalize().map_err(|_| "E_PEER_IMAGE_CANONICAL".into())
}

fn token_sid(process: *mut c_void) -> Result<String, String> {
    let mut token = std::ptr::null_mut();
    if unsafe { win32::OpenProcessToken(process, win32::TOKEN_QUERY, &mut token) } == 0 {
        return Err("E_PEER_TOKEN_QUERY".into());
    }
    get_token_sid_string(ScopedHandle::new(token).raw())
}

fn created(process: *mut c_void) -> Result<u64, String> {
    unsafe {
        let mut creation: FILETIME = std::mem::zeroed();
        let mut exit: FILETIME = std::mem::zeroed();
        let mut kernel: FILETIME = std::mem::zeroed();
        let mut user: FILETIME = std::mem::zeroed();
        if GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) == 0 { return Err("E_PEER_CREATION_QUERY".into()); }
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }
}

// PyInstaller onefile has a bootstrap parent and a Python-runtime child.
// Accept only the launched process or its direct child, with the SAME protected
// image, session, token SID and creation ordering. Hold the peer handle through
// credential transfer so a recycled PID cannot become an authorized peer.
pub fn verify(parent: &ChildProcessInfo, peer_pid: u32, expected_image: &Path, session: u32) -> Result<ScopedHandle, String> {
    if unsafe { win32::WaitForSingleObject(parent.handle.raw(), 0) } != win32::WAIT_TIMEOUT {
        return Err("E_HELPER_PARENT_NOT_ALIVE".into());
    }
    if peer_pid != parent.pid && parent_pid(peer_pid)? != parent.pid {
        return Err("E_FORGED_HELPER_PID: Not the launched helper or its direct runtime child".into());
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, peer_pid) };
    if handle.is_null() { return Err("E_PEER_OPEN_PROCESS".into()); }
    let peer = ScopedHandle::new(handle);
    let expected = expected_image.canonicalize().map_err(|_| "E_PEER_EXPECTED_IMAGE")?;
    let peer_image = image(peer.raw())?;
    let parent_image = image(parent.handle.raw())?;
    if peer_image != expected || parent_image != expected {
        eprintln!("[PEER_IMAGE] expected={:?} bootstrap={:?} runtime={:?}", expected, parent_image, peer_image);
        return Err("E_FORGED_HELPER_IMAGE".into());
    }
    let mut actual = 0;
    if unsafe { crate::lock_engine::win32_process::ProcessIdToSessionId(peer_pid, &mut actual) } == 0 || actual != session {
        return Err("E_PEER_SESSION_MISMATCH".into());
    }
    if token_sid(peer.raw())? != token_sid(parent.handle.raw())? { return Err("E_PEER_TOKEN_MISMATCH".into()); }
    if created(peer.raw())? < created(parent.handle.raw())? { return Err("E_PEER_CREATION_ORDER".into()); }
    Ok(peer)
}
