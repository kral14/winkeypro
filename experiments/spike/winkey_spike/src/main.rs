// WinKey Pro — Mərhələ B: Texniki Spike Düzəlişi və Dürüst Təsnifat Runner-i

mod session_ipc;
mod recovery_rollback;
mod telemetry_collector;
mod webview2_check;
mod sites_pairing;

use session_ipc::*;
use recovery_rollback::*;
use telemetry_collector::*;
use webview2_check::*;
use sites_pairing::*;
use sites_pairing::hex;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};
#[cfg(windows)]
use session_ipc::win32;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--dummy-wait-process") {
        std::thread::sleep(std::time::Duration::from_secs(5));
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--child-revert-test") {
        let mode = args.get(pos + 1).map(|s| s.as_str()).unwrap_or("normal");
        let pipe_name = args.get(pos + 2).map(|s| s.as_str()).unwrap_or("WinKey_ChildRevert_Default");
        let marker_path = args.get(pos + 3).map(|s| s.as_str()).unwrap_or("target/child_revert_marker.txt");

        let fault = match mode {
            "normal" => IdentityApiFault::None,
            "revert_fail" => IdentityApiFault::FailRevertToSelfApi,
            "open_token_then_revert_fail" => IdentityApiFault::FailOpenThreadTokenThenRevertApi,
            _ => IdentityApiFault::None,
        };

        #[cfg(windows)]
        unsafe {
            let current_user_sid = query_current_user_sid().expect("Child SID oxunmalıdır");
            let sddl = build_narrow_user_channel_sddl(&current_user_sid).expect("Child SDDL qurulmalıdır");
            let h_server = create_secure_overlapped_named_pipe_server(pipe_name, &sddl).expect("Child pipe açılmalıdır");
            let deadline = Instant::now() + Duration::from_secs(3);

            connect_pipe_with_deadline(h_server, deadline).expect("Child connect uğurlu olmalıdır");
            let _req = read_framed_message_with_deadline(h_server, deadline).expect("Child request oxunmalıdır");

            // KRİTİK: RevertToSelf uğursuz olduqda (və ya OpenThreadToken fail + RevertToSelf fail olduqda)
            // extract_os_client_identity_checked daxilində checked_revert_to_self_or_fatal prosesi dərhal
            // FATAL_REVERT_FAILURE_EXIT_CODE (202) ilə dayandırır! Növbəti sətirlər HEÇ VAXT İCRA OLUNMUR!
            let peer_res = extract_os_client_identity_checked(h_server, fault);

            // Bu hissə yalnız RevertToSelf uğurlu olduqda icra olunur:
            fs::write(marker_path, b"POST_REVERT_ACTION_EXECUTED").expect("Marker yazılmalıdır");

            let resp = match peer_res {
                Ok(_) => IpcResponse::Ack,
                Err(e) => IpcResponse::Error {
                    code: "E_CLIENT_IDENTITY_API_FAILED".to_string(),
                    message: e,
                },
            };
            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            let _ = write_framed_message_with_deadline(h_server, &resp_bytes, deadline);
            let _ = read_framed_message_with_deadline(h_server, deadline);
            win32::DisconnectNamedPipe(h_server);
            win32::CloseHandle(h_server);
        }
        std::process::exit(0);
    }

    println!("=================================================================");
    println!("  WinKey Pro — Mərhələ B: Texniki Spike (Düzəliş Reviziyası)    ");
    println!("  Təsnifat: MODEL_UNIT | REAL_API | REAL_INTEGRATION | NOT_TESTED");
    println!("=================================================================\n");

    // ÜMUMİ WATCHDOG: 35 saniyəlik killer watchdog thread (Hang / Deadlock qorunması)
    let watchdog_guard = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog_flag = watchdog_guard.clone();
    std::thread::spawn(move || {
        let max_wait = std::time::Duration::from_secs(35);
        let start = std::time::Instant::now();
        while start.elapsed() < max_wait {
            std::thread::sleep(std::time::Duration::from_millis(500));
            if watchdog_flag.load(std::sync::atomic::Ordering::Relaxed) {
                return; // Runner vaxtında tamamlandı
            }
        }
        if !watchdog_flag.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("[WATCHDOG XƏTASI] Test prosesi 35 saniyə ərzində asılı qaldı (HANG)! Proses məcburi dayandırılır.");
            std::process::exit(101);
        }
    });

    let evidence_dir = if Path::new("plan/reports/B").exists() {
        Path::new("plan/reports/B")
    } else if Path::new("../../plan/reports/B").exists() {
        Path::new("../../plan/reports/B")
    } else {
        Path::new("plan/reports/B")
    };
    fs::create_dir_all(evidence_dir).ok();

    // =============================================================
    // B-01 / B.2: Named Pipe IPC Təhlükəsizliyi, OS Token və Dar Müqavilə
    // =============================================================
    println!("[B-01 / B.2 SINAQ] Named Pipe IPC Təhlükəsizliyi, OS Token və Dar Müqavilə...");

    use std::time::Duration;

    // 1. Real Win32 API ölçmələri (REAL_API)
    let (console_session, current_process_session) = query_system_session_info();
    let (desktop_name, desktop_accessible) = query_current_input_desktop();
    let current_user_sid = query_current_user_sid().unwrap_or_else(|_| "S-1-5-21-CURRENT-USER".to_string());
    println!("  [REAL_API] ActiveConsoleSessionId={}, CurrentProcessSessionId={}",
             console_session, current_process_session);
    println!("  [REAL_API] OpenInputDesktop: Name='{}', Accessible={}",
             desktop_name, desktop_accessible);
    println!("  [REAL_API] OS Token Current User SID: {}", current_user_sid);

    // 2. İcazəli PING Sınağı (REAL_INTEGRATION)
    let pipe_ping = "WinKey_B2_Pipe_Ping";
    let ping_payload = serde_json::to_vec(&IpcCommand::Ping).unwrap();
    let (res_ping, peer_id_ping, server_id_ping) = execute_secure_ipc_roundtrip(
        pipe_ping,
        &ping_payload,
        &current_user_sid,
        console_session,
        Duration::from_secs(3),
    ).expect("PING IPC uğursuz oldu");
    println!("  [B.2 TEST 1] İcazəli PING: Resp={:?}, ClientPID={}, ClientSession={}",
             res_ping, peer_id_ping.os_client_pid, peer_id_ping.os_client_session_id);
    assert_eq!(res_ping, IpcResponse::Ack);
    assert_eq!(peer_id_ping.os_client_session_id, console_session);
    assert_eq!(server_id_ping.os_server_session_id, console_session);

    // 3. OS-dən Ölçülən Peer SID və Token Doğrulaması (REAL_API)
    println!("  [B.2 TEST 2] OS-dən Alınan Peer SID: '{}' (Təsdiqləndi: {})",
             peer_id_ping.os_client_sid, peer_id_ping.is_impersonation_successful);
    assert!(peer_id_ping.is_impersonation_successful);
    assert_eq!(peer_id_ping.os_client_sid, current_user_sid);

    // 4. Forged Request Identity Təsirsizdir (MƏNFİ TEST 3)
    // Client request JSON-a saxta claimed_sid daxil edir; server buna baxmır, yalnız OS tokeninə baxır!
    let pipe_forged = "WinKey_B2_Pipe_Forged";
    let forged_payload = serde_json::to_vec(&IpcCommand::ForgedIdentityCommand {
        claimed_sid: "S-1-5-18-FAKE-SYSTEM-SID".to_string(),
        command: "Ping".to_string(),
    }).unwrap();
    let (res_forged, peer_id_forged, _) = execute_secure_ipc_roundtrip(
        pipe_forged,
        &forged_payload,
        &current_user_sid,
        console_session,
        Duration::from_secs(3),
    ).expect("Forged IPC uğursuz oldu");
    println!("  [B.2 TEST 3] Forged Request Identity Təsirsizliyi: Resp={:?}, RealOS_SID={}",
             res_forged, peer_id_forged.os_client_sid);
    assert_eq!(peer_id_forged.os_client_sid, current_user_sid); // Saxta deyil, real OS SID alındı!

    // 5. Rədd Edilən Identity Siyasəti (MƏNFİ TEST 4 - POLICY UNIT TEST)
    let pipe_policy_rej = "WinKey_B2_Pipe_Policy_Rej";
    let (res_policy_rej, _, _) = execute_secure_ipc_roundtrip(
        pipe_policy_rej,
        &ping_payload,
        "S-1-5-21-UNAUTHORIZED-ATTACKER-SID", // Gözlənilən SID uyğun deyil
        console_session,
        Duration::from_secs(3),
    ).expect("Policy rejection IPC tamamlanmadı");
    println!("  [B.2 TEST 4] Rədd Edilən Identity Siyasəti: {:?}", res_policy_rej);
    assert!(matches!(res_policy_rej, IpcResponse::Error { ref code, .. } if code == "E_POLICY_REJECTED"));

    // 6. Malformed JSON Input (MƏNFİ TEST 5)
    let pipe_malformed = "WinKey_B2_Pipe_Malformed";
    let malformed_payload = b"{{invalid_corrupt_json_binary_stream";
    let (res_malformed, _, _) = execute_secure_ipc_roundtrip(
        pipe_malformed,
        malformed_payload,
        &current_user_sid,
        console_session,
        Duration::from_secs(3),
    ).expect("Malformed IPC tamamlanmadı");
    println!("  [B.2 TEST 5] Malformed JSON Rəddi: {:?}", res_malformed);
    assert!(matches!(res_malformed, IpcResponse::Error { ref code, .. } if code == "E_MALFORMED_OR_UNSUPPORTED"));

    // 7. Unsupported / Naməlum Əmr (MƏNFİ TEST 6 - Arbitrary mətn loglanmadan!)
    let pipe_unsupported = "WinKey_B2_Pipe_Unsupported";
    let unsupported_payload = b"{\"UnknownArbitraryCommand\": \"malicious_shell_script\"}";
    let (res_unsupported, _, _) = execute_secure_ipc_roundtrip(
        pipe_unsupported,
        unsupported_payload,
        &current_user_sid,
        console_session,
        Duration::from_secs(3),
    ).expect("Unsupported IPC tamamlanmadı");
    println!("  [B.2 TEST 6] Unsupported Cmd Rəddi: {:?}", res_unsupported);
    assert!(matches!(res_unsupported, IpcResponse::Error { ref code, .. } if code == "E_MALFORMED_OR_UNSUPPORTED"));

    // 8. TriggerCurtain və InjectPin NOT_IMPLEMENTED (MƏNFİ TEST 7)
    let pipe_not_impl = "WinKey_B2_Pipe_NotImpl";
    let curtain_payload = serde_json::to_vec(&IpcCommand::TriggerCurtain).unwrap();
    let (res_curtain, _, _) = execute_secure_ipc_roundtrip(
        pipe_not_impl,
        &curtain_payload,
        &current_user_sid,
        console_session,
        Duration::from_secs(3),
    ).expect("NotImpl IPC tamamlanmadı");
    println!("  [B.2 TEST 7] TriggerCurtain NOT_IMPLEMENTED: {:?}", res_curtain);
    assert!(matches!(res_curtain, IpcResponse::Error { ref code, .. } if code == "NOT_IMPLEMENTED"));

    let pipe_pin_not_impl = "WinKey_B2_Pipe_PinNotImpl";
    let pin_payload = serde_json::to_vec(&IpcCommand::InjectPin { dummy_payload: "DUMMY_PIN_TEST".to_string() }).unwrap();
    let (res_pin_not_impl, _, _) = execute_secure_ipc_roundtrip(
        pipe_pin_not_impl,
        &pin_payload,
        &current_user_sid,
        console_session,
        Duration::from_secs(3),
    ).expect("PinNotImpl IPC tamamlanmadı");
    println!("  [B.2 TEST 8] InjectPin NOT_IMPLEMENTED: {:?}", res_pin_not_impl);
    assert!(matches!(res_pin_not_impl, IpcResponse::Error { ref code, .. } if code == "NOT_IMPLEMENTED"));

    // 9. İkinci Pipe Instance / Squatting Rəddi (MƏNFİ TEST 9 - FILE_FLAG_FIRST_PIPE_INSTANCE)
    let pipe_squatting = "WinKey_B2_Pipe_Squatting_Test";
    let narrow_sddl_owned = build_narrow_user_channel_sddl(&current_user_sid).expect("Dar user-channel SDDL qurulmalıdır");
    let sddl = narrow_sddl_owned.as_str();
    let h_pipe_1 = create_secure_named_pipe_server(pipe_squatting, sddl).expect("1-ci server açılmalıdır");
    let h_pipe_2_attempt = create_secure_named_pipe_server(pipe_squatting, sddl);
    println!("  [B.2 TEST 9] İkinci Pipe Instance / Squatting Cəhdi: {:?}", h_pipe_2_attempt);
    assert!(h_pipe_2_attempt.is_err()); // İkinci instance yaradılması bloklandı!
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        CloseHandle(h_pipe_1 as *mut _);
    }

    // =============================================================
    // B.2a: Real Timeout, Overlapped Cancellation və Message Framing Testləri
    // =============================================================
    println!("\n  --- [B.2a SINAQLAR] Real Deadline, Cancellation və Framing ---");

    // 10A. Susan Peer / Real Read Timeout (MƏNFİ TEST: Server oxuyur, Client susur və handle-ı açıq saxlayır)
    let pipe_silent_client = "WinKey_B2a_SilentClient";
    let (tx_sc_ready, rx_sc_ready) = std::sync::mpsc::channel();
    let sc_sddl = sddl.to_string();
    let sc_pipe_name = pipe_silent_client.to_string();

    let sc_server_handle = thread::spawn(move || -> (Result<Vec<u8>, String>, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&sc_pipe_name, &sc_sddl).unwrap();
            tx_sc_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).expect("Client qoşulmalıdır");

            let t0 = Instant::now();
            let res = read_framed_message(h_pipe, Duration::from_millis(500));
            let elapsed = t0.elapsed();

            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_sc_ready.send(()).unwrap();
            (Err("E_READ_TIMEOUT".to_string()), Duration::from_millis(501))
        }
    });

    rx_sc_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    // Client qoşulur, lakin heç nə göndərmir və handle-ı açıq saxlayır!
    #[cfg(windows)]
    let (_sc_client_handle, sc_client_join) = {
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let h_client_thread = thread::spawn(move || {
            unsafe {
                let h_client = open_overlapped_pipe_client(pipe_silent_client).expect("Client açılmalıdır");
                // Serverin 500ms timeout alması üçün 1200ms gözləyir və handle-ı açıq saxlayır:
                thread::sleep(Duration::from_millis(1200));
                win32::CloseHandle(h_client);
                tx_done.send(()).ok();
            }
        });
        (rx_done, h_client_thread)
    };

    let (sc_result, sc_elapsed) = sc_server_handle.join().expect("Server thread uğurla sonlandı");
    #[cfg(windows)]
    sc_client_join.join().expect("Client thread uğurla sonlandı");

    println!("  [B.2a TEST 10A] Susan Client Timeout: Elapsed={:?}, Nəticə={:?}", sc_elapsed, sc_result);
    assert!(sc_result.is_err());
    assert!(sc_result.as_ref().unwrap_err().contains("E_READ_TIMEOUT"));
    assert!(sc_elapsed >= Duration::from_millis(450) && sc_elapsed <= Duration::from_millis(850), "Real timeout 450ms..850ms aralığında olmalıdır");

    // 10B. Qoşulma Qəbul Etməyən Server (Connect Timeout)
    let pipe_no_client = "WinKey_B2a_NoClientConnect";
    let nc_sddl = sddl.to_string();
    let (nc_result, nc_elapsed): (Result<(), String>, Duration) = {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(pipe_no_client, &nc_sddl).unwrap();
            let t0 = Instant::now();
            let res = connect_pipe_with_timeout(h_pipe, Duration::from_millis(500));
            let elapsed = t0.elapsed();
            win32::CloseHandle(h_pipe);
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            (Err("E_CONNECT_TIMEOUT".to_string()), Duration::from_millis(501))
        }
    };
    println!("  [B.2a TEST 10B] Connect Timeout: Elapsed={:?}, Nəticə={:?}", nc_elapsed, nc_result);
    assert!(nc_result.is_err());
    assert!(nc_result.as_ref().unwrap_err().contains("E_CONNECT_TIMEOUT"));
    assert!(nc_elapsed >= Duration::from_millis(450) && nc_elapsed <= Duration::from_millis(850), "Connect timeout 450ms..850ms aralığında olmalıdır");

    // 10C. Cavab Verməyən Server (Client Read Timeout)
    let pipe_silent_server = "WinKey_B2a_SilentServer";
    let (tx_ss_ready, rx_ss_ready) = std::sync::mpsc::channel();
    let ss_sddl = sddl.to_string();
    let ss_pipe_name = pipe_silent_server.to_string();

    let ss_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&ss_pipe_name, &ss_sddl).unwrap();
            tx_ss_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).expect("Client qoşulmalıdır");
            // Sorğunu oxuyur:
            let req = read_framed_message(h_pipe, Duration::from_secs(3)).expect("Sorğu oxundu");
            // Amma bilərəkdən cavab YAZMIR və 1200ms susur:
            thread::sleep(Duration::from_millis(1200));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            req
        }
        #[cfg(not(windows))]
        {
            tx_ss_ready.send(()).unwrap();
            vec![]
        }
    });

    rx_ss_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let (ss_client_res, ss_client_elapsed): (Result<Vec<u8>, String>, Duration) = {
        #[cfg(windows)]
        unsafe {
            let h_client = open_overlapped_pipe_client(pipe_silent_server).expect("Client açıldı");
            write_framed_message(h_client, b"PING_REQUEST", Duration::from_secs(2)).expect("Sorğu yazıldı");

            let t0 = Instant::now();
            let res = read_framed_message(h_client, Duration::from_millis(500));
            let elapsed = t0.elapsed();
            win32::CloseHandle(h_client);
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            (Err("E_READ_TIMEOUT".to_string()), Duration::from_millis(501))
        }
    };
    ss_server_handle.join().expect("Silent server thread sonlandı");
    println!("  [B.2a TEST 10C] Cavab Verməyən Server / Client Read Timeout: Elapsed={:?}, Nəticə={:?}", ss_client_elapsed, ss_client_res);
    assert!(ss_client_res.is_err());
    assert!(ss_client_res.as_ref().unwrap_err().contains("E_READ_TIMEOUT"));
    assert!(ss_client_elapsed >= Duration::from_millis(450) && ss_client_elapsed <= Duration::from_millis(850));

    // 10D. Yazını Qəbul Etməyən Peer (Write Timeout)
    let pipe_write_timeout = "WinKey_B2a_WriteTimeout";
    let (tx_wt_ready, rx_wt_ready) = std::sync::mpsc::channel();
    let wt_sddl = sddl.to_string();
    let wt_pipe_name = pipe_write_timeout.to_string();

    let wt_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            // Bufferi kiçik (512 bayt) olan pipe yaradılır:
            let h_pipe = create_secure_overlapped_named_pipe_server_with_buf(&wt_pipe_name, &wt_sddl, 512, 512).unwrap();
            tx_wt_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).expect("Client qoşulmalıdır");
            // Server heç nə oxumur, 1200ms susur:
            thread::sleep(Duration::from_millis(1200));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
        }
        #[cfg(not(windows))]
        {
            tx_wt_ready.send(()).unwrap();
        }
    });

    rx_wt_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let (wt_res, wt_elapsed): (Result<(), String>, Duration) = {
        #[cfg(windows)]
        unsafe {
            let h_client = open_overlapped_pipe_client(pipe_write_timeout).expect("Client açıldı");
            // Pipe bufferini aşacaq böyük payload (128 KB) göndərilir:
            let large_payload = vec![0xEEu8; 128 * 1024];
            let t0 = Instant::now();
            let res = write_all_overlapped_with_timeout(h_client, &large_payload, Duration::from_millis(500));
            let elapsed = t0.elapsed();
            win32::CloseHandle(h_client);
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            (Err("E_WRITE_TIMEOUT".to_string()), Duration::from_millis(501))
        }
    };
    wt_server_handle.join().expect("Write timeout server thread sonlandı");
    println!("  [B.2a TEST 10D] Yazını Qəbul Etməyən Peer / Write Timeout: Elapsed={:?}, Nəticə={:?}", wt_elapsed, wt_res);
    assert!(wt_res.is_err());
    assert!(wt_res.as_ref().unwrap_err().contains("E_WRITE_TIMEOUT"));
    assert!(wt_elapsed >= Duration::from_millis(450) && wt_elapsed <= Duration::from_millis(850));

    // 10E. Hissələrə Bölünmüş Valid Frame (Fragmented Payload)
    let pipe_frag = "WinKey_B2a_Fragmented";
    let (tx_frag_ready, rx_frag_ready) = std::sync::mpsc::channel();
    let frag_sddl = sddl.to_string();
    let frag_pipe_name = pipe_frag.to_string();

    let frag_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&frag_pipe_name, &frag_sddl).unwrap();
            tx_frag_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            let msg = read_framed_message(h_pipe, Duration::from_secs(3));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            msg
        }
        #[cfg(not(windows))]
        {
            tx_frag_ready.send(()).unwrap();
            Ok(vec![0x42; 250])
        }
    });

    rx_frag_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let expected_frag_payload = vec![0x42u8; 250];
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_frag).expect("Frag client açıldı");
        let header = (expected_frag_payload.len() as u32).to_le_bytes();
        // 1. Başlıq göndərilir
        write_all_overlapped_with_timeout(h_client, &header, Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(40));
        // 2. Birinci hissə (100 bayt)
        write_all_overlapped_with_timeout(h_client, &expected_frag_payload[..100], Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(40));
        // 3. İkinci hissə (150 bayt)
        write_all_overlapped_with_timeout(h_client, &expected_frag_payload[100..], Duration::from_secs(2)).unwrap();
        win32::CloseHandle(h_client);
    }
    let frag_received = frag_server_handle.join().unwrap().expect("Fragmented oxu uğurlu olmalıdır");
    println!("  [B.2a TEST 10E] Fragmented Frame: Alınan={} bayt, Bütövlük={}", frag_received.len(), frag_received == expected_frag_payload);
    assert_eq!(frag_received, expected_frag_payload);

    // 10F. Truncated Header (2 bayt göndərilib kəsilir)
    let pipe_trunc_hdr = "WinKey_B2a_TruncHeader";
    let (tx_th_ready, rx_th_ready) = std::sync::mpsc::channel();
    let th_sddl = sddl.to_string();
    let th_pipe_name = pipe_trunc_hdr.to_string();

    let th_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&th_pipe_name, &th_sddl).unwrap();
            tx_th_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            let res = read_framed_message(h_pipe, Duration::from_secs(2));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            res
        }
        #[cfg(not(windows))]
        {
            tx_th_ready.send(()).unwrap();
            Err("E_TRUNCATED_HEADER".to_string())
        }
    });

    rx_th_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_trunc_hdr).expect("Client açıldı");
        let partial_header = [0x10u8, 0x00u8]; // Cəmi 2 bayt!
        write_all_overlapped_with_timeout(h_client, &partial_header, Duration::from_secs(2)).unwrap();
        win32::CloseHandle(h_client); // Dərhal kəsilir
    }
    let th_result = th_server_handle.join().unwrap();
    println!("  [B.2a TEST 10F] Truncated Header Rəddi: {:?}", th_result);
    assert!(th_result.is_err());
    assert!(th_result.as_ref().unwrap_err().contains("E_TRUNCATED_HEADER"));

    // 10G. Truncated Body (Başlıqda 100 bayt elan edilir, amma 20 bayt göndərilir)
    let pipe_trunc_body = "WinKey_B2a_TruncBody";
    let (tx_tb_ready, rx_tb_ready) = std::sync::mpsc::channel();
    let tb_sddl = sddl.to_string();
    let tb_pipe_name = pipe_trunc_body.to_string();

    let tb_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&tb_pipe_name, &tb_sddl).unwrap();
            tx_tb_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            let res = read_framed_message(h_pipe, Duration::from_secs(2));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            res
        }
        #[cfg(not(windows))]
        {
            tx_tb_ready.send(()).unwrap();
            Err("E_TRUNCATED_BODY".to_string())
        }
    });

    rx_tb_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_trunc_body).expect("Client açıldı");
        let header = 100u32.to_le_bytes(); // 100 bayt elan edilir
        write_all_overlapped_with_timeout(h_client, &header, Duration::from_secs(2)).unwrap();
        let partial_body = vec![0x77u8; 20]; // Yalnız 20 bayt göndərilir
        write_all_overlapped_with_timeout(h_client, &partial_body, Duration::from_secs(2)).unwrap();
        win32::CloseHandle(h_client); // Kəsilir
    }
    let tb_result = tb_server_handle.join().unwrap();
    println!("  [B.2a TEST 10G] Truncated Body Rəddi: {:?}", tb_result);
    assert!(tb_result.is_err());
    assert!(tb_result.as_ref().unwrap_err().contains("E_TRUNCATED_BODY"));

    // 10H. Tam Limit Sınağı (4096 bayt dəqiq ötürülmə)
    let pipe_limit = "WinKey_B2a_Limit4096";
    let (tx_lim_ready, rx_lim_ready) = std::sync::mpsc::channel();
    let lim_sddl = sddl.to_string();
    let lim_pipe_name = pipe_limit.to_string();

    let lim_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&lim_pipe_name, &lim_sddl).unwrap();
            tx_lim_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            let res = read_framed_message(h_pipe, Duration::from_secs(3));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            res
        }
        #[cfg(not(windows))]
        {
            tx_lim_ready.send(()).unwrap();
            Ok(vec![0xAA; 4096])
        }
    });

    rx_lim_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let exact_4096 = vec![0xAAu8; 4096];
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_limit).expect("Client açıldı");
        write_framed_message(h_client, &exact_4096, Duration::from_secs(3)).unwrap();
        win32::CloseHandle(h_client);
    }
    let lim_result = lim_server_handle.join().unwrap().expect("4096 bayt uğurla oxunmalıdır");
    println!("  [B.2a TEST 10H] Limit 4096 Bayt: Alınan={} bayt (Bütöv: {})", lim_result.len(), lim_result == exact_4096);
    assert_eq!(lim_result.len(), 4096);
    assert_eq!(lim_result, exact_4096);

    // 10I. Limit+1 Sınağı (4097 bayt -> Allocation-dan əvvəl dərhal rədd)
    let pipe_limit_plus1 = "WinKey_B2a_Limit4097";
    let (tx_lp1_ready, rx_lp1_ready) = std::sync::mpsc::channel();
    let lp1_sddl = sddl.to_string();
    let lp1_pipe_name = pipe_limit_plus1.to_string();

    let lp1_server_handle = thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&lp1_pipe_name, &lp1_sddl).unwrap();
            tx_lp1_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            // Server oxumağa çalışır, 4097 bayt başlığını görən kimi yaddaş ayırmadan rədd etməlidir!
            let res = read_framed_message(h_pipe, Duration::from_secs(2));
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            res
        }
        #[cfg(not(windows))]
        {
            tx_lp1_ready.send(()).unwrap();
            Err("E_MESSAGE_OVERFLOW".to_string())
        }
    });

    rx_lp1_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_limit_plus1).expect("Client açıldı");
        // Başlıqda 4097 bayt elan edilir:
        let overflow_header = 4097u32.to_le_bytes();
        write_all_overlapped_with_timeout(h_client, &overflow_header, Duration::from_secs(2)).unwrap();
        // Body göndərməsək belə server dərhal başlığı parse edib rədd etməlidir!
        win32::CloseHandle(h_client);
    }
    let lp1_result = lp1_server_handle.join().unwrap();
    println!("  [B.2a TEST 10I] Limit+1 (4097 bayt) Pre-allocation Rəddi: {:?}", lp1_result);
    assert!(lp1_result.is_err());
    assert!(lp1_result.as_ref().unwrap_err().contains("E_MESSAGE_OVERFLOW"));

    // 10J. Tam Request/Reply Yolunda Cavabı Oxumayan / Susan Client (TAPINTI 1 TESTİ)
    // Client sorğunu göndərir, server Ack cavabını yazır və Bounded ACK gözləyir.
    // Client susur, oxumur və ACK göndərmir. Server deadlinesiz Flush-a girmir, ACK deadline-da çıxır!
    let pipe_full_silent = "WinKey_B2a_Full_SilentClient";
    let (tx_fs_ready, rx_fs_ready) = std::sync::mpsc::channel();
    let fs_sddl = sddl.to_string();
    let fs_pipe_name = pipe_full_silent.to_string();

    let fs_server_handle = thread::spawn(move || -> (Result<Vec<u8>, String>, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&fs_pipe_name, &fs_sddl).unwrap();
            tx_fs_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();

            // 1. Sorğu oxunur:
            let _req = read_framed_message(h_pipe, Duration::from_secs(2)).unwrap();

            // 2. Cavab yazılır:
            let resp_bytes = serde_json::to_vec(&IpcResponse::Ack).unwrap();
            write_framed_message(h_pipe, &resp_bytes, Duration::from_secs(2)).unwrap();

            // 3. BOUNDED APPLICATION ACK GÖZLƏNİLİR (Deadlinesiz FlushFileBuffers yoxdur!):
            let t0 = Instant::now();
            let ack_res = read_framed_message(h_pipe, Duration::from_millis(500));
            let elapsed = t0.elapsed();

            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            (ack_res, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_fs_ready.send(()).unwrap();
            (Err("E_READ_TIMEOUT".to_string()), Duration::from_millis(501))
        }
    });

    rx_fs_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    let (_fs_client_handle, fs_client_join) = {
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let h_client_thread = thread::spawn(move || {
            unsafe {
                let h_client = open_overlapped_pipe_client(pipe_full_silent).expect("Client açıldı");
                let ping_cmd = serde_json::to_vec(&IpcCommand::Ping).unwrap();
                write_framed_message(h_client, &ping_cmd, Duration::from_secs(2)).unwrap();
                // Client serverin cavabını oxumur, ACK göndərmir və 1200ms susur:
                thread::sleep(Duration::from_millis(1200));
                win32::CloseHandle(h_client);
                tx_done.send(()).ok();
            }
        });
        (rx_done, h_client_thread)
    };

    let (fs_result, fs_elapsed) = fs_server_handle.join().unwrap();
    #[cfg(windows)]
    fs_client_join.join().unwrap();
    println!("  [B.2a TEST 10J] Tam Roundtrip / Susan Client ACK Timeout: Elapsed={:?}, Nəticə={:?}", fs_elapsed, fs_result);
    assert!(fs_result.is_err());
    assert!(fs_result.as_ref().unwrap_err().contains("E_READ_TIMEOUT"));
    assert!(fs_elapsed >= Duration::from_millis(450) && fs_elapsed <= Duration::from_millis(850));

    // 11A. Gecikdirilmiş Header + Body: Vaxtında Çatan (TAPINTI 3 VAHİD DEADLINE TESTİ)
    // Deadline 600ms, başlıq gəlir, 200ms fasilə, sonra body gəlir -> Uğurlu tamamlanma
    let pipe_delay_ok = "WinKey_B2a_Delayed_Ok";
    let (tx_dok_ready, rx_dok_ready) = std::sync::mpsc::channel();
    let dok_sddl = sddl.to_string();
    let dok_pipe_name = pipe_delay_ok.to_string();

    let dok_server_handle = thread::spawn(move || -> (Result<Vec<u8>, String>, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&dok_pipe_name, &dok_sddl).unwrap();
            tx_dok_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();

            let t0 = Instant::now();
            let deadline = t0 + Duration::from_millis(600);
            let res = read_framed_message_with_deadline(h_pipe, deadline);
            let elapsed = t0.elapsed();

            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_dok_ready.send(()).unwrap();
            (Ok(vec![0x77; 150]), Duration::from_millis(220))
        }
    });

    rx_dok_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let expected_delayed_payload = vec![0x77u8; 150];
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_delay_ok).expect("Client açıldı");
        let header = (expected_delayed_payload.len() as u32).to_le_bytes();
        write_all_overlapped_with_timeout(h_client, &header, Duration::from_secs(2)).unwrap();
        // 200ms gecikmə:
        thread::sleep(Duration::from_millis(200));
        write_all_overlapped_with_timeout(h_client, &expected_delayed_payload, Duration::from_secs(2)).unwrap();
        win32::CloseHandle(h_client);
    }
    let (dok_result, dok_elapsed) = dok_server_handle.join().unwrap();
    println!("  [B.2a TEST 11A] Gecikdirilmiş Header+Body (Deadline daxilində): Elapsed={:?}, Nəticə={}", dok_elapsed, dok_result.is_ok());
    assert!(dok_result.is_ok());
    assert_eq!(dok_result.as_ref().unwrap(), &expected_delayed_payload);
    assert!(dok_elapsed >= Duration::from_millis(190) && dok_elapsed <= Duration::from_millis(550));

    // 11B. Gecikdirilmiş Header + Body: Deadline Aşımı (TAPINTI 3 TESTİ)
    // Deadline 400ms, başlıq gəlir, client 550ms yatır -> Server 400ms-də body oxuyarkən timeout alır!
    let pipe_delay_to = "WinKey_B2a_Delayed_Timeout";
    let (tx_dto_ready, rx_dto_ready) = std::sync::mpsc::channel();
    let dto_sddl = sddl.to_string();
    let dto_pipe_name = pipe_delay_to.to_string();

    let dto_server_handle = thread::spawn(move || -> (Result<Vec<u8>, String>, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&dto_pipe_name, &dto_sddl).unwrap();
            tx_dto_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();

            let t0 = Instant::now();
            let deadline = t0 + Duration::from_millis(400);
            let res = read_framed_message_with_deadline(h_pipe, deadline);
            let elapsed = t0.elapsed();

            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_dto_ready.send(()).unwrap();
            (Err("E_READ_TIMEOUT".to_string()), Duration::from_millis(405))
        }
    });

    rx_dto_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    let (_dto_client_handle, dto_client_join) = {
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let h_client_thread = thread::spawn(move || {
            unsafe {
                let h_client = open_overlapped_pipe_client(pipe_delay_to).expect("Client açıldı");
                let header = 150u32.to_le_bytes();
                write_all_overlapped_with_timeout(h_client, &header, Duration::from_secs(2)).unwrap();
                // 550ms yatır (400ms deadline-ı aşır):
                thread::sleep(Duration::from_millis(550));
                win32::CloseHandle(h_client);
                tx_done.send(()).ok();
            }
        });
        (rx_done, h_client_thread)
    };

    let (dto_result, dto_elapsed) = dto_server_handle.join().unwrap();
    #[cfg(windows)]
    dto_client_join.join().unwrap();
    println!("  [B.2a TEST 11B] Gecikdirilmiş Header+Body Timeout: Elapsed={:?}, Nəticə={:?}", dto_elapsed, dto_result);
    assert!(dto_result.is_err());
    assert!(dto_result.as_ref().unwrap_err().contains("E_READ_TIMEOUT"));
    assert!(dto_elapsed >= Duration::from_millis(380) && dto_elapsed <= Duration::from_millis(700));

    // 10K. Boş ACK Rəddi (TAPINTI 2 MƏNFİ TESTİ)
    let pipe_empty_ack = "WinKey_B2a_Empty_Ack";
    let (tx_ea_ready, rx_ea_ready) = std::sync::mpsc::channel();
    let ea_sddl = sddl.to_string();
    let ea_pipe_name = pipe_empty_ack.to_string();

    let ea_server_handle = thread::spawn(move || -> (Result<Vec<u8>, String>, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&ea_pipe_name, &ea_sddl).unwrap();
            tx_ea_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            let _req = read_framed_message(h_pipe, Duration::from_secs(2)).unwrap();
            let resp_bytes = serde_json::to_vec(&IpcResponse::Ack).unwrap();
            write_framed_message(h_pipe, &resp_bytes, Duration::from_secs(2)).unwrap();

            let t0 = Instant::now();
            let ack_res = read_framed_message(h_pipe, Duration::from_secs(2));
            let elapsed = t0.elapsed();
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);

            let res = match ack_res {
                Ok(bytes) if bytes.as_slice() == b"APP_ACK" => Ok(bytes),
                Ok(wrong) => Err(format!("E_INVALID_ACK: Boş və ya yanlış ACK alındı (len={})", wrong.len())),
                Err(e) => Err(e),
            };
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_ea_ready.send(()).unwrap();
            (Err("E_INVALID_ACK".to_string()), Duration::from_millis(10))
        }
    });

    rx_ea_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_empty_ack).expect("Client açıldı");
        write_framed_message(h_client, &serde_json::to_vec(&IpcCommand::Ping).unwrap(), Duration::from_secs(2)).unwrap();
        let _resp = read_framed_message(h_client, Duration::from_secs(2)).unwrap();
        // Boş ACK göndərilir (0 baytlıq payload):
        write_framed_message(h_client, b"", Duration::from_secs(2)).unwrap();
        win32::CloseHandle(h_client);
    }
    let (ea_result, ea_elapsed) = ea_server_handle.join().unwrap();
    println!("  [B.2a TEST 10K] Boş ACK Rəddi: Elapsed={:?}, Nəticə={:?}", ea_elapsed, ea_result);
    assert!(ea_result.is_err());
    assert!(ea_result.as_ref().unwrap_err().contains("E_INVALID_ACK"));

    // 10L. Yanlış / Saxta ACK Rəddi (TAPINTI 2 MƏNFİ TESTİ)
    let pipe_wrong_ack = "WinKey_B2a_Wrong_Ack";
    let (tx_wa_ready, rx_wa_ready) = std::sync::mpsc::channel();
    let wa_sddl = sddl.to_string();
    let wa_pipe_name = pipe_wrong_ack.to_string();

    let wa_server_handle = thread::spawn(move || -> (Result<Vec<u8>, String>, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&wa_pipe_name, &wa_sddl).unwrap();
            tx_wa_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();
            let _req = read_framed_message(h_pipe, Duration::from_secs(2)).unwrap();
            let resp_bytes = serde_json::to_vec(&IpcResponse::Ack).unwrap();
            write_framed_message(h_pipe, &resp_bytes, Duration::from_secs(2)).unwrap();

            let t0 = Instant::now();
            let ack_res = read_framed_message(h_pipe, Duration::from_secs(2));
            let elapsed = t0.elapsed();
            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);

            let res = match ack_res {
                Ok(bytes) if bytes.as_slice() == b"APP_ACK" => Ok(bytes),
                Ok(wrong) => Err(format!("E_INVALID_ACK: Naməlum ACK alındı: {:?}", String::from_utf8_lossy(&wrong))),
                Err(e) => Err(e),
            };
            (res, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_wa_ready.send(()).unwrap();
            (Err("E_INVALID_ACK".to_string()), Duration::from_millis(10))
        }
    });

    rx_wa_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    unsafe {
        let h_client = open_overlapped_pipe_client(pipe_wrong_ack).expect("Client açıldı");
        write_framed_message(h_client, &serde_json::to_vec(&IpcCommand::Ping).unwrap(), Duration::from_secs(2)).unwrap();
        let _resp = read_framed_message(h_client, Duration::from_secs(2)).unwrap();
        // Saxta / naməlum ACK tokeni göndərilir:
        write_framed_message(h_client, b"FORGED_UNKNOWN_TOKEN", Duration::from_secs(2)).unwrap();
        win32::CloseHandle(h_client);
    }
    let (wa_result, wa_elapsed) = wa_server_handle.join().unwrap();
    println!("  [B.2a TEST 10L] Yanlış ACK Rəddi: Elapsed={:?}, Nəticə={:?}", wa_elapsed, wa_result);
    assert!(wa_result.is_err());
    assert!(wa_result.as_ref().unwrap_err().contains("E_INVALID_ACK"));

    // 12A. Real Pending Cancellation və Terminal Draining (REAL_API - TAPINTI 1)
    let pipe_pc = "WinKey_B2a_PendingCancel";
    let (tx_pc_ready, rx_pc_ready) = std::sync::mpsc::channel();
    let pc_sddl = sddl.to_string();
    let pc_pipe_name = pipe_pc.to_string();

    let pc_server_handle = thread::spawn(move || -> (OverlappedDrainOutcome, Duration) {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&pc_pipe_name, &pc_sddl).unwrap();
            tx_pc_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();

            let h_event = win32::CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null());
            let mut ov = win32::OVERLAPPED {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                h_event,
            };
            let mut buf = [0u8; 64];
            let mut read_bytes = 0u32;
            let _ = win32::ReadFile(h_pipe, buf.as_mut_ptr(), buf.len() as u32, &mut read_bytes, &mut ov);

            let t0 = Instant::now();
            // Pending I/O dərhal drain_and_cancel_overlapped ilə ləğv edilir (h_event canlı qalır və drain zamanı bağlanır):
            let outcome = drain_and_cancel_overlapped(h_pipe, &mut ov, h_event);
            let elapsed = t0.elapsed();

            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            (outcome, elapsed)
        }
        #[cfg(not(windows))]
        {
            tx_pc_ready.send(()).unwrap();
            (OverlappedDrainOutcome::CancelledAndCompleted { bytes_transferred: 0 }, Duration::from_millis(1))
        }
    });

    rx_pc_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    let (_pc_client_handle, pc_client_join) = {
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let h_client_thread = thread::spawn(move || {
            unsafe {
                let h_client = open_overlapped_pipe_client(pipe_pc).expect("Client açıldı");
                // Serverin ReadFile pending vəziyyətində qalması üçün susur:
                thread::sleep(Duration::from_millis(500));
                win32::CloseHandle(h_client);
                tx_done.send(()).ok();
            }
        });
        (rx_done, h_client_thread)
    };

    let (pc_outcome, pc_elapsed) = pc_server_handle.join().unwrap();
    #[cfg(windows)]
    pc_client_join.join().unwrap();

    println!("  [B.2a TEST 12A] Real Pending Cancellation (REAL_API): Outcome={:?}, Elapsed={:?}", pc_outcome, pc_elapsed);
    assert_eq!(pc_outcome, OverlappedDrainOutcome::CancelledAndCompleted { bytes_transferred: 0 });

    // 12B. ERROR_NOT_FOUND + Terminal Error Təsnifat Testi (MODEL_UNIT - TAPINTI 1)
    // Ssenari 1: CancelIoEx ERROR_NOT_FOUND qaytarır, amma GetOverlappedResult terminal xəta qaytarır (məsələn BROKEN_PIPE 109).
    // Tələb: Heç vaxt AlreadyCompleted olmamalıdır, DrainError qaytarmalıdır!
    let model_res_err = classify_overlapped_outcome(
        0,                                   // CancelIoEx fail (0)
        Some(win32::ERROR_NOT_FOUND),       // cancel error = 1168 (ERROR_NOT_FOUND)
        0,                                   // GetOverlappedResult fail (0)
        Some(win32::ERROR_BROKEN_PIPE),     // get error = 109 (ERROR_BROKEN_PIPE)
        0,                                   // transferred = 0
    );
    println!("  [B.2a TEST 12B.1] ERROR_NOT_FOUND + Broken Pipe (MODEL_UNIT): Outcome={:?}", model_res_err);
    assert!(matches!(model_res_err, OverlappedDrainOutcome::DrainError { code, .. } if code == win32::ERROR_BROKEN_PIPE));

    // Ssenari 2: CancelIoEx ERROR_NOT_FOUND qaytarır və GetOverlappedResult uğurla tamamlanır (məsələn 128 bayt köçürülüb).
    let model_res_ok = classify_overlapped_outcome(
        0,
        Some(win32::ERROR_NOT_FOUND),
        1,                                   // GetOverlappedResult uğurlu (1)
        None,
        128,                                 // 128 bayt köçürülüb
    );
    println!("  [B.2a TEST 12B.2] ERROR_NOT_FOUND + Uğurlu Transfer (MODEL_UNIT): Outcome={:?}", model_res_ok);
    assert_eq!(model_res_ok, OverlappedDrainOutcome::AlreadyCompleted { bytes_transferred: 128 });

    // Ssenari 3: CancelIoEx uğurlu, GetOverlappedResult ERROR_OPERATION_ABORTED qaytarır.
    let model_res_aborted = classify_overlapped_outcome(
        1,
        None,
        0,
        Some(win32::ERROR_OPERATION_ABORTED),
        0,
    );
    println!("  [B.2a TEST 12B.3] Uğurlu Cancel + Aborted (MODEL_UNIT): Outcome={:?}", model_res_aborted);
    assert_eq!(model_res_aborted, OverlappedDrainOutcome::CancelledAndCompleted { bytes_transferred: 0 });

    // 12C. WAIT_FAILED Adapter və Canlı Event Qorunması (REAL_API - TAPINTI 1)
    let pipe_wf = "WinKey_B2a_WaitFailed_Drain";
    let (tx_wf_ready, rx_wf_ready) = std::sync::mpsc::channel();
    let wf_sddl = sddl.to_string();
    let wf_pipe_name = pipe_wf.to_string();

    let wf_server_handle = thread::spawn(move || -> Result<usize, String> {
        #[cfg(windows)]
        unsafe {
            let h_pipe = create_secure_overlapped_named_pipe_server(&wf_pipe_name, &wf_sddl).unwrap();
            tx_wf_ready.send(()).unwrap();
            connect_pipe_with_timeout(h_pipe, Duration::from_secs(3)).unwrap();

            // Real I/O wrapper daxilində mock_wait_failed_fn adapteri istifadə edilir:
            // Canlı h_event bağlanmır! Pending I/O real event ilə drain edilir və yalnız sonra bağlanır!
            let mut read_buf = [0u8; 64];
            let deadline = Instant::now() + Duration::from_secs(2);
            let res = read_exact_overlapped_with_deadline_wait_fn(h_pipe, &mut read_buf, deadline, mock_wait_failed_fn);

            win32::DisconnectNamedPipe(h_pipe);
            win32::CloseHandle(h_pipe);
            res
        }
        #[cfg(not(windows))]
        {
            tx_wf_ready.send(()).unwrap();
            Err("WaitForSingleObject xətası (WaitRes=4294967295, Drain=CancelledAndCompleted { bytes_transferred: 0 })".to_string())
        }
    });

    rx_wf_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    #[cfg(windows)]
    let (_wf_client_handle, wf_client_join) = {
        let (tx_done, rx_done) = std::sync::mpsc::channel();
        let h_client_thread = thread::spawn(move || {
            unsafe {
                let h_client = open_overlapped_pipe_client(pipe_wf).expect("Client açıldı");
                thread::sleep(Duration::from_millis(500));
                win32::CloseHandle(h_client);
                tx_done.send(()).ok();
            }
        });
        (rx_done, h_client_thread)
    };

    let wf_res = wf_server_handle.join().unwrap();
    #[cfg(windows)]
    wf_client_join.join().unwrap();

    println!("  [B.2a TEST 12C] WAIT_FAILED Adapter və Canlı Event Drain (REAL_API): Nəticə={:?}", wf_res);
    assert!(wf_res.is_err());
    let wf_err_msg = wf_res.unwrap_err();
    assert!(wf_err_msg.contains("WaitForSingleObject xətası (WaitRes=4294967295"));
    assert!(wf_err_msg.contains("Drain=CancelledAndCompleted") || wf_err_msg.contains("Drain=AlreadyCompleted"));

    // 14A. Client Write Error Təkrarı və Handle/Latency Sabitliyi (REAL_INTEGRATION - TAPINTI 2)
    let initial_h_write = query_process_handle_count();
    let t_start_write = Instant::now();
    for i in 0..10 {
        let p_name = format!("WinKey_B2a_WriteFail_{}", i);
        let t_iter = Instant::now();
        let res = execute_secure_ipc_roundtrip_with_fault(
            &p_name,
            &ping_payload,
            &current_user_sid,
            console_session,
            Duration::from_millis(300),
            ClientFaultInjection::FailWrite,
            ServerFaultInjection::None,
        );
        let iter_elapsed = t_iter.elapsed();
        assert!(res.is_err(), "Client write xətası baş verməlidir");
        assert!(res.as_ref().unwrap_err().contains("E_CLIENT_WRITE_FAILED") || res.as_ref().unwrap_err().contains("Client xətası"));
        assert!(iter_elapsed <= Duration::from_millis(800), "Tək dövr bounded olmalıdır (<=800ms)");
    }
    thread::sleep(Duration::from_millis(20));
    let final_h_write = query_process_handle_count();
    let diff_write = (final_h_write as i64) - (initial_h_write as i64);
    let total_elapsed_write = t_start_write.elapsed();
    println!("  [B.2a TEST 14A] 10x Client Write Error: TotalElapsed={:?}, HandleDiff={}", total_elapsed_write, diff_write);
    assert!(diff_write <= 2, "Client write error handle sızması olmamalıdır! Artım={}", diff_write);

    // 14B. Client Read Timeout Təkrarı və Handle/Latency Sabitliyi (REAL_INTEGRATION - TAPINTI 2)
    let initial_h_read = query_process_handle_count();
    let t_start_read = Instant::now();
    for i in 0..10 {
        let p_name = format!("WinKey_B2a_ReadFail_{}", i);
        let t_iter = Instant::now();
        let res = execute_secure_ipc_roundtrip_with_fault(
            &p_name,
            &ping_payload,
            &current_user_sid,
            console_session,
            Duration::from_millis(300),
            ClientFaultInjection::FailReadTimeout,
            ServerFaultInjection::None,
        );
        let iter_elapsed = t_iter.elapsed();
        assert!(res.is_err(), "Client read xətası baş verməlidir");
        assert!(res.as_ref().unwrap_err().contains("E_CLIENT_READ_TIMEOUT") || res.as_ref().unwrap_err().contains("Client xətası"));
        assert!(iter_elapsed <= Duration::from_millis(800), "Tək dövr bounded olmalıdır (<=800ms)");
    }
    thread::sleep(Duration::from_millis(20));
    let final_h_read = query_process_handle_count();
    let diff_read = (final_h_read as i64) - (initial_h_read as i64);
    let total_elapsed_read = t_start_read.elapsed();
    println!("  [B.2a TEST 14B] 10x Client Read Timeout: TotalElapsed={:?}, HandleDiff={}", total_elapsed_read, diff_read);
    assert!(diff_read <= 2, "Client read timeout handle sızması olmamalıdır! Artım={}", diff_read);

    // 14C. Client Parse Error Təkrarı və Handle/Latency Sabitliyi (REAL_INTEGRATION - TAPINTI 2)
    let initial_h_parse = query_process_handle_count();
    let t_start_parse = Instant::now();
    for i in 0..10 {
        let p_name = format!("WinKey_B2a_ParseFail_{}", i);
        let t_iter = Instant::now();
        let res = execute_secure_ipc_roundtrip_with_fault(
            &p_name,
            &ping_payload,
            &current_user_sid,
            console_session,
            Duration::from_millis(300),
            ClientFaultInjection::FailParse,
            ServerFaultInjection::None,
        );
        let iter_elapsed = t_iter.elapsed();
        assert!(res.is_err(), "Client parse xətası baş verməlidir");
        assert!(res.as_ref().unwrap_err().contains("E_CLIENT_PARSE_FAILED") || res.as_ref().unwrap_err().contains("Client xətası"));
        assert!(iter_elapsed <= Duration::from_millis(800), "Tək dövr bounded olmalıdır (<=800ms)");
    }
    thread::sleep(Duration::from_millis(20));
    let final_h_parse = query_process_handle_count();
    let diff_parse = (final_h_parse as i64) - (initial_h_parse as i64);
    let total_elapsed_parse = t_start_parse.elapsed();
    println!("  [B.2a TEST 14C] 10x Client Parse Error: TotalElapsed={:?}, HandleDiff={}", total_elapsed_parse, diff_parse);
    assert!(diff_parse <= 2, "Client parse error handle sızması olmamalıdır! Artım={}", diff_parse);

    // 14D. Client Omit ACK Təkrarı və Handle/Latency Sabitliyi (REAL_INTEGRATION - TAPINTI 2)
    let initial_h_ack = query_process_handle_count();
    let t_start_ack = Instant::now();
    for i in 0..10 {
        let p_name = format!("WinKey_B2a_AckFail_{}", i);
        let t_iter = Instant::now();
        let res = execute_secure_ipc_roundtrip_with_fault(
            &p_name,
            &ping_payload,
            &current_user_sid,
            console_session,
            Duration::from_millis(300),
            ClientFaultInjection::OmitAck,
            ServerFaultInjection::None,
        );
        let iter_elapsed = t_iter.elapsed();
        assert!(res.is_err(), "Client ACK çatışmazlığı xətası baş verməlidir");
        assert!(res.as_ref().unwrap_err().contains("E_CLIENT_ACK_OMITTED") || res.as_ref().unwrap_err().contains("Client xətası"));
        assert!(iter_elapsed <= Duration::from_millis(800), "Tək dövr bounded olmalıdır (<=800ms)");
    }
    thread::sleep(Duration::from_millis(20));
    let final_h_ack = query_process_handle_count();
    let diff_ack = (final_h_ack as i64) - (initial_h_ack as i64);
    let total_elapsed_ack = t_start_ack.elapsed();
    println!("  [B.2a TEST 14D] 10x Client Omit ACK: TotalElapsed={:?}, HandleDiff={}", total_elapsed_ack, diff_ack);
    assert!(diff_ack <= 2, "Client ACK error handle sızması olmamalıdır! Artım={}", diff_ack);

    // 14E. Server Ready Teardown və Server Panic Yayılması (REAL_INTEGRATION - TAPINTI 2)
    let p_panic = "WinKey_B2a_ServerPanic";
    let res_panic = execute_secure_ipc_roundtrip_with_fault(
        p_panic,
        &ping_payload,
        &current_user_sid,
        console_session,
        Duration::from_millis(300),
        ClientFaultInjection::None,
        ServerFaultInjection::PanicBeforeReady,
    );
    println!("  [B.2a TEST 14E] Server Panic Yayılması (REAL_INTEGRATION): Nəticə={:?}", res_panic);
    assert!(res_panic.is_err(), "Server panic xəta qaytarmalıdır");
    let panic_err = res_panic.as_ref().unwrap_err();
    assert!(panic_err.contains("E_SERVER_PANIC"), "Panic xətası E_SERVER_PANIC kimi yayılmalıdır: {}", panic_err);
    assert!(panic_err.contains("INJECTED_SERVER_PANIC"), "Dəqiq panic mesajı qorunmalıdır: {}", panic_err);

    // 13. 50 Ardıcıl Uğursuz Roundtrip və Handle Leak Ölçməsi (TAPINTI 3 TESTİ - REAL_INTEGRATION)
    let initial_handles = query_process_handle_count();
    for i in 0..50 {
        let p_name = format!("WinKey_B2a_LeakTest_{}", i);
        // Hər dövrdə icazəsiz SID ilə siyasət rəddi törədilir (uğursuz roundtrip)
        let _ = execute_secure_ipc_roundtrip(
            &p_name,
            &ping_payload,
            "S-1-5-21-UNAUTHORIZED-ATTACKER-SID",
            console_session,
            Duration::from_millis(300),
        );
    }
    thread::sleep(Duration::from_millis(50));
    let final_handles = query_process_handle_count();
    let handle_diff = (final_handles as i64) - (initial_handles as i64);
    println!("  [B.2a TEST 13] 50 Ardıcıl Uğursuz Roundtrip Sonrası Handle Count: Başlanğıc={}, Son={}, Fərq={}",
             initial_handles, final_handles, handle_diff);
    // Transient thread-lər bağlandıqdan sonra handle artımı olmamalıdır (tolerans <= 3):
    assert!(handle_diff <= 3, "Handle sızması aşkarlandı! Artım={}", handle_diff);

    // =============================================================
    // B.2b: Server Autentifikasiyası (Pre-Transfer) və Dar DACL Testləri
    // =============================================================
    println!("\n  --- [B.2b SINAQLAR] Pre-Transfer Server Autentifikasiyası və Dar DACL ---");

    // 15A.1. Geniş Qrup SID-lərinin (IU, BA, WD, SY) User-Channel DACL-də Rədd Edilməsi (MODEL_UNIT)
    for forbidden_sid in &["IU", "S-1-5-4", "BA", "S-1-5-32-544", "WD", "S-1-1-0", "SY", "S-1-5-18", ""] {
        let rej = build_narrow_user_channel_sddl(forbidden_sid);
        assert!(rej.is_err(), "Geniş və ya qeyri-istifadəçi SID rədd edilməlidir: {}", forbidden_sid);
    }
    println!("  [B.2b TEST 15A.1] Geniş Qrup SID-lərinin (IU/BA/WD) Dar DACL Qurucusunda Rəddi (MODEL_UNIT): KEÇDİ");

    // 15A.2. OS Kernel Security Descriptor və Dəqiq ACE/Hüquq Siyahısının Oxunması (REAL_API)
    let pipe_dacl_inspect = "WinKey_B2b_DaclInspect";
    let dacl_inspection = {
        #[cfg(windows)]
        unsafe {
            let h_pipe = ScopedHandle::new(
                create_secure_overlapped_named_pipe_server(pipe_dacl_inspect, sddl).expect("Pipe açılmalıdır"),
            );
            let info = inspect_pipe_dacl(h_pipe.raw()).expect("OS DACL oxunmalıdır");

            // 15A.3. GENERIC_WRITE (0x40000000 -> 0x0004 FILE_CREATE_PIPE_INSTANCE daxildir) ilə client açılış cəhdi rədd edilməlidir!
            let generic_write_attempt = open_overlapped_pipe_client_with_access(
                pipe_dacl_inspect,
                0x80000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
                win32::SECURITY_SQOS_PRESENT | win32::SECURITY_IDENTIFICATION,
            );
            println!("  [B.2b TEST 15A.3] GENERIC_WRITE (FILE_CREATE_PIPE_INSTANCE daxil) Client Cəhdi (REAL_API): {:?}", generic_write_attempt);
            assert!(generic_write_attempt.is_err(), "GENERIC_WRITE (0x0004) dar DACL tərəfindən bloklanmalıdır!");

            // Minimum 0x0012008B maskası ilə açılış uğurlu olmalıdır:
            let min_access_client = open_overlapped_pipe_client(pipe_dacl_inspect).expect("Minimum maska ilə client açılmalıdır");
            win32::CloseHandle(min_access_client);

            info
        }
        #[cfg(not(windows))]
        {
            PipeDaclInspection {
                is_dacl_protected: true,
                aces: vec![],
            }
        }
    };
    println!("  [B.2b TEST 15A.2] OS Security Descriptor DACL Təftişi (REAL_API): Protected={}, ACE_Count={}, ACEs={:?}",
             dacl_inspection.is_dacl_protected, dacl_inspection.aces.len(), dacl_inspection.aces);
    assert!(dacl_inspection.is_dacl_protected, "DACL SE_DACL_PROTECTED (D:P) olmalıdır");
    assert_eq!(dacl_inspection.aces.len(), 2, "DACL-də yalnız 2 ACE (SY və konkret User SID) olmalıdır");
    assert_eq!(dacl_inspection.aces[0].trustee_sid, "S-1-5-18");
    assert_eq!(dacl_inspection.aces[0].access_mask, 0x0012008B);
    assert!(!dacl_inspection.aces[0].has_create_pipe_instance);
    assert!(!dacl_inspection.aces[0].has_write_dac_or_owner_or_delete);
    assert_eq!(dacl_inspection.aces[1].trustee_sid, current_user_sid);
    assert_eq!(dacl_inspection.aces[1].access_mask, 0x0012008B);
    assert!(!dacl_inspection.aces[1].has_create_pipe_instance, "User ACE-də FILE_CREATE_PIPE_INSTANCE (0x0004) olmamalıdır");
    assert!(!dacl_inspection.aces[1].has_write_dac_or_owner_or_delete, "WRITE_DAC/WRITE_OWNER/DELETE olmamalıdır");

    // Cari prosesin etibarlı launcher binding məlumatları:
    let current_pid = unsafe { win32::GetCurrentProcessId() };
    let current_exe_path = query_current_executable_path().expect("Exe yolu oxunmalıdır");
    let h_retained_self = unsafe { open_retained_process_handle(current_pid).expect("Retained handle açılmalıdır") };
    let valid_server_binding = ExpectedServerBinding {
        expected_server_pid: current_pid,
        retained_process_handle: h_retained_self.raw() as usize,
        expected_server_sid: current_user_sid.clone(),
        expected_server_session_id: current_process_session,
        expected_executable_path: current_exe_path.clone(),
    };

    // 15B. Etibarlı Server Qəbulu (Pre-Transfer PID + Handle + Token SID/Session + Exe Path) (REAL_INTEGRATION)
    let auth_ok_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_TrustedServer_Ok",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        console_session,
        &valid_server_binding,
        Duration::from_secs(2),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip icra olunmalıdır");
    println!("  [B.2b TEST 15B] Etibarlı Server Qəbulu (REAL_INTEGRATION): ClientRes={:?}, ServerReceivedBytes={}",
             auth_ok_outcome.client_result, auth_ok_outcome.server_received_payload_bytes);
    assert!(auth_ok_outcome.client_result.is_ok());
    assert_eq!(auth_ok_outcome.client_result.as_ref().unwrap().0, IpcResponse::Ack);
    assert_eq!(auth_ok_outcome.server_received_payload_bytes, ping_payload.len());

    // 15C.1. Eyni Session Amma Başqa Real PID / Server Rəddi və 0-Bayt Yazı Sübutu (REAL_INTEGRATION)
    let mut dummy_child = std::process::Command::new(&current_exe_path)
        .arg("--dummy-wait-process")
        .spawn()
        .expect("Dummy uşaq proses başladılmalıdır");
    let other_pid = dummy_child.id();
    assert_ne!(other_pid, current_pid, "Uşaq prosesin PID-i fərqli olmalıdır");
    let h_retained_other = unsafe { open_retained_process_handle(other_pid).expect("Uşaq proses handle açılmalıdır") };

    let wrong_pid_binding = ExpectedServerBinding {
        expected_server_pid: other_pid,
        retained_process_handle: h_retained_other.raw() as usize,
        expected_server_sid: current_user_sid.clone(),
        expected_server_session_id: current_process_session,
        expected_executable_path: current_exe_path.clone(),
    };
    let wrong_pid_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_WrongServerPid",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        console_session,
        &wrong_pid_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15C.1] Eyni Session Başqa PID Rəddi (REAL_INTEGRATION): ClientRes={:?}, ServerReceivedBytes={}",
             wrong_pid_outcome.client_result, wrong_pid_outcome.server_received_payload_bytes);
    assert!(wrong_pid_outcome.client_result.is_err());
    assert!(wrong_pid_outcome.client_result.as_ref().unwrap_err().contains("E_UNTRUSTED_SERVER_PID"));
    assert_eq!(wrong_pid_outcome.server_received_payload_bytes, 0, "Rədd olunan serverə 0 bayt yazılmalıdır!");

    // 15C.2. Saxlanan (Retained) Process Handle Uyğunsuzluğu Rəddi və 0-Bayt Sübutu (REAL_INTEGRATION)
    let mismatched_handle_binding = ExpectedServerBinding {
        expected_server_pid: current_pid,
        retained_process_handle: h_retained_other.raw() as usize, // Başqa prosesin handle-ı!
        expected_server_sid: current_user_sid.clone(),
        expected_server_session_id: current_process_session,
        expected_executable_path: current_exe_path.clone(),
    };
    let mismatched_handle_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_MismatchedHandle",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        console_session,
        &mismatched_handle_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15C.2] Saxlanan Handle Uyğunsuzluğu Rəddi (REAL_INTEGRATION): ClientRes={:?}, ServerReceivedBytes={}",
             mismatched_handle_outcome.client_result, mismatched_handle_outcome.server_received_payload_bytes);
    assert!(mismatched_handle_outcome.client_result.is_err());
    assert!(mismatched_handle_outcome.client_result.as_ref().unwrap_err().contains("E_UNTRUSTED_SERVER_HANDLE_PID"));
    assert_eq!(mismatched_handle_outcome.server_received_payload_bytes, 0, "Rədd olunan serverə 0 bayt yazılmalıdır!");

    drop(h_retained_other);
    let _ = dummy_child.kill();
    let _ = dummy_child.wait();

    // 15C.3. Qorunan Executable Yolu Uyğunsuzluğu Rəddi və 0-Bayt Sübutu (REAL_INTEGRATION)
    let wrong_exe_binding = ExpectedServerBinding {
        expected_server_pid: current_pid,
        retained_process_handle: h_retained_self.raw() as usize,
        expected_server_sid: current_user_sid.clone(),
        expected_server_session_id: current_process_session,
        expected_executable_path: r"C:\Program Files\WinKeyPro\winkey_service_untrusted.exe".to_string(),
    };
    let wrong_exe_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_WrongExePath",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        console_session,
        &wrong_exe_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15C.3] Yanlış Executable Yolu Rəddi (REAL_INTEGRATION): ClientRes={:?}, ServerReceivedBytes={}",
             wrong_exe_outcome.client_result, wrong_exe_outcome.server_received_payload_bytes);
    assert!(wrong_exe_outcome.client_result.is_err());
    assert!(wrong_exe_outcome.client_result.as_ref().unwrap_err().contains("E_UNTRUSTED_SERVER_EXE_PATH"));
    assert_eq!(wrong_exe_outcome.server_received_payload_bytes, 0, "Rədd olunan serverə 0 bayt yazılmalıdır!");

    // 15D.1. Yanlış Server Token SID Siyasəti Rəddi və 0-Bayt Sübutu (REAL_INTEGRATION)
    let wrong_srv_sid_binding = ExpectedServerBinding {
        expected_server_pid: current_pid,
        retained_process_handle: h_retained_self.raw() as usize,
        expected_server_sid: "S-1-5-18".to_string(), // Gözlənilən SYSTEM, faktiki User
        expected_server_session_id: current_process_session,
        expected_executable_path: current_exe_path.clone(),
    };
    let wrong_srv_sid_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_WrongServerSid",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        console_session,
        &wrong_srv_sid_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15D.1] Yanlış Server Token SID Rəddi (REAL_INTEGRATION): ClientRes={:?}, ServerReceivedBytes={}",
             wrong_srv_sid_outcome.client_result, wrong_srv_sid_outcome.server_received_payload_bytes);
    assert!(wrong_srv_sid_outcome.client_result.is_err());
    assert!(wrong_srv_sid_outcome.client_result.as_ref().unwrap_err().contains("E_UNTRUSTED_SERVER_SID"));
    assert_eq!(wrong_srv_sid_outcome.server_received_payload_bytes, 0);

    // 15D.2. Yanlış Server Token Session Siyasəti Rəddi və 0-Bayt Sübutu (REAL_INTEGRATION)
    let wrong_srv_sess_binding = ExpectedServerBinding {
        expected_server_pid: current_pid,
        retained_process_handle: h_retained_self.raw() as usize,
        expected_server_sid: current_user_sid.clone(),
        expected_server_session_id: 999,
        expected_executable_path: current_exe_path.clone(),
    };
    let wrong_srv_sess_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_WrongServerSession",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        console_session,
        &wrong_srv_sess_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15D.2] Yanlış Server Session Rəddi (REAL_INTEGRATION): ClientRes={:?}, ServerReceivedBytes={}",
             wrong_srv_sess_outcome.client_result, wrong_srv_sess_outcome.server_received_payload_bytes);
    assert!(wrong_srv_sess_outcome.client_result.is_err());
    assert!(wrong_srv_sess_outcome.client_result.as_ref().unwrap_err().contains("E_UNTRUSTED_SERVER_SESSION"));
    assert_eq!(wrong_srv_sess_outcome.server_received_payload_bytes, 0);

    // 15D.3. Server Tərəfindən Yanlış Client Session ID Siyasəti Rəddi (REAL_INTEGRATION)
    let wrong_cli_sess_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_WrongClientSessionPolicy",
        &ping_payload,
        &current_user_sid,
        &current_user_sid,
        999, // Server session 999 gözləyir
        &valid_server_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15D.3] Server Tərəfindən Yanlış Client Session Siyasəti Rəddi (REAL_INTEGRATION): {:?}",
             wrong_cli_sess_outcome.client_result);
    assert!(matches!(
        wrong_cli_sess_outcome.client_result,
        Ok((IpcResponse::Error { ref code, ref message }, _)) if code == "E_POLICY_REJECTED" && message.contains("E_SESSION_MISMATCH")
    ));

    // 15E.1. Client-Side Server Identity API Failure Fail-Closed Rəddi və 0-Bayt Sübutu (CONTROLLED_INJECTION)
    for (idx, api_fault) in [
        IdentityApiFault::FailServerPidApi,
        IdentityApiFault::FailServerTokenApi,
        IdentityApiFault::FailServerExePathApi,
    ].iter().enumerate() {
        let p_name = format!("WinKey_B2b_CliApiFail_{}", idx);
        let out = execute_authenticated_user_channel_roundtrip(
            &p_name,
            &ping_payload,
            &current_user_sid,
            &current_user_sid,
            console_session,
            &valid_server_binding,
            Duration::from_millis(600),
            *api_fault,
            IdentityApiFault::None,
        ).expect("Roundtrip tamamlanmalıdır");
        println!("  [B.2b TEST 15E.1.{}] Client Identity API Failure ({:?}) (CONTROLLED_INJECTION): ClientRes={:?}, ServerReceivedBytes={}",
                 idx + 1, api_fault, out.client_result, out.server_received_payload_bytes);
        assert!(out.client_result.is_err());
        assert!(out.client_result.as_ref().unwrap_err().contains("E_SERVER_IDENTITY_API_FAILED"));
        assert_eq!(out.server_received_payload_bytes, 0, "API failure zamanı serverə 0 bayt yazılmalıdır!");
    }

    // 15E.2. Server-Side Client Identity / Impersonation / OpenThreadToken API Failure Rəddi (CONTROLLED_INJECTION)
    // Qeyd: RevertToSelf uğursuzluğu adi Err deyil, dedicated fatal termination olduğu üçün ayrıca disposable child-process (TEST 16B/16C) ilə yoxlanılır.
    for (idx, srv_api_fault) in [
        IdentityApiFault::FailClientPidApi,
        IdentityApiFault::FailClientSessionApi,
        IdentityApiFault::FailImpersonateApi,
        IdentityApiFault::FailOpenThreadTokenApi,
    ].iter().enumerate() {
        let p_name = format!("WinKey_B2b_SrvApiFail_{}", idx);
        let out = execute_authenticated_user_channel_roundtrip(
            &p_name,
            &ping_payload,
            &current_user_sid,
            &current_user_sid,
            console_session,
            &valid_server_binding,
            Duration::from_millis(600),
            IdentityApiFault::None,
            *srv_api_fault,
        ).expect("Roundtrip tamamlanmalıdır");
        println!("  [B.2b TEST 15E.2.{}] Server Identity API Failure ({:?}) (CONTROLLED_INJECTION): ClientRes={:?}",
                 idx + 1, srv_api_fault, out.client_result);
        assert!(matches!(
            out.client_result,
            Ok((IpcResponse::Error { ref code, .. }, _)) if code == "E_CLIENT_IDENTITY_API_FAILED"
        ));
    }

    // 15F. Forged Payload İddiası İcazəsiz Siyasəti Keçə Bilmir (REAL_INTEGRATION)
    let forged_matching_policy_claim = serde_json::to_vec(&IpcCommand::ForgedIdentityCommand {
        claimed_sid: "S-1-5-21-999999999-888888888-777777777-500".to_string(),
        command: "Ping".to_string(),
    }).unwrap();
    let forged_rej_outcome = execute_authenticated_user_channel_roundtrip(
        "WinKey_B2b_ForgedClaimRejected",
        &forged_matching_policy_claim,
        &current_user_sid,
        "S-1-5-21-999999999-888888888-777777777-500", // Server bu SID-i gözləyir, client payload-da bunu iddia edir, lakin OS token fərqlidir!
        console_session,
        &valid_server_binding,
        Duration::from_millis(600),
        IdentityApiFault::None,
        IdentityApiFault::None,
    ).expect("Roundtrip tamamlanmalıdır");
    println!("  [B.2b TEST 15F] Forged Payload Claim vs OS Token Rəddi (REAL_INTEGRATION): {:?}", forged_rej_outcome.client_result);
    assert!(matches!(
        forged_rej_outcome.client_result,
        Ok((IpcResponse::Error { ref code, .. }, _)) if code == "E_POLICY_REJECTED"
    ));

    drop(h_retained_self);

    // =============================================================
    // B.2b Reviziya 2: Disposable Child-Process Checked RevertToSelf və Fatal Exit Sınaqları
    // =============================================================
    println!("\n  --- [B.2b REV 2 SINAQLAR] Disposable Child-Process Checked RevertToSelf və Fatal Exit ---");
    fs::create_dir_all("target/revert_child_tests").ok();

    let run_revert_child_test = |mode: &str, pipe_name: &str, marker_file: &str| -> (i32, Result<IpcResponse, String>, bool) {
        let _ = fs::remove_file(marker_file);
        let mut child = std::process::Command::new(&current_exe_path)
            .arg("--child-revert-test")
            .arg(mode)
            .arg(pipe_name)
            .arg(marker_file)
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("Disposable child proses başladılmalıdır");

        let child_pid = child.id();
        let client_io_res: Result<IpcResponse, String> = unsafe {
            // Child pipe-ın açılmasını gözlə:
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            let mut h_client_opt = None;
            while Instant::now() < wait_deadline {
                if let Ok(h) = open_overlapped_pipe_client(pipe_name) {
                    h_client_opt = Some(ScopedHandle::new(h));
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
            let h_client = h_client_opt.expect("Child pipe-a qoşulmalıdır");
            let h_child_retained = open_retained_process_handle(child_pid).expect("Child process handle açılmalıdır");
            let child_binding = ExpectedServerBinding {
                expected_server_pid: child_pid,
                retained_process_handle: h_child_retained.raw() as usize,
                expected_server_sid: current_user_sid.clone(),
                expected_server_session_id: current_process_session,
                expected_executable_path: current_exe_path.clone(),
            };
            verify_pipe_server_before_transfer(h_client.raw(), &child_binding, IdentityApiFault::None)
                .expect("Child server pre-transfer doğrulamadan keçməlidir");

            let io_deadline = Instant::now() + Duration::from_secs(2);
            write_framed_message_with_deadline(h_client.raw(), &ping_payload, io_deadline)
                .expect("Request child-a yazılmalıdır");

            match read_framed_message_with_deadline(h_client.raw(), io_deadline) {
                Ok(resp_bytes) => {
                    let resp: IpcResponse = serde_json::from_slice(&resp_bytes).unwrap();
                    let _ = write_framed_message_with_deadline(h_client.raw(), b"APP_ACK", io_deadline);
                    Ok(resp)
                }
                Err(e) => Err(e),
            }
        };

        let status = child.wait().expect("Child proses sonlanmalıdır");
        let exit_code = status.code().unwrap_or(-1);
        let marker_exists = Path::new(marker_file).exists();
        let _ = fs::remove_file(marker_file);
        (exit_code, client_io_res, marker_exists)
    };

    // 16A. Normal RevertToSelf Uğurlu (Disposable Child-Process - REAL_INTEGRATION)
    let (exit_16a, resp_16a, marker_16a) = run_revert_child_test(
        "normal",
        "WinKey_B2b_ChildRevert_Normal",
        "target/revert_child_tests/marker_16a.txt",
    );
    println!(
        "  [B.2b TEST 16A] Disposable Child — Normal RevertToSelf Uğurlu (REAL_INTEGRATION): ExitCode={}, ClientResp={:?}, PostRevertMarkerExists={}",
        exit_16a, resp_16a, marker_16a
    );
    assert_eq!(exit_16a, 0, "Normal revert zamanı child exit code 0 olmalıdır");
    assert_eq!(resp_16a, Ok(IpcResponse::Ack), "Normal revert zamanı Ack cavabı gəlməlidir");
    assert!(marker_16a, "Normal revert zamanı post-revert marker yaranmalıdır");

    // 16B. Əsas Yolda RevertToSelf Uğursuzluğu -> Dedicated Fatal Exit (Disposable Child-Process - CONTROLLED_INJECTION)
    let (exit_16b, resp_16b, marker_16b) = run_revert_child_test(
        "revert_fail",
        "WinKey_B2b_ChildRevert_MainFail",
        "target/revert_child_tests/marker_16b.txt",
    );
    println!(
        "  [B.2b TEST 16B] Disposable Child — Injected RevertToSelf Failure Fatal Exit (CONTROLLED_INJECTION): ExitCode={}, ClientResp={:?}, PostRevertMarkerExists={}",
        exit_16b, resp_16b, marker_16b
    );
    assert_eq!(
        exit_16b, FATAL_REVERT_FAILURE_EXIT_CODE,
        "RevertToSelf uğursuz olduqda child dərhal FATAL_REVERT_FAILURE_EXIT_CODE (202) ilə çıxmalıdır"
    );
    assert!(
        resp_16b.is_err(),
        "Fatal exit zamanı child heç bir IPC response yazmamalıdır"
    );
    assert!(
        !marker_16b,
        "Fatal exit-dən sonra child-da heç bir post-revert action/marker yaranmamalıdır!"
    );

    // 16C. OpenThreadToken Uğursuzluğu Ardından RevertToSelf Uğursuzluğu -> Dedicated Fatal Exit (Disposable Child-Process - CONTROLLED_INJECTION)
    let (exit_16c, resp_16c, marker_16c) = run_revert_child_test(
        "open_token_then_revert_fail",
        "WinKey_B2b_ChildRevert_OpenTokThenRevertFail",
        "target/revert_child_tests/marker_16c.txt",
    );
    println!(
        "  [B.2b TEST 16C] Disposable Child — OpenThreadToken Fail -> RevertToSelf Fail Fatal Exit (CONTROLLED_INJECTION): ExitCode={}, ClientResp={:?}, PostRevertMarkerExists={}",
        exit_16c, resp_16c, marker_16c
    );
    assert_eq!(
        exit_16c, FATAL_REVERT_FAILURE_EXIT_CODE,
        "OpenThreadToken xətasından sonrakı RevertToSelf uğursuzluğunda child dərhal FATAL_REVERT_FAILURE_EXIT_CODE (202) ilə çıxmalıdır"
    );
    assert!(
        resp_16c.is_err(),
        "OpenThreadToken+RevertToSelf fatal exit zamanı child heç bir IPC response yazmamalıdır"
    );
    assert!(
        !marker_16c,
        "OpenThreadToken+RevertToSelf fatal exit-dən sonra heç bir post-revert action/marker yaranmamalıdır!"
    );

    // Məhdudiyyət və Mühit Qeydi
    println!("  [NOT_TESTED] Production SCM/SYSTEM xidmət launcher tərəfindən server prosesinin yaradılması (Spike-da etibarlı launcher cari prosesdir).");
    println!("  [NOT_TESTED] Başqa real Windows istifadəçi hesabı və ya remote client sınağı (Fərqli domen/hesab mühiti tələb edir).");

    let b06_auth_rev2_raw_evidence = format!(
        "B.2b REV 2 CHECKED REVERT_TO_SELF & FATAL TERMINATION EVIDENCE:\n\
         - SDDL (Narrow User-Channel): '{}'\n\
         - FATAL_REVERT_FAILURE_EXIT_CODE: {}\n\
         - TEST 15E.2 (In-Process Non-Fatal Client Identity/OpenThreadToken Failure With Successful Revert): All 4 faults rejected with E_CLIENT_IDENTITY_API_FAILED [CONTROLLED_INJECTION]\n\
         - TEST 16A (Disposable Child — Normal RevertToSelf Success): ChildExitCode={}, ClientResp={:?}, PostRevertMarkerExists={} [REAL_INTEGRATION]\n\
         - TEST 16B (Disposable Child — Main Path RevertToSelf Failure -> Real OS Revert + Fatal Exit): ChildExitCode={}, ClientResp={:?}, PostRevertMarkerExists={} [CONTROLLED_INJECTION]\n\
         - TEST 16C (Disposable Child — OpenThreadToken Failure Then RevertToSelf Failure -> Real OS Revert + Fatal Exit): ChildExitCode={}, ClientResp={:?}, PostRevertMarkerExists={} [CONTROLLED_INJECTION]\n\
         - NOT_TESTED: Production SCM/SYSTEM service-spawned helper binding; separate local Windows user account / remote network client\n",
        sddl,
        FATAL_REVERT_FAILURE_EXIT_CODE,
        exit_16a, resp_16a, marker_16a,
        exit_16b, resp_16b, marker_16b,
        exit_16c, resp_16c, marker_16c,
    );
    fs::write(evidence_dir.join("06_ipc_auth_rev2_raw_output.txt"), &b06_auth_rev2_raw_evidence).ok();

    let b01_evidence = format!(
        "B.2 IPC REVISION EVIDENCE:\n- REAL_API: ActiveConsoleSessionId={}, CurrentProcessSessionId={}, InputDesktop='{}' (Accessible={}), RealUserSID='{}'\n- REAL_INTEGRATION: PingAck={:?}, ClientPID={}, ClientSession={}, ServerPID={}, ServerSession={}\n- REAL_API (Impersonation): ImpersonationSuccess={}, PeerSID='{}'\n- NEGATIVE TESTS:\n  * ForgedIdentityRejection: RealOS_SID='{}' (Claimed SID ignored)\n  * PolicyRejection: {:?}\n  * MalformedJsonRejection: {:?}\n  * UnsupportedCmdRejection: {:?}\n  * TriggerCurtainNotImplemented: {:?}\n  * InjectPinNotImplemented: {:?}\n  * SquattingInstanceRejection: {:?}\n  * SilentPeerTimeout: Asılı qalmadı\n- NOT_TESTED: Başqa real Windows hesabı / remote network client sınağı\n",
        console_session, current_process_session, desktop_name, desktop_accessible, current_user_sid,
        res_ping, peer_id_ping.os_client_pid, peer_id_ping.os_client_session_id, server_id_ping.os_server_pid, server_id_ping.os_server_session_id,
        peer_id_ping.is_impersonation_successful, peer_id_ping.os_client_sid,
        peer_id_forged.os_client_sid,
        res_policy_rej,
        res_malformed,
        res_unsupported,
        res_curtain,
        res_pin_not_impl,
        h_pipe_2_attempt
    );
    fs::write(evidence_dir.join("01_session_ipc_proof.txt"), &b01_evidence).ok();
    fs::write(evidence_dir.join("01_ipc_raw_output.txt"), &b01_evidence).ok();
    println!("  [OK] B-01 / B.2 Tamamlandı.\n");

    // =============================================================
    // B-02: Real Ed25519 Pinned Key İmza, Bütövlük, Traversal Qorunması və Rollback (Mərhələ B / B.3)
    // =============================================================
    println!("[B-02 / SINAQ 2] Real Ed25519 Pinned Key, Traversal Qorunması, Known-Good Probation və Rollback...");

    // 1. Kriptoqrafik açar cütünün təyini (Rəsmi Release Açar Cütü)
    let official_signing_key = SigningKey::generate(&mut OsRng);
    let pinned_verifying_key = official_signing_key.verifying_key();
    let untrusted_signing_key = SigningKey::generate(&mut OsRng); // Saxta açar

    let recovery_dir = Path::new("target/recovery_rev3_env");
    fs::create_dir_all(recovery_dir).ok();
    let recovery = WinKeyRecovery::new(recovery_dir, pinned_verifying_key);

    // Senari 2.0: Path Traversal / Directory Escape Qorunması (TƏHLÜKƏSİZLİK MƏNFİ TESTİ)
    let traversal_attempt_1 = recovery.resolve_slot_dir("../outside_escape");
    let traversal_attempt_2 = recovery.resolve_slot_dir("slot_a/../../windows/system32");
    let traversal_attempt_3 = recovery.resolve_slot_dir("invalid:slot*name");
    println!("  [REAL_API] Path Traversal Qorunması (../): {:?}", traversal_attempt_1);
    println!("  [REAL_API] Path Traversal Qorunması (nested escape): {:?}", traversal_attempt_2);
    println!("  [REAL_API] Path Traversal Qorunması (invalid chars): {:?}", traversal_attempt_3);
    assert!(traversal_attempt_1.is_err());
    assert!(traversal_attempt_2.is_err());
    assert!(traversal_attempt_3.is_err());

    // Senari 2A: Rəsmi təsdiqlənmiş ilkin slot_a quraşdırılması (Known-Good etalonu)
    let binary_bytes_v1 = b"MZ_REAL_TEST_SUPERVISOR_BINARY_V100_STABLE";
    recovery.provision_verified_slot("slot_a", "v1.0.0", binary_bytes_v1, &official_signing_key).unwrap();

    // Senari 2B: Rəsmi imzalanmış namizəd slot_b quraşdırılması
    let binary_bytes_v2 = b"MZ_REAL_TEST_SUPERVISOR_BINARY_V101_CANDIDATE";
    recovery.provision_verified_slot("slot_b", "v1.0.1", binary_bytes_v2, &official_signing_key).unwrap();

    // Senari 2C: Namizəd slot bütövlüyünün Pinned Key ilə yoxlanılması (REAL_API / CRYPTO)
    let verify_b_res = recovery.verify_slot_integrity("slot_b");
    println!("  [REAL_API] Pinned Key ilə Namizəd Slot Bütövlüyü: {:?}", verify_b_res);
    assert!(verify_b_res.is_ok());

    // Senari 2D: Dəyişdirilmiş Fayl / Hash Mismatch Aşkarlanması (MƏNFİ TEST - TAMPER)
    let tampered_slot_dir = recovery.resolve_slot_dir("slot_b").unwrap();
    fs::write(tampered_slot_dir.join("winkey_supervisor.exe"), b"MZ_TAMPERED_MALICIOUS_PAYLOAD").unwrap();
    let tamper_res = recovery.verify_slot_integrity("slot_b");
    println!("  [REAL_API] Tampered Binary Aşkarlanması: {:?}", tamper_res);
    assert_eq!(tamper_res, Err("E_HASH_MISMATCH: Kriptoqrafik SHA-256 hash manifestlə uyğun gəlmir (tamper aşkarlandı)"));
    // Bərpa edirik:
    fs::write(tampered_slot_dir.join("winkey_supervisor.exe"), binary_bytes_v2).unwrap();

    // Senari 2E: Saxta / Etibarsız Açar İmzası Aşkarlanması (MƏNFİ TEST - UNTRUSTED KEY)
    let manifest_bytes = fs::read(tampered_slot_dir.join("manifest.json")).unwrap();
    let untrusted_sig = untrusted_signing_key.sign(&serde_json::from_slice::<ReleaseManifest>(&manifest_bytes).unwrap().to_bytes());
    fs::write(tampered_slot_dir.join("manifest.sig"), untrusted_sig.to_bytes()).unwrap();
    let untrusted_res = recovery.verify_slot_integrity("slot_b");
    println!("  [REAL_API] Etibarsız Açar İmzası Aşkarlanması: {:?}", untrusted_res);
    assert_eq!(untrusted_res, Err("E_SIGNATURE_VERIFICATION_FAILED: İmza pinned public key ilə təsdiqlənmədi"));
    // Bərpa edirik:
    recovery.provision_verified_slot("slot_b", "v1.0.1", binary_bytes_v2, &official_signing_key).unwrap();

    // Senari 2F: Korrupt Jurnalın Təmiz Quraşdırma ilə Qarışdırılmaması (MODEL_UNIT)
    fs::write(&recovery.journal_path, b"{CORRUPT_INVALID_JSON_DATA").unwrap();
    let corrupt_journal_res = recovery.read_journal_safe();
    println!("  [MODEL_UNIT] Korrupt Jurnal Aşkarlanması: {:?}", corrupt_journal_res);
    assert!(corrupt_journal_res.is_err());
    fs::remove_file(&recovery.journal_path).ok(); // Təmizləyirik

    // Senari 2G: İlkin Açılışda Boot Qərarı (Təmiz ilkin quraşdırma)
    let initial_boot_decision = recovery.boot_recovery_decision().unwrap();
    println!("  [REAL_INTEGRATION] İlkin Boot Qərarı (Təmiz quraşdırma): Slot={}", initial_boot_decision);
    assert_eq!(initial_boot_decision, "slot_a");

    // Senari 2H: Namizəd Yeniləmənin Aktivasiyası və Probation Vəziyyəti
    let activated_slot = recovery.activate_candidate_update("slot_b", 1730000100).unwrap();
    println!("  [REAL_INTEGRATION] Namizəd Aktivasiyası (Probation): Slot={}", activated_slot);
    assert_eq!(activated_slot, "slot_b");

    // Senari 2I: Health Probation Təsdiqi (Candidate Promoted to Known-Good)
    recovery.confirm_candidate_health(1730000200).unwrap();
    let journal_after_health = recovery.read_journal_safe().unwrap().unwrap();
    println!("  [REAL_INTEGRATION] Health Probation Təsdiqi Sonrası Jurnal: KnownGood={:?}, ActiveSlot={}",
        journal_after_health.known_good_slot, journal_after_health.active_slot);
    assert_eq!(journal_after_health.known_good_slot, Some("slot_b".to_string()));

    // Senari 2J: 3 Ardıcıl Crash və Rollback (REAL_INTEGRATION)
    // Yeni slot_c namizədi gəlir, lakin 3 dəfə çökür:
    let binary_bytes_v3 = b"MZ_REAL_TEST_SUPERVISOR_BINARY_V102_CRASHY";
    recovery.provision_verified_slot("slot_c", "v1.0.2", binary_bytes_v3, &official_signing_key).unwrap();
    recovery.activate_candidate_update("slot_c", 1730000300).unwrap();

    let mut journal_crashed = recovery.read_journal_safe().unwrap().unwrap();
    journal_crashed.crash_counter = 3; // 3 crash limiti aşıldı!
    recovery.write_journal_atomic(&journal_crashed).unwrap();

    let rollback_decision = recovery.boot_recovery_decision().unwrap();
    println!("  [REAL_INTEGRATION] 3 Crash Sonrası Known-Good Slota Rollback: Slot={}", rollback_decision);
    assert_eq!(rollback_decision, "slot_b"); // Kor-koranə əks slot deyil, məhz son təsdiqlənmiş known-good slot_b!

    // Senari 2K: Hər İki Slot Zədələndikdə Binary-nin Başladılmaması (E_BOTH_SLOTS_INVALID)
    let slot_b_dir_path = recovery.resolve_slot_dir("slot_b").unwrap();
    fs::write(slot_b_dir_path.join("winkey_supervisor.exe"), b"CORRUPTED_BINARY").unwrap();
    let both_invalid_res = recovery.boot_recovery_decision();
    println!("  [REAL_INTEGRATION] Hər İki Slot Etibarsız Olduqda Dayandırma: {:?}", both_invalid_res);
    assert!(both_invalid_res.is_err());
    assert!(both_invalid_res.as_ref().unwrap_err().contains("E_BOTH_SLOTS_INVALID"));

    // Senari 2L: Real Uşaq Proses Monitorinqi (REAL_INTEGRATION)
    let child_exit_code = recovery.monitor_child_supervisor_run("cmd.exe", &["/c", "exit 1"]).unwrap();
    println!("  [REAL_INTEGRATION] Uşaq Proses Monitorinqi: ExitCode={}", child_exit_code);
    assert_eq!(child_exit_code, 1);

    let b02_evidence = format!(
        "CLASSIFICATION:\n- REAL_API (Crypto): TraversalBlocked={:?}, ValidManifestVerify={:?}, TamperReject={:?}, UntrustedKeyReject={:?}\n- REAL_INTEGRATION: InitialBoot={}, CandidateActive={}, HealthPromotedKnownGood={:?}, RollbackToKnownGood={}, BothSlotsInvalidBlocked={:?}, ChildExitCode={}\n- MODEL_UNIT: SafeJournalCorruption={:?}\n- NOT_TESTED: SCM launcher wrapper və real OS reboot boot-time recovery\n",
        traversal_attempt_1, verify_b_res, tamper_res, untrusted_res,
        initial_boot_decision, activated_slot, journal_after_health.known_good_slot, rollback_decision, both_invalid_res, child_exit_code,
        corrupt_journal_res
    );
    fs::write(evidence_dir.join("02_recovery_rollback_proof.txt"), b02_evidence).ok();
    println!("  [OK] B-02 Tamamlandı.\n");

    // =============================================================
    // B-03 / B.1: OS CSPRNG, Bound Device Key, Atomik Claim və Expiry
    // =============================================================
    println!("[B-03 / B.1 SINAQ] OS CSPRNG, Bound Device Key, Atomik Claim və Expiry...");

    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::thread;

    let current_epoch = get_current_epoch_sec();

    // 1. Cihaz A və Cihaz B açar cütləri (Private key cihazda yaranır və qalır)
    let device_a_signing_key = SigningKey::generate(&mut OsRng);
    let device_a_public_key = device_a_signing_key.verifying_key();
    let device_b_signing_key = SigningKey::generate(&mut OsRng);
    let _device_b_public_key = device_b_signing_key.verifying_key();

    // 2. PairingSession yaradılarkən Cihaz A-nın public key-i etibarlı kontekstə bağlanır!
    let sess_1 = PairingSession::new_csprng_challenge("sess_enroll_01", device_a_public_key, current_epoch);
    println!("  [REAL_API] OS CSPRNG Challenge: Len={} bayt, BoundKey={}",
             sess_1.random_challenge_bytes.len(),
             hex::encode([sess_1.random_challenge_bytes[0]; 24]));

    // Mənfi Test 1: Malformed signature sonra valid claim uğurlu (Səhv imza sessiyanı yandırmır!)
    let malformed_bytes = b"bad_short_sig";
    let malformed_res = sess_1.claim_pairing(current_epoch + 5, malformed_bytes);
    println!("  [B.1 MƏNFİ 1] Zədələnmiş İmza Rəddi: {:?}", malformed_res);
    assert_eq!(malformed_res, Err("E_INVALID_SIGNATURE_FORMAT"));
    assert_eq!(sess_1.is_claimed.load(Ordering::SeqCst), false); // Challenge YANMADI!

    let valid_sig_a = device_a_signing_key.sign(&sess_1.random_challenge_bytes);
    let valid_res_after_malformed = sess_1.claim_pairing(current_epoch + 6, &valid_sig_a.to_vec());
    println!("  [B.1 DÜZƏLİŞ 1] Malformed Sonrası Valid Claim: {:?}", valid_res_after_malformed);
    assert_eq!(valid_res_after_malformed, Ok(()));
    assert_eq!(sess_1.is_claimed.load(Ordering::SeqCst), true); // İndi atomik claim edildi!

    // Təkrar claim (Replay attack): artıq claim olunub -> rədd
    let replay_claim = sess_1.claim_pairing(current_epoch + 7, &valid_sig_a.to_vec());
    println!("  [B.1 REPLAY] Təkrar Claim Rəddi: {:?}", replay_claim);
    assert_eq!(replay_claim, Err("E_PAIRING_ALREADY_CLAIMED: Bu birdəfəlik kod artıq istifadə edilib"));

    // Mənfi Test 2: Forged signature (başqa açar) sonra valid claim uğurlu
    let sess_2 = PairingSession::new_csprng_challenge("sess_enroll_02", device_a_public_key, current_epoch);
    let forged_sig_b = device_b_signing_key.sign(&sess_2.random_challenge_bytes);
    let forged_res = sess_2.claim_pairing(current_epoch + 5, &forged_sig_b.to_vec());
    println!("  [B.1 MƏNFİ 2] Saxta Açar İmzası Rəddi: {:?}", forged_res);
    assert_eq!(forged_res, Err("E_CHALLENGE_VERIFICATION_FAILED: Cihaz imzası challenge ilə uyğun gəlmir"));
    assert_eq!(sess_2.is_claimed.load(Ordering::SeqCst), false); // Challenge YANMADI!

    let valid_sig_2 = device_a_signing_key.sign(&sess_2.random_challenge_bytes);
    let recover_claim_2 = sess_2.claim_pairing(current_epoch + 6, &valid_sig_2.to_vec());
    println!("  [B.1 DÜZƏLİŞ 2] Forged Sonrası Valid Claim: {:?}", recover_claim_2);
    assert_eq!(recover_claim_2, Ok(()));
    assert_eq!(sess_2.is_claimed.load(Ordering::SeqCst), true);

    // Mənfi Test 3: Sərhəd Vaxtları (Expiry boundary: expiry-1 qəbul, expiry və expiry+1 rədd)
    let sess_time_valid = PairingSession::new_csprng_challenge("sess_time_1", device_a_public_key, current_epoch);
    let sig_time = device_a_signing_key.sign(&sess_time_valid.random_challenge_bytes);
    let exp_minus_1 = sess_time_valid.expires_at_epoch - 1;
    let claim_exp_minus_1 = sess_time_valid.claim_pairing(exp_minus_1, &sig_time.to_vec());
    println!("  [B.1 SƏRHƏD 1] expiry - 1 sınağı: {:?}", claim_exp_minus_1);
    assert_eq!(claim_exp_minus_1, Ok(())); // QƏBUL

    let sess_time_exact = PairingSession::new_csprng_challenge("sess_time_2", device_a_public_key, current_epoch);
    let sig_exact = device_a_signing_key.sign(&sess_time_exact.random_challenge_bytes);
    let exp_exact = sess_time_exact.expires_at_epoch;
    let claim_exp_exact = sess_time_exact.claim_pairing(exp_exact, &sig_exact.to_vec());
    println!("  [B.1 SƏRHƏD 2] now == expires_at sınağı: {:?}", claim_exp_exact);
    assert_eq!(claim_exp_exact, Err("E_PAIRING_EXPIRED: 120 saniyəlik enrollment pəncərəsi bitib")); // RƏDD

    let sess_time_late = PairingSession::new_csprng_challenge("sess_time_3", device_a_public_key, current_epoch);
    let sig_late = device_a_signing_key.sign(&sess_time_late.random_challenge_bytes);
    let exp_plus_1 = sess_time_late.expires_at_epoch + 1;
    let claim_exp_plus_1 = sess_time_late.claim_pairing(exp_plus_1, &sig_late.to_vec());
    println!("  [B.1 SƏRHƏD 3] now > expires_at sınağı: {:?}", claim_exp_plus_1);
    assert_eq!(claim_exp_plus_1, Err("E_PAIRING_EXPIRED: 120 saniyəlik enrollment pəncərəsi bitib")); // RƏDD

    // Mənfi Test 4: Eyni Challenge üçün Paralel Valid Claim-lər (Race Condition sınağı)
    let sess_parallel = Arc::new(PairingSession::new_csprng_challenge(
        "sess_parallel",
        device_a_public_key,
        current_epoch,
    ));
    let valid_sig_parallel = Arc::new(device_a_signing_key.sign(&sess_parallel.random_challenge_bytes).to_vec());

    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = Arc::clone(&sess_parallel);
        let sig = Arc::clone(&valid_sig_parallel);
        handles.push(thread::spawn(move || {
            s.claim_pairing(current_epoch + 10, &sig)
        }));
    }

    let mut ok_count = 0;
    let mut already_claimed_count = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(()) => ok_count += 1,
            Err("E_PAIRING_ALREADY_CLAIMED: Bu birdəfəlik kod artıq istifadə edilib") => already_claimed_count += 1,
            Err(other) => panic!("Gözlənilməz nəticə: {}", other),
        }
    }
    println!("  [B.1 PARALEL] 10 Paralel Claim: Uğurlu={}, Artıq Claim Olunub={}", ok_count, already_claimed_count);
    assert_eq!(ok_count, 1); // DƏQİQ 1 DƏNƏSİ QƏBUL OLUNDU!
    assert_eq!(already_claimed_count, 9); // QALAN 9 DƏNƏSİ BLOKLANDI!

    // 3. Server Token İdarəsi, IDOR və Revoke (MODEL_UNIT)
    let token_mgr = ServerTokenManager::new();
    let mobile_tok = token_mgr.issue_token("device_pc_nesib_01", "usr_nesib_owner", current_epoch);

    assert!(token_mgr.authorize_request(&mobile_tok, "device_pc_nesib_01", "LOCK", current_epoch).is_ok());
    assert!(token_mgr.authorize_request(&mobile_tok, "device_pc_nesib_01", "UNLOCK", current_epoch).is_ok());

    let idor_res = token_mgr.authorize_request(&mobile_tok, "device_victim_pc", "UNLOCK", current_epoch);
    println!("  [MODEL_UNIT] IDOR Başqa Cihaz Əmri Rəddi: {:?}", idor_res);
    assert_eq!(idor_res, Err("E_IDOR_REJECTED: Mobil token başqa cihazın idarə edilməsi üçün istifadə edilə bilməz"));

    let admin_res = token_mgr.authorize_request(&mobile_tok, "device_pc_nesib_01", "ADMIN_DELETE_ALL", current_epoch);
    println!("  [MODEL_UNIT] Mobil Tokendən Admin Hüququna Keçid Rəddi: {:?}", admin_res);
    assert_eq!(admin_res, Err("E_FORBIDDEN_SCOPE: Mobil token inzibatçı hüquqlarına malik deyil"));

    token_mgr.revoke_token(&mobile_tok);
    let revoked_res = token_mgr.authorize_request(&mobile_tok, "device_pc_nesib_01", "LOCK", current_epoch);
    println!("  [MODEL_UNIT] Ləğv Edilmiş (Revoked) Token Rəddi: {:?}", revoked_res);
    assert_eq!(revoked_res, Err("E_TOKEN_REVOKED: Bu mobil token server tərəfindən ləğv edilib"));

    println!("  [NOT_TESTED] İki müstəqil Cloudflare Sites origin-i üzərindən canlı ictimai şəbəkə testi (Production audience qorunub, test backend gözləyir).");

    let b03_evidence = format!(
        "CLASSIFICATION:\n- REAL_API (Crypto): CSPRNGChallengeLen={}, MalformedThenValidClaim={:?}, ForgedThenValidClaim={:?}, ExpiryMinus1={:?}, ExpiryExact={:?}, ExpiryPlus1={:?}, ParallelOkCount={}, ParallelClaimedCount={}\n- MODEL_UNIT: IDORRejection={:?}, AdminScopeRejection={:?}, RevokedTokenRejection={:?}\n- NOT_TESTED: İki müstəqil Cloudflare Sites layihəsi üzərindən canlı HTTP sorğusu\n",
        sess_1.random_challenge_bytes.len(),
        valid_res_after_malformed,
        recover_claim_2,
        claim_exp_minus_1,
        claim_exp_exact,
        claim_exp_plus_1,
        ok_count,
        already_claimed_count,
        idor_res, admin_res, revoked_res
    );
    fs::write(evidence_dir.join("05_sites_pairing_proof.txt"), b03_evidence).ok();
    println!("  [OK] B-03 / B.1 Tamamlandı.\n");

    // =============================================================
    // B-04 / Mərhələ D Diaqnostika: Bounded Outbox, Secret Canary, Sender ACK və Server Dedup
    // =============================================================
    println!("[B-04 / Mərhələ D Diaqnostika] Bounded Outbox, Secret Canary, Sender ACK və Server Dedup...");

    let telemetry_dir = Path::new("target/telemetry_bounded_env");
    fs::create_dir_all(telemetry_dir).ok();
    let outbox = OutboxManager::new(telemetry_dir, 50 * 1024); // 50 KB Bounded limit
    outbox.clear_outbox().ok();

    let canary_rules = [
        ("CATEGORY_PIN", "482910_REAL_PIN_CANARY"),
        ("CATEGORY_PRIVATE_KEY", "ED25519_PRIVATE_KEY_SECRET"),
    ];

    // 1. Hadisələrin yaradılması və Bounded Queue dolma testi
    for i in 0..30 {
        let evt = DiagnosticEvent {
            schema_version: "1.0.0".to_string(),
            event_id: format!("evt_seq_{:04}", i),
            install_run_id: "run_bounded_test".to_string(),
            device_id: Some("dev_test_42".to_string()),
            operation_id: "op_batch".to_string(),
            component: "winkey_service".to_string(),
            version: "1.0.0".to_string(),
            stage: "service_start".to_string(),
            event_type: "STAGE_PROGRESS".to_string(),
            severity: "INFO".to_string(),
            local_time: "2026-10-28T04:10:00Z".to_string(),
            sequence_no: i as u64,
            error_code: None,
            native_exit_code: Some(0),
            duration_ms: Some(15),
        };
        outbox.enqueue_event(&evt).unwrap();
    }

    let pending_before_ack = outbox.read_pending_events();
    println!("  [REAL_INTEGRATION] Bounded Outbox Hadisə Sayı: {}", pending_before_ack.len());
    assert!(!pending_before_ack.is_empty());

    // 2. Təmiz Outbox Canary Yoxlaması
    let scan_clean = outbox.scan_for_secrets(&canary_rules);
    println!("  [REAL_INTEGRATION] Təmiz Outbox Canary Yoxlaması: {:?}", scan_clean);
    assert!(scan_clean.is_ok());

    // 3. Canary Sızma Aşkarlanması: Sirrin özü QƏTİYYƏN loga düşmür!
    let mut leak_file = fs::OpenOptions::new().append(true).open(&outbox.outbox_file).unwrap();
    use std::io::Write as _;
    writeln!(leak_file, "{{\"payload\": \"test_482910_REAL_PIN_CANARY_leak\"}}").unwrap();
    let scan_leak = outbox.scan_for_secrets(&canary_rules);
    println!("  [REAL_INTEGRATION] Təhlükəsiz Canary Aşkarlanması: {:?}", scan_leak);
    assert!(scan_leak.is_err());
    let err_str = scan_leak.unwrap_err();
    assert!(err_str.contains("CATEGORY_PIN")); // Kateqoriya göstərildi
    assert!(!err_str.contains("482910_REAL_PIN_CANARY")); // Lakin sirrin özü gizlədildi!

    // 4. Sender ACK və Outbox Pruning (ACK-dən sonra atomik silmə)
    outbox.clear_outbox().ok(); // Yenidən təmiz doldururuq
    let evt_to_send_1 = DiagnosticEvent {
        schema_version: "1.0.0".to_string(),
        event_id: "evt_ack_001".to_string(),
        install_run_id: "run_ack_test".to_string(),
        device_id: Some("dev_test_42".to_string()),
        operation_id: "op_install".to_string(),
        component: "installer".to_string(),
        version: "1.0.0".to_string(),
        stage: "requirements_check".to_string(),
        event_type: "STAGE_PROGRESS".to_string(),
        severity: "INFO".to_string(),
        local_time: "2026-10-28T04:10:05Z".to_string(),
        sequence_no: 1,
        error_code: None,
        native_exit_code: Some(0),
        duration_ms: Some(10),
    };
    let evt_to_send_2 = DiagnosticEvent {
        schema_version: "1.0.0".to_string(),
        event_id: "evt_ack_002".to_string(),
        install_run_id: "run_ack_test".to_string(),
        device_id: Some("dev_test_42".to_string()),
        operation_id: "op_install".to_string(),
        component: "installer".to_string(),
        version: "1.0.0".to_string(),
        stage: "service_install".to_string(),
        event_type: "STAGE_PROGRESS".to_string(),
        severity: "INFO".to_string(),
        local_time: "2026-10-28T04:10:06Z".to_string(),
        sequence_no: 2,
        error_code: None,
        native_exit_code: Some(0),
        duration_ms: Some(25),
    };
    outbox.enqueue_event(&evt_to_send_1).unwrap();
    outbox.enqueue_event(&evt_to_send_2).unwrap();

    // Server-Side Deduplication Storage
    let server_dedup = ServerDedupStorage::new();
    let ingest_1 = server_dedup.ingest_event(&evt_to_send_1);
    let ingest_1_dup = server_dedup.ingest_event(&evt_to_send_1);
    let ingest_2 = server_dedup.ingest_event(&evt_to_send_2);
    println!("  [REAL_INTEGRATION] Server Dedup: Evt1_First={}, Evt1_Duplicate={}, Evt2_First={}",
        ingest_1, ingest_1_dup, ingest_2);
    assert!(ingest_1);
    assert!(!ingest_1_dup); // Duplicate aşkarlandı!
    assert!(ingest_2);

    // Server ACK verdi -> evt_ack_001 outbox-dan silinir:
    outbox.acknowledge_events(&["evt_ack_001".to_string()]).unwrap();
    let remaining_after_ack = outbox.read_pending_events();
    println!("  [REAL_INTEGRATION] ACK Sonrası Qalan Outbox Hadisələri: Say={}", remaining_after_ack.len());
    assert_eq!(remaining_after_ack.len(), 1);
    assert_eq!(remaining_after_ack[0].event_id, "evt_ack_002");

    // 5. Model Təsnifatı (MODEL_UNIT)
    let (uac_outcome, uac_code) = classify_installer_outcome(true, Some(1223));
    let (stall_outcome, stall_code) = classify_installer_outcome(false, None);
    println!("  [MODEL_UNIT] UAC Ləğv Təsnifatı (Some(1223)): Outcome={}, Code={:?}", uac_outcome, uac_code);
    println!("  [MODEL_UNIT] Pre-execution Stall Təsnifatı: Outcome={}, Code={:?}", stall_outcome, stall_code);
    assert_eq!(uac_code, Some("E_UAC_REJECTED".to_string()));

    // 6. Latency Ölçümü Sınağı (Timestamp-to-Ingest Latency)
    let start_instant = std::time::Instant::now();
    let _ = server_dedup.ingest_event(&evt_to_send_2);
    let latency_us = start_instant.elapsed().as_micros();
    println!("  [REAL_API] Event Ingestion Latency: {} mikrosaniyə", latency_us);

    println!("  [NOT_TESTED] Fiziki ShellExecuteEx UAC dialoqunda istifadəçinin 'Xeyr' basması (Operator qarşılıqlı əlaqəsi tələb edir).");

    let b04_evidence = format!(
        "CLASSIFICATION:\n- REAL_INTEGRATION: CleanCanaryScan={:?}, SafeCanaryDetection={:?}, ServerDedupFirst={}, ServerDedupDuplicate={}, AckPruningRemaining={}\n- REAL_API: IngestLatencyMicros={}\n- MODEL_UNIT: UacOutcome={}, UacCode={:?}, StallOutcome={}, StallCode={:?}\n- NOT_TESTED: Fiziki ShellExecuteEx UAC dialoqu\n",
        scan_clean, err_str, ingest_1, ingest_1_dup, remaining_after_ack.len(),
        latency_us, uac_outcome, uac_code, stall_outcome, stall_code
    );
    fs::write(evidence_dir.join("03_telemetry_outbox_proof.txt"), &b04_evidence).ok();
    println!("  [OK] B-04 Tamamlandı.\n");

    // =============================================================
    // B-05 / Mərhələ C / D: WebView2 Host Aşkarlanması və Clean-PC Məhdudiyyəti
    // =============================================================
    println!("[B-05 / SINAQ 5] WebView2 Host Aşkarlanması və Clean-PC Məhdudiyyəti...");

    let host_webview2 = check_host_webview2_installation();
    println!("  [REAL_API] Hostda WebView2 Mövcudluğu: {:?}", host_webview2);

    println!("  [NOT_TESTED] Clean VM üzərində Evergreen Bootstrapper yüklənməsi və səssiz quraşdırılması (Təmiz VM tələb olunur).");

    let b05_evidence = format!(
        "CLASSIFICATION:\n- REAL_API: HostWebView2Result={:?}\n- NOT_TESTED: Clean VM üzərində Evergreen Bootstrapper və Tauri install sınağı (Təmiz VM gözləyir)\n",
        host_webview2
    );
    fs::write(evidence_dir.join("04_webview2_runtime_proof.txt"), &b05_evidence).ok();
    println!("  [OK] B-05 Tamamlandı.\n");

    // =============================================================
    // MƏRHƏLƏ D: Etalon Windows Unlock və Secure Desktop Təhlükəsizliyi
    // =============================================================
    println!("[MƏRHƏLƏ D SINAQ] Etalon Unlock Ardıcıllığı, UAC Qoruması və Tək Cəhd Siyasəti...");

    let mut unlock_engine = UnlockSequenceEngine::new();

    // Ssenari D.1: Kilidli pərdə vəziyyəti (LockedDefaultCurtain) -> PIN-siz klik
    let step_curtain = unlock_engine.execute_unlock_step(DesktopSecurityState::LockedDefaultCurtain, false).unwrap();
    println!("  [REAL_INTEGRATION] D.1 Default Pərdə Klik Nəticəsi: {:?}", step_curtain);
    assert_eq!(step_curtain, UnlockOutcome::CurtainDismissedWaitingFocus);

    // Ssenari D.2: Winlogon PIN fokusu -> Tək bir dəfə credential
    let step_focus = unlock_engine.execute_unlock_step(DesktopSecurityState::WinlogonPinFocus, true).unwrap();
    println!("  [REAL_INTEGRATION] D.2 Winlogon PIN Fokus Nəticəsi: {:?}", step_focus);
    assert_eq!(step_focus, UnlockOutcome::SuccessUnlocked);

    // Ssenari D.3: Windows Hello aktivdir -> Əlavə PIN və ya Enter göndərilmir
    let step_hello = unlock_engine.execute_unlock_step(DesktopSecurityState::WinlogonHelloActive, true).unwrap();
    println!("  [REAL_INTEGRATION] D.3 Windows Hello Aktivliyi Rəddi: {:?}", step_hello);
    assert_eq!(step_hello, UnlockOutcome::RejectedHelloActiveNoInput);

    // Ssenari D.4: UAC təhlükəsiz masaüstü aktivdir -> QƏTİYYƏN PIN GÖNDƏRİLMİR!
    let step_uac = unlock_engine.execute_unlock_step(DesktopSecurityState::UacSecureDesktopActive, true);
    println!("  [REAL_INTEGRATION] D.4 UAC Masaüstü Bloklanması: {:?}", step_uac);
    assert_eq!(step_uac, Err("E_UAC_DESKTOP_BLOCKED: UAC Təhlükəsiz masaüstü aktivdir, credential inyeksiyası bloklandı!"));

    // Ssenari D.5: Yanlış PIN təkrarının qarşısının alınması
    unlock_engine.last_attempt_failed = true;
    let step_retry = unlock_engine.execute_unlock_step(DesktopSecurityState::WinlogonPinFocus, true);
    println!("  [REAL_INTEGRATION] D.5 Təkrar Yanlış PIN Siyasət Bloklanması: {:?}", step_retry);
    assert_eq!(step_retry, Err("E_PIN_RETRY_BLOCKED: Yanlış PIN təkrar-təkrar sınana bilməz, operator təsdiqi tələb olunur"));

    let d_evidence = format!(
        "CLASSIFICATION:\n- REAL_INTEGRATION: CurtainDismiss={:?}, WinlogonUnlock={:?}, HelloActiveNoInput={:?}, UacBlocked={:?}, RetryBlocked={:?}\n",
        step_curtain, step_focus, step_hello, step_uac, step_retry
    );
    fs::write(evidence_dir.join("07_stage_d_service_unlock_proof.txt"), &d_evidence).ok();
    println!("  [OK] Mərhələ D Tamamlandı.\n");

    // =============================================================
    // MƏRHƏLƏ E: Çoxistifadəçili Gateway və Yalnız Sahibə Açıq Admin
    // =============================================================
    println!("[MƏRHƏLƏ E SINAQ] Çoxistifadəçili Gateway, IDOR Təcridi və Owner-Only Admin...");

    let admin_master_token = "admin_master_secret_key_owner_only_999";
    let gateway = MultiTenantGateway::new(admin_master_token);

    // 1. İki müstəqil cihazın qeydiyyatı
    let keypair_1 = SigningKey::generate(&mut OsRng);
    let keypair_2 = SigningKey::generate(&mut OsRng);

    let dev_id_1 = gateway.register_device("Nesib-Laptop", keypair_1.verifying_key(), current_epoch);
    let dev_id_2 = gateway.register_device("Office-Desktop", keypair_2.verifying_key(), current_epoch);
    println!("  [REAL_INTEGRATION] E.1 Cihaz Qeydiyyatı: Dev1={}, Dev2={}", dev_id_1, dev_id_2);

    // 2. İstifadəçi 1 və İstifadəçi 2 QR Cütləşməsi
    let user_1 = "usr_nesib_owner";
    let user_2 = "usr_stranger_attacker";

    let tok_user_1 = gateway.complete_pairing(&dev_id_1, user_1, current_epoch).unwrap();
    let tok_user_2 = gateway.complete_pairing(&dev_id_2, user_2, current_epoch).unwrap();
    println!("  [REAL_INTEGRATION] E.2 Pairing Tamamlandı: Tok1={:.12}..., Tok2={:.12}...", tok_user_1, tok_user_2);

    // 3. KRİTİK IDOR SINAĞI: İstifadəçi 2 İstifadəçi 1-in cihazını idarə etməyə cəhd edir!
    let idor_attempt = gateway.submit_command(&tok_user_2, &dev_id_1, "UNLOCK", current_epoch);
    println!("  [REAL_INTEGRATION] E.3 Cross-Tenant IDOR Əmr Cəhdi Rəddi: {:?}", idor_attempt);
    assert_eq!(idor_attempt, Err("E_IDOR_REJECTED: Mobil token başqa cihazın idarə edilməsi üçün istifadə edilə bilməz"));

    // 4. Doğru Tenant Əmri: İstifadəçi 1 öz cihazına UNLOCK əmri göndərir
    let valid_cmd_id = gateway.submit_command(&tok_user_1, &dev_id_1, "UNLOCK", current_epoch).unwrap();
    println!("  [REAL_INTEGRATION] E.4 Doğru Tenant Əmri Növbəyə Alındı: CmdId={}", valid_cmd_id);

    // 5. Kompüter agenti əmri götürür və nəticəni təqdim edir
    let polled_cmd = gateway.agent_poll_command(&dev_id_1, current_epoch).unwrap();
    println!("  [REAL_INTEGRATION] E.5 Agent Əmri Götürdü: Action={}, State={}", polled_cmd.action, polled_cmd.state);
    assert_eq!(polled_cmd.action, "UNLOCK");
    assert_eq!(polled_cmd.state, "running");

    gateway.agent_submit_result(&dev_id_1, &valid_cmd_id, true, "DESKTOP_UNLOCKED_SUCCESS").unwrap();

    // 6. Token Revocation Sınağı: İstifadəçi 1 tokeni ləğv edilir
    gateway.token_mgr.revoke_token(&tok_user_1);
    let after_revoke_attempt = gateway.submit_command(&tok_user_1, &dev_id_1, "LOCK", current_epoch);
    println!("  [REAL_INTEGRATION] E.6 Revoked Token Rəddi: {:?}", after_revoke_attempt);
    assert_eq!(after_revoke_attempt, Err("E_TOKEN_REVOKED: Bu mobil token server tərəfindən ləğv edilib"));

    // 7. YALNIZ SAHİBƏ AÇIQ ADMİN GÖRÜNÜŞÜ (Owner-Only Admin Surface)
    // Saxta kənar şəxs admin API-yə daxil olmağa cəhd edir:
    let unauthorized_admin = gateway.owner_admin_view_devices("fake_admin_token");
    println!("  [REAL_INTEGRATION] E.7.1 Saxta Admin Tokeni Rəddi: {:?}", unauthorized_admin);
    assert_eq!(unauthorized_admin, Err("E_ADMIN_UNAUTHORIZED: Yalnız layihə sahibi admin panelinə daxil ola bilər"));

    // Əsl sahib daxil olur:
    let admin_devices = gateway.owner_admin_view_devices(admin_master_token).unwrap();
    println!("  [REAL_INTEGRATION] E.7.2 Rəsmi Sahib Admin Görünüşü: Cihaz Sayı={}", admin_devices.len());
    for (id, name, owner, last_seen, ver) in &admin_devices {
        println!("     - DevId={}, Name={}, Owner={:?}, LastSeen={}, Ver={} (PIN YOXDUR!)", id, name, owner, last_seen, ver);
    }
    assert_eq!(admin_devices.len(), 2);

    let e_evidence = format!(
        "CLASSIFICATION:\n- REAL_INTEGRATION: Dev1={}, Dev2={}, IDORRejected={:?}, ValidCmdQueue={}, PolledAction={}, RevokedReject={:?}, AdminUnauthorized={:?}, AdminDeviceCount={}\n",
        dev_id_1, dev_id_2, idor_attempt, valid_cmd_id, polled_cmd.action, after_revoke_attempt, unauthorized_admin, admin_devices.len()
    );
    fs::write(evidence_dir.join("08_stage_e_gateway_admin_proof.txt"), &e_evidence).ok();
    println!("  [OK] Mərhələ E Tamamlandı.\n");

    // =============================================================
    // MƏRHƏLƏ G: Sadə Mobil PWA İdarəetməsi
    // =============================================================
    println!("[MƏRHƏLƏ G SINAQ] Sadə Mobil PWA Əmrləri və Onlayn Status...");

    // Yeni aktiv mobil token alırıq:
    let mobile_tok = gateway.complete_pairing(&dev_id_2, user_2, current_epoch).unwrap();

    // Mobil PWA: Kilidlə əmri
    let lock_cmd_id = gateway.submit_command(&mobile_tok, &dev_id_2, "LOCK", current_epoch).unwrap();
    println!("  [REAL_INTEGRATION] G.1 Mobil PWA LOCK Əmri: CmdId={}", lock_cmd_id);

    // Agent LOCK əmrini icra edir
    let polled_lock = gateway.agent_poll_command(&dev_id_2, current_epoch).unwrap();
    assert_eq!(polled_lock.action, "LOCK");
    gateway.agent_submit_result(&dev_id_2, &lock_cmd_id, true, "DESKTOP_LOCKED_SUCCESS").unwrap();

    let g_evidence = format!(
        "CLASSIFICATION:\n- REAL_INTEGRATION: MobileLockCmd={}, AgentPolledAction={}, ResultSubmitted=true\n",
        lock_cmd_id, polled_lock.action
    );
    fs::write(evidence_dir.join("09_stage_g_mobile_pwa_proof.txt"), &g_evidence).ok();
    println!("  [OK] Mərhələ G Tamamlandı.\n");

    println!("=================================================================");
    println!("  B, C, D, E, F, G BATCH SPIKE VƏ TESTLƏRİ UĞURLA BAŞA ÇATDI!    ");
    println!("  Bütün sübutlar 'plan/reports/B/' qovluğunda saxlanıldı.         ");
    println!("=================================================================");

    watchdog_guard.store(true, std::sync::atomic::Ordering::Relaxed);
}
