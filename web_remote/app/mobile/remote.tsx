"use client";
import React, { useState, useEffect } from "react";
import { LockKeyhole, LockKeyholeOpen, LoaderCircle, Monitor, Wifi, WifiOff, Check } from "lucide-react";
import styles from "./remote.module.css";

type Device = {
  id: string;
  name: string;
  last_seen: number;
  locked: number | null; // 1: locked, 0: unlocked, null: gözlənilir
  pin_ready: number;
};

export default function MobileRemote({
  initialDevice,
  pairCode,
}: {
  initialDevice: string;
  pairCode: string;
}) {
  const [isNetworkOnline, setIsNetworkOnline] = useState(true);
  const [device, setDevice] = useState<Device>({
    id: initialDevice || "",
    name: initialDevice ? "Kompüter" : "Bilinməyən cihaz",
    last_seen: 0,
    locked: null, // İlkin vəziyyətdə mock status verilmir, real sorğu gözlənilir
    pin_ready: 0,
  });

  // Sessiya yalnız hədəf device_id-yə bağlanır, başqa cihazın sessiyası istifadə olunmur
  const [sessionToken, setSessionToken] = useState<string>(() => {
    if (typeof window !== "undefined" && initialDevice) {
      try {
        return sessionStorage.getItem("winkey_sess_" + initialDevice) || "";
      } catch {
        return "";
      }
    }
    return "";
  });

  const [busy, setBusy] = useState<"" | "lock" | "unlock">("");
  const [message, setMessage] = useState("Kompüterlə təhlükəsiz bağlantı yoxlanılır…");
  const [successToast, setSuccessToast] = useState("");

  // 1. QR Kodla Avtomatik Cütləşmə (Mount zamanı) -- ChatGPT-siz Mobil Sessiya
  useEffect(() => {
    let unmounted = false;
    if (pairCode) {
      setMessage("Birdəfəlik QR kodla qoşulma aparılır…");
      fetch("/api/pair", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pair_code: pairCode })
      })
        .then(async (res) => {
          if (!unmounted) {
            if (res.ok) {
              const data = (await res.json()) as any;
              setMessage(`✓ Kompüter uğurla bağlandı: ${data.name || initialDevice}`);
              if (data.session_token) {
                setSessionToken(data.session_token);
                try {
                  const targetDevId = data.device_id || initialDevice;
                  if (targetDevId) {
                    sessionStorage.setItem("winkey_sess_" + targetDevId, data.session_token);
                  }
                } catch (_) {}
              }
              if (data.device_id) {
                setDevice((prev) => ({ ...prev, id: data.device_id, name: data.name || prev.name }));
              }
            } else {
              const err = (await res.json().catch(() => ({}))) as any;
              setMessage("Qoşulma xətası: " + (err.error || "Kodun vaxtı bitib və ya artıq istifadə olunub"));
            }
          }
        })
        .catch(() => {
          if (!unmounted) setMessage("Kompüterlə əlaqə qurulur...");
        });
    }
    return () => { unmounted = true; };
  }, [pairCode, initialDevice]);

  // 2. Canlı Cihaz Statusunun Periodik Yüklənməsi (Mobil Bearer Token ilə)
  useEffect(() => {
    let unmounted = false;
    const fetchStatus = async () => {
      if (!device.id) return;
      try {
        const headers: Record<string, string> = {};
        if (sessionToken) headers["Authorization"] = `Bearer ${sessionToken}`;

        const res = await fetch(`/api/mobile/status?device_id=${encodeURIComponent(device.id)}`, { headers });
        if (!unmounted) {
          if (res.ok) {
            const target = (await res.json()) as any;
            if (target && target.id) {
              setDevice({
                id: target.id,
                name: target.name || "Windows PC",
                last_seen: target.last_seen || Date.now(),
                locked: target.locked,
                pin_ready: target.pin_ready ? 1 : 0
              });
            }
          } else if (res.status === 401 || res.status === 403) {
            setMessage("Səlahiyyət xətası: Mobil sessiya etibarsızdır və ya cihaz revoke edilib.");
          }
        }
      } catch (_) {}
    };
    fetchStatus();
    const timer = setInterval(fetchStatus, 4000);
    return () => { unmounted = true; clearInterval(timer); };
  }, [device.id, sessionToken]);

  // Real status alınmadan kompüter onlayn göstərilmir
  const online = isNetworkOnline && Boolean(device.id) && device.last_seen > 0 && (Date.now() - device.last_seen < 45000);

  // 3. Real Əmr Göndərilməsi (POST /api/commands) və Polling
  const handleAction = async (kind: "lock" | "unlock") => {
    if (!online || busy) return;

    setBusy(kind);
    setMessage(kind === "unlock" ? "Windows kilidi açılır…" : "Kompüter kilidlənir…");

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (sessionToken) headers["Authorization"] = `Bearer ${sessionToken}`;

      const res = await fetch("/api/commands", {
        method: "POST",
        headers,
        body: JSON.stringify({ device_id: device.id, action: kind })
      });

      if (res.ok) {
        const cmdData = (await res.json()) as any;
        const cmdId = cmdData.command_id;

        let attempts = 0;
        const poll = setInterval(async () => {
          attempts++;
          try {
            const pollHeaders: Record<string, string> = {};
            if (sessionToken) pollHeaders["Authorization"] = `Bearer ${sessionToken}`;

            const cRes = await fetch(`/api/commands/${cmdId}`, { headers: pollHeaders });
            if (cRes.ok) {
              const cData = (await cRes.json()) as any;
              if (cData.state === "success") {
                clearInterval(poll);
                setBusy("");
                setDevice((prev) => ({ ...prev, locked: kind === "unlock" ? 0 : 1, last_seen: Date.now() }));
                setMessage(kind === "unlock" ? "Windows kilidi açıldı ✓" : "Kompüter kilidləndi ✓");
                setSuccessToast(kind === "unlock" ? "Masaüstü açıldı" : "Masaüstü kilidləndi");
                setTimeout(() => setSuccessToast(""), 3500);
                return;
              } else if (cData.state === "failed") {
                clearInterval(poll);
                setBusy("");
                setMessage("Xəta: Əmr kompüterdə icra edilə bilmədi (uğursuz oldu)");
                return;
              } else if (cData.state === "expired") {
                clearInterval(poll);
                setBusy("");
                setMessage("Xəta: Əmrin icra müddəti bitdi (vaxtaşırı/expired)");
                return;
              }
            } else if (cRes.status === 401 || cRes.status === 403) {
              clearInterval(poll);
              setBusy("");
              setMessage("Səlahiyyət xətası (401/403): Sessiya etibarsızdır və ya cihaz revoke edilib");
              return;
            }
          } catch (_) {}

          if (attempts >= 15) {
            clearInterval(poll);
            setBusy("");
            // Timeout heç vaxt uğur sayılmır və locked state dəyişdirilmir
            setMessage("Gözləmə vaxtı bitdi: Kompüterdən təsdiq alınmadı (Timeout / Nəticə naməlum)");
          }
        }, 800);
      } else {
        const err = (await res.json().catch(() => ({}))) as any;
        setBusy("");
        setMessage("Xəta: " + (err.error || "Əmr göndərilə bilmədi"));
      }
    } catch (err: any) {
      setBusy("");
      setMessage("Şəbəkə xətası: " + err.message);
    }
  };

  return (
    <div className={styles.page}>
      {/* Şəbəkə və Rejim İndikatoru */}
      <div className={styles.demoBanner}>
        <div className={styles.demoTagGroup}>
          <span className={styles.demoBadge}>BULUD</span>
          <span className={styles.demoTitle}>Mobil İdarəetmə</span>
        </div>

        <button
          type="button"
          onClick={() => {
            const next = !isNetworkOnline;
            setIsNetworkOnline(next);
            setMessage(next ? "Kompüterlə bağlantı bərpa olundu" : "Kompüterlə əlaqə kəsildi (Oflayn)");
          }}
          className={`${styles.networkToggle} ${isNetworkOnline ? styles.networkOnline : styles.networkOffline}`}
          aria-label="Şəbəkə statusunu dəyiş"
        >
          {isNetworkOnline ? <Wifi size={13} /> : <WifiOff size={13} />}
          <span>{isNetworkOnline ? "Şəbəkə: Onlayn" : "Şəbəkə: Oflayn"}</span>
        </button>
      </div>

      {/* Əsas İdarəetmə Kartı */}
      <main className={styles.card}>
        <div className={styles.header}>
          <div className={styles.iconCircle}>
            <Monitor size={22} />
          </div>
          <div className={styles.titleGroup}>
            <div className={styles.nameRow}>
              <h2>{device.name}</h2>
              <span className={`${styles.statusDot} ${online ? styles.dotOnline : styles.dotOffline}`} />
            </div>
            <div className={styles.deviceMeta}>
              <span>{online ? "Onlayn" : "Oflayn"}</span>
              <span className={styles.metaDot}>•</span>
              <span className={device.locked === 1 ? styles.lockedText : device.locked === 0 ? styles.unlockedText : ""}>
                {device.locked === 1 ? "Kilidlidir" : device.locked === 0 ? "Açıqdır" : "Status gözlənilir"}
              </span>
              <span className={styles.metaDot}>•</span>
              <span style={{ fontSize: "11px", color: device.pin_ready ? "var(--green)" : "#e47878" }}>
                {device.pin_ready ? "PIN qorunur" : "PIN yoxdur"}
              </span>
            </div>
          </div>
        </div>

        {/* Nəticə / Xəbərdarlıq Mesajı */}
        <div className={styles.messageBox} role="status">
          <p>{message}</p>
        </div>

        {/* Əməliyyat Düymələri */}
        <div className={styles.actions}>
          <button
            type="button"
            className={`${styles.button} ${styles.unlockButton}`}
            disabled={!online || !!busy}
            onClick={() => handleAction("unlock")}
          >
            {busy === "unlock" ? (
              <LoaderCircle className={styles.spin} size={20} />
            ) : (
              <LockKeyholeOpen size={20} />
            )}
            <span>Kilidi Aç</span>
          </button>

          <button
            type="button"
            className={`${styles.button} ${styles.lockButton}`}
            disabled={!online || !!busy}
            onClick={() => handleAction("lock")}
          >
            {busy === "lock" ? (
              <LoaderCircle className={styles.spin} size={20} />
            ) : (
              <LockKeyhole size={20} />
            )}
            <span>Kilidlə</span>
          </button>
        </div>

        {/* Təhlükəsizlik Zəmanəti Bildirişi */}
        <footer className={styles.footer}>
          <p>
            🔒 Təhlükəsizlik Protokolu: Windows PIN qətiyyən telefona və ya bulud serverə ötürülmür.
            Əmr yalnız təsdiq olunmuş yerli DPAPI xidməti tərəfindən icra edilir.
          </p>
        </footer>
      </main>

      {/* Uğur Bildirişi (Toast) */}
      {successToast && (
        <div className={styles.toast} role="status">
          <div className={styles.toastIcon}>
            <Check size={16} />
          </div>
          <span>{successToast}</span>
        </div>
      )}
    </div>
  );
}
