"use client";
import React, { useEffect, useState, useRef } from "react";
import {
  LockKeyhole,
  Monitor,
  Plus,
  Wifi,
  ArrowUpRight,
  ShieldCheck,
  Power,
  X,
  Check,
  LoaderCircle,
  Smartphone,
  ChevronRight,
  CircleHelp,
  Fingerprint,
  AlertTriangle,
  History,
  Trash2,
  Laptop
} from "lucide-react";

type Device = {
  id: string;
  name: string;
  last_seen: number;
  locked: number | null;
  pin_ready: number;
  version?: string;
  is_revoked?: boolean;
};

type TimelineEvent = {
  id: string;
  time: string;
  action: string;
  status: "success" | "blocked" | "info" | "warning";
  detail: string;
};

const labels: Record<string, string> = { unlock: "Kilidi aç", lock: "Kilidlə", wake: "Ekranı oyat" };

export default function Dashboard({ userName }: { userName: string }) {
  // Real Cihazlar Siyahısı (Boş başlanğıc, sıfır demo fixture)
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);

  const [pair, setPair] = useState(false);
  const [help, setHelp] = useState(false);
  const [code, setCode] = useState("");
  const [pairBusy, setPairBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [tick, setTick] = useState(Date.now());
  const [loading, setLoading] = useState(true);

  // 1. Cihazlar və Tarixçənin Canlı Yüklənməsi
  useEffect(() => {
    let unmounted = false;
    const fetchDevices = async () => {
      try {
        const res = await fetch("/api/devices");
        if (res.ok) {
          const data = (await res.json()) as any;
          if (!unmounted && Array.isArray(data.devices)) {
            const list: Device[] = data.devices.map((d: any) => ({
              id: d.id,
              name: d.name || "Windows PC",
              last_seen: d.last_seen || Date.now(),
              locked: d.locked,
              pin_ready: d.pin_ready ? 1 : 0,
              version: "v1.0.0",
              is_revoked: d.status === "REVOKED"
            }));
            setDevices(list);
            if (list.length > 0) {
              setSelected((curr) => (curr && list.some(x => x.id === curr) ? curr : list[0].id));
            }
          }
        }
      } catch (_) {} finally {
        if (!unmounted) setLoading(false);
      }
    };

    const fetchHistory = async () => {
      try {
        const res = await fetch("/api/history");
        if (res.ok && !unmounted) {
          const data = (await res.json()) as any;
          if (Array.isArray(data.commands)) {
            setTimeline(data.commands.map((c: any) => ({
              id: c.id,
              time: new Date(c.created).toLocaleTimeString("az-AZ", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
              action: labels[c.action] || c.action,
              status: c.state === "success" ? "success" : c.state === "failed" ? "blocked" : "info",
              detail: c.result ? String(c.result) : `Vəziyyət: ${c.state}`
            })));
          }
        }
      } catch (_) {}
    };

    fetchDevices();
    fetchHistory();
    const interval = setInterval(() => {
      setTick(Date.now());
      fetchDevices();
      fetchHistory();
    }, 4000);
    return () => { unmounted = true; clearInterval(interval); };
  }, []);

  const device = devices.find((d) => d.id === selected) || devices[0];
  const isOnline = !!device && !device.is_revoked && tick - device.last_seen < 45000;
  const isLocked = device?.locked === 1;

  // 2. Real Cihazın Əlaqəsinin Ləğv Edilməsi (Revoke)
  const revokeDevice = async (devId: string) => {
    if (!confirm("Bu kompüteri idarəetmə panelindən çıxarmaq istədiyinizə əminsiniz?")) return;
    try {
      const res = await fetch("/api/devices/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: devId })
      });
      if (res.ok) {
        setDevices((prev) => prev.filter((d) => d.id !== devId));
        setSelected((prev) => (prev === devId ? "" : prev));
        setMessage("Kompüter qeydiyyatdan çıxarıldı (Ləğv edildi)");
      } else {
        const err = (await res.json().catch(() => ({}))) as any;
        setError(err.error || "Cihaz ləğv edilə bilmədi");
      }
    } catch (e: any) {
      setError("Şəbəkə xətası: " + e.message);
    }
  };

  // 3. Real Əmrin Göndərilməsi və Status Polling
  const triggerAction = async (action: "unlock" | "lock" | "wake") => {
    if (!device) return;
    if (!isOnline && action !== "wake") {
      setError("Kompüter oflayndır. Əmr yalnız aktiv kompüterə göndərilə bilər.");
      return;
    }
    if (action === "unlock" && !device.pin_ready) {
      setError("Bu kompüterdə Windows PIN saxlanılmayıb. Əvvəlcə WinKey Desktop proqramında PIN-i quraşdırın.");
      return;
    }

    setBusy(true);
    setError("");
    setMessage(action === "unlock" ? "Windows kilidi açılır…" : action === "lock" ? "Kompüter kilidlənir…" : "Ekran oyadılır…");

    try {
      const res = await fetch("/api/commands", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: device.id, action })
      });

      if (res.ok) {
        const data = (await res.json()) as any;
        const cmdId = data.command_id;
        
        let attempts = 0;
        const poll = setInterval(async () => {
          attempts++;
          try {
            const cRes = await fetch(`/api/commands/${cmdId}`);
            if (cRes.ok) {
              const cData = (await cRes.json()) as any;
              if (cData.state === "success") {
                clearInterval(poll);
                setBusy(false);
                setMessage(action === "unlock" ? "Windows kilidi açıldı ✓" : action === "lock" ? "Kompüter kilidləndi ✓" : "Ekran oyadıldı ✓");
                setDevices((prev) => prev.map((d) => (d.id === device.id ? { ...d, locked: action === "unlock" ? 0 : 1, last_seen: Date.now() } : d)));
                return;
              } else if (cData.state === "failed") {
                clearInterval(poll);
                setBusy(false);
                setError("Xəta: Əməliyyat kompüterdə icra edilə bilmədi");
                return;
              }
            }
          } catch (_) {}

          if (attempts >= 15) {
            clearInterval(poll);
            setBusy(false);
            setMessage("Əmr növbəyə alındı, xidmət cavabı gözlənilir…");
          }
        }, 800);
      } else {
        const err = (await res.json().catch(() => ({}))) as any;
        setBusy(false);
        setError("Əmr xətası: " + (err.error || "Əmr göndərilə bilmədi"));
      }
    } catch (err: any) {
      setBusy(false);
      setError("Şəbəkə xətası: " + err.message);
    }
  };

  // 4. Real Kodla Cihaz Cütləşməsi (Heç bir saxta fallback yoxdur)
  const pairDevice = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanCode = code.replace(/[-\s]/g, "").toUpperCase();
    if (cleanCode.length < 6) {
      setError("Düzgün qoşulma kodunu daxil edin");
      return;
    }
    setPairBusy(true);
    setError("");
    try {
      const res = await fetch("/api/pair", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pair_code: cleanCode })
      });
      if (res.ok) {
        const data = (await res.json()) as any;
        setMessage("Yeni kompüter uğurla bağlandı: " + (data.name || "Windows PC") + " ✓");
        setPair(false);
        setCode("");
        // Cihazlar siyahısını dərhal yenilə
        const dRes = await fetch("/api/devices");
        if (dRes.ok) {
          const dData = (await dRes.json()) as any;
          if (Array.isArray(dData.devices)) {
            setDevices(dData.devices.map((d: any) => ({
              id: d.id,
              name: d.name || "Windows PC",
              last_seen: d.last_seen || Date.now(),
              locked: d.locked,
              pin_ready: d.pin_ready ? 1 : 0,
              version: "v1.0.0",
              is_revoked: false
            })));
            if (data.device_id) setSelected(data.device_id);
          }
        }
      } else {
        const err = (await res.json().catch(() => ({}))) as any;
        setError(err.error || "Qoşulma kodu yanlışdır və ya vaxtı bitib");
      }
    } catch (e: any) {
      setError("Şəbəkə xətası: " + e.message);
    } finally {
      setPairBusy(false);
    }
  };

  return (
    <div className="shell">
      {/* Sol Sidebar */}
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brandIcon">
            <LockKeyhole size={22} />
          </span>
          WinKey
          <span className="brandDot" />
        </a>

        {/* CLOUD PROD BADGE */}
        <div style={{
          background: "#1c2c1e",
          border: "1px solid #2d4530",
          color: "#c8f279",
          padding: "5px 10px",
          borderRadius: "6px",
          fontSize: "10px",
          fontWeight: 700,
          marginBottom: "20px",
          textAlign: "center"
        }}>
          BULUD İDARƏETMƏ MƏRKƏZİ
        </div>

        <div className="navLabel">İDARƏETMƏ</div>
        <div className="navItem active">
          <Monitor size={18} />
          Kompüterlərim
          <span>{devices.length}</span>
        </div>

        <button className="navItem" onClick={() => setHelp(true)}>
          <CircleHelp size={18} />
          Necə işləyir
        </button>

        <a className="navItem" href="/desktop" target="_blank" rel="noopener noreferrer">
          <Laptop size={18} />
          Desktop Görünüşü ↗
        </a>

        <a className="navItem" href="/mobile" target="_blank" rel="noopener noreferrer">
          <Smartphone size={18} />
          Mobil PWA ↗
        </a>

        <div className="sidebarBottom">
          <div className="secureIcon">
            <ShieldCheck size={21} />
          </div>
          <strong>Sənin kompüterin.<br />Sənin nəzarətin.</strong>
          <p>PIN kodları buluda göndərilmir, yalnız yerli kompüterdə saxlanılır.</p>
          <div className="profile">
            <div className="avatar">{userName ? userName.slice(0, 1).toUpperCase() : "U"}</div>
            <div>
              <strong>{userName || "İstifadəçi"}</strong>
              <small>Layihə Sahibi</small>
            </div>
          </div>
        </div>
      </aside>

      {/* Əsas Panel */}
      <main>
        <header>
          <div className="mobileBrand">
            <LockKeyhole size={20} />
            WinKey
          </div>
          <div className="breadcrumb">
            İdarəetmə paneli <ChevronRight size={14} /> Kompüterlərim
          </div>
          <div className="privateBadge">
            <ShieldCheck size={14} />
            Yalnız Təsdiqli Giriş
          </div>
        </header>

        <div className="content">
          <div className="pageTop">
            <div>
              <div className="eyebrow">HƏR YERDƏN TƏHLÜKƏSİZ İDARƏ</div>
              <h1>Kompüterləriniz.</h1>
              <p>Masaüstü vəziyyətini izləyin, kilidi açın və təhlükəsizlik hadisələrini yoxlayın.</p>
            </div>
            <button className="addButton" onClick={() => { setPair(true); setError(""); }}>
              <Plus size={18} />
              Yeni Kompüter Qoş
            </button>
          </div>

          {error && (
            <div className="alert error" role="alert">
              {error}
              <button aria-label="Bağla" onClick={() => setError("")}>
                <X size={16} />
              </button>
            </div>
          )}

          {message && (
            <div className="alert success" role="status" style={{ background: "#1c2b1e", borderColor: "#304b34", color: "#c8f279", marginBottom: "16px", padding: "10px 14px", borderRadius: "8px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span>{message}</span>
              <button aria-label="Bağla" onClick={() => setMessage("")} style={{ background: "transparent", border: "none", color: "#c8f279", cursor: "pointer" }}>
                <X size={16} />
              </button>
            </div>
          )}

          <div className="workspace">
            {/* Cihazlar Siyahısı */}
            <section className="devicesPanel">
              <div className="sectionTitle">
                KOMPÜTERLƏRİM <span>{devices.length.toString().padStart(2, "0")}</span>
              </div>

              {devices.length === 0 ? (
                <div style={{ padding: "36px 16px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>
                  <Monitor size={36} style={{ margin: "0 auto 12px", opacity: 0.35 }} />
                  <p style={{ fontWeight: 600, color: "var(--text)" }}>Hələ bağlı kompüter yoxdur</p>
                  <p style={{ fontSize: "11px", marginTop: "6px", lineHeight: "1.5" }}>
                    WinKey Desktop proqramını kompüterinizdə açın və yuxarıdakı "Yeni Kompüter Qoş" düyməsi ilə QR kodunu daxil edin.
                  </p>
                </div>
              ) : (
                devices.map((d) => (
                  <button
                    key={d.id}
                    className={"deviceTile " + (device?.id === d.id ? "chosen" : "")}
                    onClick={() => setSelected(d.id)}
                  >
                    <div className="deviceTileTop">
                      <span className="monitorIcon">
                        <Monitor size={23} />
                      </span>
                      <span
                        className={
                          "dot " +
                          (d.is_revoked ? "" : tick - d.last_seen < 45000 ? "online" : "")
                        }
                        style={{ background: d.is_revoked ? "#e47878" : undefined }}
                      />
                    </div>
                    <div className="deviceTileBottom">
                      <div className="tileName">{d.name}</div>
                      <div className="tileSub">
                        {d.is_revoked ? "Ləğv edilib" : tick - d.last_seen < 45000 ? "Bağlıdır · Hazırdır" : "Oflayn"}
                      </div>
                    </div>
                  </button>
                ))
              )}
            </section>

            {/* Seçilmiş Cihazın Detalları və İdarəetmə Paneli */}
            {device ? (
              <section className="detailPanel">
                <div className="deviceHeader">
                  <div>
                    <span className="onlinePill">
                      <span className={"dot " + (isOnline ? "online" : "")} />
                      {isOnline ? "CANLI ƏLAQƏ" : "OFLAYN"}
                    </span>
                    <h2>{device.name}</h2>
                    <div className="deviceUuid">ID: {device.id}</div>
                  </div>

                  <button
                    className="btnDangerOutline"
                    title="Cihazı sistemdən ləğv et (Revoke)"
                    onClick={() => revokeDevice(device.id)}
                    style={{
                      background: "transparent",
                      border: "1px solid #4a2828",
                      color: "#f78d7e",
                      padding: "6px 12px",
                      borderRadius: "6px",
                      cursor: "pointer",
                      fontSize: "12px",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px"
                    }}
                  >
                    <Trash2 size={14} />
                    Cihazı Sil
                  </button>
                </div>

                <div className="metricsGrid">
                  <div className="metricCard">
                    <span className="metricLabel">Masaüstü Vəziyyəti</span>
                    <span className="metricVal" style={{ color: isLocked ? "#f78d7e" : "var(--green)" }}>
                      {isLocked ? "Kilidlidir" : "Açıqdır"}
                    </span>
                  </div>
                  <div className="metricCard">
                    <span className="metricLabel">Yerli DPAPI PIN</span>
                    <span className="metricVal" style={{ color: device.pin_ready ? "var(--green)" : "#f78d7e" }}>
                      {device.pin_ready ? "Qorunur (Hazırdır)" : "Təyin Edilməyib"}
                    </span>
                  </div>
                  <div className="metricCard">
                    <span className="metricLabel">Son Siqnal (Heartbeat)</span>
                    <span className="metricVal">
                      {Math.max(0, Math.floor((tick - device.last_seen) / 1000))} saniyə əvvəl
                    </span>
                  </div>
                </div>

                {/* Əmr Düymələri */}
                <div className="actionRow" style={{ display: "flex", gap: "10px", marginTop: "20px" }}>
                  <button
                    className="btnAction"
                    disabled={!isOnline || busy}
                    onClick={() => triggerAction("unlock")}
                    style={{
                      flex: 1,
                      padding: "12px",
                      background: "var(--green)",
                      color: "#121810",
                      border: "none",
                      borderRadius: "8px",
                      fontWeight: 700,
                      cursor: isOnline && !busy ? "pointer" : "not-allowed",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "8px"
                    }}
                  >
                    {busy ? <LoaderCircle className="spin" size={16} /> : <LockKeyhole size={16} />}
                    Masaüstü Kilidini Aç
                  </button>

                  <button
                    className="btnSecondary"
                    disabled={!isOnline || busy}
                    onClick={() => triggerAction("lock")}
                    style={{
                      flex: 1,
                      padding: "12px",
                      background: "#232b25",
                      color: "var(--text)",
                      border: "1px solid var(--line)",
                      borderRadius: "8px",
                      fontWeight: 600,
                      cursor: isOnline && !busy ? "pointer" : "not-allowed",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "8px"
                    }}
                  >
                    <Power size={16} />
                    Masaüstünü Kilidlə
                  </button>
                </div>

                {/* Hadisə İzləmə Tarixçəsi */}
                <div style={{ marginTop: "28px" }}>
                  <div style={{ fontSize: "13px", fontWeight: 700, color: "var(--text)", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
                    <History size={16} />
                    Audit və Hadisələr Tarixçəsi
                  </div>
                  {timeline.length === 0 ? (
                    <div style={{ fontSize: "12px", color: "var(--text-muted)", padding: "16px 0" }}>
                      Hələ əməliyyat hadisəsi qeydə alınmayıb.
                    </div>
                  ) : (
                    <div className="timelineList" style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {timeline.slice(0, 5).map((evt) => (
                        <div key={evt.id} style={{ background: "#141716", padding: "10px 14px", borderRadius: "6px", border: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <span style={{ fontWeight: 600, fontSize: "13px", color: evt.status === "success" ? "var(--green)" : evt.status === "blocked" ? "#f78d7e" : "var(--text)" }}>{evt.action}</span>
                            <span style={{ fontSize: "11px", color: "var(--text-muted)", marginLeft: "8px" }}>{evt.detail}</span>
                          </div>
                          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "monospace" }}>{evt.time}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </section>
            ) : (
              <section className="detailPanel" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "360px", color: "var(--text-muted)", flexDirection: "column", gap: "10px" }}>
                <Monitor size={48} style={{ opacity: 0.3 }} />
                <span>Heç bir kompüter seçilməyib</span>
              </section>
            )}
          </div>
        </div>
      </main>

      {/* Cütləşmə Modalı (Yalnız həqiqi D1 API yoxlanışı) */}
      {pair && (
        <div className="modalBackdrop">
          <div className="modal">
            <div className="modalHeader">
              <h3>Yeni Kompüter Qoş</h3>
              <button aria-label="Bağla" onClick={() => setPair(false)}>
                <X size={18} />
              </button>
            </div>
            <form onSubmit={pairDevice}>
              <p style={{ fontSize: "12px", color: "var(--text-muted)", marginBottom: "16px" }}>
                Kompüterinizdəki WinKey Desktop proqramının göstərdiyi 8 simvollu birdəfəlik qoşulma kodunu daxil edin.
              </p>
              <div className="inputGroup">
                <input
                  type="text"
                  placeholder="Məsələn: WK-AB12-CD34"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  maxLength={16}
                  autoFocus
                  style={{ textTransform: "uppercase", letterSpacing: "1px", fontFamily: "monospace" }}
                />
              </div>
              <div style={{ display: "flex", gap: "8px", justifyContent: "flex-end", marginTop: "16px" }}>
                <button type="button" className="btnSecondary" onClick={() => setPair(false)}>
                  Ləğv Et
                </button>
                <button type="submit" className="btnAction" disabled={pairBusy}>
                  {pairBusy ? "Yoxlanılır…" : "Kompüteri Bağla"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Təlimat Modalı */}
      {help && (
        <div className="modalBackdrop">
          <div className="modal">
            <div className="modalHeader">
              <h3>WinKey Pro Necə İşləyir?</h3>
              <button aria-label="Bağla" onClick={() => setHelp(false)}>
                <X size={18} />
              </button>
            </div>
            <div style={{ fontSize: "13px", color: "var(--text-muted)", lineHeight: "1.6" }}>
              <p style={{ marginBottom: "10px" }}>
                <strong>1. Sıfır Bulud PIN Yaddaşı:</strong> Windows giriş PIN-iniz heç vaxt bulud serverə və ya telefona göndərilmir. Windows DPAPI ilə kompüterinizdə qorunur.
              </p>
              <p style={{ marginBottom: "10px" }}>
                <strong>2. Ed25519 Kriptoqrafik İmza:</strong> Hər bir əmr cihaz tərəfindən imzalanır və təhlükəsizlik kanalı ilə ötürülür.
              </p>
              <p>
                <strong>3. İkiqat Rejim:</strong> Həm lokal Wi-Fi şəbəkəsində birbaşa (LAN), həm də internet vasitəsilə qlobal idarəetməni dəstəkləyir.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
