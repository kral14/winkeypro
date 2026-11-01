"use client";
import React, { useState } from "react";
import {
  Monitor,
  ShieldCheck,
  LockKeyhole,
  QrCode,
  Sliders,
  HelpCircle,
  Eye,
  EyeOff,
  CheckCircle2,
  Power,
  Info,
  Laptop,
  Check,
  Smartphone,
  X,
  AlertTriangle,
  RotateCcw,
  Layers,
  ArrowRight
} from "lucide-react";

export default function DesktopPreview() {
  const [tab, setTab] = useState<"onboarding" | "status" | "qr" | "settings" | "support">("status");
  const [pcName, setPcName] = useState("Nesib-Workstation");
  const [isEditingName, setIsEditingName] = useState(false);
  const [tempName, setTempName] = useState("Nesib-Workstation");
  const [pinMasked, setPinMasked] = useState(true);
  const [dummyPin, setDummyPin] = useState("984120");
  const [pinSavedToast, setPinSavedToast] = useState(false);
  const [isServiceRunning, setIsServiceRunning] = useState(true);
  const [isMobilePaired, setIsMobilePaired] = useState(true);
  const [trayHidden, setTrayHidden] = useState(false);
  const [supportCopied, setSupportCopied] = useState(false);
  const [onboardingStep, setOnboardingStep] = useState(1);

  // X düyməsi -> Sistem Tepsisi (Tray) simulyasiyası
  if (trayHidden) {
    return (
      <div style={{
        minHeight: "100vh",
        background: "#101312",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "24px",
        fontFamily: 'Inter, "Segoe UI", Arial, sans-serif',
        color: "#f0f4ed"
      }}>
        <div style={{
          background: "#191d1b",
          border: "1px solid #2a302c",
          borderRadius: "16px",
          padding: "36px",
          maxWidth: "480px",
          textAlign: "center",
          boxShadow: "0 20px 50px rgba(0,0,0,0.6)"
        }}>
          <div style={{
            width: "56px",
            height: "56px",
            borderRadius: "50%",
            background: "#263221",
            color: "#c8f279",
            display: "grid",
            placeItems: "center",
            margin: "0 auto 20px"
          }}>
            <LockKeyhole size={28} />
          </div>
          <h2 style={{ fontSize: "20px", fontWeight: 600, margin: "0 0 10px 0", color: "#f0f4ed" }}>
            WinKey Sistem Tepsisindədir (Tray)
          </h2>
          <p style={{ fontSize: "13px", color: "#89958a", lineHeight: 1.7, margin: "0 0 24px 0" }}>
            X düyməsinə basıldıqda tətbiq pəncərəsi gizləndi, lakin <strong>Windows xidməti və mobil uzaqdan idarəetmə arxa fonda fasiləsiz işləyir</strong>.
          </p>
          <div style={{
            background: "#121513",
            border: "1px solid #2a302c",
            borderRadius: "8px",
            padding: "10px 14px",
            fontSize: "11px",
            color: "#c8f279",
            marginBottom: "24px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            justifyContent: "center"
          }}>
            <span style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#c8f279" }} />
            <span>Heartbeat və təhlükəsiz IPC əlaqəsi aktivdir</span>
          </div>
          <button
            onClick={() => setTrayHidden(false)}
            style={{
              width: "100%",
              background: "#c8f279",
              color: "#21301b",
              border: "none",
              borderRadius: "8px",
              padding: "12px 20px",
              fontWeight: 600,
              fontSize: "13px",
              cursor: "pointer"
            }}
          >
            Pəncərəni Ekrana Qaytar
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{
      minHeight: "100vh",
      background: "#101312",
      color: "#f0f4ed",
      fontFamily: 'Inter, "Segoe UI", Arial, sans-serif',
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: "24px"
    }}>
      {/* Yuxarı DEMO Rejimi Banneri */}
      <div style={{
        maxWidth: "920px",
        width: "100%",
        marginBottom: "12px",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "#263221",
        border: "1px solid #3d4f34",
        padding: "8px 16px",
        borderRadius: "10px",
        fontSize: "12px"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{
            background: "#c8f279",
            color: "#1c2616",
            fontWeight: 700,
            fontSize: "10px",
            padding: "2px 7px",
            borderRadius: "4px",
            letterSpacing: "0.5px"
          }}>
            DEMO REJİMİ
          </span>
          <span style={{ color: "#d2dec9" }}>
            Lokal Önizləmə: Bütün kliklər və vəziyyətlər canlı simulyasiya edilir, production əmri göndərilmir.
          </span>
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <a
            href="/mobile"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "#c8f279", textDecoration: "underline", fontSize: "11px", fontWeight: 600 }}
          >
            Mobil PWA-nı aç ↗
          </a>
          <span style={{ color: "#4f6345" }}>|</span>
          <a
            href="/admin"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: "#c8f279", textDecoration: "underline", fontSize: "11px", fontWeight: 600 }}
          >
            Admin Paneli aç ↗
          </a>
        </div>
      </div>

      {/* Əsas Desktop Pəncərə Çərçivəsi */}
      <div style={{
        width: "100%",
        maxWidth: "920px",
        background: "#191d1b",
        borderRadius: "16px",
        border: "1px solid #2a302c",
        boxShadow: "0 25px 60px -15px rgba(0, 0, 0, 0.8)",
        overflow: "hidden",
        display: "flex",
        flexDirection: "column"
      }}>
        {/* Windows Titlebar */}
        <div style={{
          height: "46px",
          background: "#141815",
          borderBottom: "1px solid #2a302c",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 18px",
          userSelect: "none"
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{
              width: "24px",
              height: "24px",
              borderRadius: "6px",
              background: "#c8f279",
              display: "grid",
              placeItems: "center",
              color: "#21301b"
            }}>
              <LockKeyhole size={14} />
            </div>
            <strong style={{ fontSize: "13px", fontWeight: 600, color: "#f0f4ed" }}>
              WinKey Pro Desktop
            </strong>
            <span style={{
              fontSize: "10px",
              background: "#222a24",
              border: "1px solid #334035",
              color: "#9aab9c",
              padding: "2px 8px",
              borderRadius: "12px",
              marginLeft: "4px"
            }}>
              v1.0.0 · x64
            </span>
          </div>

          {/* Window Buttons */}
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <button
              onClick={() => alert("Pəncərə minimum ölçüyə salındı")}
              style={{
                width: "12px",
                height: "12px",
                borderRadius: "50%",
                background: "#4b574d",
                border: "none",
                cursor: "pointer"
              }}
              title="Kiçilt"
            />
            <button
              onClick={() => alert("Pəncərə böyüdüldü")}
              style={{
                width: "12px",
                height: "12px",
                borderRadius: "50%",
                background: "#4b574d",
                border: "none",
                cursor: "pointer"
              }}
              title="Tam Ekran"
            />
            <button
              onClick={() => setTrayHidden(true)}
              style={{
                width: "12px",
                height: "12px",
                borderRadius: "50%",
                background: "#e47878",
                border: "none",
                cursor: "pointer"
              }}
              title="Bağla (Sistem Tepsisinə Gizlənir)"
            />
          </div>
        </div>

        {/* Gövdə: Sol Naviqasiya + Sağ Məzmun */}
        <div style={{ display: "flex", minHeight: "510px" }}>
          {/* Sol Sidebar */}
          <div style={{
            width: "220px",
            background: "#141815",
            borderRight: "1px solid #2a302c",
            padding: "20px 14px",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between"
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              <div style={{
                fontSize: "10px",
                fontWeight: 700,
                color: "#68776a",
                letterSpacing: "1.5px",
                padding: "0 10px 8px 10px"
              }}>
                İDARƏETMƏ
              </div>

              <button
                onClick={() => setTab("status")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  background: tab === "status" ? "#263221" : "transparent",
                  color: tab === "status" ? "#c8f279" : "#9aab9c",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "12px",
                  fontWeight: tab === "status" ? 600 : 500,
                  textAlign: "left"
                }}
              >
                <Monitor size={16} />
                <span>Cihaz Statusu</span>
              </button>

              <button
                onClick={() => setTab("qr")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  background: tab === "qr" ? "#263221" : "transparent",
                  color: tab === "qr" ? "#c8f279" : "#9aab9c",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "12px",
                  fontWeight: tab === "qr" ? 600 : 500,
                  textAlign: "left"
                }}
              >
                <QrCode size={16} />
                <span>Mobil QR Qoşma</span>
              </button>

              <button
                onClick={() => setTab("settings")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  background: tab === "settings" ? "#263221" : "transparent",
                  color: tab === "settings" ? "#c8f279" : "#9aab9c",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "12px",
                  fontWeight: tab === "settings" ? 600 : 500,
                  textAlign: "left"
                }}
              >
                <Sliders size={16} />
                <span>Təhlükəsizlik & PIN</span>
              </button>

              <button
                onClick={() => setTab("onboarding")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  background: tab === "onboarding" ? "#263221" : "transparent",
                  color: tab === "onboarding" ? "#c8f279" : "#9aab9c",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "12px",
                  fontWeight: tab === "onboarding" ? 600 : 500,
                  textAlign: "left"
                }}
              >
                <Layers size={16} />
                <span>Quraşdırma Bələdçisi</span>
              </button>

              <button
                onClick={() => setTab("support")}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "10px",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  background: tab === "support" ? "#263221" : "transparent",
                  color: tab === "support" ? "#c8f279" : "#9aab9c",
                  border: "none",
                  cursor: "pointer",
                  fontSize: "12px",
                  fontWeight: tab === "support" ? 600 : 500,
                  textAlign: "left"
                }}
              >
                <HelpCircle size={16} />
                <span>Dəstək & Loqlar</span>
              </button>
            </div>

            {/* Sol alt status */}
            <div style={{
              background: "#1c221e",
              border: "1px solid #2d382c",
              borderRadius: "10px",
              padding: "12px",
              fontSize: "11px"
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "7px", marginBottom: "4px" }}>
                <span style={{
                  width: "7px",
                  height: "7px",
                  borderRadius: "50%",
                  background: isServiceRunning ? "#c8f279" : "#e47878",
                  boxShadow: isServiceRunning ? "0 0 8px #c8f27955" : "none"
                }} />
                <strong style={{ color: "#f0f4ed", fontSize: "11px" }}>
                  {isServiceRunning ? "Xidmət Onlayndır" : "Xidmət Dayandı"}
                </strong>
              </div>
              <p style={{ color: "#89958a", margin: 0, fontSize: "10px", lineHeight: 1.5 }}>
                {isMobilePaired ? "1 Telefon bağlıdır (Onlayn)" : "Mobil bağlantı gözlənilir"}
              </p>
            </div>
          </div>

          {/* Sağ Əsas Məzmun */}
          <div style={{ flex: 1, padding: "28px 32px", overflowY: "auto" }}>
            {/* 1. Status Ekranı */}
            {tab === "status" && (
              <div>
                <div style={{ marginBottom: "22px" }}>
                  <div style={{ color: "#c8f279", fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", marginBottom: "6px" }}>
                    CİHAZINIZ
                  </div>
                  <h1 style={{ fontSize: "22px", fontWeight: 600, color: "#f0f4ed", margin: 0 }}>
                    Kompüterinizin Vəziyyəti
                  </h1>
                </div>

                {/* PC Adı Kartı */}
                <div style={{
                  background: "#1c221e",
                  border: "1px solid #2d382c",
                  borderRadius: "12px",
                  padding: "16px 20px",
                  marginBottom: "16px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
                    <div style={{
                      width: "42px",
                      height: "42px",
                      borderRadius: "10px",
                      background: "#263221",
                      display: "grid",
                      placeItems: "center",
                      color: "#c8f279"
                    }}>
                      <Laptop size={22} />
                    </div>
                    <div>
                      <div style={{ fontSize: "10px", color: "#89958a", fontWeight: 600 }}>KOMPÜTER ADI</div>
                      {isEditingName ? (
                        <div style={{ display: "flex", gap: "8px", marginTop: "4px" }}>
                          <input
                            type="text"
                            value={tempName}
                            onChange={(e) => setTempName(e.target.value)}
                            style={{
                              background: "#101312",
                              border: "1px solid #c8f279",
                              color: "#f0f4ed",
                              borderRadius: "6px",
                              padding: "4px 8px",
                              fontSize: "13px"
                            }}
                          />
                          <button
                            onClick={() => {
                              setPcName(tempName);
                              setIsEditingName(false);
                            }}
                            style={{
                              background: "#c8f279",
                              border: "none",
                              borderRadius: "6px",
                              color: "#21301b",
                              padding: "4px 10px",
                              cursor: "pointer",
                              fontSize: "11px",
                              fontWeight: 600
                            }}
                          >
                            Saxla
                          </button>
                        </div>
                      ) : (
                        <strong style={{ fontSize: "15px", color: "#f0f4ed" }}>{pcName}</strong>
                      )}
                    </div>
                  </div>

                  {!isEditingName && (
                    <button
                      onClick={() => {
                        setTempName(pcName);
                        setIsEditingName(true);
                      }}
                      style={{
                        background: "#222a21",
                        border: "1px solid #3c4a37",
                        color: "#9ead95",
                        borderRadius: "6px",
                        padding: "6px 12px",
                        fontSize: "11px",
                        cursor: "pointer"
                      }}
                    >
                      Dəyişdir
                    </button>
                  )}
                </div>

                {/* 2 Sütunlu Kartlar */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px", marginBottom: "20px" }}>
                  <div style={{
                    background: "#1c221e",
                    border: "1px solid #2d382c",
                    borderRadius: "12px",
                    padding: "16px 18px"
                  }}>
                    <div style={{ fontSize: "10px", color: "#89958a", fontWeight: 600, marginBottom: "6px" }}>
                      WİNDOWS KİLİDİ
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <CheckCircle2 size={16} color="#c8f279" />
                      <strong style={{ fontSize: "13px", color: "#f0f4ed" }}>Qorunur və hazırdır</strong>
                    </div>
                    <p style={{ fontSize: "11px", color: "#89958a", margin: "6px 0 0 0", lineHeight: 1.5 }}>
                      Pərdə toxunuşu və tək cəhd təsdiqi aktivdir.
                    </p>
                  </div>

                  <div style={{
                    background: "#1c221e",
                    border: "1px solid #2d382c",
                    borderRadius: "12px",
                    padding: "16px 18px"
                  }}>
                    <div style={{ fontSize: "10px", color: "#89958a", fontWeight: 600, marginBottom: "6px" }}>
                      YERLİ CREDENTIAL (DPAPI)
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <ShieldCheck size={16} color="#c8f279" />
                      <strong style={{ fontSize: "13px", color: "#f0f4ed" }}>PIN yerli saxlanılıb</strong>
                    </div>
                    <p style={{ fontSize: "11px", color: "#89958a", margin: "6px 0 0 0", lineHeight: 1.5 }}>
                      PIN internetə və ya serverə getmir.
                    </p>
                  </div>
                </div>

                {/* Qoşulmuş Mobil Cihaz Kartı */}
                <div style={{
                  background: "#181d1a",
                  border: "1px solid #2a3428",
                  borderRadius: "12px",
                  padding: "16px 20px",
                  marginBottom: "20px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between"
                }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                    <div style={{
                      width: "36px",
                      height: "36px",
                      borderRadius: "8px",
                      background: "#263221",
                      display: "grid",
                      placeItems: "center",
                      color: "#c8f279"
                    }}>
                      <Smartphone size={18} />
                    </div>
                    <div>
                      <strong style={{ fontSize: "13px", color: "#f0f4ed" }}>
                        {isMobilePaired ? "iPhone 15 Pro (Sahib)" : "Heç bir mobil telefon qoşulmayıb"}
                      </strong>
                      <div style={{ fontSize: "11px", color: isMobilePaired ? "#c8f279" : "#e47878" }}>
                        {isMobilePaired ? "● Onlayn · İdarəetmə icazəsi var" : "○ Qoşulma gözlənilir"}
                      </div>
                    </div>
                  </div>

                  {isMobilePaired ? (
                    <button
                      onClick={() => setIsMobilePaired(false)}
                      style={{
                        background: "#352220",
                        border: "1px solid #5a332d",
                        color: "#f5a596",
                        borderRadius: "6px",
                        padding: "6px 12px",
                        fontSize: "11px",
                        cursor: "pointer"
                      }}
                    >
                      Bağlantını Ləğv Et (Revoke)
                    </button>
                  ) : (
                    <button
                      onClick={() => setTab("qr")}
                      style={{
                        background: "#263221",
                        border: "1px solid #3d4f34",
                        color: "#c8f279",
                        borderRadius: "6px",
                        padding: "6px 12px",
                        fontSize: "11px",
                        cursor: "pointer",
                        fontWeight: 600
                      }}
                    >
                      QR Kodu Göstər
                    </button>
                  )}
                </div>

                {/* Əməliyyat Düymələri */}
                <div style={{ display: "flex", gap: "12px" }}>
                  <button
                    onClick={() => setTab("qr")}
                    style={{
                      flex: 1,
                      background: "#c8f279",
                      color: "#21301b",
                      border: "none",
                      borderRadius: "8px",
                      padding: "12px 18px",
                      fontSize: "13px",
                      fontWeight: 600,
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      gap: "8px"
                    }}
                  >
                    <QrCode size={16} />
                    <span>Yeni Telefonu QR ilə Qoş</span>
                  </button>

                  <button
                    onClick={() => setIsServiceRunning(!isServiceRunning)}
                    style={{
                      background: isServiceRunning ? "#222a21" : "#c8f279",
                      border: "1px solid #3c4a37",
                      color: isServiceRunning ? "#9ead95" : "#21301b",
                      borderRadius: "8px",
                      padding: "12px 16px",
                      fontSize: "13px",
                      fontWeight: 600,
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px"
                    }}
                  >
                    <Power size={15} />
                    <span>{isServiceRunning ? "Uzaqdan İdarəni Dayandır" : "Xidməti Başlat"}</span>
                  </button>
                </div>
              </div>
            )}

            {/* 2. QR Qoşma Ekranı */}
            {tab === "qr" && (
              <div>
                <div style={{ marginBottom: "20px" }}>
                  <div style={{ color: "#c8f279", fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", marginBottom: "6px" }}>
                    TELEFON BAĞLANTISI
                  </div>
                  <h1 style={{ fontSize: "22px", fontWeight: 600, color: "#f0f4ed", margin: 0 }}>
                    Telefonunuzu Kompüterə Qoşun
                  </h1>
                </div>

                <div style={{
                  background: "#1c221e",
                  border: "1px solid #2d382c",
                  borderRadius: "14px",
                  padding: "24px",
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: "18px"
                }}>
                  {/* Realist SVG QR Vizualı */}
                  <div style={{
                    width: "170px",
                    height: "170px",
                    background: "#ffffff",
                    borderRadius: "10px",
                    padding: "12px",
                    display: "grid",
                    placeItems: "center",
                    boxShadow: "0 8px 24px rgba(0,0,0,0.5)"
                  }}>
                    <svg viewBox="0 0 100 100" width="100%" height="100%" fill="#141815">
                      <rect x="0" y="0" width="30" height="30" rx="4" />
                      <rect x="6" y="6" width="18" height="18" fill="#fff" rx="2" />
                      <rect x="10" y="10" width="10" height="10" rx="1" />

                      <rect x="70" y="0" width="30" height="30" rx="4" />
                      <rect x="76" y="6" width="18" height="18" fill="#fff" rx="2" />
                      <rect x="80" y="10" width="10" height="10" rx="1" />

                      <rect x="0" y="70" width="30" height="30" rx="4" />
                      <rect x="6" y="76" width="18" height="18" fill="#fff" rx="2" />
                      <rect x="10" y="80" width="10" height="10" rx="1" />

                      <rect x="40" y="10" width="20" height="10" />
                      <rect x="40" y="35" width="25" height="15" />
                      <rect x="10" y="45" width="15" height="15" />
                      <rect x="75" y="45" width="15" height="20" />
                      <rect x="45" y="70" width="20" height="20" />
                      <rect x="75" y="75" width="15" height="15" />
                    </svg>
                  </div>

                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: "10px", color: "#89958a", fontWeight: 700, letterSpacing: "1px", marginBottom: "4px" }}>
                      BİRDƏFƏLİK QOŞULMA KODU (120 SANİYƏ)
                    </div>
                    <div style={{
                      fontSize: "20px",
                      fontWeight: 700,
                      letterSpacing: "0.15em",
                      color: "#c8f279",
                      fontFamily: "monospace",
                      background: "#101312",
                      padding: "8px 18px",
                      borderRadius: "8px",
                      border: "1px solid #2d382c"
                    }}>
                      ABCD-EFGH-JKLM
                    </div>
                  </div>

                  {/* Kliklənən Simulyasiya Düyməsi */}
                  <button
                    onClick={() => {
                      setIsMobilePaired(true);
                      setTab("status");
                    }}
                    style={{
                      background: "#263221",
                      border: "1px solid #3d4f34",
                      color: "#c8f279",
                      borderRadius: "8px",
                      padding: "8px 16px",
                      fontSize: "12px",
                      cursor: "pointer",
                      fontWeight: 600
                    }}
                  >
                    Mobil Qoşulmanı Simulyasiya Et ✓
                  </button>

                  <p style={{ fontSize: "11px", color: "#89958a", maxWidth: "420px", textAlign: "center", margin: 0, lineHeight: 1.6 }}>
                    Telefon kamerasını QR koda tutun və ya kodu WinKey Mobil səhifəsinə yazın.
                    QR kodda heç bir PIN və ya daimi açar daşınmır.
                  </p>
                </div>
              </div>
            )}

            {/* 3. Təhlükəsizlik və PIN Ekranı */}
            {tab === "settings" && (
              <div>
                <div style={{ marginBottom: "20px" }}>
                  <div style={{ color: "#c8f279", fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", marginBottom: "6px" }}>
                    MƏXFİLİK VƏ GİRİŞ
                  </div>
                  <h1 style={{ fontSize: "22px", fontWeight: 600, color: "#f0f4ed", margin: 0 }}>
                    Təhlükəsizlik və PIN İdarəsi
                  </h1>
                </div>

                <div style={{
                  background: "#1c221e",
                  border: "1px solid #2d382c",
                  borderRadius: "14px",
                  padding: "24px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "18px"
                }}>
                  <div>
                    <label style={{ display: "block", fontSize: "11px", fontWeight: 600, color: "#9aab9c", marginBottom: "8px" }}>
                      WINDOWS UNLOCK PIN / PAROL
                    </label>
                    <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                      <input
                        type={pinMasked ? "password" : "text"}
                        value={dummyPin}
                        onChange={(e) => setDummyPin(e.target.value)}
                        style={{
                          flex: 1,
                          background: "#101312",
                          border: "1px solid #2d382c",
                          borderRadius: "8px",
                          padding: "10px 14px",
                          color: "#f0f4ed",
                          fontSize: "15px",
                          letterSpacing: pinMasked ? "0.2em" : "normal"
                        }}
                      />
                      <button
                        onClick={() => setPinMasked(!pinMasked)}
                        style={{
                          background: "#222a21",
                          border: "1px solid #3c4a37",
                          color: "#9ead95",
                          borderRadius: "8px",
                          padding: "10px 14px",
                          cursor: "pointer",
                          display: "flex",
                          alignItems: "center",
                          gap: "6px",
                          fontSize: "11px"
                        }}
                      >
                        {pinMasked ? <Eye size={15} /> : <EyeOff size={15} />}
                        <span>{pinMasked ? "Göstər" : "Gizlət"}</span>
                      </button>
                      <button
                        onClick={() => {
                          setPinSavedToast(true);
                          setTimeout(() => setPinSavedToast(false), 3000);
                        }}
                        style={{
                          background: "#c8f279",
                          color: "#21301b",
                          border: "none",
                          borderRadius: "8px",
                          padding: "10px 16px",
                          cursor: "pointer",
                          fontWeight: 600,
                          fontSize: "11px"
                        }}
                      >
                        Yadda Saxla
                      </button>
                    </div>

                    {pinSavedToast && (
                      <div style={{
                        marginTop: "8px",
                        fontSize: "11px",
                        color: "#c8f279",
                        display: "flex",
                        alignItems: "center",
                        gap: "6px"
                      }}>
                        <Check size={14} />
                        <span>PIN yerli Windows DPAPI yaddaşında təhlükəsiz saxlanıldı. Serverə göndərilmədi.</span>
                      </div>
                    )}
                  </div>

                  <div style={{
                    background: "#141815",
                    border: "1px solid #2a3428",
                    borderRadius: "10px",
                    padding: "14px",
                    fontSize: "11px",
                    lineHeight: 1.6,
                    color: "#9aab9c"
                  }}>
                    <strong style={{ color: "#c8f279", display: "block", marginBottom: "4px" }}>
                      Təhlükəsizlik Zəmanəti:
                    </strong>
                    PIN kodunuz yalnız bu fərdi kompüterdə saxlanır və heç vaxt internet serverlərinə, skrinşotlara və ya telemetriya loqlarına düşmür.
                  </div>
                </div>
              </div>
            )}

            {/* 4. Onboarding Bələdçisi */}
            {tab === "onboarding" && (
              <div>
                <div style={{ marginBottom: "20px" }}>
                  <div style={{ color: "#c8f279", fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", marginBottom: "6px" }}>
                    İLK QURAŞDIRMA
                  </div>
                  <h1 style={{ fontSize: "22px", fontWeight: 600, color: "#f0f4ed", margin: 0 }}>
                    4 Sadə Addımda Quraşdırın
                  </h1>
                </div>

                <div style={{
                  background: "#1c221e",
                  border: "1px solid #2d382c",
                  borderRadius: "14px",
                  padding: "24px"
                }}>
                  <div style={{ display: "flex", gap: "12px", marginBottom: "24px" }}>
                    {[1, 2, 3, 4].map((step) => (
                      <button
                        key={step}
                        onClick={() => setOnboardingStep(step)}
                        style={{
                          flex: 1,
                          padding: "10px",
                          borderRadius: "8px",
                          border: "1px solid " + (onboardingStep === step ? "#c8f279" : "#2a3428"),
                          background: onboardingStep === step ? "#263221" : "transparent",
                          color: onboardingStep === step ? "#c8f279" : "#89958a",
                          cursor: "pointer",
                          fontWeight: 600,
                          fontSize: "11px"
                        }}
                      >
                        Addım {step}
                      </button>
                    ))}
                  </div>

                  {onboardingStep === 1 && (
                    <div>
                      <h3 style={{ fontSize: "15px", color: "#f0f4ed", margin: "0 0 8px 0" }}>1. Kompüterinizə ad verin</h3>
                      <p style={{ fontSize: "12px", color: "#89958a", lineHeight: 1.6, margin: "0 0 16px 0" }}>
                        Telefonunuzda bu kompüteri tanımaq üçün asan bir ad seçin (Məsələn: <em>İş Kompüteri</em>).
                      </p>
                      <button
                        onClick={() => setOnboardingStep(2)}
                        style={{ background: "#c8f279", color: "#21301b", border: "none", borderRadius: "6px", padding: "8px 16px", fontWeight: 600, fontSize: "12px", cursor: "pointer" }}
                      >
                        Növbəti Addım →
                      </button>
                    </div>
                  )}

                  {onboardingStep === 2 && (
                    <div>
                      <h3 style={{ fontSize: "15px", color: "#f0f4ed", margin: "0 0 8px 0" }}>2. Windows PIN/Parolunu daxil edin</h3>
                      <p style={{ fontSize: "12px", color: "#89958a", lineHeight: 1.6, margin: "0 0 16px 0" }}>
                        PIN yalnız bu kompüterin özündə Windows DPAPI vasitəsilə şifrələnir. İnternetə göndərilmir.
                      </p>
                      <button
                        onClick={() => setOnboardingStep(3)}
                        style={{ background: "#c8f279", color: "#21301b", border: "none", borderRadius: "6px", padding: "8px 16px", fontWeight: 600, fontSize: "12px", cursor: "pointer" }}
                      >
                        Növbəti Addım →
                      </button>
                    </div>
                  )}

                  {onboardingStep === 3 && (
                    <div>
                      <h3 style={{ fontSize: "15px", color: "#f0f4ed", margin: "0 0 8px 0" }}>3. Telefonunuzla QR kodu oxudun</h3>
                      <p style={{ fontSize: "12px", color: "#89958a", lineHeight: 1.6, margin: "0 0 16px 0" }}>
                        Telefonun kamerasını QR koda yönəldin. Heç bir tətbiq yükləmədən birbaşa Safari və ya Chrome-da açılır.
                      </p>
                      <button
                        onClick={() => setOnboardingStep(4)}
                        style={{ background: "#c8f279", color: "#21301b", border: "none", borderRadius: "6px", padding: "8px 16px", fontWeight: 600, fontSize: "12px", cursor: "pointer" }}
                      >
                        Növbəti Addım →
                      </button>
                    </div>
                  )}

                  {onboardingStep === 4 && (
                    <div>
                      <h3 style={{ fontSize: "15px", color: "#f0f4ed", margin: "0 0 8px 0" }}>4. Quraşdırma tamamlandı!</h3>
                      <p style={{ fontSize: "12px", color: "#89958a", lineHeight: 1.6, margin: "0 0 16px 0" }}>
                        Artıq telefonunuzdan bir toxunuşla Windows kilidini aça və ya kompüterinizi kilidləyə bilərsiniz.
                      </p>
                      <button
                        onClick={() => setTab("status")}
                        style={{ background: "#c8f279", color: "#21301b", border: "none", borderRadius: "6px", padding: "8px 16px", fontWeight: 600, fontSize: "12px", cursor: "pointer" }}
                      >
                        Əsas Ekrana Keç
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 5. Dəstək və Texniki Loqlar Ekranı */}
            {tab === "support" && (
              <div>
                <div style={{ marginBottom: "20px" }}>
                  <div style={{ color: "#c8f279", fontSize: "10px", fontWeight: 700, letterSpacing: "1.5px", marginBottom: "6px" }}>
                    DİAQNOSTİKA VƏ DƏSTƏK
                  </div>
                  <h1 style={{ fontSize: "22px", fontWeight: 600, color: "#f0f4ed", margin: 0 }}>
                    Texniki Detallar və Loqlar
                  </h1>
                </div>

                <div style={{
                  background: "#1c221e",
                  border: "1px solid #2d382c",
                  borderRadius: "14px",
                  padding: "20px",
                  marginBottom: "16px"
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                    <span style={{ fontSize: "11px", fontWeight: 600, color: "#89958a" }}>SİSTEM VƏ XİDMƏT MƏLUMATLARI</span>
                    <button
                      onClick={() => {
                        setSupportCopied(true);
                        setTimeout(() => setSupportCopied(false), 2500);
                      }}
                      style={{
                        background: "#222a21",
                        border: "1px solid #3c4a37",
                        color: "#c8f279",
                        borderRadius: "6px",
                        padding: "6px 12px",
                        fontSize: "11px",
                        cursor: "pointer",
                        fontWeight: 600
                      }}
                    >
                      {supportCopied ? "Paket İxrac Edildi ✓" : "Dəstək Paketini Çıxar"}
                    </button>
                  </div>

                  {/* Texniki Jarqonlar Bura Daşındı: İstifadəçi əsas ekranda çaşmır */}
                  <div style={{
                    background: "#101312",
                    borderRadius: "8px",
                    padding: "14px",
                    fontFamily: "monospace",
                    fontSize: "11px",
                    lineHeight: 1.7,
                    color: "#cbd5e1",
                    border: "1px solid #263222"
                  }}>
                    <div><span style={{ color: "#c8f279" }}>[XİDMƏT]</span> WinKeySupervisor SCM Service (Session 0) Aktivdir</div>
                    <div><span style={{ color: "#c8f279" }}>[SESSİYA]</span> Target User Desktop: Session 1 (Default pərdə)</div>
                    <div><span style={{ color: "#9aab9c" }}>[IPC DACL]</span> Dar SDDL: Yalnız LocalSystem və Authenticated User SID</div>
                    <div><span style={{ color: "#c8f279" }}>[OUTBOX]</span> Bounded Telemetry: 50 KB Limit, 0 leak aşkarlandı</div>
                    <div><span style={{ color: "#9aab9c" }}>[REVERT]</span> Win32 Checked RevertToSelf Fatal Exit Code: 202</div>
                  </div>
                </div>

                <div style={{ fontSize: "11px", color: "#68776a" }}>
                  Mövcud audit və texniki tapıntılar üçün: <code>plan/KNOWN_ISSUES.md</code>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
