// WinKey Pro — Desktop Client Application Logic
(() => {
// Keep declarations private and bind UI handlers only once per document.
if (window.__WINKEY_UI_LOADED__) return;
window.__WINKEY_UI_LOADED__ = true;
function reportUiError(kind, source = '', line = 0) {
  const invoke = window.__TAURI__?.core?.invoke;
  if (invoke) invoke('report_ui_error', {
    kind, source: source.split('?')[0].split('/').pop(), line
  }).catch(() => {});
}
window.addEventListener('error', event => reportUiError('script', event.filename || '', event.lineno || 0));
window.addEventListener('unhandledrejection', () => reportUiError('unhandled-promise'));
console.log('[WinKey] app.js yükləndi');
let configuredCloudOrigin = 'http://158.101.172.228:8080';

// 1. Qlobal Tab Dəyişmə Funksiyası
function switchTab(target) {
  console.log('[WinKey] switchTab çağırıldı:', target);
  try {
    var allTabs = document.querySelectorAll('.tab');
    for (var i = 0; i < allTabs.length; i++) {
      var isTarget = allTabs[i].getAttribute('data-tab') === target;
      if (isTarget) {
        allTabs[i].classList.add('active');
        allTabs[i].setAttribute('aria-selected', 'true');
      } else {
        allTabs[i].classList.remove('active');
        allTabs[i].setAttribute('aria-selected', 'false');
      }
    }
    var allPanels = document.querySelectorAll('.panel');
    for (var j = 0; j < allPanels.length; j++) {
      allPanels[j].style.display = 'none';
      allPanels[j].classList.remove('active');
    }
    var targetPanel = document.getElementById('panel-' + target);
    if (targetPanel) {
      targetPanel.style.display = 'flex';
      targetPanel.classList.add('active');
    }
  } catch (err) {
    console.error('[WinKey] switchTab xətası:', err);
  }
}
window.switchTab = switchTab;

// 2. Tab Hadisələrinin Bağlanması (Click & Pointerdown)
function initTabs() {
  console.log('[WinKey] initTabs icra olunur');
  var tabsContainer = document.querySelector('.tabs');
  if (tabsContainer) {
    tabsContainer.addEventListener('click', function(e) {
      var btn = e.target.closest('.tab');
      if (btn) {
        var target = btn.getAttribute('data-tab');
        if (target) switchTab(target);
      }
    });
  }
  var allTabs = document.querySelectorAll('.tab');
  allTabs.forEach(function(tab) {
    tab.addEventListener('click', function(e) {
      e.preventDefault();
      var target = tab.getAttribute('data-tab');
      if (target) switchTab(target);
    });
  });
}

// 3. Native Tauri və ya Brauzer API Körpüsü
const isTauri = typeof window !== 'undefined' && Boolean(window.__TAURI__ && (window.__TAURI__.core || window.__TAURI__.invoke));

async function callNative(cmd, args = {}) {
  const tauri = (typeof window !== 'undefined' && window.__TAURI__) ? window.__TAURI__ : null;
  if (tauri) {
    try {
      if (tauri.core && typeof tauri.core.invoke === 'function') {
        return await tauri.core.invoke(cmd, args);
      }
      if (typeof tauri.invoke === 'function') {
        return await tauri.invoke(cmd, args);
      }
    } catch (err) {
      // Native failures must never turn into a successful demo response.
      reportUiError('invoke:' + cmd);
      throw err;
    }
    throw new Error('Tauri native körpüsü hazır deyil. Proqramı yenidən açın.');
  }

  // Standalone brauzer rejimi üçün fallback
  if (cmd === 'get_device_status') {
    return {
      computer_name: 'Windows-PC',
      service_status: 'RUNNING',
      is_registered: true,
      device_id: 'dev_local_pc',
      pin_ready: false,
      current_process_session_id: 1,
      active_console_session_id: 1,
      version: '0.1.0'
    };
  }
  if (cmd === 'set_computer_name') return args.name;
  if (cmd === 'save_credential_dpapi') return 'DPAPI_SUCCESS';
  if (cmd === 'generate_qr_pairing') {
    const pairing_url = 'http://192.168.0.101:8788/remote?device=dev_local_pc&code=WK-DEMO-2026';
    return {
      device_id: 'dev_local_pc',
      computer_name: 'Windows-PC',
      pair_code: 'WK-DEMO-2026',
      pairing_url: pairing_url,
      qr_svg_data_uri: 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(pairing_url),
      expires_at: Math.floor(Date.now() / 1000) + 3600
    };
  }
  if (cmd === 'revoke_pairing') return 'REVOKED';
  if (cmd === 'get_support_diagnostics') {
    return {
      os_name: 'Windows 11 / 10 64-bit',
      current_process_session_id: 1,
      active_console_session_id: 1,
      service_status: 'RUNNING',
      credential_stored_locally: true,
      config_dir: 'C:\\ProgramData\\WinKey',
      redacting_policy: 'STRICT_CANARY_ACTIVE',
      dpapi_service_boundary: 'ISOLATED'
    };
  }
  return null;
}

function showToast(id, msg) {
  const t = document.getElementById(id);
  if (!t) return;
  t.textContent = msg;
  t.style.display = 'flex';
  setTimeout(() => { t.style.display = 'none'; }, 3500);
}

function showQrError(error) {
  const message = String(error);
  const status = document.getElementById('qrStatus');
  if (status) status.textContent = message.includes('E_UNAUTHORIZED_AGENT')
    ? 'PC qeydiyyatı ləğv edilib və ya giriş açarı uyğun deyil. Admində cihazı aktivləşdirin, sonra Yeni QR Yarat basın.'
    : 'QR yaranmadı: ' + message;
  const wrapper = document.getElementById('qrSvgWrapper');
  if (wrapper) wrapper.innerHTML = '<div style="color:#666;font-size:12px;font-family:inherit;display:flex;align-items:center;justify-content:center;height:100%;text-align:center;">QR Gözlənilir</div>';
  const image = document.getElementById('imgQrVisual');
  if (image) { image.style.display = 'none'; image.removeAttribute('src'); }
  const url = document.getElementById('lblQrPayload');
  if (url) url.textContent = 'Hazır qoşulma linki yoxdur';
  const code = document.getElementById('lblPairCode');
  if (code) code.textContent = 'Qoşulma kodu yaradılmayıb';
  const timer = document.getElementById('lblQrTimer');
  if (timer) timer.textContent = '';
}

function showQrReady(qr) {
  const wrapper = document.getElementById('qrSvgWrapper');
  const image = document.getElementById('imgQrVisual');
  if (wrapper && qr.qr_svg_raw) {
    wrapper.innerHTML = qr.qr_svg_raw;
    const svgEl = wrapper.querySelector('svg');
    if (svgEl) {
      svgEl.setAttribute('width', '140');
      svgEl.setAttribute('height', '140');
      svgEl.style.display = 'block';
    }
  } else if (image) {
    image.src = qr.qr_svg_data_uri;
    image.style.display = 'block';
  }
  const status = document.getElementById('qrStatus');
  if (status) status.textContent = 'QR hazırdır. Telefonla bu yeni kodu oxudun.';
}

async function loadStatus() {
  try {
    const s = await callNative('get_device_status');
    if (s) {
      const versionLabel = document.getElementById('lblDesktopVersion');
      if (versionLabel) versionLabel.textContent = isTauri ? 'v' + s.version : 'Önizləmə';
      if (document.getElementById('lblPcName')) document.getElementById('lblPcName').textContent = s.computer_name;
      if (document.getElementById('txtPcName')) document.getElementById('txtPcName').value = s.computer_name;
      if (document.getElementById('txtPairPcName')) document.getElementById('txtPairPcName').value = s.computer_name;
      window.currentDeviceId = s.device_id || '';
      if (s.cloud_gateway_origin) configuredCloudOrigin = s.cloud_gateway_origin;
      if (window.applyConnectionMode && !window.__userChangedMode) window.applyConnectionMode(s.connection_mode === 'wifi' ? 'wifi' : 'cloud');
      if (document.getElementById('txtGatewayOrigin')) {
        document.getElementById('txtGatewayOrigin').value = configuredCloudOrigin;
      }
      if (document.getElementById('lblServiceStatus')) document.getElementById('lblServiceStatus').textContent = s.service_status === 'RUNNING' ? 'İşləyir (Running)' : s.service_status;
      if (document.getElementById('lblPinStatus')) document.getElementById('lblPinStatus').textContent = s.pin_ready ? 'Qorunur (Hazırdır)' : 'Təyin Edilməyib';
      const pinState = document.getElementById('pinSavedState');
      if (pinState) pinState.textContent = s.pin_ready
        ? '✓ PIN saxlanılıb. Yenidən yazmaq lazım deyil. Bu, Windows-un PIN-i qəbul etdiyini hələ təsdiqləmir.'
        : 'PIN saxlanılmayıb. Aşağıda daxil edib Saxla düyməsinə basın.';
      if (document.getElementById('dotPin')) document.getElementById('dotPin').className = s.pin_ready ? 'status-dot' : 'status-dot inactive';
      if (document.getElementById('lblRegStatus')) document.getElementById('lblRegStatus').textContent = s.is_registered ? 'Təsdiqləndi (' + s.device_id + ')' : 'Qeydiyyat Yoxdur';
      if (document.getElementById('dotReg')) document.getElementById('dotReg').className = s.is_registered ? 'status-dot' : 'status-dot inactive';
      if (document.getElementById('lblDiagSession')) document.getElementById('lblDiagSession').textContent = `Process: ${s.current_process_session_id} / Console: ${s.active_console_session_id}`;
    }
  } catch (e) {
    console.error(e);
  }
}

function initButtons() {
  const showPin = document.getElementById('btnShowPin');
  if (showPin) showPin.addEventListener('click', () => {
    const input = document.getElementById('txtPin');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    showPin.textContent = show ? 'Gizlət' : 'Göstər';
    showPin.setAttribute('aria-pressed', String(show));
  });
  console.log('[WinKey] initButtons icra olunur');

  var btnSavePcName = document.getElementById('btnSavePcName');
  if (btnSavePcName) {
    btnSavePcName.addEventListener('click', async () => {
      const name = document.getElementById('txtPcName').value;
      try {
        await callNative('set_computer_name', { name });
        document.getElementById('lblPcName').textContent = name;
        if (document.getElementById('txtPairPcName')) document.getElementById('txtPairPcName').value = name;
        showToast('toastPc', '✓ Kompüter adı uğurla saxlanıldı: ' + name);
      } catch (err) {
        showToast('toastPc', 'Xəta: ' + err);
      }
    });
  }

  var btnApplyPairPcName = document.getElementById('btnApplyPairPcName');
  if (btnApplyPairPcName) {
    btnApplyPairPcName.addEventListener('click', async () => {
      const pairInput = document.getElementById('txtPairPcName');
      const name = pairInput ? pairInput.value.trim() : '';
      if (!name) {
        showToast('toastPair', 'Zəhmət olmasa bu kompüter üçün bir ad daxil edin.');
        return;
      }
      try {
        await callNative('set_computer_name', { name });
        if (document.getElementById('lblPcName')) document.getElementById('lblPcName').textContent = name;
        if (document.getElementById('txtPcName')) document.getElementById('txtPcName').value = name;
        showToast('toastPair', '✓ Kompüter adı "' + name + '" olaraq qeyd edildi. Yeni QR generasiya olunur...');
        await refreshQrForCurrentMode();
      } catch (err) {
        showToast('toastPair', 'Xəta: ' + err);
      }
    });
  }

  var btnAddNewDeviceNav = document.getElementById('btnAddNewDeviceNav');
  if (btnAddNewDeviceNav) {
    btnAddNewDeviceNav.addEventListener('click', () => {
      if (window.switchTab) window.switchTab('pairing');
      const input = document.getElementById('txtPairPcName');
      if (input) {
        input.focus();
        input.select();
      }
    });
  }

  let isRemotePaused = false;
  var btnTogglePause = document.getElementById('btnTogglePause');
  if (btnTogglePause) {
    btnTogglePause.addEventListener('click', async () => {
      try {
        isRemotePaused = !isRemotePaused;
        await callNative('toggle_remote_service_control', { pause: isRemotePaused });
        if (isRemotePaused) {
          document.getElementById('lblPauseState').textContent = 'DAYANDIRILIB (PAUSED)';
          document.getElementById('lblPauseState').style.color = '#f78d7e';
          btnTogglePause.textContent = 'Mobil İdarəni Bərpa Et';
          showToast('toastPc', '⏸ Uzaqdan mobil idarə müvəqqəti dayandırıldı.');
        } else {
          document.getElementById('lblPauseState').textContent = 'AKTİV (Mobil əmrlər qəbul edilir)';
          document.getElementById('lblPauseState').style.color = 'var(--green)';
          btnTogglePause.textContent = 'Mobil İdarəni Dayandır';
          showToast('toastPc', '▶ Uzaqdan mobil idarə bərpa edildi.');
        }
      } catch (err) {
        showToast('toastPc', 'Xəta: ' + err);
      }
    });
  }

  let qrTimerInterval = null;
  function startCountdown(seconds) {
    if (qrTimerInterval) clearInterval(qrTimerInterval);
    let left = seconds;
    const lbl = document.getElementById('lblQrTimer');
    if (lbl) lbl.textContent = `Qalan vaxt: ${left} saniyə`;
    qrTimerInterval = setInterval(() => {
      left--;
      if (lbl) {
        if (left > 0) {
          lbl.textContent = `Qalan vaxt: ${left} saniyə`;
        } else {
          lbl.textContent = 'Vaxt bitdi! Zəhmət olmasa "Yeni QR Yarat" sıxın.';
          clearInterval(qrTimerInterval);
        }
      }
    }, 1000);
  }

  let activeMode = 'cloud';

  function updateModeUI(mode) {
    activeMode = mode;
    const btnWifi = document.getElementById('btnModeWifi');
    const btnCloud = document.getElementById('btnModeCloud');
    const banner = document.getElementById('lblModeBanner');

    if (mode === 'wifi') {
      if (btnWifi) {
        btnWifi.className = 'btn-mode active';
        btnWifi.style.border = '1px solid var(--green)';
        btnWifi.style.background = '#13241b';
        btnWifi.style.color = 'var(--green)';
        btnWifi.style.fontWeight = '600';
      }
      if (btnCloud) {
        btnCloud.className = 'btn-mode';
        btnCloud.style.border = '1px solid var(--line)';
        btnCloud.style.background = '#181c1a';
        btnCloud.style.color = 'var(--text-muted)';
        btnCloud.style.fontWeight = '500';
      }
      if (banner) {
        banner.innerHTML = '<span>📶 <strong>Lokal Wi-Fi Rejimi:</strong> Telefon kompüterlə eyni Wi-Fi şəbəkəsində olmalıdır. Şəbəkədaxili birbaşa (LAN) sürətli və təhlükəsiz idarəetmə.</span>';
      }
    } else {
      if (btnWifi) {
        btnWifi.className = 'btn-mode';
        btnWifi.style.border = '1px solid var(--line)';
        btnWifi.style.background = '#181c1a';
        btnWifi.style.color = 'var(--text-muted)';
        btnWifi.style.fontWeight = '500';
      }
      if (btnCloud) {
        btnCloud.className = 'btn-mode active';
        btnCloud.style.border = '1px solid var(--green)';
        btnCloud.style.background = '#13241b';
        btnCloud.style.color = 'var(--green)';
        btnCloud.style.fontWeight = '600';
      }
      if (banner) {
        banner.textContent = '🌐 İnternet rejimi — Server: ' + configuredCloudOrigin;
      }
    }
  }

  window.applyConnectionMode = updateModeUI;
  updateModeUI(activeMode);

  async function refreshQrForCurrentMode() {
    try {
      const qr = await callNative('generate_qr_pairing', { mode: activeMode });
      if (qr) {
        if (document.getElementById('lblQrPayload')) document.getElementById('lblQrPayload').textContent = qr.pairing_url;
        if (document.getElementById('lblPairCode')) document.getElementById('lblPairCode').textContent = 'Qoşulma Kodu: ' + qr.pair_code;
        if (document.getElementById('imgQrVisual')) document.getElementById('imgQrVisual').src = qr.qr_svg_data_uri;
        showQrReady(qr);
        startCountdown(120);
        showToast('toastPair', '✓ Yeni 120s-lik ' + (activeMode === 'wifi' ? 'Lokal Wi-Fi' : 'Bulud') + ' QR açar cütü generasiya olundu');
      }
      loadStatus();
    } catch (err) {
      showQrError(err);
      showToast('toastPair', 'Xəta: ' + err);
    }
  }

  const btnWifi = document.getElementById('btnModeWifi');
  if (btnWifi) {
    btnWifi.addEventListener('click', () => {
      window.__userChangedMode = true;
      updateModeUI('wifi');
      refreshQrForCurrentMode();
    });
  }

  const btnCloud = document.getElementById('btnModeCloud');
  if (btnCloud) {
    btnCloud.addEventListener('click', () => {
      window.__userChangedMode = true;
      updateModeUI('cloud');
      refreshQrForCurrentMode();
    });
  }

  var btnSaveGateway = document.getElementById('btnSaveGateway');
  if (btnSaveGateway) {
    btnSaveGateway.addEventListener('click', async () => {
      const origin = document.getElementById('txtGatewayOrigin').value.trim();
      if (!origin) {
        showToast('toastGateway', 'Zəhmət olmasa Gateway ünvanını daxil edin.');
        return;
      }
      try {
        await callNative('set_gateway_origin', { origin });
        configuredCloudOrigin = origin.replace(/\/+$/, '');
        updateModeUI('cloud');
        showToast('toastGateway', '✓ Gateway ünvanı təyin edildi: ' + origin);
        refreshQrForCurrentMode();
      } catch (err) {
        showToast('toastGateway', 'Xəta: ' + err);
      }
    });
  }

  var btnSavePin = document.getElementById('btnSavePin');
  if (btnSavePin) {
    btnSavePin.addEventListener('click', async () => {
      const pinInput = document.getElementById('txtPin');
      const pin = pinInput.value;
      if (!pin) {
        showToast('toastPin', 'Zəhmət olmasa PIN daxil edin.');
        return;
      }
      try {
        await callNative('save_credential_dpapi', { pin });
        pinInput.value = '';
        pinInput.type = 'password';
        if (showPin) { showPin.textContent = 'Göstər'; showPin.setAttribute('aria-pressed', 'false'); }
        await loadStatus();
        document.getElementById('lblPinStatus').textContent = 'Qorunur (Hazırdır)';
        document.getElementById('dotPin').className = 'status-dot';
        showToast('toastPin', '✓ PIN Windows DPAPI vasitəsilə yerli yaddaşda təhlükəsiz saxlanıldı! Native zeroize icra edildi.');
      } catch (err) {
        showToast('toastPin', 'Xəta: ' + err);
      }
    });
  }

  var btnRefreshQr = document.getElementById('btnRefreshQr');
  if (btnRefreshQr) {
    btnRefreshQr.addEventListener('click', () => {
      refreshQrForCurrentMode();
    });
  }

  var btnRevokePair = document.getElementById('btnRevokePair');
  if (btnRevokePair) {
    btnRevokePair.addEventListener('click', async () => {
      try {
        await callNative('revoke_pairing');
        showToast('toastPair', '✓ Cütləşmə ləğv edildi (Revoked)');
        loadStatus();
      } catch (err) {
        showToast('toastPair', 'Xəta: ' + err);
      }
    });
  }

  const modal = document.getElementById('trayModal');
  function hideToTray() {
    if (isTauri) {
      callNative('minimize_to_tray');
    } else if (modal) {
      modal.style.display = 'flex';
    }
  }

  var btnMinimizeTray = document.getElementById('btnMinimizeTray');
  if (btnMinimizeTray) btnMinimizeTray.addEventListener('click', hideToTray);

  var btnCloseSim = document.getElementById('btnCloseSim');
  if (btnCloseSim) btnCloseSim.addEventListener('click', hideToTray);

  var btnRestoreWindow = document.getElementById('btnRestoreWindow');
  if (btnRestoreWindow) {
    btnRestoreWindow.addEventListener('click', () => {
      if (modal) modal.style.display = 'none';
      if (isTauri) callNative('restore_window');
    });
  }

  var btnCopyDiag = document.getElementById('btnCopyDiag');
  if (btnCopyDiag) {
    btnCopyDiag.addEventListener('click', async () => {
      const diag = await callNative('get_support_diagnostics');
      const text = JSON.stringify(diag, null, 2);
      navigator.clipboard.writeText(text);
      showToast('toastDiag', '✓ Redacted diaqnostika buferə kopyalandı');
    });
  }

  // İlkin QR-i avtomatik yüklə (Lokal Wi-Fi rejimində)
  refreshQrForCurrentMode();
}

// Səhifə yüklənəndə hər şeyi işə sal
async function loadUpdateStatus() {
  const button = document.getElementById('btnCheckUpdate');
  const message = document.getElementById('lblUpdateMessage');
  if (!button || !message || button.disabled) return;
  if (!isTauri) { message.textContent = 'Önizləmə rejimi: real yenilənmə yoxlanmır.'; return; }
  button.disabled = true;
  message.textContent = 'Serverdəki imzalı buraxılış yoxlanır…';
  try {
    const status = await callNative('get_update_status', { checkServer: true });
    document.getElementById('lblDesktopVersion').textContent = status.channel === 'dev' ? 'Dev build (setup deyil)' : 'v' + status.desktop_version;
    document.getElementById('lblWorkerVersion').textContent = status.worker_version ? 'v' + status.worker_version : 'Bildirilməyib';
    document.getElementById('lblLatestVersion').textContent = status.latest_version ? 'v' + status.latest_version : 'Məlum deyil';
    const messages = {
      up_to_date: '✓ Ən son versiya quraşdırılıb və təsdiqlənib.',
      ahead: 'Yerli versiya serverdəki buraxılışdan yenidir; downgrade edilmir.',
      dev: 'Dev build işləyir. Quraşdırılmış versiya kimi müqayisə edilmir və xidmət yenilənməsi başladılmır.',
      service_unknown: 'Proqram versiyası yoxlandı, amma xidmət versiyası təsdiqlənmədi.',
      requested: 'Yeni versiya var. Xidmətə yenilənmə sorğusu göndərildi; əməliyyat bitəndə tətbiq ediləcək.',
      service_unavailable: 'Yeni versiya var, amma xidmət sorğunu qəbul etmədi. Xidmətin vəziyyətini yoxlayın.',
      setup_required: 'Yeni versiya üçün proqram quraşdırıcısının (Setup.exe) yenilənməsi tələb olunur.',
      no_release: 'Serverdə yenilənmə paketi yayımlanmayıb.',
      unreachable: 'Serverə qoşulmaq alınmadı. Son versiya təsdiqlənmədi.'
    };
    const phases = {
      STAGING: 'Yeni paket yüklənir və bütövlüyü yoxlanılır…',
      PENDING_ACTIVATION: 'Yeni versiya paketi uğurla endirildi və hazırlandı; xidmət təhlükəsiz keçidi gözləyir.',
      PROBATION: 'Yeni versiya aktivləşdirilib sağlamlıq sınağındadır (təsdiq gözlənilir).',
      COMMITTED: '✓ Yenilənmə tam təsdiqləndi. Ən son versiya işləyir.',
      SETUP_REQUIRED: 'Yeni versiya üçün proqram quraşdırıcısının (Setup.exe) yenilənməsi tələb olunur.',
      ROLLED_BACK: 'Xidmət əvvəlki işləyən versiyaya qayıtdı (Rollback). Yenilənmə loqlarını yoxlayın.'
    };
    message.textContent = phases[status.phase] || messages[status.status] || 'Yenilənmə vəziyyəti məlum deyil.';
  } catch (error) {
    document.getElementById('lblLatestVersion').textContent = 'Yoxlama alınmadı';
    message.textContent = 'Yenilənmə yoxlanmadı: ' + String(error);
  } finally {
    button.disabled = false;
    document.getElementById('lblUpdateChecked').textContent = 'Son yoxlama cəhdi: ' + new Date().toLocaleTimeString('az-AZ');
  }
}

function initApp() {
  initTabs();
  initButtons();
  loadStatus();
  document.getElementById('btnCheckUpdate')?.addEventListener('click', loadUpdateStatus);
  loadUpdateStatus();
  const envBadge = document.getElementById('envBadge');
  if (envBadge && !isTauri) {
    envBadge.textContent = 'ÖNİZLƏMƏ REJİMİ';
    envBadge.style.background = '#2e2518';
    envBadge.style.color = '#f5c078';
    envBadge.style.borderColor = '#5c4627';
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
})();



window.renderAccountDevices = function(devices, currentId) {
  const list = document.getElementById('accountDevicesList');
  if (!list) return;
  list.innerHTML = '';
  if (!Array.isArray(devices) || devices.length === 0) {
    list.innerHTML = '<div style="font-size:12px;color:var(--text-muted);padding:8px 12px;background:#101412;border-radius:6px;">Hesabınızda hələ heç bir əlavə cihaz yoxdur. "+ Yeni Cihaz Əlavə Et" ilə digər kompüterlərinizi də bağlaya bilərsiniz.</div>';
    return;
  }
  const curr = currentId || window.currentDeviceId || '';
  devices.forEach(d => {
    const item = document.createElement('div');
    item.style.cssText = 'display:flex;align-items:center;justify-content:space-between;background:#141716;border:1px solid var(--line);border-radius:8px;padding:10px 14px;';
    const isCurrent = Boolean(curr && d.device_id === curr);
    const isLocked = Boolean(d.locked);
    item.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-size:18px;">💻</span>
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:6px;">
            ${d.computer_name || 'Kompüter'}
            ${isCurrent ? '<span style="font-size:10px;padding:1px 6px;border-radius:4px;background:var(--green-dark);color:var(--green);font-weight:700;">Bu PC</span>' : ''}
          </div>
          <div style="font-size:11px;color:var(--text-muted);font-family:monospace;">${d.device_id || ''}</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:11px;padding:3px 8px;border-radius:12px;background:${isLocked ? '#2d1917;color:var(--red)' : '#13241b;color:var(--green)'};font-weight:600;">
          ${isLocked ? '🔒 Kilidli' : '🔓 Açıq'}
        </span>
      </div>
    `;
    list.appendChild(item);
  });
};
