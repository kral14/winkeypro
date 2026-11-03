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
  window.setRemotePauseState = paused => {
    isRemotePaused = Boolean(paused);
    const label = document.getElementById('lblPauseState');
    const button = document.getElementById('btnTogglePause');
    if (label) label.textContent = isRemotePaused ? 'DAYANDIRILIB' : 'AKTİV';
    if (button) button.textContent = isRemotePaused ? 'Mobil İdarəni Bərpa Et' : 'Mobil İdarəni Dayandır';
  };
  var btnTogglePause = document.getElementById('btnTogglePause');
  if (btnTogglePause) {
    btnTogglePause.addEventListener('click', async () => {
      try {
        const nextPaused = !isRemotePaused;
        await callNative('account_device_action', {deviceId:window.currentDeviceId,action:nextPaused ? 'pause' : 'resume'});
        isRemotePaused = nextPaused;
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
    if (isTauri && !window.__WINKEY_ACCOUNT_READY__) { showQrError('Əvvəl hesaba daxil olun.'); return; }
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

// Səhifə yüklənəndə hər şeyi işə sal və canlı avtomatik yenilənməni idarə et
let isUpdatingCheck = false;
let isSingleRestartScheduled = false;

function renderProgressBar(percent, label, desc, color) {
  const container = document.getElementById('updateProgressContainer');
  if (container) container.style.display = 'block';

  const progressBar = document.getElementById('barUpdateProgress');
  const progressPercent = document.getElementById('lblProgressPercent');
  const progressStage = document.getElementById('lblProgressStage');
  const message = document.getElementById('lblUpdateMessage');

  if (progressBar) {
    progressBar.style.width = percent + '%';
    progressBar.style.background = color;
  }
  if (progressPercent) {
    progressPercent.textContent = percent + '%';
    progressPercent.style.color = color;
  }
  if (progressStage) {
    progressStage.innerHTML = label;
  }
  if (message) {
    message.textContent = desc;
  }
}

async function triggerSingleRestartCountdown() {
  if (isSingleRestartScheduled) return;
  isSingleRestartScheduled = true;

  for (let sec = 3; sec >= 1; sec--) {
    renderProgressBar(
      100,
      `<span>🔄</span> Proqram restart edəcək (${sec}s)…`,
      `✓ Yeni versiya slota uğurla quruldu! Proqram ${sec} saniyəyə yeni binarla restart edir…`,
      'var(--green)'
    );
    await new Promise(r => setTimeout(r, 1000));
  }

  renderProgressBar(
    100,
    '<span>🔄</span> Proqram restart edir…',
    'Yalnız bir dəfə təmiz keçid: yeni versiya başladılır…',
    'var(--green)'
  );

  try {
    await callNative('restart_desktop_app');
  } catch (e) {
    console.error('restart_desktop_app xətası:', e);
    isSingleRestartScheduled = false;
    if (typeof window !== 'undefined' && window.location && window.location.reload) {
      window.location.reload();
    }
  }
}

async function loadUpdateStatus(isSilent = false) {
  const button = document.getElementById('btnCheckUpdate');
  const message = document.getElementById('lblUpdateMessage');
  const container = document.getElementById('updateProgressContainer');

  if (isUpdatingCheck) return;
  if (!isTauri) {
    if (message) message.textContent = 'Önizləmə rejimi: real yenilənmə yoxlanmır.';
    return;
  }
  isUpdatingCheck = true;
  if (!isSilent && button) button.disabled = true;

  try {
    const status = await callNative('get_update_status', { checkServer: true });
    if (document.getElementById('lblDesktopVersion'))
      document.getElementById('lblDesktopVersion').textContent = status.channel === 'dev' ? 'Dev build (setup deyil)' : 'v' + status.desktop_version;
    if (document.getElementById('lblWorkerVersion'))
      document.getElementById('lblWorkerVersion').textContent = status.worker_version ? 'v' + status.worker_version : 'Bildirilməyib';
    if (document.getElementById('lblLatestVersion'))
      document.getElementById('lblLatestVersion').textContent = status.latest_version ? 'v' + status.latest_version : 'Məlum deyil';

    const dVer = status.desktop_version;
    const wVer = status.worker_version;
    const lVer = status.latest_version;
    const isDev = status.channel === 'dev';

    // 1. Setup tələb olunursa
    if (status.status === 'setup_required' || status.phase === 'SETUP_REQUIRED') {
      renderProgressBar(100, '<span>⚠️</span> Setup yenilənməsi tələb olunur', 'Yeni versiya üçün Setup.exe quraşdırıcısının yenilənməsi tələb olunur.', 'var(--red)');
      return;
    }

    // 2. Dev build işləyirsə
    if (isDev) {
      if (container) container.style.display = 'none';
      if (message) message.textContent = 'Dev build işləyir. Quraşdırılmış versiya kimi müqayisə edilmir və xidmət yenilənməsi başladılmır.';
      return;
    }

    // 3. Əgər yeni hədəf slota yazılıb və tam hazırdırsa (yalnız İNDİ tək 1 dəfə restart):
    if (status.has_ready_target && lVer && dVer !== lVer) {
      await triggerSingleRestartCountdown();
      return;
    }

    // 4. MƏRHƏLƏ 2: Qurulur / Doğrulanır (Xidmət paketi hazırlayır və yoxlayır, RESTART EDİLMİR)
    if (status.phase === 'PENDING_ACTIVATION' || status.phase === 'PROBATION') {
      renderProgressBar(
        80,
        '<span>⚙️</span> Qurulur…',
        `Yeni versiya (v${lVer || ''}) faylları çıxarılır, Ed25519 kriptoqrafik imza və bütövlük yoxlanılır…`,
        '#f59e0b'
      );
      // Canlı sürətli sorğu (2 saniyədən bir)
      setTimeout(() => loadUpdateStatus(true), 2000);
      return;
    }

    // 5. MƏRHƏLƏ 1: Yüklənir (Paket serverdən endirilir, RESTART EDİLMİR)
    if (status.status === 'requested' || status.phase === 'STAGING') {
      renderProgressBar(
        45,
        '<span>📥</span> Yüklənir…',
        `Yeni versiya (v${lVer || ''}) üçün xidmətə yenilənmə sorğusu göndərildi; paket endirilir (45%)…`,
        '#38bdf8'
      );
      // Canlı sürətli sorğu (2 saniyədən bir)
      setTimeout(() => loadUpdateStatus(true), 2000);
      return;
    }

    // 6. Əgər hər şey son versiyadadırsa
    if (status.status === 'up_to_date' || (lVer && dVer === lVer)) {
      if (container && !isSingleRestartScheduled) container.style.display = 'none';
      if (message) message.textContent = '✓ Ən son versiya quraşdırılıb və təsdiqlənib.';
      return;
    }

    // 7. Qalan digər statuslar
    if (container && !isSingleRestartScheduled) container.style.display = 'none';
    if (status.status === 'unreachable') {
      if (message) message.textContent = 'Serverə qoşulmaq alınmadı. Son versiya təsdiqlənmədi.';
    } else if (status.status === 'ahead') {
      if (message) message.textContent = 'Yerli versiya serverdəki buraxılışdan yenidir; downgrade edilmir.';
    } else if (status.status === 'service_unavailable') {
      if (message) message.textContent = 'Yeni versiya var, amma xidmət sorğunu qəbul etmədi. Xidmətin vəziyyətini yoxlayın.';
    } else if (lVer && dVer !== lVer) {
      if (message) message.textContent = `⚠️ Proqram hələ yenilənməyib (Desktop: v${dVer}, Xidmət: v${wVer || '?'}). Serverdə son versiya: v${lVer}.`;
    } else if (message) {
      message.textContent = '✓ Yenilənmə vəziyyəti normaldır.';
    }
  } catch (error) {
    if (document.getElementById('lblLatestVersion'))
      document.getElementById('lblLatestVersion').textContent = 'Yoxlama alınmadı';
    if (message)
      message.textContent = 'Yenilənmə yoxlanmadı: ' + String(error);
    renderProgressBar(100, '<span>⚠️</span> Yoxlama xətası', 'Yenilənmə yoxlanmadı: ' + String(error), '#ef4444');
  } finally {
    isUpdatingCheck = false;
    if (button) button.disabled = false;
    const checkedEl = document.getElementById('lblUpdateChecked');
    if (checkedEl) checkedEl.textContent = 'Son yoxlama: ' + new Date().toLocaleTimeString('az-AZ');
  }
}

function initApp() {
  initTabs();
  initButtons();
  loadStatus();
  document.getElementById('btnCheckUpdate')?.addEventListener('click', () => loadUpdateStatus(false));
  loadUpdateStatus(false);

  // Arxa planda avtomatik canlı yenilənmə yoxlanışı (hər 10 saniyədən bir əllə basmağa ehtiyac qalmadan)
  if (isTauri) {
    setInterval(() => {
      if (!document.hidden) {
        loadUpdateStatus(true);
      }
    }, 10000);
  }
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
