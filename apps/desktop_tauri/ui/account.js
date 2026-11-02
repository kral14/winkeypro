(() => {
  async function startAccount() {
    const overlay = document.getElementById('accountOverlay');
    const form = document.getElementById('accountForm');
    const message = document.getElementById('accountMessage');
    if (!overlay || !window.__TAURI__) return;
    const invoke = (command, args = {}) => window.__TAURI__.core
      ? window.__TAURI__.core.invoke(command, args) : window.__TAURI__.invoke(command, args);
    const continueButton = document.getElementById('accountContinue');
    function showMessage(text, kind = 'info') {
      message.textContent = text;
      message.style.color = kind === 'error' ? 'var(--red)' : kind === 'success' ? 'var(--green)' : 'var(--text)';
      message.dataset.state = kind;
    }
    try {
      const device = await invoke('get_device_status');
      const originInput = document.getElementById('accountServerOrigin');
      if (originInput) originInput.value = device.cloud_gateway_origin || '';
    } catch (_) {}
    async function status() {
      try {
        const account = await invoke('account_status');
        document.getElementById('accountOpen').textContent = account.email;
        document.getElementById('accountEmail').value = account.email;
        showMessage('Hesab aktivdir. Davam et düyməsini basa bilərsiniz.', 'success');
        continueButton.hidden = false;
        overlay.hidden = true;
      } catch (error) {
        overlay.hidden = false;
        showMessage(String(error).includes('HTTPS') ? String(error) : 'Davam etmək üçün hesab yaradın və ya daxil olun.', String(error).includes('HTTPS') ? 'error' : 'info');
      }
    }
    const btnAccountOpen = document.getElementById('accountOpen');
    if (btnAccountOpen) btnAccountOpen.onclick = () => { overlay.hidden = false; };
    
    const btnSettings = document.getElementById('accountSettings');
    if (btnSettings) {
      btnSettings.onclick = () => {
        overlay.hidden = true;
        if (window.switchTab) window.switchTab('status');
        const field = document.getElementById('txtGatewayOrigin');
        if (field) { field.scrollIntoView({block:'center'}); field.focus(); }
      };
    }
    const btnSaveServer = document.getElementById('accountSaveServer');
    if (btnSaveServer) {
      btnSaveServer.onclick = async () => {
        btnSaveServer.disabled = true;
        try {
          const originInput = document.getElementById('accountServerOrigin');
          const origin = originInput ? originInput.value.trim() : '';
          const url = new URL(origin);
          if (url.protocol !== 'https:' && !['localhost','127.0.0.1','[::1]'].includes(url.hostname)) {
            throw Error('Server hələ HTTP ilə işləyir. Əvvəl VM-də HTTPS qurun, sonra HTTPS ünvanını yazın.');
          }
          await invoke('set_gateway_origin', {origin});
          continueButton.hidden = true;
          showMessage('Server ünvanı saxlanıldı. İndi hesab yaradın və ya daxil olun.', 'success');
        } catch (error) { showMessage(String(error), 'error'); }
        finally { btnSaveServer.disabled = false; }
      };
    }
    continueButton.onclick = () => {
      overlay.hidden = true;
      document.getElementById('btnRefreshQr')?.click();
    };
    const btnSkip = document.getElementById('accountSkip');
    if (btnSkip) {
      btnSkip.onclick = () => {
        overlay.hidden = true;
        document.getElementById('btnRefreshQr')?.click();
      };
    }
    form.addEventListener('invalid', () => {
      showMessage('E-poçtu düzgün yazın və ən azı 10 simvollu şifrə daxil edin.', 'error');
    }, true);
    form.onsubmit = async event => {
      event.preventDefault();
      const button = event.submitter || document.getElementById('accountLogin');
      const controls = form.querySelectorAll('button');
      controls.forEach(item => { item.disabled = true; });
      continueButton.hidden = true;
      showMessage(button.value === 'register' ? 'Hesab yaradılır…' : 'Giriş yoxlanılır…');
      const password = document.getElementById('accountPassword');
      try {
        const account = await invoke('account_authenticate', {
          action: button.value, email: document.getElementById('accountEmail').value.trim(), password: password.value,
        });
        password.value = '';
        document.getElementById('accountOpen').textContent = account.email;
        showMessage(button.value === 'register' ? 'Hesab uğurla yaradıldı. Davam et düyməsini basın.' : 'Hesaba uğurla daxil oldunuz. Davam et düyməsini basın.', 'success');
        continueButton.hidden = false;
      } catch (error) { showMessage('Əməliyyat alınmadı: ' + String(error), 'error'); }
      finally { password.value = ''; controls.forEach(item => { item.disabled = false; }); }
    };
    await status();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startAccount);
  else startAccount();
})();
