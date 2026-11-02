(() => {
  async function startAccount() {
    const overlay = document.getElementById('accountOverlay');
    const form = document.getElementById('accountForm');
    const message = document.getElementById('accountMessage');
    if (!overlay || !window.__TAURI__) return;
    const invoke = (command, args = {}) => window.__TAURI__.core
      ? window.__TAURI__.core.invoke(command, args) : window.__TAURI__.invoke(command, args);
    async function status() {
      try {
        const account = await invoke('account_status');
        document.getElementById('accountOpen').textContent = account.email;
        overlay.hidden = true;
      } catch (error) {
        overlay.hidden = false;
        message.textContent = String(error).includes('HTTPS') ? String(error) : 'Davam etmək üçün hesab yaradın və ya daxil olun.';
      }
    }
    document.getElementById('accountOpen').onclick = () => { overlay.hidden = false; };
    document.getElementById('accountSettings').onclick = () => {
      overlay.hidden = true;
      if (window.switchTab) window.switchTab('pairing');
    };
    form.onsubmit = async event => {
      event.preventDefault();
      const button = event.submitter || document.getElementById('accountLogin');
      const controls = form.querySelectorAll('button');
      controls.forEach(item => { item.disabled = true; });
      message.textContent = 'Yoxlanılır…';
      const password = document.getElementById('accountPassword');
      try {
        const account = await invoke('account_authenticate', {
          action: button.value, email: document.getElementById('accountEmail').value.trim(), password: password.value,
        });
        password.value = '';
        document.getElementById('accountOpen').textContent = account.email;
        overlay.hidden = true;
        document.getElementById('btnRefreshQr')?.click();
      } catch (error) { message.textContent = String(error); }
      finally { password.value = ''; controls.forEach(item => { item.disabled = false; }); }
    };
    await status();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startAccount);
  else startAccount();
})();
