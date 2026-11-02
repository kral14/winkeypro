(() => {
  async function startAccount() {
    const overlay = document.getElementById('accountOverlay');
    const form = document.getElementById('accountForm');
    const message = document.getElementById('accountMessage');
    const btnAccountOpen = document.getElementById('accountOpen');
    const btnCloseDrawer = document.getElementById('accountCloseDrawer');
    const continueButton = document.getElementById('accountContinue');
    const btnSkip = document.getElementById('accountSkip');

    if (!overlay) return;

    if (btnAccountOpen) {
      btnAccountOpen.onclick = () => { overlay.hidden = false; };
    }
    if (btnCloseDrawer) {
      btnCloseDrawer.onclick = () => { overlay.hidden = true; };
    }
    if (btnSkip) {
      btnSkip.onclick = () => {
        overlay.hidden = true;
        document.getElementById('btnRefreshQr')?.click();
      };
    }
    if (continueButton) {
      continueButton.onclick = () => {
        overlay.hidden = true;
        document.getElementById('btnRefreshQr')?.click();
      };
    }

    function showMessage(text, kind = 'info') {
      if (!message) return;
      message.textContent = text;
      message.style.color = kind === 'error' ? 'var(--red)' : kind === 'success' ? 'var(--green)' : 'var(--text)';
      message.dataset.state = kind;
    }

    function updateNavAccountUI(email) {
      const navUser = document.getElementById('navUserText');
      if (navUser) navUser.textContent = email;
      const navAv = document.getElementById('navAvatar');
      if (navAv) navAv.textContent = (email || 'U').charAt(0).toUpperCase();
      const drvAv = document.getElementById('drawerAvatar');
      if (drvAv) drvAv.textContent = (email || 'U').charAt(0).toUpperCase();
      const drvTitle = document.getElementById('drawerHeaderTitle');
      if (drvTitle) drvTitle.textContent = email;
      const drvSub = document.getElementById('drawerHeaderSub');
      if (drvSub) drvSub.textContent = 'Hesab Aktivdir';
    }

    const hasTauri = typeof window !== 'undefined' && Boolean(window.__TAURI__ && (window.__TAURI__.core || window.__TAURI__.invoke));

    const invoke = (command, args = {}) => {
      if (!hasTauri) return Promise.reject(new Error('Tauri mühiti deyil'));
      return window.__TAURI__.core ? window.__TAURI__.core.invoke(command, args) : window.__TAURI__.invoke(command, args);
    };

    async function status() {
      if (!hasTauri) {
        // Brauzer önizləmə rejimi üçün standart görünüş
        showMessage('Önizləmə rejimi: Hesab funksionallığı aktivdir.', 'info');
        return;
      }
      try {
        const account = await invoke('account_status');
        updateNavAccountUI(account.email);
        const emailInput = document.getElementById('accountEmail');
        if (emailInput) emailInput.value = account.email;
        if (account.devices && window.renderAccountDevices) {
          window.renderAccountDevices(account.devices);
        }
        showMessage('Hesab aktivdir. Davam et düyməsini basa bilərsiniz.', 'success');
        if (continueButton) continueButton.hidden = false;
        overlay.hidden = true;
      } catch (error) {
        overlay.hidden = false;
        showMessage(String(error).includes('HTTPS') ? String(error) : 'Davam etmək üçün hesab yaradın və ya daxil olun.', String(error).includes('HTTPS') ? 'error' : 'info');
      }
    }

    if (form) {
      form.addEventListener('invalid', () => {
        showMessage('E-poçtu düzgün yazın və ən azı 10 simvollu şifrə daxil edin.', 'error');
      }, true);

      form.onsubmit = async event => {
        event.preventDefault();
        const button = event.submitter || document.getElementById('accountLogin');
        const controls = form.querySelectorAll('button');
        controls.forEach(item => { item.disabled = true; });
        if (continueButton) continueButton.hidden = true;
        showMessage(button.value === 'register' ? 'Hesab yaradılır…' : 'Giriş yoxlanılır…');
        const email = document.getElementById('accountEmail').value.trim();
        const password = document.getElementById('accountPassword');

        if (!hasTauri) {
          // Brauzer standalone rejimində istifadəçiyə dərhal aydın cavab
          setTimeout(() => {
            updateNavAccountUI(email || 'demo@winkey.az');
            showMessage('Önizləmə: Hesaba daxil olundu (' + (email || 'demo@winkey.az') + ').', 'success');
            if (continueButton) continueButton.hidden = false;
            controls.forEach(item => { item.disabled = false; });
            if (password) password.value = '';
          }, 400);
          return;
        }

        try {
          const account = await invoke('account_authenticate', {
            action: button.value, email: email, password: password.value,
          });
          password.value = '';
          updateNavAccountUI(account.email);
          showMessage(button.value === 'register' ? 'Hesab uğurla yaradıldı. Davam et düyməsini basın.' : 'Hesaba uğurla daxil oldunuz. Davam et düyməsini basın.', 'success');
          if (continueButton) continueButton.hidden = false;
          await status();
        } catch (error) {
          showMessage('Əməliyyat alınmadı: ' + String(error), 'error');
        } finally {
          if (password) password.value = '';
          controls.forEach(item => { item.disabled = false; });
        }
      };
    }

    await status();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', startAccount);
  else startAccount();
})();
