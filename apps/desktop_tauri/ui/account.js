(() => {
  async function startAccount() {
    const byId = id => document.getElementById(id);
    const overlay = byId('accountOverlay'), form = byId('accountForm');
    if (!overlay || !form) return;
    const message = byId('accountMessage'), continueButton = byId('accountContinue');
    const close = byId('accountCloseDrawer'), logout = byId('accountLogout');
    const native = window.__TAURI__?.core?.invoke || window.__TAURI__?.invoke;
    let authenticated = false, currentId = '', refreshing = false;
    window.__WINKEY_ACCOUNT_READY__ = false;
    const invoke = (command,args={}) => native ? native(command,args) : Promise.reject(Error('Önizləmədə real hesab açılmır. WinKey proqramını işə salın.'));
    function showMessage(text, kind='info') {
      message.textContent = text;
      message.style.color = kind==='error' ? 'var(--red)' : kind==='success' ? 'var(--green)' : 'var(--text)';
      message.dataset.state = kind;
    }
    function signedIn(value) {
      authenticated = value;
      window.__WINKEY_ACCOUNT_READY__ = value;
      if (close) close.hidden = !value;
      if (logout) logout.style.display = value ? 'block' : 'none';
      const loginBtn = byId('accountLogin');
      if (loginBtn) loginBtn.style.display = value ? 'none' : 'block';
      const regBtn = byId('accountRegister');
      if (regBtn) regBtn.style.display = value ? 'none' : 'block';
      const passWrap = byId('accountPasswordWrapper');
      if (passWrap) passWrap.style.display = value ? 'none' : 'flex';
      const emailInput = byId('accountEmail');
      if (emailInput) emailInput.disabled = value;
      if (continueButton) continueButton.hidden = true;
    }
    function updateUser(email) {
      for (const id of ['navUserText','drawerHeaderTitle']) if (byId(id)) byId(id).textContent=email;
      for (const id of ['navAvatar','drawerAvatar']) if (byId(id)) byId(id).textContent=email.charAt(0).toUpperCase();
      if (byId('drawerHeaderSub')) byId('drawerHeaderSub').textContent='Hesab aktivdir';
    }
    function renderDevices(devices) {
      const list = byId('accountDevicesList');
      if (!list) return;
      list.replaceChildren();
      if (!devices.length) {
        const empty = document.createElement('div');
        empty.style.cssText = 'font-size:11px;color:var(--text-muted);padding:8px 10px;background:var(--card);border-radius:var(--radius-sm);';
        empty.textContent = 'Hesabınızda hələ heç bir əlavə cihaz yoxdur. "+ Əlavə Et" ilə bu kompüteri və ya başqa PC-ləri bağlaya bilərsiniz.';
        list.appendChild(empty);
        return;
      }
      for (const device of devices) {
        const row = document.createElement('div');
        row.style.cssText = 'padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);display:flex;align-items:center;justify-content:space-between;gap:8px;';

        const title = document.createElement('span');
        title.style.cssText = 'font-weight:700;font-size:12px;color:var(--text);';
        title.textContent = device.computer_name + (device.device_id === currentId ? ' (Bu PC)' : '');
        row.appendChild(title);

        const state = document.createElement('span');
        const isOnline = Boolean(device.online);
        state.textContent = (isOnline ? 'Onlayn' : 'Oflayn') + ' · ' + (device.locked ? 'Kilidli' : 'Açıq') + (device.paused ? ' · Dayandırılıb' : '');
        state.style.cssText = `font-size:11px;font-weight:600;color:${isOnline ? 'var(--green)' : 'var(--text-muted)'};`;
        row.appendChild(state);

        for (const [action, label, isDanger] of [
          [device.paused ? 'resume' : 'pause', device.paused ? 'Davam et' : 'Dayandır', false],
          ['delete', 'Sil', true]
        ]) {
          const button = document.createElement('button');
          button.type = 'button';
          button.className = 'btn-secondary';
          button.style.cssText = `font-size:10px;padding:3px 8px;${isDanger ? 'color:var(--red);border-color:var(--red-border);' : ''}`;
          button.textContent = label;
          button.onclick = async () => {
            if (action === 'delete' && !window.confirm(`"${device.computer_name}" kompüterini silib telefon girişini ləğv etmək istəyirsiniz?`)) return;
            button.disabled = true;
            try {
              await invoke('account_device_action', { deviceId: device.device_id, action });
              await refresh();
            } catch (error) {
              showMessage(String(error), 'error');
            } finally {
              button.disabled = false;
            }
          };
          row.appendChild(button);
        }
        list.appendChild(row);
      }
    }
    async function refresh() {
      if (refreshing) return;
      refreshing=true;
      try {
        const account=await invoke('account_status');
        currentId=account.current_device_id || '';
        window.currentDeviceId=currentId;
        updateUser(account.email);
        byId('accountEmail').value=account.email;
        renderDevices(account.devices || []);
        const local = (account.devices || []).find(device=>device.device_id===currentId);
        if(local) window.setRemotePauseState?.(local.paused);
        return account;
      } finally {refreshing=false;}
    }
    byId('accountOpen').onclick=()=>{overlay.hidden=false;};
    if(close) close.onclick=()=>{if(authenticated)overlay.hidden=true;};
    if(continueButton) continueButton.onclick=()=>{if(authenticated){overlay.hidden=true;window.switchTab?.('status');}};
    const btnShowPass = byId('btnShowAccountPassword');
    if (btnShowPass) {
      btnShowPass.onclick = () => {
        const pass = byId('accountPassword');
        if (!pass) return;
        const isPass = pass.type === 'password';
        pass.type = isPass ? 'text' : 'password';
        btnShowPass.textContent = isPass ? 'Gizlət' : 'Göstər';
      };
    }
    if(logout) logout.onclick=async()=>{
      logout.disabled=true;
      try {
        await invoke('account_logout');
        signedIn(false);overlay.hidden=false;
        updateUser('Hesaba daxil olun');
        if(byId('drawerHeaderSub'))byId('drawerHeaderSub').textContent='Bu PC mobil idarəetmə üçün oflayndır';
        if(byId('lblQrPayload'))byId('lblQrPayload').textContent='Hesaba daxil olun';
        if(byId('qrSvgWrapper'))byId('qrSvgWrapper').textContent='QR üçün hesaba daxil olun';
        if(byId('imgQrVisual'))byId('imgQrVisual').removeAttribute('src');
        showMessage('Hesabdan çıxıldı. Bu PC oflayndır; hesab və telefon bağlantıları saxlanıldı.','success');
      }catch(error){showMessage('Çıxış alınmadı: '+String(error),'error');}
      finally{logout.disabled=false;}
    };
    form.addEventListener('invalid',()=>showMessage('Düzgün e-poçt və ən azı 10 simvollu şifrə daxil edin.','error'),true);
    form.onsubmit=async event=>{
      event.preventDefault();
      const action=(event.submitter || byId('accountLogin')).value;
      const password=byId('accountPassword'), controls=form.querySelectorAll('button');
      controls.forEach(button=>{button.disabled=true;});
      showMessage(action==='register'?'Hesab yaradılır…':'Giriş yoxlanılır…');
      try {
        const account=await invoke('account_authenticate',{action,email:byId('accountEmail').value.trim(),password:password.value});
        signedIn(true);updateUser(account.email);
        await refresh();
        if (action === 'register') {
          overlay.hidden = false;
          if (continueButton) continueButton.hidden = false;
          showMessage('Hesabınız uğurla yaradıldı! Bu PC hesaba bağlandı.', 'success');
        } else {
          overlay.hidden = true;
          if (window.switchTab) window.switchTab('status');
        }
      }catch(error){showMessage('Əməliyyat alınmadı: '+String(error),'error');}
      finally{password.value='';controls.forEach(button=>{button.disabled=false;});}
    };
    // Stored valid sessions resume without bypassing the account check.
    try {await refresh();signedIn(true);overlay.hidden=true;}
    catch(error){signedIn(false);overlay.hidden=false;showMessage(native?'Davam etmək üçün hesab yaradın və ya daxil olun.':'Önizləmə rejimi: real qeydiyyat yalnız WinKey proqramında işləyir.');}
    if(native) setInterval(async()=>{
      if(!authenticated || document.hidden) return;
      try {await refresh();}catch(error){
        if(String(error).includes('E_ACCOUNT_REQUIRED')){signedIn(false);overlay.hidden=false;}
      }
    },5000);
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',startAccount);
  else startAccount();
})();
