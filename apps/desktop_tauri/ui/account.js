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
      if (logout) logout.hidden = !value;
      continueButton.hidden = !value;
    }
    function updateUser(email) {
      for (const id of ['navUserText','drawerHeaderTitle']) if (byId(id)) byId(id).textContent=email;
      for (const id of ['navAvatar','drawerAvatar']) if (byId(id)) byId(id).textContent=email.charAt(0).toUpperCase();
      if (byId('drawerHeaderSub')) byId('drawerHeaderSub').textContent='Hesab aktivdir';
    }
    function renderDevices(devices) {
      const list=byId('accountDevicesList'); if (!list) return;
      list.replaceChildren();
      if (!devices.length) {list.textContent='Bu PC-ni əlavə etmək üçün əvvəl ona ad verin.';return;}
      for (const device of devices) {
        const row=document.createElement('div');
        row.style.cssText='padding:10px;border:1px solid var(--line);border-radius:8px;display:flex;flex-wrap:wrap;align-items:center;gap:8px;';
        const title=document.createElement('span');
        title.textContent=device.computer_name+(device.device_id===currentId ? ' (Bu PC)' : '');
        row.appendChild(title);
        const state=document.createElement('span');
        state.textContent=(device.online ? 'Onlayn' : 'Oflayn')+' · '+(device.locked ? 'Kilidli' : 'Açıq')+(device.paused ? ' · Dayandırılıb' : '');
        state.style.color=device.online ? 'var(--green)' : 'var(--text-muted)';row.appendChild(state);
        for (const [action,label] of [[device.paused?'resume':'pause',device.paused?'Davam et':'Dayandır'],['delete','Sil']]) {
          const button=document.createElement('button'); button.type='button';button.className='btn-secondary';button.textContent=label;
          button.onclick=async()=>{
            if (action==='delete' && !window.confirm('Bu kompüteri silib telefon girişini ləğv edəsiniz?')) return;
            button.disabled=true;
            try {await invoke('account_device_action',{deviceId:device.device_id,action});await refresh();}
            catch(error){showMessage(String(error),'error');}
            finally{button.disabled=false;}
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
    continueButton.onclick=()=>{if(authenticated){overlay.hidden=true;window.switchTab?.('status');}};
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
        overlay.hidden=false;
        showMessage(action==='register'?'Hesab uğurla yaradıldı. Davam et düyməsini basın.':'Hesaba uğurla daxil oldunuz. Davam et düyməsini basın.','success');
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
