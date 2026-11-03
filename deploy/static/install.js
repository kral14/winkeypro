/* PWA installation: transfer existing pairings, never persist remote tokens in URLs. */
(function(root) {
  'use strict';
  async function post(win,path,body) {
    const response=await win.fetch(path,{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:win.AbortSignal.timeout(15000)});
    const data=await response.json();
    if(!response.ok)throw Error(data.message || data.error || 'Qoşulma alınmadı.');
    return data;
  }
  function standalone(win) {
    return Boolean(win.navigator?.standalone || win.matchMedia?.('(display-mode: standalone)').matches);
  }
  async function restoreTicket(win,ticket) {
    if(!win.isSecureContext)throw Error('Qoşulmanın bərpası üçün HTTPS lazımdır.');
    if(!/^[0-9a-f]{64}$/.test(ticket))throw Error('Qoşulma kodu düzgün deyil.');
    let nonce=win.localStorage.getItem('winkey_install_client_id');
    if(!/^[0-9a-f]{64}$/.test(nonce || '')) {
      const bytes=new Uint8Array(32);win.crypto.getRandomValues(bytes);
      nonce=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
      win.localStorage.setItem('winkey_install_client_id',nonce);
    }
    return post(win,'/mobile/restore',{ticket,client_nonce:nonce});
  }
  function createInstaller(win,provider=()=>null,report=()=>{}) {
    const byId=id=>win.document.getElementById(id);
    let source=provider,notify=report,promptEvent=null,ticket=null,signature='',expires=0,preparing=null,initialized=false,appInstalled=false;
    const isIOS=()=>/iPad|iPhone|iPod/.test(win.navigator?.userAgent || '') ||
      (win.navigator?.platform==='MacIntel' && win.navigator.maxTouchPoints>1);
    function handoffReady() {
      const current=source();
      const payload=current?.devices?.length ? {devices:current.devices.map(d=>({id:d.id,token:d.token,name:d.name})),selected:current.selected} : null;
      return Boolean(ticket && payload && signature===JSON.stringify(payload) && expires>Date.now()+300000 && !preparing);
    }
    function render() {
      const current=source(),installed=standalone(win) || appInstalled,button=byId('prepareInstall');
      if(button) {
        button.hidden=installed;
        button.disabled=!current?.devices?.length;
        button.textContent=isIOS()?'Ana ekrana əlavə et':promptEvent?'Android-də quraşdır':'Tətbiqi quraşdır';
      }
      const copy=byId('copyInstallCode');if(copy){copy.hidden=installed || !ticket || !current?.devices?.length;copy.disabled=!handoffReady();}
      const recovery=byId('installRecovery');if(recovery)recovery.hidden=!(installed && !current?.devices?.length);
    }
    win.addEventListener('beforeinstallprompt',event=>{event.preventDefault();promptEvent=event;render();});
    win.addEventListener('appinstalled',()=>{promptEvent=null;appInstalled=true;notify('WinKey tətbiqi quraşdırıldı. Ana ekrandakı ikonla aça bilərsiniz.');render();});
    async function prepare(force=false) {
      const current=source();
      if(standalone(win) || appInstalled || !current?.devices?.length){render();return null;}
      if(!win.isSecureContext)throw Error('Ana ekran tətbiqi üçün HTTPS lazımdır. Hazırkı HTTP serverində quraşdırma qoşulmanı saxlaya bilmir.');
      const payload={devices:current.devices.map(d=>({id:d.id,token:d.token,name:d.name})),selected:current.selected};
      const fingerprint=JSON.stringify(payload);
      if(!force && ticket && signature===fingerprint && expires>Date.now()+300000)return ticket;
      if(preparing){await preparing;return prepare(force);}
      preparing=(async()=>{
        const result=await post(win,'/mobile/install',payload);
        ticket=result.ticket;signature=fingerprint;expires=Date.now()+(result.expires_in || 86400)*1000;
        byId('appManifest').href='/mobile-assets/manifest.webmanifest?install='+encodeURIComponent(ticket);
        // iOS versions may keep either manifest start_url or the current page.
        // Put the same one-use handoff in both, never a persistent device token.
        win.history.replaceState({},'','/mobile#install='+ticket);
        render();return ticket;
      })();
      render();
      try{return await preparing;}finally{preparing=null;render();}
    }
    async function install() {
      const button=byId('prepareInstall');if(button)button.disabled=true;
      try {
        const ready=handoffReady();
        if(promptEvent && ready) {
          // prompt() must run in this click's user activation, before network awaits.
          const event=promptEvent;
          await event.prompt();promptEvent=null;
          const choice=await event.userChoice;
          notify(choice.outcome==='accepted'?'Quraşdırma qəbul edildi. WinKey ikonunu ana ekranda açın.':'Quraşdırma ləğv edildi. Sonra yenidən cəhd edə bilərsiniz.');
        }else{
          await prepare(!ready);
          if(promptEvent){notify('Qoşulma hazırdır. Quraşdırmaq üçün düyməni yenidən basın.');return;}
          notify(isIOS()?'Hazırdır. Safari → Paylaş → Ana ekrana əlavə et. Tətbiqi 24 saat içində ilk dəfə açın.':'Hazırdır. Chrome menyusu → Tətbiqi quraşdır / Ana ekrana əlavə et.');
        }
      }catch(error){notify(error.message);}finally{render();}
    }
    async function init(nextProvider,nextReport) {
      if(nextProvider)source=nextProvider;if(nextReport)notify=nextReport;
      if(!initialized) {
        initialized=true;
        if(byId('prepareInstall'))byId('prepareInstall').onclick=install;
        if(byId('copyInstallCode'))byId('copyInstallCode').onclick=async()=>{
          try {if(!handoffReady())throw Error('Qoşulma hələ hazırlanır. Bir az sonra yenidən basın.');await win.navigator.clipboard.writeText(ticket);notify('Qoşulma kodu kopyalandı. Boş açılan tətbiqdə bərpa sahəsinə yapışdırın.');}
          catch(error){notify('Kopyalama alınmadı: '+error.message);}
        };
        if(byId('installRecoveryForm'))byId('installRecoveryForm').onsubmit=async event=>{
          event.preventDefault();
          const button=byId('restoreInstall');button.disabled=true;
          try {
            const text=byId('installRecoveryCode').value.trim();
            const code=/^[0-9a-f]{64}$/.test(text)?text:new URL(text,win.location.origin).hash.slice(1).replace(/^install=/,'');
            const payload=await restoreTicket(win,code);
            await source().restore(payload);
            win.history.replaceState({},'','/mobile');render();notify('Qoşulma bərpa edildi. Kompüterinizi seçə bilərsiniz.');
          }catch(error){notify(error.message.includes('HTTPS')?error.message:'Bərpa alınmadı. Safari-də yeni qoşulma kodu hazırlayıb yenidən yoxlayın.');}
          finally{button.disabled=false;}
        };
        if(win.isSecureContext && win.navigator?.serviceWorker) {
          try{await win.navigator.serviceWorker.register('/mobile-sw.js',{scope:'/'});}
          catch(error){notify('Tətbiqin oflayn görünüşü hazırlana bilmədi. İnternet bağlantısını yoxlayın.');}
        }
      }
      render();
      try{await prepare();}catch(error){notify(error.message);}
    }
    return {init,prepare,restore:code=>restoreTicket(win,code),refresh:()=>prepare().catch(error=>{notify(error.message);return null;})};
  }
  if(typeof module!=='undefined')module.exports={createInstaller,restoreTicket,standalone};
  if(root?.document)root.WinKeyInstall=createInstaller(root);
})(typeof window!=='undefined'?window:null);
