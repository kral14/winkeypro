/* WinKey Pro - Multi-Device Portfolio Manager (Mobile Controller) */
(function (root) {
  'use strict';
  const KEY = 'winkey_devices_v1';

  class DevicePortfolio {
    constructor(storage) {
      this.storage = storage;
      this.devices = [];
      this.selected = '';
      try {
        const value = JSON.parse(storage.getItem(KEY) || '{}');
        this.devices = Array.isArray(value.devices) ? value.devices.filter(d => d &&
          typeof d.id === 'string' && typeof d.token === 'string' && d.id && d.token &&
          typeof d.name === 'string').slice(0, 50) : [];
        this.selected = value.selected || '';
      } catch (_) {}
      if (!this.devices.length) {
        const id = storage.getItem('winkey_dev_id'), token = storage.getItem('winkey_token');
        if (id && token) this.devices.push({id, token, name: 'Kompüter'});
      }
      if (!this.devices.some(d => d.id === this.selected)) this.selected = this.devices[0]?.id || '';
      this.save();
    }
    current() { return this.devices.find(d => d.id === this.selected) || null; }
    save() {
      this.storage.setItem(KEY, JSON.stringify({devices:this.devices, selected:this.selected}));
      const current = this.current();
      if (current) {
        this.storage.setItem('winkey_token', current.token);
        this.storage.setItem('winkey_dev_id', current.id);
      } else {
        this.storage.removeItem('winkey_token'); this.storage.removeItem('winkey_dev_id');
      }
    }
    add(device, activate = true) {
      if (!device || !device.id || !device.token) throw Error('Cihaz məlumatı natamamdır.');
      const name = (device.name && device.name.trim()) ? device.name.trim().slice(0, 80) : 'Kompüter';
      if (this.devices.length >= 50 && !this.devices.some(d => d.id === device.id)) throw Error('Ən çox 50 kompüter əlavə edilə bilər.');
      this.devices = this.devices.filter(d => d.id !== device.id);
      this.devices.push({id: device.id, token: device.token, name});
      if (activate || !this.selected) this.selected = device.id;
      this.save();
    }
    select(id) {
      if (!this.devices.some(d => d.id === id)) throw Error('Kompüter tapılmadı.');
      this.selected = id; this.save(); return this.current();
    }
    remove(id) {
      this.devices = this.devices.filter(d => d.id !== id);
      if (this.selected === id) this.selected = this.devices[0]?.id || '';
      this.save();
    }
  }

  if (typeof module !== 'undefined') module.exports = {DevicePortfolio};
  if (!root || !root.document) return;

  let portfolio, onSelect, onPresence, pairing=false, syncing=false;
  const byId=id=>document.getElementById(id);
  const message=text=>{const el=byId('deviceMessage');if(el)el.textContent=text;};
  async function post(path,body,token) {
    const response=await fetch(path,{method:'POST',cache:'no-store',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(15000)});
    const result=await response.json();
    if(!response.ok)throw Error(result.message || result.error || 'Sorğu alınmadı.');
    return result;
  }
  function render() {
    const select=byId('deviceSelect');if(!select)return;
    select.replaceChildren();
    for(const device of portfolio.devices) {
      const option=document.createElement('option');option.value=device.id;
      option.textContent=device.name+' · '+(device.online?'Onlayn':'Oflayn');select.appendChild(option);
    }
    select.value=portfolio.selected;select.disabled=!portfolio.devices.length;
    if(byId('deviceCountBadge'))byId('deviceCountBadge').textContent=portfolio.devices.length+' Kompüter';
  }
  async function sync() {
    if(syncing || pairing || !portfolio.devices.length || document.hidden)return;
    syncing=true;
    try {
      const data=await post('/mobile/devices',{devices:portfolio.devices.map(d=>({id:d.id,token:d.token}))});
      if(!Array.isArray(data.devices))throw Error('Cihaz siyahısı alınmadı.');
      // Do not rotate a command target while its physical operation is pending.
      if(!onSelect(null,true))return;
      const previous=portfolio.selected;
      portfolio.devices=data.devices.map(d=>({id:d.device_id,token:d.token,name:d.computer_name,online:Boolean(d.online),locked:Boolean(d.locked)}));
      if(!portfolio.devices.some(d=>d.id===previous))portfolio.selected=portfolio.devices[0]?.id || '';
      portfolio.save();render();watchDevices();
      if(previous!==portfolio.selected)onSelect(portfolio.current());
      onPresence?.(portfolio.current());

    }catch(error){
      for(const device of portfolio.devices)device.online=false;
      render();onPresence?.(portfolio.current());
      message('Serverə əlaqə yoxdur. Cihaz seçimləri yadda saxlanılıb.');
    }finally{syncing=false;}
  }
  const stateSockets=new Map();
  function watchDevices() {
    if(!root.WebSocket)return;
    for(const [id,entry] of stateSockets) {
      if(!portfolio.devices.some(d=>d.id===id && d.token===entry.token)) {
        stateSockets.delete(id);clearTimeout(entry.retry);entry.socket?.close();
      }
    }
    for(const device of portfolio.devices) {
      if(stateSockets.has(device.id))continue;
      const entry={token:device.token,socket:null,retry:null};stateSockets.set(device.id,entry);
      const connect=()=>{
        if(stateSockets.get(device.id)!==entry)return;
        const socket=new root.WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws');entry.socket=socket;
        socket.onopen=()=>socket.send(JSON.stringify({type:'auth',role:'mobile',device_id:device.id,session_token:entry.token}));
        socket.onmessage=event=>{
          if(stateSockets.get(device.id)!==entry)return;
          const data=JSON.parse(event.data);
          if(data.type!=='device_state' || data.device_id!==device.id)return;
          const current=portfolio.devices.find(d=>d.id===device.id);if(!current)return;
          current.online=Boolean(data.online);current.locked=Boolean(data.locked);
          render();if(portfolio.selected===device.id)onPresence?.(current);
        };
        socket.onclose=event=>{
          if(stateSockets.get(device.id)!==entry)return;
          if(event.code===4401 || event.code===4403){stateSockets.delete(device.id);return;}
          entry.retry=setTimeout(connect,2000);
        };
        socket.onerror=()=>socket.close();
      };
      connect();
    }
  }
  function getSafeStorage() {
    return root?.localStorage || (typeof localStorage !== 'undefined' ? localStorage : null);
  }

  async function syncAccount() {
    const s = getSafeStorage();
    const acctToken = s?.getItem ? s.getItem('winkey_account_token') : null;
    if (!acctToken) return null;
    try {
      const data = await post('/accounts/session', {}, acctToken);
      if (data && Array.isArray(data.devices)) {
        for (const dev of data.devices) {
          const existing = portfolio.devices.find(d => d.id === dev.device_id);
          const devToken = existing?.token || acctToken;
          portfolio.add({
            id: dev.device_id,
            token: devToken,
            name: dev.computer_name || 'Kompüter'
          }, false);
        }
        if (!portfolio.selected && portfolio.devices.length) {
          portfolio.select(portfolio.devices[0].id);
        }
        render();watchDevices();
        if (portfolio.current()) onSelect(portfolio.current());
      }
      return data;
    } catch (e) {
      if (String(e).includes('401') || String(e).includes('E_ACCOUNT')) {
        const s = getSafeStorage();
        if (s?.removeItem) {
          s.removeItem('winkey_account_token');
          s.removeItem('winkey_account_email');
        }
      }
      return null;
    }
  }

  async function login(email, password) {
    const res = await post('/accounts/login', { email, password });
    const s = getSafeStorage();
    if (s?.setItem) {
      s.setItem('winkey_account_token', res.account_token);
      s.setItem('winkey_account_email', res.email);
    }
    await syncAccount();
    return res;
  }

  async function register(email, password) {
    const res = await post('/accounts/register', { email, password });
    const s = getSafeStorage();
    if (s?.setItem) {
      s.setItem('winkey_account_token', res.account_token);
      s.setItem('winkey_account_email', res.email);
    }
    await syncAccount();
    return res;
  }

  async function logout() {
    const s = getSafeStorage();
    const acctToken = s?.getItem ? s.getItem('winkey_account_token') : null;
    try {
      if (acctToken) await post('/accounts/logout', {}, acctToken);
    } catch (_) {}
    if (s?.removeItem) {
      s.removeItem('winkey_account_token');
      s.removeItem('winkey_account_email');
    }
    portfolio.devices = [];
    portfolio.selected = '';
    portfolio.save();
    render();
    watchDevices();
    onSelect(null);
  }

  function getAccountInfo() {
    const s = getSafeStorage();
    return {
      token: s?.getItem ? s.getItem('winkey_account_token') : null,
      email: s?.getItem ? s.getItem('winkey_account_email') : null
    };
  }

  async function start(selectCallback,presenceCallback) {
    portfolio=new DevicePortfolio(localStorage);onSelect=selectCallback;onPresence=presenceCallback;
    await syncAccount();
    // Old installed shortcuts may still contain a retired handoff ticket.
    if(new URLSearchParams(location.hash.slice(1)).has('install'))history.replaceState({},'',location.pathname+location.search);
    const query=new URLSearchParams(location.search);
    const code=query.get('code') || query.get('pair_code');
    if(code) {
      pairing=true;
      try {
        const result=await post('/pair',{pair_code:code},portfolio.current()?.token);
        portfolio.add({id:result.device_id,token:result.session_token,name:result.computer_name || result.name || 'Kompüter'});
        history.replaceState({},'',location.pathname);
        message('Kompüter əlavə edildi. Siyahıdan Ev və ya Ofis seçə bilərsiniz.');
      }catch(error){message('Qoşulma alınmadı: '+error.message);}
      finally{pairing=false;}
    }
    render();
    const select=byId('deviceSelect');
    if(select)select.onchange=event=>{
      const previous=portfolio.selected,next=portfolio.devices.find(d=>d.id===event.target.value);
      if(!next || !onSelect(next,true)){event.target.value=previous;message('Cari əmrin bitməsini gözləyin.');return;}
      portfolio.select(next.id);onSelect(next);onPresence?.(next);message('Seçim yadda saxlanıldı.');
    };
    await sync();
    if(!portfolio.devices.length)message('Kompüterlərinizi görmək üçün hesabınıza daxil olun.');
    root.WinKeyInstall?.init();
    watchDevices();
    root.addEventListener('pageshow',sync);
    document.addEventListener('visibilitychange',()=>{if(!document.hidden)sync();});
    return portfolio.current();
  }
  root.WinKeyDevices={start,current:()=>portfolio?.current(),isPairing:()=>pairing,
    login,register,logout,getAccountInfo,syncAccount,
    remove(id){if(!onSelect(null,true))return false;portfolio.remove(id);render();onSelect(portfolio.current());return true;}};
})(typeof window!=='undefined'?window:null);
