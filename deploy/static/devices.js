/* Named device sessions and iOS install handoff. No account password on mobile. */
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
      if (!device || !device.id || !device.token || !device.name?.trim() || device.name.length > 80) throw Error('Kompüterin adını yazın.');
      if (this.devices.length >= 50 && !this.devices.some(d => d.id === device.id)) throw Error('Ən çox 50 kompüter əlavə edilə bilər.');
      this.devices = this.devices.filter(d => d.id !== device.id);
      this.devices.push({id:device.id,token:device.token,name:device.name.trim()});
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

  let portfolio, onSelect, stream, animation, pairing = false, scannerEpoch = 0;
  const byId = id => document.getElementById(id);
  const message = text => { byId('deviceMessage').textContent = text; };
  async function post(path, body, token) {
    const response = await fetch(path, {method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/json',...(token ? {Authorization:'Bearer '+token} : {})},
      body:JSON.stringify(body), signal:AbortSignal.timeout(15000)});
    const data = await response.json();
    if (!response.ok) throw Error(data.message || data.error || 'Sorğu alınmadı.');
    return data;
  }
  function render() {
    const select = byId('deviceSelect');
    select.replaceChildren();
    for (const device of portfolio.devices) {
      const option = document.createElement('option');
      option.value = device.id; option.textContent = device.name; select.appendChild(option);
    }
    select.value = portfolio.selected;
    select.disabled = !portfolio.devices.length;
    byId('prepareInstall').disabled = !portfolio.devices.length;
  }
  function stopScanner() {
    scannerEpoch++;
    if (stream) stream.getTracks().forEach(track => track.stop());
    stream = null; cancelAnimationFrame(animation);
    byId('deviceCamera').hidden = true;
  }
  function codeFrom(value) {
    value = value.trim();
    if (/^PAIR_[A-Z0-9]+$/.test(value)) return value;
    const url = new URL(value, location.origin);
    if (url.origin !== location.origin || !['/mobile','/remote'].includes(url.pathname)) throw Error('Bu serverə aid WinKey QR kodunu oxudun.');
    const code = url.searchParams.get('code') || url.searchParams.get('pair_code');
    if (!code || !/^PAIR_[A-Z0-9]+$/.test(code)) throw Error('Etibarlı WinKey QR kodu deyil.');
    return code;
  }
  function decoded(value) {
    try { byId('devicePairCode').value = codeFrom(value); stopScanner(); message('QR oxundu. Kompüterə ad verib Əlavə et düyməsini basın.'); return true; }
    catch (error) { message(error.message); return false; }
  }
  async function startScanner() {
    stopScanner();
    if (!root.isSecureContext) { message('Kamera üçün HTTPS lazımdır. QR şəklini seçə və ya qoşulma kodunu yaza bilərsiniz.'); return; }
    try {
      const epoch = scannerEpoch;
      const acquired = await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'},audio:false});
      if (epoch !== scannerEpoch) { acquired.getTracks().forEach(track => track.stop()); return; }
      stream = acquired;
      const video = byId('deviceCamera'); video.srcObject = stream; video.hidden = false; await video.play();
      const canvas = document.createElement('canvas'), context = canvas.getContext('2d', {willReadFrequently:true});
      function scan() {
        if (!stream) return;
        if (video.readyState >= 2 && video.videoWidth) {
          const scale = Math.min(1, 800/video.videoWidth);
          canvas.width = Math.round(video.videoWidth*scale); canvas.height = Math.round(video.videoHeight*scale);
          context.drawImage(video,0,0,canvas.width,canvas.height);
          const pixels = context.getImageData(0,0,canvas.width,canvas.height);
          const result = root.jsQR?.(pixels.data,canvas.width,canvas.height);
          if (result && decoded(result.data)) return;
        }
        animation = requestAnimationFrame(scan);
      }
      scan();
    } catch (_) { stopScanner(); message('Kamera açılmadı. Kamera icazəsini yoxlayın və ya QR şəklini seçin.'); }
  }
  async function addDevice(event) {
    event.preventDefault();
    if (pairing) return;
    if (!onSelect(null, true)) { message('Cari əmrin bitməsini gözləyin.'); return; }
    pairing = true;
    const previousSelection = portfolio.selected;
    const button = byId('deviceAddConfirm'); button.disabled = true;
    try {
      const name = byId('deviceName').value.trim();
      if (!name || name.length > 80) throw Error('Kompüterə 1–80 simvollu ad verin.');
      const pair_code = codeFrom(byId('devicePairCode').value);
      const result = await post('/mobile/pair', {pair_code,name}, portfolio.current()?.token);
      const activate = portfolio.selected === previousSelection && onSelect(null, true);
      portfolio.add({id:result.device_id,token:result.session_token,name:result.name || name}, activate);
      render();
      if (activate) onSelect(portfolio.current());
      byId('deviceAddPanel').hidden = true; stopScanner();
      history.replaceState({}, '', location.pathname);
      message(activate ? 'Kompüter əlavə edildi. Seçim yadda saxlanıldı.' : 'Kompüter əlavə edildi. Cari əmrdən sonra siyahıdan seçə bilərsiniz.');
    } catch (error) { message(error.message); }
    finally { pairing = false; button.disabled = false; }
  }
  async function prepareInstall() {
    byId('prepareInstall').disabled = true;
    try {
      const data = await post('/mobile/install', {devices:portfolio.devices,selected:portfolio.selected});
      byId('appManifest').href = '/mobile-assets/manifest.webmanifest?install='+encodeURIComponent(data.ticket);
      message('Hazırdır. iPhone-da Paylaş → Ana ekrana əlavə et seçin. İlk açılışı 24 saat içində edin.');
    } catch (error) { message(error.message); }
    finally { byId('prepareInstall').disabled = false; }
  }
  async function start(selectCallback) {
    portfolio = new DevicePortfolio(localStorage); onSelect = selectCallback;
    // An installed iOS web app can start with storage separate from Safari.
    const ticket = new URLSearchParams(location.hash.slice(1)).get('install');
    if (ticket && !portfolio.devices.length) {
      try {
        const restored = await post('/mobile/restore', {ticket});
        for (const device of restored.devices) portfolio.add(device);
        portfolio.select(restored.selected);
        history.replaceState({}, '', location.pathname);
      } catch (_) { message('Qoşulma bərpa edilmədi. Yeni cihaz əlavə et ilə PC-dəki yeni QR-ni oxudun.'); }
    }
    render();
    byId('deviceSelect').onchange = event => {
      const previous = portfolio.selected;
      const next = portfolio.devices.find(d => d.id === event.target.value);
      if (!onSelect(next, true)) { event.target.value = previous; message('Cari əmrin bitməsini gözləyin.'); return; }
      portfolio.select(next.id); onSelect(next); message('Seçim yadda saxlanıldı.');
    };
    byId('deviceAdd').onclick = () => {
      byId('deviceAddPanel').hidden = false; byId('deviceName').value = '';
      byId('devicePairCode').value = ''; message('Yeni kompüterdəki QR-ni oxudun və ad verin.');
    };
    byId('deviceAddCancel').onclick = () => { stopScanner(); byId('deviceAddPanel').hidden = true; };
    byId('deviceScan').onclick = startScanner;
    byId('deviceAddForm').onsubmit = addDevice;
    byId('prepareInstall').onclick = prepareInstall;
    byId('devicePhoto').onchange = async event => {
      const file = event.target.files[0]; if (!file) return;
      const url = URL.createObjectURL(file);
      try {
        const image = new Image(); image.src = url; await image.decode();
        const canvas = document.createElement('canvas');
        const scale = Math.min(1, 1600/image.width);
        canvas.width = Math.round(image.width*scale); canvas.height = Math.round(image.height*scale);
        const context = canvas.getContext('2d'); context.drawImage(image,0,0,canvas.width,canvas.height);
        const pixels = context.getImageData(0,0,canvas.width,canvas.height);
        const qr = root.jsQR(pixels.data,canvas.width,canvas.height);
        if (!qr) throw Error('Şəkildə QR tapılmadı.'); decoded(qr.data);
      } catch (error) { message(error.message); }
      finally { URL.revokeObjectURL(url); event.target.value = ''; }
    };
    root.addEventListener('pagehide', stopScanner);
    const query = new URLSearchParams(location.search);
    const code = query.get('code') || query.get('pair_code');
    if (code) {
      byId('deviceAddPanel').hidden = false; byId('devicePairCode').value = code;
      message('QR alındı. Kompüterə ad verib Əlavə et düyməsini basın.');
      history.replaceState({}, '', location.pathname);
    }
    return portfolio.current();
  }
  root.WinKeyDevices = {start, current:() => portfolio?.current(), isPairing:() => pairing,
    remove(id) {
      if (!onSelect(null, true)) return false;
      portfolio.remove(id); render(); onSelect(portfolio.current()); return true;
    }};
})(typeof window !== 'undefined' ? window : null);
