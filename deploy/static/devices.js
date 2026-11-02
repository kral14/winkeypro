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

  let portfolio, onSelect, pairing = false;
  const byId = id => document.getElementById(id);
  const message = text => {
    const el = byId('deviceMessage');
    if (el) el.textContent = text;
  };

  async function post(path, body, token) {
    const response = await fetch(path, {
      method: 'POST',
      cache: 'no-store',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? {Authorization: 'Bearer ' + token} : {})
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15000)
    });
    const data = await response.json();
    if (!response.ok) throw Error(data.message || data.error || 'Sorğu alınmadı.');
    return data;
  }

  function render() {
    const select = byId('deviceSelect');
    if (!select) return;
    select.replaceChildren();
    if (!portfolio.devices.length) {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'Heç bir kompüter qoşulmayıb (PC QR oxudun)';
      select.appendChild(opt);
      select.disabled = true;
    } else {
      select.disabled = false;
      for (const device of portfolio.devices) {
        const option = document.createElement('option');
        option.value = device.id;
        option.textContent = '🖥️ ' + device.name;
        select.appendChild(option);
      }
      select.value = portfolio.selected;
    }
    const badge = byId('deviceCountBadge');
    if (badge) badge.textContent = portfolio.devices.length + ' Kompüter';
  }

  function codeFrom(value) {
    if (!value) return '';
    value = value.trim();
    if (/^PAIR_[A-Z0-9]+$/.test(value)) return value;
    try {
      const url = new URL(value, location.origin);
      const code = url.searchParams.get('code') || url.searchParams.get('pair_code');
      if (code && /^PAIR_[A-Z0-9]+$/.test(code)) return code;
    } catch (_) {}
    return value;
  }

  async function start(selectCallback) {
    portfolio = new DevicePortfolio(localStorage);
    onSelect = selectCallback;

    // iOS install bərpası (varsa)
    const ticket = new URLSearchParams(location.hash.slice(1)).get('install');
    if (ticket && !portfolio.devices.length) {
      try {
        const restored = await post('/mobile/restore', {ticket});
        for (const device of restored.devices) portfolio.add(device);
        portfolio.select(restored.selected);
        history.replaceState({}, '', location.pathname);
      } catch (_) {}
    }

    render();

    const devSelect = byId('deviceSelect');
    if (devSelect) {
      devSelect.onchange = event => {
        const previous = portfolio.selected;
        const next = portfolio.devices.find(d => d.id === event.target.value);
        if (!next) return;
        if (!onSelect(next, true)) {
          event.target.value = previous;
          message('Cari əmrin bitməsini gözləyin.');
          return;
        }
        portfolio.select(next.id);
        onSelect(next);
        message('Seçim dəyişdirildi: ' + next.name);
      };
    }

    // Telefonun kamerası ilə birbaşa QR oxudulduqda avtomatik cütləşmə
    const query = new URLSearchParams(location.search);
    const rawCode = query.get('code') || query.get('pair_code');
    const nameParam = query.get('name') || '';

    if (rawCode) {
      const pairCode = codeFrom(rawCode);
      if (pairCode) {
        pairing = true;
        message('Yeni kompüter qoşulur...');
        (async () => {
          try {
            const reqBody = { pair_code: pairCode };
            if (nameParam) reqBody.name = nameParam;
            const res = await post('/pair', reqBody, portfolio.current()?.token);
            const assignedName = nameParam || res.name || res.computer_name || ('Kompüter ' + (portfolio.devices.length + 1));
            portfolio.add({
              id: res.device_id,
              token: res.session_token,
              name: assignedName
            }, true);
            render();
            if (onSelect) onSelect(portfolio.current());
            history.replaceState({}, '', location.pathname);
            message('✓ "' + assignedName + '" kompüteri uğurla əlavə edildi!');
          } catch (err) {
            message('Qoşulma xətası: ' + err.message);
          } finally {
            pairing = false;
          }
        })();
      }
    }

    return portfolio.current();
  }

  root.WinKeyDevices = {
    start,
    current: () => portfolio?.current(),
    isPairing: () => pairing,
    remove(id) {
      if (!onSelect(null, true)) return false;
      portfolio.remove(id);
      render();
      onSelect(portfolio.current());
      return true;
    }
  };
})(typeof window !== 'undefined' ? window : null);
