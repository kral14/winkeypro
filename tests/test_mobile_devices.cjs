const assert = require('node:assert/strict');
const {DevicePortfolio} = require('../deploy/static/devices.js');
const store = new Map();
const storage = {getItem: key => store.get(key) || null,
  setItem: (key,value) => store.set(key,value), removeItem: key => store.delete(key)};
let devices = new DevicePortfolio(storage);
devices.add({id:'pc1',token:'session1',name:'Ofis 1'});
devices.add({id:'pc2',token:'session2',name:'PC 2'});
devices.select('pc1');
devices = new DevicePortfolio(storage);
assert.equal(devices.current().id, 'pc1');
assert.equal(devices.current().token, 'session1');
assert.equal(devices.devices.length, 2);
devices.add({id:'pc2',token:'rotated-session',name:'Ofis 2'});
assert.equal(devices.devices.length, 2);
assert.equal(devices.current().token, 'rotated-session');
assert.throws(() => devices.select('foreign'));
devices.remove('pc2');
assert.equal(devices.current().id, 'pc1');
assert.equal(storage.getItem('winkey_token'), 'session1');
store.clear();
storage.setItem('winkey_token','old-token'); storage.setItem('winkey_dev_id','old-pc');
devices = new DevicePortfolio(storage);
assert.equal(devices.current().id, 'old-pc');
assert.equal(devices.current().token, 'old-token');
store.set('winkey_devices_v1','bad json');
assert.doesNotThrow(() => new DevicePortfolio(storage));
console.log('PASS named devices, selection reload, token isolation, deduplication and legacy migration');

async function browserFlow() {
  const vm = require('node:vm'), fs = require('node:fs');
  function browser(initial = {}, hash = '') {
    const values = new Map(Object.entries(initial)), elements = new Map(), calls = [];
    const storage = {getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
    const element = id => {
      if (!elements.has(id)) elements.set(id, {value:'',hidden:true,replaceChildren() {},appendChild() {}});
      return elements.get(id);
    };
    const document = {getElementById:element,createElement:()=>({})};
    const location = {origin:'https://winkey.test',pathname:'/mobile',search:'',hash};
    const root = {document,location,addEventListener() {}};
    const context = vm.createContext({window:root,document,location,localStorage:storage,
      URL,URLSearchParams,AbortSignal,history:{replaceState() {}},cancelAnimationFrame() {},
      fetch:async (url,options) => {
        calls.push({url,body:JSON.parse(options.body),headers:options.headers});
        let data;
        if (url === '/mobile/restore') data = {devices:[{id:'pc1',token:'t1',name:'Ofis 1'}],selected:'pc1'};
        else if (url === '/mobile/install') data = {ticket:'a'.repeat(64)};
        else data = {device_id:'pc2',session_token:'t2',name:'PC 2'};
        return {ok:true,json:async()=>data};
      }});
    vm.runInContext(fs.readFileSync('deploy/static/devices.js','utf8'),context);
    return {root,element,values,calls,context};
  }
  const initial = JSON.stringify({devices:[{id:'pc1',token:'t1',name:'Ofis 1'}],selected:'pc1'});
  const b = browser({winkey_devices_v1:initial});
  let busy = false, selected;
  const choose = (device,probe) => { if (probe) return !busy; selected = device; return true; };
  const restored = await b.root.WinKeyDevices.start(choose);
  assert.equal(restored.id,'pc1');
  b.element('deviceName').value = 'PC 2';
  b.element('devicePairCode').value = 'https://winkey.test/mobile?code=PAIR_TWO';
  await b.element('deviceAddForm').onsubmit({preventDefault() {}});
  assert.equal(selected.id,'pc2');
  assert.equal(b.calls[0].headers.Authorization,'Bearer t1');
  assert.equal(b.calls[0].body.pair_code,'PAIR_TWO');
  const change = b.element('deviceSelect'); change.value = 'pc1';
  busy = true; change.onchange({target:change});
  assert.equal(change.value,'pc2');
  busy = false; change.value='pc1'; change.onchange({target:change});
  assert.equal(selected.id,'pc1'); assert.equal(selected.token,'t1');
  await b.element('prepareInstall').onclick();
  assert.match(b.element('appManifest').href,/install=a{64}$/);
  assert.equal(b.calls[1].body.devices.length,2);
  assert.equal(b.calls[1].body.selected,'pc1');
  const installed = browser({},'#install='+'a'.repeat(64));
  const device = await installed.root.WinKeyDevices.start(()=>true);
  assert.equal(device.id,'pc1'); assert.equal(device.token,'t1');
  assert.equal(installed.calls[0].url,'/mobile/restore');
  const race = browser({winkey_devices_v1:initial});
  let commandBusy = false, target = 'pc1', releasePair;
  await race.root.WinKeyDevices.start((device,probe) => {
    if (commandBusy) return false;
    if (!probe) target = device.id;
    return true;
  });
  race.context.fetch = async () => {
    await new Promise(resolve => { releasePair = resolve; });
    return {ok:true,json:async()=>({device_id:'pc2',session_token:'t2',name:'PC 2'})};
  };
  race.element('deviceName').value='PC 2'; race.element('devicePairCode').value='PAIR_TWO';
  const pairing = race.element('deviceAddForm').onsubmit({preventDefault() {}});
  assert.equal(race.root.WinKeyDevices.isPairing(),true);
  commandBusy = true; releasePair(); await pairing;
  assert.equal(target,'pc1');
  assert.equal(race.root.WinKeyDevices.current().id,'pc1');
  assert.equal(JSON.parse(race.values.get('winkey_devices_v1')).devices.length,2);
  assert.equal(race.root.WinKeyDevices.remove('pc1'),false);
  assert.equal(race.root.WinKeyDevices.current().id,'pc1');
  console.log('PASS in-page pairing, busy-switch guard, selected token, install handoff and separate iOS storage restore');
}
browserFlow().catch(error => {console.error(error);process.exitCode=1;});
