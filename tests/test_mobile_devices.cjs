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
 const vm=require('node:vm'),fs=require('node:fs');
 function browser(initial={},search='',hash='') {
  const values=new Map(Object.entries(initial)),elements=new Map(),calls=[];
  const states=[{device_id:'pc1',token:'t1',computer_name:'Ofis',online:true,locked:false},{device_id:'pc2',token:'t2',computer_name:'Ev',online:false,locked:true}];
  const element=id=>{if(!elements.has(id))elements.set(id,{value:'',hidden:true,children:[],replaceChildren(){this.children=[]},appendChild(c){this.children.push(c)}});return elements.get(id);};
  const document={hidden:false,getElementById:element,createElement:()=>({}),addEventListener(){}};
  const location={origin:'https://winkey.test',pathname:'/mobile',search,hash};
  const root={document,location,isSecureContext:true,addEventListener(){},setInterval(fn){root.refresh=fn}};
  const storage={getItem:k=>values.get(k)||null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
  const context=vm.createContext({window:root,document,location,localStorage:storage,URL,URLSearchParams,AbortSignal,history:{replaceState(){}},fetch:async(url,options)=>{
   calls.push({url,body:JSON.parse(options.body),headers:options.headers});
   let data;
   if(url==='/pair')data={device_id:'pc2',session_token:'t2',computer_name:'Ev'};
   else if(url==='/mobile/restore')data={devices:[{id:'pc1',token:'t1',name:'Ofis'}],selected:'pc1'};
   else if(url==='/mobile/install')data={ticket:'a'.repeat(64)};
   else if(url==='/mobile/devices')data={devices:states};
   else throw Error('Unexpected route '+url);
   return{ok:true,json:async()=>data};
  }});
  vm.runInContext(fs.readFileSync('deploy/static/devices.js','utf8'),context);
  return{root,values,calls,states,element,context};
 }
 const initial=JSON.stringify({devices:[{id:'pc1',token:'t1',name:'Ofis'}],selected:'pc1'});
 const b=browser({winkey_devices_v1:initial},'?code=PAIR_TWO&name=Tampered');
 let busy=false,selected,presence;
 const choose=(device,probe)=>{if(probe)return !busy;selected=device;return true;};
 const current=await b.root.WinKeyDevices.start(choose,d=>{presence=d});
 assert.equal(current.id,'pc2');assert.equal(current.name,'Ev');
 assert.equal(b.calls[0].headers.Authorization,'Bearer t1');assert.equal(b.calls[0].body.pair_code,'PAIR_TWO');
 assert.equal(JSON.parse(b.values.get('winkey_devices_v1')).devices.length,2);
 const select=b.element('deviceSelect');select.value='pc1';busy=true;select.onchange({target:select});assert.equal(select.value,'pc2');
 busy=false;select.value='pc1';select.onchange({target:select});assert.equal(selected.id,'pc1');assert.equal(selected.token,'t1');
 b.states[0].online=false;await b.root.refresh();assert.equal(presence.online,false);
 assert.match(b.element('deviceSelect').children[0].textContent,/Oflayn/);
 await b.element('prepareInstall').onclick();assert.match(b.element('appManifest').href,/install=a{64}$/);
 const installed=browser({},'','#install='+'a'.repeat(64));
 const restored=await installed.root.WinKeyDevices.start(choose);
 assert.equal(restored.id,'pc1');assert.equal(JSON.parse(installed.values.get('winkey_devices_v1')).devices.length,2,'Existing phone group receives second PC without a mobile Add flow');
 assert(!fs.readFileSync('deploy/gateway_production_server.py','utf8').includes('id="deviceAddForm"'));
 console.log('PASS PC-named QR, phone-group synchronization, remembered selection, presence and iOS restore; no mobile Add device');
}
browserFlow().catch(error=>{console.error(error);process.exitCode=1;});
