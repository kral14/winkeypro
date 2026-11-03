const assert=require('node:assert/strict');
const {webcrypto}=require('node:crypto');
const {createInstaller,restoreTicket}=require('../deploy/static/install.js');
function browser({secure=true,installed=false,ios=false}={}) {
  const nodes=new Map(),events=new Map(),values=new Map(),calls=[],messages=[],registrations=[];
  const node=id=>{if(!nodes.has(id))nodes.set(id,{hidden:false,disabled:false,value:'',href:'',textContent:''});return nodes.get(id);};
  let count=0;
  const win={isSecureContext:secure,crypto:webcrypto,AbortSignal,document:{getElementById:node},
    location:{origin:'https://winkey.test'},matchMedia:()=>({matches:installed}),
    localStorage:{getItem:key=>values.get(key)||null,setItem:(key,value)=>values.set(key,value)},
    history:{replaceState(a,b,url){calls.push({navigation:url});}},
    addEventListener:(type,fn)=>events.set(type,fn),
    navigator:{userAgent:ios?'iPhone':'Android',standalone:installed,
      clipboard:{async writeText(text){values.set('clipboard',text);}},
      serviceWorker:{async register(url,options){registrations.push({url,options});}}},
    fetch:async(url,options)=>{
      calls.push({url,body:JSON.parse(options.body)});
      const data=url==='/mobile/install'?{ticket:(++count).toString(16).padStart(64,'0'),expires_in:86400}:
        {devices:[{id:'pc1',token:'private-token',name:'Ofis'}],selected:'pc1'};
      return{ok:true,json:async()=>data};
    }};
  return{win,node,events,values,calls,messages,registrations};
}
(async()=>{
  const b=browser({ios:true});
  let state={devices:[{id:'pc1',token:'private-token',name:'Ofis'}],selected:'pc1'};
  const install=createInstaller(b.win,()=>state,text=>b.messages.push(text));
  await install.init();
  assert.equal(b.registrations[0].url,'/mobile-sw.js');
  assert.match(b.node('appManifest').href,/install=[0-9a-f]{64}$/);
  assert.match(b.calls.find(c=>c.navigation).navigation,/\/mobile#install=[0-9a-f]{64}$/);
  assert(!b.calls.find(c=>c.navigation).navigation.includes('private-token'));
  const first=b.calls.filter(c=>c.url==='/mobile/install').length;
  await install.refresh();assert.equal(b.calls.filter(c=>c.url==='/mobile/install').length,first,'No ticket churn for unchanged portfolio');
  state={...state,devices:[...state.devices,{id:'pc2',token:'second-token',name:'Ev'}],selected:'pc2'};
  await install.refresh();assert.equal(b.calls.filter(c=>c.url==='/mobile/install').at(-1).body.selected,'pc2');
  await b.node('copyInstallCode').onclick();assert.match(b.values.get('clipboard'),/^[0-9a-f]{64}$/);
  await b.node('prepareInstall').onclick();assert.match(b.messages.at(-1),/Safari/);
  const android=browser();let prompts=0,prevented=0,clickActive=false;
  const androidInstall=createInstaller(android.win,()=>state,text=>android.messages.push(text));
  android.events.get('beforeinstallprompt')({preventDefault(){prevented++;},async prompt(){assert(clickActive,'Prompt must run synchronously during the click');prompts++;},userChoice:Promise.resolve({outcome:'accepted'})});
  await androidInstall.init();
  const prepared=android.calls.filter(c=>c.url==='/mobile/install').length;
  clickActive=true;const clicked=android.node('prepareInstall').onclick();clickActive=false;await clicked;
  assert.equal(android.calls.filter(c=>c.url==='/mobile/install').length,prepared,'Ready Android install never waits for a network call');
  assert.equal(prompts,1);assert.equal(prevented,1);assert.match(android.messages.at(-1),/qəbul/);
  android.events.get('appinstalled')();assert.equal(android.node('prepareInstall').hidden,true);
  const http=browser({secure:false});
  await createInstaller(http.win,()=>state,text=>http.messages.push(text)).init();
  assert.equal(http.calls.length,0);assert.equal(http.registrations.length,0);assert.match(http.messages.at(-1),/HTTPS/);
  const old=browser({installed:true,ios:true});let recovered;
  let empty={devices:[],selected:'',restore:async payload=>{recovered=payload;empty={...payload,restore:empty.restore};}};
  await createInstaller(old.win,()=>empty,text=>old.messages.push(text)).init();
  assert.equal(old.node('installRecovery').hidden,false);assert.equal(old.calls.filter(c=>c.url==='/mobile/install').length,0);
  old.node('installRecoveryCode').value='a'.repeat(64);
  await old.node('installRecoveryForm').onsubmit({preventDefault(){}});
  assert.equal(recovered.devices[0].token,'private-token');assert.equal(old.node('installRecovery').hidden,true);
  await restoreTicket(old.win,'a'.repeat(64));
  const receipts=old.calls.filter(c=>c.url==='/mobile/restore');
  assert.equal(receipts[0].body.client_nonce,receipts[1].body.client_nonce,'Lost-response retry is installation-bound');
  assert.match(receipts[0].body.client_nonce,/^[0-9a-f]{64}$/);
  console.log('PASS automatic iOS launch handoff, no token URLs, Android install, HTTP rejection, installed-app recovery and stable retry nonce');
})().catch(error=>{console.error(error);process.exitCode=1;});
