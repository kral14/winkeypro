const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const html = fs.readFileSync('build/codex_mobile_ws_audit.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
let connections = 0; const intervals = [], nodes = new Map(), requests=[];
class WS { static OPEN=1; static CONNECTING=0; constructor(){connections++;this.sent=[];this.readyState=0;WS.instance=this;} send(text){this.sent.push(JSON.parse(text));} }
const store = new Map([['winkey_token','isolated-test-token'],['winkey_dev_id','test-device']]);
const context = vm.createContext({URLSearchParams, AbortController, performance,
  crypto: require('node:crypto').webcrypto, WebSocket:WS,
  window:{location:{search:'',pathname:'/mobile',protocol:'http:',host:'localhost'},addEventListener(){}},
  document:{hidden:false,addEventListener(){},getElementById(id){if(!nodes.has(id))nodes.set(id,{});return nodes.get(id);}},
  localStorage:{getItem:k=>store.get(k)||null,setItem:(k,v)=>store.set(k,v),removeItem:k=>store.delete(k)},
  setInterval:(f,ms)=>intervals.push(ms),setTimeout:()=>0,clearTimeout(){},
  fetch:async(url,options={})=>{requests.push({url,method:options.method||'GET'});return {ok:true,status:200,json:async()=>({locked:false,command_id:'audit-mock-command'})};}});
vm.runInContext(script,context);
console.log(JSON.stringify({websocket_connections_on_authenticated_start:connections,http_poll_intervals_ms:intervals}));
assert(connections > 0, 'Authenticated mobile startup did not open WebSocket');
WS.instance.readyState=WS.OPEN;
WS.instance.onopen();
WS.instance.onmessage({data:JSON.stringify({type:'auth_ok',role:'mobile'})});
requests.length=0;
vm.runInContext("sendCommand('lock')",context).then(()=>{
  const commands=WS.instance.sent.filter(m=>m.type==='command').length;
  const posts=requests.filter(r=>r.method==='POST'&&r.url.endsWith('/command')).length;
  console.log(JSON.stringify({healthy_websocket_command_frames:commands,http_command_posts:posts}));
  assert.equal(commands,1,'Healthy mobile still sends command through HTTP instead of WebSocket');
}).catch(error=>{console.error(error.message);process.exitCode=1;});
