const assert = require('node:assert/strict');
const fs = require('node:fs'), vm = require('node:vm');
(async () => {
  const nodes = new Map(), calls = [], tabs = [];
  let authFails = true, refreshes = 0;
  const node = id => {
    if (!nodes.has(id)) nodes.set(id,{hidden:true,value:'',style:{},textContent:'',dataset:{},
      addEventListener() {},focus() {},scrollIntoView() {},click() {if(id==='btnRefreshQr') refreshes++;}});
    return nodes.get(id);
  };
  node('accountForm').querySelectorAll = () => [node('accountLogin'),node('accountRegister')];
  const ctx = vm.createContext({URL,console,document:{readyState:'complete',getElementById:node},
    window:{switchTab:tab=>tabs.push(tab),__TAURI__:{core:{invoke:async (cmd,args)=>{
      calls.push({cmd,args});
      if(cmd==='get_device_status')return {cloud_gateway_origin:'http://158.101.172.228:8080'};
      if(cmd==='account_status')throw Error('HTTPS server ünvanı lazımdır');
      if(cmd==='set_gateway_origin')return args.origin;
      if(cmd==='account_authenticate'){
        if(authFails)throw Error('E-poçt və ya şifrə yanlışdır.');
        return {email:'arif@example.com'};
      }
    }}}}});
  vm.runInContext(fs.readFileSync('apps/desktop_tauri/ui/account.js','utf8'),ctx);
  await new Promise(setImmediate);
  assert.equal(node('accountServerOrigin').value,'http://158.101.172.228:8080');
  node('accountSettings').onclick();
  assert.equal(tabs.pop(),'status');
  node('accountOpen').onclick();
  node('accountEmail').value='arif@example.com'; node('accountPassword').value='long password';
  node('accountRegister').value='register';
  const event = {preventDefault() {},submitter:node('accountRegister')};
  await node('accountForm').onsubmit(event);
  assert.match(node('accountMessage').textContent,/yanlışdır/);
  assert.equal(node('accountOverlay').hidden,false);
  assert.equal(node('accountPassword').value,'');
  authFails=false; node('accountPassword').value='long password';
  await node('accountForm').onsubmit(event);
  assert.match(node('accountMessage').textContent,/uğurla/);
  assert.equal(node('accountOverlay').hidden,false,'Keep success visible until Continue');
  assert.equal(node('accountContinue').hidden,false);
  node('accountContinue').onclick();
  assert.equal(node('accountOverlay').hidden,true);
  assert.equal(refreshes,1);
  node('accountServerOrigin').value='http://158.101.172.228:8080';
  await node('accountSaveServer').onclick();
  assert.match(node('accountMessage').textContent,/HTTPS/);
  assert.equal(calls.filter(c=>c.cmd==='set_gateway_origin').length,0);
  node('accountServerOrigin').value='https://winkey.example.com';
  await node('accountSaveServer').onclick();
  assert.equal(calls.filter(c=>c.cmd==='set_gateway_origin').length,1);
  assert.match(node('accountMessage').textContent,/saxlanıldı/);
  console.log('PASS account failure/success messages, explicit continue and correct server settings');
})().catch(error=>{console.error(error);process.exitCode=1;});
