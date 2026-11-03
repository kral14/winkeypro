const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
(async()=>{
 const nodes=new Map(),calls=[];let logged=false,fail=false;
 function node(id){if(!nodes.has(id))nodes.set(id,{hidden:true,value:'',textContent:'',style:{},dataset:{},children:[],addEventListener(){},removeAttribute(){},replaceChildren(){this.children=[];this.textContent='';},appendChild(child){this.children.push(child);},querySelectorAll(){return[node('accountLogin'),node('accountRegister')];}});return nodes.get(id);}
 const devices=[{device_id:'pc1',computer_name:'Ofis <img>',online:true,locked:false,paused:false}];
 const root={confirm:()=>true,switchTab(){},__TAURI__:{core:{invoke:async(cmd,args)=>{
  calls.push({cmd,args});
  if(cmd==='account_status'){if(!logged)throw Error('E_ACCOUNT_REQUIRED');return{email:'arif@example.com',current_device_id:'pc1',devices};}
  if(cmd==='account_authenticate'){if(fail)throw Error('Şifrə yanlışdır');logged=true;return{email:'arif@example.com'};}
  if(cmd==='account_logout'){logged=false;return{success:true};}
  if(cmd==='account_device_action')return{success:true};
 }}}};
 vm.runInNewContext(fs.readFileSync('apps/desktop_tauri/ui/account.js','utf8'),{window:root,setInterval(){},document:{readyState:'complete',hidden:false,getElementById:node,createElement:()=>node('generated'+nodes.size)}});
 await new Promise(setImmediate);
 assert.equal(root.__WINKEY_ACCOUNT_READY__,false);
 assert.equal(node('accountOverlay').hidden,false);
 node('accountCloseDrawer').onclick();assert.equal(node('accountOverlay').hidden,false);
 fail=true;node('accountPassword').value='long password';
 await node('accountForm').onsubmit({preventDefault(){},submitter:{value:'register'}});
 assert.match(node('accountMessage').textContent,/yanlışdır/);assert.equal(node('accountPassword').value,'');
 fail=false;node('accountPassword').value='long password';
 await node('accountForm').onsubmit({preventDefault(){},submitter:{value:'register'}});
 assert.equal(root.__WINKEY_ACCOUNT_READY__,true);assert.equal(node('accountOverlay').hidden,false);
 assert.match(node('accountMessage').textContent,/uğurla yaradıldı/);
 assert.equal(node('accountContinue').hidden,false);
 const row=node('accountDevicesList').children[0];assert.equal(row.children[0].textContent,'Ofis <img> (Bu PC)');
 assert.match(row.children[1].textContent,/Onlayn/);
 node('accountContinue').onclick();assert.equal(node('accountOverlay').hidden,true);
 await node('accountLogout').onclick();assert.equal(root.__WINKEY_ACCOUNT_READY__,false);
 assert.equal(node('accountOverlay').hidden,false);assert.equal(node('accountCloseDrawer').hidden,true);
 assert.match(node('accountMessage').textContent,/bağlantıları saxlanıldı/);
 assert(!calls.some(c=>['revoke_pairing','toggle_remote_service_control'].includes(c.cmd)));
 const html=fs.readFileSync('apps/desktop_tauri/ui/index.html','utf8');assert(!html.includes('id="accountSkip"'));
 console.log('PASS mandatory login, visible success, safe named device list, logout without unpair/disconnect');
})().catch(error=>{console.error(error);process.exitCode=1;});
