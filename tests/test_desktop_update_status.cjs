// Execute the actual packaged UI against a deterministic native bridge.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const code = fs.readFileSync(path.join(__dirname,'../apps/desktop_tauri/ui/app.js'),'utf8');

async function main() {
  const ids=['btnCheckUpdate','lblUpdateMessage','lblDesktopVersion','lblWorkerVersion','lblLatestVersion','lblUpdateChecked'];
  const elements=Object.fromEntries(ids.map(id=>[id,{textContent:'',disabled:false,style:{},addEventListener(type,fn){this[type]=fn;}}]));
  let start, calls=0;
  let status={desktop_version:'0.1.3',worker_version:'0.1.3',latest_version:'0.1.3',channel:'installed',status:'up_to_date'};
  const context=vm.createContext({console:{log(){},error(){}},setTimeout,setInterval:()=>0,clearInterval(){},
    window:{addEventListener(){},__TAURI__:{core:{invoke:async(cmd,args)=>{
      if(cmd==='get_update_status'){calls++;assert.equal(args.checkServer,true);if(status instanceof Error)throw status;return status;}
      if(cmd==='get_device_status')return null;
      if(cmd==='report_ui_error')return;
      throw new Error('TEST_UNAVAILABLE');
    }}}},
    document:{readyState:'loading',addEventListener(type,fn){if(type==='DOMContentLoaded')start=fn;},
      getElementById:id=>elements[id]||null,querySelectorAll:()=>[],querySelector:()=>null}});
  vm.runInContext(code,context);
  start(); await new Promise(setImmediate);
  assert.equal(elements.lblDesktopVersion.textContent,'v0.1.3');
  assert.equal(elements.lblWorkerVersion.textContent,'v0.1.3');
  assert.match(elements.lblUpdateMessage.textContent,/Ən son/);
  status={desktop_version:'0.1.2',worker_version:'0.1.2',latest_version:null,status:'unreachable'};
  await elements.btnCheckUpdate.click();
  assert.match(elements.lblUpdateMessage.textContent,/təsdiqlənmədi/);
  assert.doesNotMatch(elements.lblUpdateMessage.textContent,/Ən son/);
  status=new Error('E_UPDATE_SIGNATURE');await elements.btnCheckUpdate.click();
  assert.match(elements.lblUpdateMessage.textContent,/E_UPDATE_SIGNATURE/);
  assert.equal(elements.btnCheckUpdate.disabled,false);
  status={desktop_version:'0.1.0',channel:'dev',latest_version:'0.1.3',status:'dev'};
  await elements.btnCheckUpdate.click();
  assert.match(elements.lblDesktopVersion.textContent,/Dev build/);
  assert.doesNotMatch(elements.lblUpdateMessage.textContent,/Ən son/);
  let resolve;
  status=new Promise(done=>resolve=done);
  const before=calls;
  const pending=elements.btnCheckUpdate.click();
  assert.equal(elements.btnCheckUpdate.disabled,true);
  await elements.btnCheckUpdate.click();
  assert.equal(calls,before+1);
  resolve({desktop_version:'0.1.2',worker_version:'0.1.2',latest_version:'0.1.3',status:'requested'});
  await pending;
  assert.match(elements.lblUpdateMessage.textContent,/sorğusu göndərildi/);
  assert.equal(elements.btnCheckUpdate.disabled,false);
  assert.ok(elements.lblUpdateChecked.textContent);
  console.log('PASS: actual UI shows versions, handles offline/signature/dev states honestly, and prevents overlapping checks.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
