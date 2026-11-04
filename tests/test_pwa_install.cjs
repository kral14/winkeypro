const assert=require('node:assert/strict');
const fs=require('node:fs');
const {createInstaller}=require('../deploy/static/install.js');
(async()=>{
 let registrations=0;
 const win={isSecureContext:true,navigator:{serviceWorker:{register:async(path,options)=>{assert.equal(path,'/mobile-sw.js');assert.equal(options.scope,'/');registrations++;}}},fetch:()=>{throw Error('Installation must not transfer credentials');}};
 const installer=createInstaller(win);
 await installer.init();await installer.init();assert.equal(registrations,1);
 await createInstaller({...win,isSecureContext:false}).init();assert.equal(registrations,1);
 assert.equal(installer.restore,undefined);
 const html=fs.readFileSync('deploy/gateway_production_server.py','utf8');
 for(const id of ['installRecoveryForm','restoreInstall','copyInstallCode'])assert.ok(!html.includes('id="'+id+'"'));
 const devices=fs.readFileSync('deploy/static/devices.js','utf8');
 assert.ok(!devices.includes("post('/mobile/restore'"));
 assert.ok(!devices.includes("post('/mobile/install'"));
 assert.ok(devices.includes("post('/accounts/login'"));
 console.log('PASS account-based PWA installation, no recovery UI or credential transfer, secure worker registration');
})().catch(error=>{console.error(error);process.exitCode=1;});
