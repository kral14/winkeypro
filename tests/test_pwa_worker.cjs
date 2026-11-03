const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
(async()=>{
  const handlers=new Map(),store=new Map(),writes=[],requests=[];
  let offline=false;
  const cache={async put(key,response){writes.push(key);store.set(key,response);},async match(key){return store.get(key)?.clone();}};
  const self={location:{origin:'https://winkey.test'},addEventListener:(type,fn)=>handlers.set(type,fn),async skipWaiting(){},clients:{async claim(){}}};
  vm.runInNewContext(fs.readFileSync('deploy/static/mobile-sw.js','utf8'),{self,URL,Response,caches:{async open(){return cache;},async keys(){return[];},async delete(){}},
    fetch:async(request,options)=>{requests.push({request,options});if(offline)throw Error('offline');return new Response('shell',{status:200});}});
  let installing;
  handlers.get('install')({waitUntil(promise){installing=promise;}});await installing;
  assert(store.has('/mobile'));assert(store.has('/mobile-assets/install.js'));
  assert(requests.every(r=>r.options.credentials==='omit'));
  function event(url,{method='GET',mode='cors',auth=false}={}) {
    let response;
    handlers.get('fetch')({request:{url:'https://winkey.test'+url,method,mode,headers:{has:()=>auth}},respondWith(promise){response=promise;}});
    return response;
  }
  writes.length=0;
  for(const path of ['/pair','/mobile/install','/mobile/restore','/devices/pc1/status','/commands','/accounts/login','/mobile-assets/manifest.webmanifest?install=secret'])assert.equal(event(path),undefined,path);
  assert.equal(event('/mobile',{method:'POST'}),undefined);
  assert.equal(event('/mobile',{auth:true}),undefined);
  await event('/mobile?code=PAIR_SECRET',{mode:'navigate'});
  assert.equal(writes.length,0,'Never cache a QR query URL or its response');
  offline=true;
  assert.equal(await (await event('/mobile',{mode:'navigate'})).text(),'shell');
  assert.equal(event('/commands/secret'),undefined,'API traffic stays network-only even offline');
  console.log('PASS offline shell, no credentials/API/QR/manifest caching');
})().catch(error=>{console.error(error);process.exitCode=1;});
