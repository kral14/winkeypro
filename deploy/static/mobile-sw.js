/* Offline shell only. No commands, sessions, QR URLs or API results are cached. */
const CACHE='winkey-shell-v1';
const FILES=['/mobile','/mobile-assets/devices.js','/mobile-assets/install.js',
  '/mobile-assets/icon-192.png','/mobile-assets/icon-512.png','/mobile-assets/apple-touch-icon.png'];
self.addEventListener('install',event=>{
  event.waitUntil(caches.open(CACHE).then(async cache=>{
    for(const path of FILES){const response=await fetch(path,{cache:'reload',credentials:'omit'});if(response.ok)await cache.put(path,response);}
  }).then(()=>self.skipWaiting()));
});
self.addEventListener('activate',event=>{
  event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('winkey-shell-') && key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch',event=>{
  const request=event.request,url=new URL(request.url);
  if(request.method!=='GET' || url.origin!==self.location.origin || request.headers.has('Authorization'))return;
  const navigation=request.mode==='navigate' && ['/mobile','/remote'].includes(url.pathname);
  if(!navigation && (!FILES.includes(url.pathname) || url.search))return;
  event.respondWith((async()=>{
    const cache=await caches.open(CACHE),key=navigation?'/mobile':url.pathname;
    try {
      const response=await fetch(request);
      if(response.ok && !url.search)await cache.put(key,response.clone());
      return response;
    }catch(error){
      const cached=await cache.match(key);
      return cached || new Response('İnternet bağlantısını yoxlayın və WinKey-ni yenidən açın.',{status:503,headers:{'Content-Type':'text/plain; charset=utf-8'}});
    }
  })());
});
