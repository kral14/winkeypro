/* Account-based PWA: installation never transfers device credentials. */
(function(root) {
  'use strict';
  function standalone(win) {
    return Boolean(win.navigator?.standalone || win.matchMedia?.('(display-mode: standalone)').matches);
  }
  function createInstaller(win) {
    let initialized=false;
    async function init() {
      if(initialized)return;
      initialized=true;
      if(win.isSecureContext && win.navigator?.serviceWorker) {
        try { await win.navigator.serviceWorker.register('/mobile-sw.js',{scope:'/'}); }
        catch(error) { win.console?.warn('Service worker registration failed',error); }
      }
    }
    return {init};
  }
  if(typeof module!=='undefined')module.exports={createInstaller,standalone};
  if(root?.document)root.WinKeyInstall=createInstaller(root);
})(typeof window!=='undefined'?window:null);
