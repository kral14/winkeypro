// Exercise the actual packaged UI script without calling Windows input/service APIs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ui = path.join(__dirname, '../apps/desktop_tauri/ui');
const html = fs.readFileSync(path.join(ui, 'index.html'), 'utf8');
const script = fs.readFileSync(path.join(ui, 'app.js'), 'utf8');
assert.match(html, /<script src="app\.js"><\/script>/);

async function main() {
  const panels = Object.fromEntries(['status', 'security', 'pairing', 'support'].map(id => [id, {style: {}}]));
  const tabs = Object.keys(panels).map(id => ({
    getAttribute: () => id,
    classList: {add() {}, remove() {}},
    addEventListener(type, fn) { this.click = fn; }
  }));
  const context = vm.createContext({
    window: {addEventListener() {}, __TAURI__: {core: {invoke: async () => { throw new Error('TEST_NATIVE_UNAVAILABLE'); }}}},
    console, setTimeout,
    document: {
      readyState: 'loading', addEventListener() {},
      querySelector: () => null,
      querySelectorAll: selector => selector === '.tab' ? tabs : Object.values(panels),
      getElementById: id => panels[id.replace('panel-', '')] || null
    }
  });
  vm.runInContext(script, context, {filename: 'packaged-app.js'});
  vm.runInContext(script, context, {filename: 'packaged-app-second-load.js'});
  for (let i = 0; i < tabs.length; i++) {
    context.window.switchTab(Object.keys(panels)[i]);
    assert.equal(panels[Object.keys(panels)[i]].style.display, 'block');
    assert.equal(Object.values(panels).filter(p => p.style.display === 'block').length, 1);
  }
  assert.equal(context.window.__WINKEY_UI_LOADED__, true);
  console.log('PASS: script loads twice without declaration collisions; all four native-mode panels switch.');
}
main().catch(err => { console.error(err); process.exitCode = 1; });
