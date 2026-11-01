// Execute the actual shipped mobile JS with controlled network faults. No PC input.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const source = fs.readFileSync('deploy/gateway_production_server.py', 'utf8');
const start = source.indexOf('        const urlParams =');
const end = source.indexOf('        init();', start) + '        init();'.length;
const script = source.slice(start, end);

function context() {
  const storage = new Map(), elements = new Map();
  const ctx = vm.createContext({URLSearchParams, AbortController, Uint8Array,
    crypto: webcrypto, performance, console,
    setTimeout: (f, ms) => (ms === 2000 || ms === 10000) ? 0 : setTimeout(f, Math.min(ms, 10)), clearTimeout,
    setInterval: () => { throw Error('Unexpected overlapping interval'); },
    window: {location: {search: '', pathname: '/mobile'}},
    document: {hidden: false, getElementById: id => {
      if (!elements.has(id)) elements.set(id, {}); return elements.get(id);
    }},
    localStorage: {getItem: k => storage.get(k) || null, setItem: (k,v) => storage.set(k,v),
      removeItem: k => storage.delete(k)}, fetch: () => {throw Error('Unexpected fetch');}
  });
  vm.runInContext(script, ctx);
  vm.runInContext("authToken='test-token'; targetDevice='test-pc';", ctx);
  return {ctx, storage, elements, run: code => vm.runInContext(code, ctx)};
}
const response = data => ({ok: true, status: 200, json: async () => data});

(async () => {
  const a = context(), posts = [];
  a.ctx.fetch = async (url, options) => {
    if (options.method === 'POST') {
      posts.push(JSON.parse(options.body));
      if (posts.length === 1) throw Error('Response lost AFTER server accepted');
      return response({command_id: 'same-command'});
    }
    return response({status: 'completed', result: 'MOCK_ONLY'});
  };
  await a.run("sendCommand('lock')");
  assert.equal(posts.length, 2);
  assert.equal(posts[0].request_id, posts[1].request_id);
  assert(posts.every(p => p.action === 'lock'));
  assert.equal(a.storage.has('winkey_pending_command'), false);
  assert.equal(a.run('commandBusy'), false);
  console.log('PASS lost response retries same ID; busy state released');

  const b = context();
  b.ctx.fetch = async (url, options) => ({ok:true, status:200,
    json: () => new Promise((resolve,reject) => options.signal.addEventListener('abort', () => reject(Error('body timeout'))))});
  await assert.rejects(b.run("request('/test', {}, 50)"));
  console.log('PASS deadline includes stalled response body');

  const c = context();
  let active = 0, maxActive = 0;
  c.ctx.fetch = async () => {
    active++; maxActive = Math.max(maxActive, active);
    await new Promise(resolve => setTimeout(resolve, 5)); active--;
    return response({computer_name:'test',locked:false});
  };
  await Promise.all([c.run('pollStatus()'), c.run('pollStatus()'), c.run('pollStatus()')]);
  assert.equal(maxActive, 1);
  console.log('PASS status requests never overlap');

  const d = context();
  d.ctx.fetch = async () => {throw Error('offline');};
  await d.run("sendCommand('lock')");
  const pending = JSON.parse(d.storage.get('winkey_pending_command'));
  const resumed = [];
  d.ctx.fetch = async (url, options) => {
    if (options.method === 'POST') {resumed.push(JSON.parse(options.body)); return response({command_id:'same-command'});}
    return response({status:'completed'});
  };
  await d.run("sendCommand('unlock')");
  assert.notEqual(resumed[0].request_id, pending.requestId);
  assert.equal(resumed[0].action, 'unlock');
  console.log('PASS explicit latest intent replaces an unresolved old command');

  const e = context();
  let inflight = 0, maxInflight = 0, polls = 0;
  e.ctx.fetch = async (url, options) => {
    if (options.method === 'POST') return response({command_id:'serial'});
    if (!url.startsWith('/commands/')) return response({locked:false});
    inflight++; maxInflight = Math.max(maxInflight, inflight);
    await new Promise(resolve => setTimeout(resolve, 2)); inflight--;
    return response({status: ++polls < 3 ? 'pending' : 'completed'});
  };
  await e.run("sendCommand('lock')");
  assert.equal(polls, 3);
  assert.equal(maxInflight, 1);
  console.log('PASS command result polling is serial');

  const f = context(), latestPosts = [];
  let release;
  f.ctx.fetch = async (url, options) => {
    if (options.method === 'POST') {
      latestPosts.push(JSON.parse(options.body));
      if (latestPosts.length === 1) await new Promise(resolve => {release = resolve;});
      return response({command_id:'latest'});
    }
    return response({status:'completed'});
  };
  const first = f.run("sendCommand('lock')");
  await f.run("sendCommand('unlock')");
  await f.run("sendCommand('lock')");
  await f.run("sendCommand('unlock')");
  release();
  await first;
  assert.deepEqual(latestPosts.map(p => p.action), ['lock','unlock']);
  assert.notEqual(latestPosts[0].request_id, latestPosts[1].request_id);
  console.log('PASS rapid taps coalesce into last intent; busy state never drops it');

  const g = context(), immediate = [];
  let resultStarted, aborted = false;
  const waiting = new Promise(resolve => {resultStarted = resolve;});
  g.ctx.fetch = async (url, options) => {
    if (options.method === 'POST') {
      immediate.push(JSON.parse(options.body).action);
      return response({command_id:'abort-old-result'});
    }
    if (!url.startsWith('/commands/') || immediate.length > 1) return response({status:'completed'});
    resultStarted();
    return new Promise((resolve,reject) => options.signal.addEventListener('abort', () => {
      aborted = true; reject(Error('superseded result request'));
    }));
  };
  const old = g.run("sendCommand('lock')");
  await waiting;
  await g.run("sendCommand('unlock')");
  await old;
  assert.equal(aborted, true);
  assert.deepEqual(immediate, ['lock', 'unlock']);
  console.log('PASS new tap aborts stalled result GET and immediately submits latest intent');

  const h = context();
  h.run("mobileEvent('request', 'REQUEST_TIMEOUT', 4001, 'unlock', 'a'.repeat(32), true)");
  h.run("displayDiagnostic('Xəta: E_TEST_ERROR token=private-test-value-should-not-be-stored')");
  const stored = h.storage.get('winkey_diagnostics');
  assert.equal(JSON.parse(stored).length, 2);
  assert(!stored.includes('private-test-value-should-not-be-stored'));
  assert(!stored.includes('test-token'));
  let diagCalls = 0;
  h.ctx.fetch = async () => {diagCalls++; throw Error('offline');};
  h.run('commandBusy = true');
  await h.run('flushDiagnostics()');
  assert.equal(diagCalls, 0);
  h.run('commandBusy = false');
  await h.run('flushDiagnostics()');
  assert.equal(JSON.parse(h.storage.get('winkey_diagnostics')).length, 2);
  h.ctx.fetch = async (url, options) => {
    assert.equal(url, '/mobile/telemetry');
    const body = JSON.parse(options.body);
    return response({accepted: body.events.map(e => e.id)});
  };
  await h.run('flushDiagnostics()');
  assert.equal(JSON.parse(h.storage.get('winkey_diagnostics')).length, 0);
  console.log('PASS diagnostics persist offline, omit secrets, yield to commands, clear only after server ACK');
})().catch(error => {console.error(error); process.exitCode = 1;});
