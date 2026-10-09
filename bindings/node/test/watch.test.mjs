import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const addon = createRequire(import.meta.url).resolve('../proxy-watch.node');
const { readSync, watch, watchSync } = createRequire(import.meta.url)(addon);

const env = { https_proxy: 'http://proxy.example:3128' };

// Runs `script` in a fresh Node with `addon` bound, and returns what it printed.
function node(script, extraEnv = {}) {
  return execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, ...extraEnv, ADDON: addon },
    encoding: 'utf8',
    timeout: 30_000,
  });
}

const prelude = `
import { createRequire } from 'node:module';
const { watch } = createRequire(import.meta.url)(process.env.ADDON);
`;

for (const [name, start, startWith] of [
  ['watch()', (options) => watch(() => {}, options), watch],
  ['watchSync()', (options) => watchSync(() => {}, options), watchSync],
]) {
  test(`${name}: current() answers as read() does, and close() ends it`, async () => {
    const watcher = await start({ env });
    assert.deepEqual(
      { ...watcher.current().route('https://a.example/') },
      { ...readSync({ env }).route('https://a.example/') },
    );
    watcher.close();
    watcher.close();
    assert.throws(() => watcher.current(), { code: 'ERR_WATCHER_CLOSED' });
  });

  test(`${name}: options are checked before anything starts`, () => {
    assert.throws(() => start({ precedence: 'sideways' }), { code: 'ERR_INVALID_ARG_VALUE' });
    // A number, not a u32, so that -1 is refused rather than wrapped to 49 days.
    for (const pollIntervalMs of [-1, NaN, Infinity]) {
      assert.throws(() => start({ pollIntervalMs }), { code: 'ERR_INVALID_ARG_VALUE' }, `${pollIntervalMs}`);
    }
    assert.throws(() => startWith(5), { code: 'ERR_INVALID_ARG_TYPE' });
  });
}

test('an open watcher does not keep the process alive', () => {
  assert.equal(
    node(`${prelude} globalThis.w = await watch(() => {}); console.log('started');`),
    'started\n',
  );
});

test('a worker can exit with its watcher open', () => {
  const script = `${prelude}
import { Worker } from 'node:worker_threads';
// An eval'd worker inherits --input-type=module.
const worker = new Worker(\`
  const { createRequire } = process.getBuiltinModule('node:module');
  const { watch } = createRequire(process.env.ADDON)(process.env.ADDON);
  watch(() => {}).then((w) => { globalThis.w = w; });
\`, { eval: true });
worker.on('exit', (code) => console.log('worker exit', code));
`;
  assert.equal(node(script), 'worker exit 0\n');
});

test('a worker can exit with a read, a routeNative and a watch pending', () => {
  const script = `${prelude}
import { Worker } from 'node:worker_threads';
const worker = new Worker(\`
  const { createRequire } = process.getBuiltinModule('node:module');
  const { read, readSync, watch } = createRequire(process.env.ADDON)(process.env.ADDON);
  read();
  readSync().routeNative('https://a.example/');
  watch(() => {});
  process.exit(0);
\`, { eval: true });
worker.on('exit', (code) => console.log('worker exit', code));
`;
  assert.equal(node(script), 'worker exit 0\n');
});

// KDE's store is a file, so a private XDG_CONFIG_HOME makes the change hermetic.
test('a change reaches onChange', { skip: process.platform !== 'linux' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'proxy-watch-'));
  try {
    writeFileSync(join(dir, 'kioslaverc'), '[Proxy Settings]\nProxyType=0\n');
    const script = `${prelude}
import { writeFileSync } from 'node:fs';
const timeout = setTimeout(() => console.log('no change within 5 s'), 5_000);
const watcher = await watch((err, snapshot) => {
  console.log(err ? 'error ' + err.code : JSON.stringify(snapshot.route('http://a.example/')));
  watcher.close();
  clearTimeout(timeout);
}, { precedence: 'ignore' });
console.log(JSON.stringify(watcher.current().route('http://a.example/')));
writeFileSync(process.env.XDG_CONFIG_HOME + '/kioslaverc',
  '[Proxy Settings]\\nProxyType=1\\nhttpProxy=http://proxy.corp:8080\\n');
`;
    const out = node(script, { XDG_CURRENT_DESKTOP: 'KDE', XDG_CONFIG_HOME: dir });
    assert.equal(
      out,
      '{"kind":"steps","engine":"none","steps":["direct"]}\n' +
        '{"kind":"steps","engine":"none","steps":["http://proxy.corp:8080/"]}\n',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Each shape a route takes from the OS, under each precedence: the environment outranks
// the OS before it, the OS outranks the environment after it, and ignore leaves it out.
test('each OS mode reaches the route in its own shape under each precedence', { skip: process.platform !== 'linux' }, () => {
  const script = `${prelude}
const { readSync } = createRequire(import.meta.url)(process.env.ADDON);
const env = { https_proxy: 'http://env.example:3128' };
for (const precedence of ['ignore', 'before-system', 'after-system']) {
  console.log(precedence, JSON.stringify(readSync({ env, precedence }).route('https://a.example/')));
}
`;
  const os = {
    pac: ['ProxyType=2\nProxy Config Script=http://wpad.example/proxy.pac\n', '{"kind":"pac","engine":"none","pacUrl":"http://wpad.example/proxy.pac"}'],
    wpad: ['ProxyType=3\n', '{"kind":"wpad","engine":"none"}'],
    manual: ['ProxyType=1\nhttpsProxy=http://os.example:8080\n', '{"kind":"steps","engine":"none","steps":["http://os.example:8080/"]}'],
  };
  const fromEnv = '{"kind":"steps","engine":"none","steps":["http://env.example:3128/"]}';
  for (const [name, [settings, fromOs]] of Object.entries(os)) {
    const dir = mkdtempSync(join(tmpdir(), 'proxy-watch-'));
    try {
      writeFileSync(join(dir, 'kioslaverc'), `[Proxy Settings]\n${settings}`);
      const out = node(script, { XDG_CURRENT_DESKTOP: 'KDE', XDG_CONFIG_HOME: dir, XDG_CONFIG_DIRS: '/nonexistent' });
      assert.equal(
        out,
        `ignore ${fromOs}\nbefore-system ${fromEnv}\nafter-system ${fromOs}\n`,
        name,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

// A PAC URL from the OS with the body the caller fetched: QuickJS runs it under the policy,
// and the defaults place the script off every network.
test('quickjs runs a fetched script under the policy, on either thread', {
  skip: process.platform !== 'linux' || !['x64', 'arm64', 'arm'].includes(process.arch),
}, () => {
  const script = `
import { createRequire } from 'node:module';
const { readSync } = createRequire(import.meta.url)(process.env.ADDON);
const script = "function FindProxyForURL(u, h) { return isInNet(myIpAddress(), '10.0.0.0', '255.0.0.0') ? 'PROXY corp.example:8080' : 'DIRECT'; }";
const snapshot = readSync({ precedence: 'ignore' });
const inside = { pac: 'quickjs', script, policy: { myIpAddress: '10.1.2.3' } };
console.log(JSON.stringify(snapshot.route('http://a.example/')));
console.log(JSON.stringify(snapshot.route('http://a.example/', { pac: 'quickjs', script })));
console.log(JSON.stringify(snapshot.route('http://a.example/', inside)));
console.log(JSON.stringify(await snapshot.routeAsync('http://a.example/', inside)));
console.log(JSON.stringify(snapshot.route('http://a.example/', { pac: 'auto' })));
try {
  snapshot.route('http://a.example/', { pac: 'native', script });
} catch (error) {
  console.log(error.code);
}
`;
  const dir = mkdtempSync(join(tmpdir(), 'proxy-watch-'));
  try {
    writeFileSync(join(dir, 'kioslaverc'), '[Proxy Settings]\nProxyType=2\nProxy Config Script=http://wpad.example/proxy.pac\n');
    const out = node(script, { XDG_CURRENT_DESKTOP: 'KDE', XDG_CONFIG_HOME: dir, XDG_CONFIG_DIRS: '/nonexistent' });
    const left = '{"kind":"pac","engine":"none","pacUrl":"http://wpad.example/proxy.pac"}';
    const proxied = '{"kind":"steps","engine":"quickjs","steps":["http://corp.example:8080/"]}';
    assert.equal(
      out,
      `${left}\n{"kind":"steps","engine":"quickjs","steps":["direct"]}\n${proxied}\n${proxied}\n${left}\n` +
        'ERR_PAC_ENGINE_UNAVAILABLE\n',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The pump delivers while the JavaScript thread is blocked, so the call is queued when
// `close()` runs. On a slow machine the call may not be queued yet, and the test passes
// without having reached the window; it cannot fail for that reason.
test('onChange is not called once close() has returned', { skip: process.platform !== 'linux' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'proxy-watch-'));
  try {
    writeFileSync(join(dir, 'kioslaverc'), '[Proxy Settings]\nProxyType=0\n');
    const script = `${prelude}
import { writeFileSync } from 'node:fs';
let closed = false;
let late = 0;
const watcher = await watch(() => { if (closed) late++; }, { precedence: 'ignore' });
writeFileSync(process.env.XDG_CONFIG_HOME + '/kioslaverc',
  '[Proxy Settings]\\nProxyType=1\\nhttpProxy=http://proxy.corp:8080\\n');
Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1_500);
watcher.close();
closed = true;
setTimeout(() => console.log('late calls ' + late), 300);
`;
    const out = node(script, { XDG_CURRENT_DESKTOP: 'KDE', XDG_CONFIG_HOME: dir });
    assert.equal(out, 'late calls 0\n');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The worker thread starts after `XDG_CONFIG_HOME` moves to an empty directory, so only the
// copy taken at the call still points at the proxy. One worker thread, held by `pbkdf2`,
// fixes that order.
test('read() and watch() read the environment copied at the call', { skip: process.platform !== 'linux' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'proxy-watch-'));
  const empty = mkdtempSync(join(tmpdir(), 'proxy-watch-'));
  try {
    writeFileSync(
      join(dir, 'kioslaverc'),
      '[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.corp:8080\n',
    );
    const script = `
import { pbkdf2 } from 'node:crypto';
import { createRequire } from 'node:module';
const { read, watch } = createRequire(import.meta.url)(process.env.ADDON);
const busy = () => pbkdf2('x', 'y', 100_000, 32, 'sha256', () => {});
const route = (snapshot) => JSON.stringify(snapshot.route('http://a.example/'));
busy();
const reading = read({ precedence: 'ignore' });
busy();
const watching = watch(() => {}, { precedence: 'ignore' });
process.env.XDG_CONFIG_HOME = process.env.EMPTY;
console.log(route(await reading));
const watcher = await watching;
console.log(route(watcher.current()));
watcher.close();
`;
    const out = node(script, {
      XDG_CURRENT_DESKTOP: 'KDE',
      XDG_CONFIG_HOME: dir,
      EMPTY: empty,
      UV_THREADPOOL_SIZE: '1',
    });
    const proxied = '{"kind":"steps","engine":"none","steps":["http://proxy.corp:8080/"]}\n';
    assert.equal(out, proxied + proxied);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(empty, { recursive: true, force: true });
  }
});