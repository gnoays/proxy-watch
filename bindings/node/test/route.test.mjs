import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pbkdf2 } from 'node:crypto';
import { createRequire } from 'node:module';
import { inspect } from 'node:util';

const { read, readSync, watchSync } = createRequire(import.meta.url)('../proxy-watch.node');

const env = {
  https_proxy: 'http://user:pass@proxy.example:3128',
  no_proxy: 'internal.example',
};

// napi would read each of these as an object holding no variables, which answers as
// though nothing were configured.
test('an env that is not a plain object is refused', () => {
  for (const env of ['https_proxy=http://p.example:1', 5, ['https_proxy'], true]) {
    assert.throws(() => readSync({ env }), { code: 'ObjectExpected' }, JSON.stringify(env));
    assert.throws(() => watchSync(() => {}, { env }), { code: 'ObjectExpected' }, JSON.stringify(env));
  }
  // A Map's entries are not properties, so it would read as holding nothing and route direct.
  for (const env of [new Map([['https_proxy', 'http://p.example:1']]), new Date()]) {
    assert.throws(() => readSync({ env }), { code: 'ObjectExpected' }, String(env));
  }
});

test('a CGI environment holding http_proxy is refused, as the core refuses it', () => {
  const env = { REQUEST_METHOD: 'GET', http_proxy: 'http://attacker.example:1' };
  assert.throws(() => readSync({ env }), { code: 'ERR_CGI_HTTP_PROXY' });
  assert.throws(() => watchSync(() => {}, { env }), { code: 'ERR_CGI_HTTP_PROXY' });
});

test('process.env itself and an undefined value are accepted; a non-string value is refused', () => {
  assert.doesNotThrow(() => readSync({ env: process.env }));
  assert.deepEqual(
    readSync({ env: { https_proxy: 'http://p.example:1', http_proxy: undefined } })
      .route('https://a.example/').steps,
    ['http://p.example:1/'],
  );
  for (const value of [null, 5]) {
    assert.throws(() => readSync({ env: { https_proxy: value } }), String(value));
  }
});

// A malformed https_proxy alone does not win, so the route falls to the OS; the dropped
// value is how the caller learns it was set and why it did not apply.
test('diagnostics list a dropped value without its password', () => {
  const { rejected } = readSync({ env: { https_proxy: 'http://user:hunter2@proxy.example:99999' } })
    .diagnostics();
  assert.equal(rejected.length, 1, JSON.stringify(rejected));
  assert.match(rejected[0], /https_proxy/);
  assert.doesNotMatch(rejected[0], /hunter2/);
  assert.deepEqual(readSync({ env }).diagnostics().rejected, []);
});

test('a snapshot inspects as its configuration with the password masked', () => {
  const shown = inspect(readSync({ env }));
  assert.match(shown, /^Snapshot \{ osReadable: \w+, config: ProxyConfig/);
  assert.match(shown, /proxy\.example/);
  assert.doesNotMatch(shown, /"pass"/);
});

test('toJSON holds the configuration with its password', () => {
  const snapshot = readSync({ env });
  const { mode, osReadable } = snapshot.toJSON();
  assert.equal(typeof osReadable, 'boolean');
  assert.deepEqual(mode.proxies.https, {
    kind: 'use',
    scheme: 'http',
    host: 'proxy.example',
    port: 3128,
    username: 'user',
    password: 'pass',
    passwordState: 'Present',
  });
  assert.deepEqual(mode.bypass.patterns, ['internal.example']);
  assert.deepEqual(JSON.parse(JSON.stringify(snapshot)), snapshot.toJSON());
});

test('the environment outranks the OS by default', async () => {
  const snapshot = await read({ env });
  assert.deepEqual(
    { ...snapshot.route('https://a.example/') },
    { kind: 'steps', steps: ['http://user:pass@proxy.example:3128/'], engine: 'none' },
  );
  assert.deepEqual(snapshot.route('https://internal.example/').steps, ['direct']);
  assert.equal(snapshot.diagnostics().sources[0], 'Env');
  assert.deepEqual(
    { ...readSync({ env }).route('https://a.example/') },
    { ...snapshot.route('https://a.example/') },
  );
});

// Occupies every libuv worker thread for a while, so work queued next starts only after
// the code that follows it has run.
function saturate() {
  const size = Number(process.env.UV_THREADPOOL_SIZE) || 4;
  return Promise.all(
    Array.from(
      { length: size },
      () => new Promise((resolve) => pbkdf2('x', 'y', 100_000, 32, 'sha256', resolve)),
    ),
  );
}

// The worker starts after the change below, so a copy taken there would see it.
test('read() takes process.env when called', async () => {
  const saved = process.env.https_proxy;
  try {
    const busy = saturate();
    process.env.https_proxy = 'http://at-call.example:3128';
    const pending = read();
    process.env.https_proxy = 'http://after-call.example:3128';
    assert.deepEqual((await pending).route('https://a.example/').steps, [
      'http://at-call.example:3128/',
    ]);
    await busy;
  } finally {
    if (saved === undefined) delete process.env.https_proxy;
    else process.env.https_proxy = saved;
  }
});

test('failures carry a code', async () => {
  const snapshot = readSync({ env });
  assert.throws(() => snapshot.route('not a url'), { code: 'ERR_INVALID_URL' });
  // Options are checked before the promise exists, as `dns.promises.lookup` checks its own.
  assert.throws(() => read({ precedence: 'sideways' }), { code: 'ERR_INVALID_ARG_VALUE' });
  assert.throws(() => readSync({ precedence: 'sideways' }), { code: 'ERR_INVALID_ARG_VALUE' });
  for (const pac of ['native', 'quickjs', 'auto']) {
    assert.deepEqual(
      { ...snapshot.route('https://a.example/', { pac }) },
      { kind: 'steps', steps: ['http://user:pass@proxy.example:3128/'], engine: 'none' },
      pac,
    );
  }
});

// Each is refused before anything runs, from `routeAsync()` as a throw rather than a
// rejected promise.
test('pac options with nothing to run them, or out of range, are refused', () => {
  const snapshot = readSync({ env });
  for (const options of [
    { pac: 'v8' },
    { script: 'function FindProxyForURL(u, h) { return "DIRECT"; }' },
    { wpad: true },
    { pac: 'quickjs', wpad: true },
    { pac: 'quickjs', script: ' '.repeat((1 << 20) + 1) },
    { pac: 'quickjs', policy: { timeoutMs: 0 } },
    { pac: 'quickjs', policy: { timeoutMs: 60_001 } },
    { pac: 'quickjs', policy: { myIpAddress: 'corp.example' } },
    { pac: 'quickjs', policy: { utcOffsetSeconds: 86_400 } },
  ]) {
    const name = JSON.stringify(options).slice(0, 80);
    assert.throws(() => snapshot.route('https://a.example/', options), { code: 'ERR_INVALID_ARG_VALUE' }, name);
    assert.throws(() => snapshot.routeAsync('https://a.example/', options), { code: 'ERR_INVALID_ARG_VALUE' }, name);
  }
});

test('routeAsync and routeNative answer off the JavaScript thread with the same codes', async () => {
  const snapshot = readSync({ env });
  const expected = { kind: 'steps', steps: ['http://user:pass@proxy.example:3128/'], engine: 'none' };
  assert.deepEqual({ ...(await snapshot.routeNative('https://a.example/')) }, expected);
  assert.deepEqual({ ...(await snapshot.routeAsync('https://a.example/', { pac: 'auto' })) }, expected);
  assert.deepEqual({ ...(await snapshot.routeAsync('https://a.example/')) }, expected);
  await assert.rejects(snapshot.routeNative('not a url'), { code: 'ERR_INVALID_URL' });
  await assert.rejects(snapshot.routeAsync('not a url'), { code: 'ERR_INVALID_URL' });
});

// The OS settings are the machine's own, so only the shape is checked.
test('ignoring the environment answers from the OS alone', async () => {
  const snapshot = await read({ env, precedence: 'ignore' });
  const { kind } = snapshot.route('https://a.example/');
  assert.ok(['steps', 'pac', 'pac-inline', 'wpad'].includes(kind), kind);
  assert.ok(!snapshot.diagnostics().sources.includes('Env'));
});
