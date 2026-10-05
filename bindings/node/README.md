# proxy-watch

The operating system's proxy settings for Node.js, layered with `http_proxy`,
`https_proxy`, `all_proxy` and `no_proxy`, and the route each URL takes under them.
Windows, macOS and Linux (GNOME, KDE) settings are read directly; nothing is spawned.

```sh
npm install proxy-watch
```

```js
const { readSync } = require('proxy-watch');

const snapshot = readSync(); // or `await read()`, which reads the OS on a libuv worker
const route = snapshot.route('https://example.com/');
if (route.kind === 'steps') {
  console.log(route.steps); // ['direct'] or proxy URLs, credentials included
} else {
  console.log(route.kind);  // 'pac', 'pac-inline' or 'wpad': the caller runs the script
}
```

## PAC

`route(url, { pac })` and `routeAsync(url, { pac })` choose who runs a PAC configuration:

| `pac` | Engine |
|---|---|
| `'none'` (default) | No engine: the route names the PAC URL, script or WPAD |
| `'native'` | The OS's engine (WinHTTP, CFNetwork), with real DNS |
| `'quickjs'` | QuickJS in this process, under `policy` |
| `'auto'` | The OS's engine where it has one for the mode, else QuickJS |

`script` runs a PAC body you fetched yourself, and `wpad: true` lets the OS discover one
(Windows, macOS). `route.engine` says which engine answered. QuickJS's default policy
answers as if off every network (`myIpAddress()` is `127.0.0.1` and `dnsResolve` answers
`null`), so a script that picks a proxy by network needs a `policy` that says where the
machine is. `routeAsync` runs on a libuv worker, so a download or a slow script does not
block the event loop.

## Watching

```js
const { watchSync } = require('proxy-watch');

const watcher = watchSync((err, snapshot) => {
  if (err) console.error(err.code);
  else console.log(snapshot.route('https://example.com/').kind);
});
// later
watcher.close();
```

The watch does not keep the process alive.

## Platforms

Prebuilt for Linux x64 and arm64 (glibc 2.17 and later, and musl), macOS x64 and arm64,
and Windows x64 and arm64. npm installs the one package that matches the machine.

## License

MIT OR Apache-2.0. Each platform package carries `THIRD-PARTY-LICENSES.txt` for the Rust
crates, the C sources and the Rust standard library linked into it.
