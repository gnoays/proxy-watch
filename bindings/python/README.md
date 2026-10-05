# proxy-watch

The operating system's proxy settings for Python, layered with `http_proxy`,
`https_proxy`, `all_proxy` and `no_proxy`, and the route each URL takes under them.
Windows, macOS and Linux (GNOME, KDE) settings are read directly; nothing is spawned.

```sh
pip install proxy-watch
```

```python
import proxy_watch

snapshot = proxy_watch.read()
route = snapshot.route("https://example.com/")
if route.kind == "steps":
    print(route.steps)  # ["direct"] or proxy URLs, credentials included
else:
    print(route.kind)   # "pac", "pac-inline" or "wpad": the caller runs the script
```

## PAC

`route(url, pac=...)` chooses who runs a PAC configuration:

| `pac` | Engine |
|---|---|
| `"none"` (default) | No engine: the route names the PAC URL, script or WPAD |
| `"native"` | The OS's engine (WinHTTP, CFNetwork), with real DNS |
| `"quickjs"` | QuickJS in this process, under a `PacPolicy` |
| `"auto"` | The OS's engine where it has one for the mode, else QuickJS |

`script=` runs a PAC body you fetched yourself, and `wpad=True` lets the OS discover one
(Windows, macOS). `route.engine` says which engine answered. QuickJS's default policy
answers as if off every network (`myIpAddress()` is `127.0.0.1` and `dnsResolve` answers
`None`), so a script that picks a proxy by network needs a `PacPolicy` that says where the
machine is.

## Watching

```python
with proxy_watch.watch(lambda err, snapshot: print(err or snapshot.route("https://example.com/").kind)) as watcher:
    ...
```

`on_change` runs on the watch's own thread after each change.

## Wheels

One `abi3` wheel per platform serves CPython 3.10 and later: Linux x86-64 and AArch64
(manylinux2014 and musllinux 1.2), macOS x86-64 and arm64, Windows x86-64 and ARM64.
QuickJS is built into each of them.

## License

MIT OR Apache-2.0. Each wheel carries `THIRD-PARTY-LICENSES.txt` for the Rust crates, the C
sources and the Rust standard library linked into it.
