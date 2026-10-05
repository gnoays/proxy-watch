# proxy-watch C ABI

The operating system's proxy settings layered with `*_proxy`, and the route each URL takes
under them, behind a C header. `include/proxy_watch.h` documents every function.

```c
#include <stdio.h>
#include <proxy_watch.h>

pw_context *context = NULL;
pw_route *route = NULL;
if (pw_context_open(PW_PRECEDENCE_BEFORE_SYSTEM, &context) == PW_OK &&
    pw_resolve(context, "https://example.com/", &route) == PW_OK) {
    for (size_t i = 0; i < pw_route_len(route); i++)
        puts(pw_route_uri(route, i)); /* "direct" or a proxy URL without credentials */
}
pw_route_free(route);
pw_context_free(context);
```

## Linking

- Shared: `lib/libproxy_watch_c.so`, `lib/libproxy_watch_c.dylib`, or `lib/proxy_watch_c.dll`
  with its import library `lib/proxy_watch_c.dll.lib`.
- Static: `lib/libproxy_watch_c.a` or `lib/proxy_watch_c.lib`, plus the system libraries
  listed in `lib/native-static-libs.txt` for that target. On Windows the static library
  uses the DLL C runtime, so the program compiles with `/MD`.

Linux builds need glibc 2.17 or later. Windows builds load `VCRUNTIME140.dll`, which the
Microsoft Visual C++ Redistributable installs, and the Universal CRT that Windows 10 and later
ship. On Android, call `pw_android_init` with the `JavaVM` and a `Context` before the first
read.

## License

MIT OR Apache-2.0. `THIRD-PARTY-LICENSES.txt` covers the Rust crates, the C sources and the
Rust standard library linked into the libraries.
