export interface ReadOptions {
  /** The variables to read `*_proxy` from; the process environment when absent. Pass
   * `process.env` from a worker thread, whose `process.env` is its own copy. Anything
   * `Object.prototype.toString` does not tag `[object Object]` (a `Map` included) throws
   * `ObjectExpected`. Enumerable string keys are read, inherited ones included; an
   * `undefined` value is skipped and any other non-string value throws. */
  env?: Record<string, string | undefined>;
  /** `before-system` (the default) lets any `*_proxy` or `no_proxy` outrank the OS,
   * `after-system` uses them only where the OS has no configuration, `ignore` skips them. */
  precedence?: 'before-system' | 'after-system' | 'ignore';
}

/** Who answered a route: `'native'` the OS's PAC engine, `'quickjs'` QuickJS in this
 * process, `'none'` no PAC engine. Two engines can answer one script differently. */
export type Engine = 'none' | 'native' | 'quickjs';

/** Where a request goes. A step is `"direct"` or a proxy URL, credentials included. A
 * `pac`, `pac-inline` or `wpad` route is the caller's to run; its `engine` is `'none'`. */
export type Route =
  | { kind: 'steps'; engine: Engine; steps: string[] }
  | { kind: 'pac'; engine: 'none'; pacUrl: string }
  | { kind: 'pac-inline'; engine: 'none'; script: string }
  | { kind: 'wpad'; engine: 'none' };

export interface Diagnostics {
  /** `false` where the OS has no proxy settings to read, such as a Linux server. */
  osReadable: boolean;
  sources: string[];
  fallbacks: string[];
  /** Values the sources held but the snapshot dropped (settings that silently stopped
   * applying), each as `"<kind> from <source>: <value>"`, credentials masked. */
  rejected: string[];
}

/** What QuickJS runs a script under; each field left out keeps its default. The defaults
 * answer a script that asks where it runs as if off every network (`myIpAddress()` is
 * `127.0.0.1`, `dnsResolve` answers `null`, local time is UTC), so a script that chooses a
 * proxy by network goes direct unless these say where the machine is. A field out of range
 * throws `ERR_INVALID_ARG_VALUE`. The OS's engine runs with the machine's own values and
 * takes none of these. */
export interface PacPolicy {
  /** What `myIpAddress()` returns; an IPv4 or IPv6 address. */
  myIpAddress?: string;
  /** Whether `dnsResolve`, `isResolvable` and `isInNet` query DNS. Default `false`. */
  resolveDns?: boolean;
  /** Whether DNS answers in internal space (RFC 1918, loopback, …) reach the script.
   * Default `false`. */
  allowInternalAddresses?: boolean;
  /** Seconds east of UTC that the date and time functions take as local, within a day.
   * Default `0`. */
  utcOffsetSeconds?: number;
  /** The budget for one evaluation, 1 to 60000. Default 5000. */
  timeoutMs?: number;
}

export interface RouteOptions {
  /** Who runs a PAC configuration. `'none'` (the default): nobody, and the route is `pac`,
   * `pac-inline` or `wpad`. `'native'`: the OS's engine (WinHTTP, CFNetwork, Android's PAC
   * service), with real DNS; it downloads a PAC URL, runs a body only on macOS and iOS,
   * and runs WPAD only with `wpad` on Windows, macOS and iOS. `'quickjs'`: QuickJS in this
   * process under `policy`, for a body (the configuration's own or `script`); built for
   * x64 and arm64 Windows, Linux and macOS and for arm (ARMv7) Linux with glibc,
   * `ERR_PAC_ENGINE_UNAVAILABLE` elsewhere.
   * `'auto'`: the OS's engine where it has one for the mode, else QuickJS, else the
   * caller's route; chosen before anything runs, so an engine's failure is thrown, not
   * retried on the other. A mode no chosen engine runs stays the caller's route. A URL
   * with no host (`mailto:`, `file:`, `data:`) is `['direct']` under every choice. */
  pac?: 'none' | 'native' | 'quickjs' | 'auto';
  /** A PAC body the caller fetched (for a PAC URL, or after its own WPAD discovery) run in
   * place of the configuration's. Up to 1 MiB. A `script` no engine here can run throws
   * `ERR_PAC_ENGINE_UNAVAILABLE`: `'native'` never hands one to QuickJS. */
  script?: string;
  /** Let the OS discover a script by WPAD (Windows, macOS, iOS). Off by default; with
   * `'none'` or `'quickjs'` it throws `ERR_INVALID_ARG_VALUE`. Discovery answers whatever
   * the network offers, and WinHTTP remembers a miss for the life of the process, answering
   * direct until it restarts. */
  wpad?: boolean;
  /** What QuickJS runs a script under. */
  policy?: PacPolicy;
}

export declare class Snapshot {
  private constructor();
  /** Throws with an `ERR_*` `code` (`ERR_INVALID_URL`, for one, or `ERR_PROXY_ENTRY_UNUSABLE`
   * when the entry for the URL's scheme was dropped: the request goes nowhere rather than
   * direct). Blocks while an engine downloads or runs a script; `routeAsync()` does not. */
  route(url: string, options?: RouteOptions): Route;
  /** `route()` on a libuv worker thread. Bad options throw before any promise exists; the
   * promise rejects with `route()`'s other codes. QuickJS's `Date` can read `TZ` there, so
   * the glibc caveat on `read()` applies to a script that reads local time. */
  routeAsync(url: string, options?: RouteOptions): Promise<Route>;
  /** @deprecated `routeAsync(url, { pac: 'native' })`. */
  routeNative(url: string): Promise<Route>;
  diagnostics(): Diagnostics;
  /** The configuration on one line, passwords masked; also what `util.inspect` shows. */
  toString(): string;
  /** The whole configuration as plain data, which `JSON.stringify` also takes. A proxy's
   * password is in it as the value. */
  toJSON(): SnapshotJson;
}

/** The fields each kind carries. `kind` and the other enumerations are open: a later
 * release can add a value. */
export type ModeJson =
  | { kind: 'direct' }
  | { kind: 'manual'; proxies: Record<string, EntryJson>; bypass: BypassJson; rejected: string[] }
  | { kind: 'pac'; url: string; rejected: string[] }
  | { kind: 'pac-inline'; script: string; rejected: string[] }
  | { kind: 'wpad' };

/** Keyed by `http`, `https`, `ftp`, `socks` or `all`. `unusable` is a proxy the source
 * named that could not be read; `rejected` says why, credentials masked. */
export type EntryJson =
  | {
      kind: 'use';
      /** The protocol the source named (`http`, `socks5h`, …), or `null` where it named none. */
      scheme: string | null;
      host: string;
      port: number;
      username: string | null;
      password: string | null;
      /** `Present`, `Absent`, `NotRead` (GNOME's stored password, which is not read) or
       * `InKeychain` (macOS); `null` without a username. */
      passwordState: string | null;
    }
  | { kind: 'disabled' }
  | { kind: 'unusable'; rejected: string };

export interface BypassJson {
  /** Each rule in the form it parses back from. */
  patterns: string[];
  /** The destinations bypassed without a rule: `Broad`, `WinInet`, `CfNetwork` or `Empty`. */
  implicit: string;
  excludeSimpleHostnames: boolean;
  reversedExceptions: boolean;
  requireExplicitPort: boolean;
  ipv4MappedAsIpv4: boolean;
  stripTrailingDot: boolean;
  rejected: string[];
}

export interface SnapshotJson {
  /** The mode in effect. */
  mode: ModeJson;
  /** Every source read, highest precedence first, with its own mode. */
  sources: { source: string; mode: ModeJson }[];
  fallbacks: string[];
  rejected: string[];
  osReadable: boolean;
}

/**
 * One read of the OS settings and the environment. The environment is copied when this is
 * called; the OS read runs on a libuv worker thread. Throws before any promise exists for
 * bad options (`ERR_INVALID_ARG_VALUE`, or `ObjectExpected` for `env`) and with
 * `ERR_CGI_HTTP_PROXY` when the environment is a CGI request's (a non-empty
 * `REQUEST_METHOD`) holding `http_proxy`, which the request's `Proxy` header can set.
 * `precedence: 'ignore'` does not layer the environment, but on Linux a KDE setting that
 * names environment variables (`ProxyType=4`) still reads the process's own, and refuses
 * the same way.
 *
 * On Linux, GLib reads variables of its own on that worker. glibc 2.41 made `getenv` safe
 * against a concurrent `setenv`; before it, writing `process.env` while the promise is
 * pending races those reads, so use `readSync()` there.
 */
export declare function read(options?: ReadOptions): Promise<Snapshot>;

/** `read()` on the calling thread, blocking it until the OS answers. */
export declare function readSync(options?: ReadOptions): Snapshot;

export interface WatchOptions extends ReadOptions {
  /** Also re-read on this interval. Required where the OS gives no change notification: a
   * Flatpak or Snap sandbox, iOS, Android below API 26 or where in-memory code loading is
   * refused, or a Linux session without a D-Bus session bus. Anything under 200, zero
   * included, is raised to 200; leaving it out turns the timer off. A negative or
   * non-finite value throws `ERR_INVALID_ARG_VALUE`. */
  pollIntervalMs?: number;
}

export declare class Watcher {
  private constructor();
  /** The latest configuration, layered with the environment captured when the watch
   * started. Throws with `code` `ERR_WATCHER_CLOSED` after `close()`, and
   * `ERR_PROXY_WATCH` once the OS watch has stopped on its own. */
  current(): Snapshot;
  /** Stop watching. Safe to call more than once. Once it returns, `onChange` is not
   * called again. */
  close(): void;
  /** `Watcher { open: <boolean> }`; also what `util.inspect` shows. */
  toString(): string;
}

/**
 * Watch the OS settings and call `onChange` after each change: with a new snapshot, or
 * with an error when a re-read failed (the watch goes on). Not called for the starting
 * configuration, which `current()` answers. A watch that stops on its own calls it a last
 * time with `ERR_PROXY_WATCH`. The first call can come before the promise `watch()`
 * returns has settled; `watchSync()` returns first. What `onChange` throws becomes an
 * `uncaughtException`, as a throwing event listener's does; the watch goes on.
 *
 * The watch does not keep the process alive, and it keeps running while unreferenced until
 * `close()` or until its thread's environment shuts down. Where the OS has no settings to
 * read, such as a Linux server, it answers from the environment and never calls back.
 *
 * The environment is copied when this is called, and the watcher starts on a libuv worker
 * thread, as `read()` does; bad options throw before any promise exists. The glibc caveat
 * on `read()` applies to that start too.
 */
export declare function watch(
  onChange: (err: Error | null, snapshot?: Snapshot) => void,
  options?: WatchOptions,
): Promise<Watcher>;

/** `watch()` on the calling thread, blocking it while the watcher starts. */
export declare function watchSync(
  onChange: (err: Error | null, snapshot?: Snapshot) => void,
  options?: WatchOptions,
): Watcher;
