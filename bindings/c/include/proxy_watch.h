/*
 * proxy-watch C ABI: one snapshot of the OS proxy settings layered with *_proxy.
 *
 * Open a context, ask it for the route to a URL, read the route's steps, free both. A
 * watch hands out a fresh context after each change.
 * Functions returning int return a PW_OK / PW_ERR_* status unless documented otherwise;
 * pw_last_error() holds the message of the calling thread's last failure. Contexts and
 * routes never change after they are made and a watch locks what it shares, so any handle
 * may be read from several threads at once - but not while another thread frees or
 * closes it.
 * Every string a route returns lives until pw_route_free, and every string a context
 * returns until pw_context_free. Every *_free accepts NULL.
 */
#ifndef PROXY_WATCH_H
#define PROXY_WATCH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum pw_status {
    PW_OK = 0,
    PW_ERR_PROXY_WATCH = 1,
    PW_ERR_UNSUPPORTED_PROXY_SCHEME = 2,
    PW_ERR_INVALID_URL = 3,
    PW_ERR_INVALID_PROXY_SERVER = 4,
    PW_ERR_INVALID_BYPASS_PATTERN = 5,
    PW_ERR_INVALID_PROXY_URL = 6,
    PW_ERR_CGI_HTTP_PROXY = 7,
    PW_ERR_IO = 8,
    PW_ERR_SANDBOXED = 9,
    PW_ERR_UNSUPPORTED = 10,
    PW_ERR_PAC_NOT_SUPPORTED = 11,
    PW_ERR_PROXY_ENTRY_UNUSABLE = 12,
    PW_ERR_PAC_FETCH_REQUIRED = 13,
    PW_ERR_PAC_EVALUATION = 14,
    PW_ERR_PAC_TIMEOUT = 15,
    PW_ERR_PAC_SATURATED = 16,
    PW_ERR_PAC_INVALID_RESULT = 17,
    PW_ERR_PAC_ENGINE_UNAVAILABLE = 18,
    PW_ERR_NULL_ARGUMENT = 50,
    PW_ERR_INVALID_UTF8 = 51,
    PW_ERR_INVALID_ARGUMENT = 52,
    PW_ERR_EMBEDDED_NUL = 53,
    PW_ERR_PANIC = 54
};

enum pw_env_precedence {
    PW_PRECEDENCE_BEFORE_SYSTEM = 0,
    PW_PRECEDENCE_AFTER_SYSTEM = 1,
    PW_PRECEDENCE_IGNORE = 2
};

enum pw_route_kind {
    PW_ROUTE_STEPS = 0,
    PW_ROUTE_PAC = 1,
    PW_ROUTE_PAC_INLINE = 2,
    PW_ROUTE_WPAD = 3
};

enum pw_step_kind {
    PW_STEP_DIRECT = 0,
    PW_STEP_HTTP = 1,
    PW_STEP_HTTPS = 2,
    PW_STEP_SOCKS4 = 3,
    PW_STEP_SOCKS5 = 4
};

/* Who runs a PAC configuration; the call blocks while an engine downloads or runs one.
 * PW_PAC_NONE: nobody, and the route is PW_ROUTE_PAC, PW_ROUTE_PAC_INLINE or PW_ROUTE_WPAD.
 * PW_PAC_NATIVE: the OS's engine (WinHTTP, CFNetwork, Android's PAC service) with real DNS;
 * it downloads a PAC URL, runs a body only on macOS and iOS, and runs WPAD only with wpad
 * on Windows, macOS and iOS. PW_PAC_QUICKJS: QuickJS in this process under the options'
 * policy, for a body - the configuration's own or script; built for x86-64 and AArch64
 * Windows, Linux and macOS, PW_ERR_PAC_ENGINE_UNAVAILABLE elsewhere. PW_PAC_AUTO: the OS's
 * engine where it has one for the mode, else QuickJS, else the caller's route; chosen
 * before anything runs, so an engine's failure is returned, not retried on the other. A
 * mode no chosen engine runs stays the caller's route. A URL with no host (mailto:, file:,
 * data:) is one direct step under every choice. */
enum pw_pac {
    PW_PAC_NONE = 0,
    PW_PAC_NATIVE = 1,
    PW_PAC_QUICKJS = 2,
    PW_PAC_AUTO = 3
};

/* Who answered a route. Two engines can answer one script differently. */
enum pw_engine {
    PW_ENGINE_NONE = 0,
    PW_ENGINE_NATIVE = 1,
    PW_ENGINE_QUICKJS = 2
};

/* Options for pw_resolve_ex. Zero every field, set size to sizeof(struct pw_route_options),
 * then set what differs from the default; a size under this header's is refused with
 * PW_ERR_INVALID_ARGUMENT. The policy fields apply to QuickJS alone; the OS's engine runs
 * with the machine's own values. Their defaults answer a script that asks where it runs as
 * if off every network - myIpAddress() is 127.0.0.1, dnsResolve answers null, local time is
 * UTC - so a script that chooses a proxy by network goes direct unless they say where the
 * machine is. A value out of range is PW_ERR_INVALID_ARGUMENT. */
struct pw_route_options {
    size_t size;
    int pac;                      /* a pw_pac */
    /* NULL, or a PAC body the caller fetched (up to 1 MiB) - for a PAC URL, or after its
     * own WPAD discovery - run in place of the configuration's. One no engine here can run
     * is PW_ERR_PAC_ENGINE_UNAVAILABLE: PW_PAC_NATIVE never hands it to QuickJS. With
     * PW_PAC_NONE it is PW_ERR_INVALID_ARGUMENT. */
    const char *script;
    /* Nonzero lets the OS discover a script by WPAD (Windows, macOS, iOS); with PW_PAC_NONE
     * or PW_PAC_QUICKJS it is PW_ERR_INVALID_ARGUMENT. WinHTTP remembers a miss for the life
     * of the process, answering direct until it restarts. */
    int wpad;
    const char *my_ip_address;    /* What myIpAddress() returns; NULL is 127.0.0.1. */
    int resolve_dns;              /* Nonzero lets dnsResolve, isResolvable, isInNet query DNS. */
    int allow_internal_addresses; /* Nonzero passes DNS answers in RFC 1918, loopback, ... */
    int utc_offset_seconds;       /* East of UTC, within a day, for the date and time functions. */
    unsigned timeout_ms;          /* One evaluation's budget, up to 60000; 0 is 5000. */
};

typedef struct pw_context pw_context;
typedef struct pw_route pw_route;

/* Android: hand the library the process's JavaVM* and a JNI reference to an
 * android.content.Context (an Activity, a Service or the Application), once, before the
 * first context or watch is opened; it keeps the application Context and only borrows
 * context. Call it from a JNI function the app's Java or Kotlin side calls with a Context;
 * JNI_OnLoad has the JavaVM but no Context. Without it every read fails with PW_ERR_IO,
 * unless the host registered both with ndk-context. A second call with the same JavaVM
 * changes nothing; one with another is PW_ERR_IO. PW_ERR_UNSUPPORTED on every other OS. */
int pw_android_init(void *java_vm, void *context);

/* Read the OS settings and the process environment. PW_ERR_CGI_HTTP_PROXY when the
 * environment read is a CGI request's (a non-empty REQUEST_METHOD) and holds http_proxy,
 * which the request's Proxy header can set. */
int pw_context_open(int precedence, pw_context **out);
/* As pw_context_open, reading *_proxy from a NULL-terminated "NAME=VALUE" array. An entry
 * that is not UTF-8 fails nothing: a name that is not is skipped, and a value that is not is
 * read with replacement characters, so a proxy variable holding one is refused and listed
 * by pw_rejected_text. A name given twice keeps its first value, as getenv and
 * pw_context_open do. */
int pw_context_open_with_env(int precedence, const char *const *envp, pw_context **out);
void pw_context_free(pw_context *context);
/* 1 when the OS had settings to read, 0 when it had none, -1 for NULL. */
int pw_context_os_readable(const pw_context *context);

/* pw_resolve_with_pac with PW_PAC_NONE. PW_ERR_PROXY_ENTRY_UNUSABLE when the entry for
 * the URL's scheme was dropped: the request goes nowhere rather than direct. */
int pw_resolve(const pw_context *context, const char *url, pw_route **out);
/* pw_resolve_ex with only pac set. */
int pw_resolve_with_pac(const pw_context *context, const char *url, int pac, pw_route **out);
/* pw_resolve, with options choosing who runs a PAC configuration; NULL options is
 * pw_resolve. */
int pw_resolve_ex(const pw_context *context, const char *url,
                  const struct pw_route_options *options, pw_route **out);
void pw_route_free(pw_route *route);
/* A pw_route_kind, or -1 for NULL. */
int pw_route_kind(const pw_route *route);
/* The pw_engine that answered; PW_ENGINE_NONE for every kind but PW_ROUTE_STEPS. -1 for
 * NULL. */
int pw_route_engine(const pw_route *route);
/* The PAC URL (PW_ROUTE_PAC) or script (PW_ROUTE_PAC_INLINE); NULL otherwise. */
const char *pw_route_pac(const pw_route *route);
/* The number of steps; 0 for PAC, WPAD and NULL. */
size_t pw_route_len(const pw_route *route);

/* Per step; out of range answers -1 or NULL. */
int pw_route_step_kind(const pw_route *route, size_t index);
/* "http", "https", "socks4", "socks4a", "socks5" or "socks5h"; NULL when direct. */
const char *pw_route_scheme(const pw_route *route, size_t index);
/* "direct" or the proxy URL without credentials, safe to log. */
const char *pw_route_uri(const pw_route *route, size_t index);
/* The proxy URL with credentials. Do not log it. */
const char *pw_route_uri_with_auth(const pw_route *route, size_t index);
/* NULL when the step has none. */
const char *pw_route_username(const pw_route *route, size_t index);
const char *pw_route_password(const pw_route *route, size_t index);

/* The whole configuration on one line, credentials masked, for a log. The sources and the
 * fallbacks a snapshot records appear only here. */
const char *pw_describe(const pw_context *context);
/* Values the sources held but the snapshot dropped: settings that silently stopped
 * applying. Each reads "<kind> from <source>: <value>", credentials masked. */
size_t pw_rejected_len(const pw_context *context);
const char *pw_rejected_text(const pw_context *context, size_t index);

/* This thread's last failure message; "" before any. Valid until the next failure. */
const char *pw_last_error(void);

typedef struct pw_watch pw_watch;

/* Called on the watch's own thread after each change of the OS settings: PW_OK, or a
 * failure status whose message pw_last_error() holds on that thread. A watch that stops on
 * its own calls it a last time with PW_ERR_PROXY_WATCH. It must return
 * normally (no longjmp, no C++ exception) and may call pw_watch_close on its own watch. */
typedef void (*pw_on_change)(void *userdata, int status);

/* Watch the OS settings. envp as for pw_context_open_with_env, or NULL for the process
 * environment; either is read once, here. poll_interval_ms 0 relies on the OS's change
 * notification, and 1 to 199 is raised to 200; give one where the OS has none (a Flatpak
 * or Snap sandbox, iOS, Android below API 26 or where in-memory code loading is refused,
 * or a Linux session without a D-Bus session bus). on_change may be NULL. It can run
 * before this returns, so before *out is set: what it needs goes through userdata. */
int pw_watch_open(int precedence, const char *const *envp, unsigned poll_interval_ms,
                  pw_on_change on_change, void *userdata, pw_watch **out);
/* A new context holding the latest reading, layered with the environment open read.
 * PW_ERR_PROXY_WATCH once the watch has stopped on its own; open a new one. */
int pw_watch_current(const pw_watch *watch, pw_context **out);
/* Stop and free. Once it returns, on_change is not running and is not called again;
 * called from on_change, it returns without waiting. NULL is accepted. A forked child
 * must not close or read its parent's watch: the watch's thread is not in the child, and
 * a lock it held at the fork stays held there. */
void pw_watch_close(pw_watch *watch);

#ifdef __cplusplus
}
#endif

#endif
