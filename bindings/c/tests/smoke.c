/* Links against the built library through the header alone and exits non-zero on any
 * mismatch between the two. On Linux it also watches a private KDE configuration change. */
#ifdef __linux__
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#endif
#include <stdio.h>
#include <string.h>

#include "proxy_watch.h"

#define CHECK(cond)                                                   \
    do {                                                              \
        if (!(cond)) {                                                \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #cond); \
            return 1;                                                 \
        }                                                             \
    } while (0)

#ifdef __linux__
struct change {
    pthread_mutex_t lock;
    pthread_cond_t done;
    pw_watch *watch;
    int status;
    int step; /* the first step to http://a.example/ after the change */
    int calls;
};

/* Reads the new settings, then closes its own watch, which must return without waiting
 * for this thread. */
static void on_change(void *userdata, int status) {
    struct change *change = userdata;
    pw_context *context = NULL;
    pw_route *route = NULL;
    int step = -1;
    if (pw_watch_current(change->watch, &context) == PW_OK &&
        pw_resolve(context, "http://a.example/", &route) == PW_OK) {
        step = pw_route_step_kind(route, 0);
    }
    pw_route_free(route);
    pw_context_free(context);
    pw_watch_close(change->watch);
    pthread_mutex_lock(&change->lock);
    change->status = status;
    change->step = step;
    change->calls++;
    pthread_cond_signal(&change->done);
    pthread_mutex_unlock(&change->lock);
}

static int write_kioslaverc(const char *dir, const char *body) {
    char path[512];
    snprintf(path, sizeof path, "%s/kioslaverc", dir);
    FILE *file = fopen(path, "w");
    if (!file) return 0;
    fputs(body, file);
    return fclose(file) == 0;
}

/* KDE's store is a file, so a private XDG_CONFIG_HOME makes the change hermetic. */
static int watch_a_change(void) {
    char dir[] = "/tmp/pw-smoke-XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    CHECK(write_kioslaverc(dir, "[Proxy Settings]\nProxyType=0\n"));
    setenv("XDG_CURRENT_DESKTOP", "KDE", 1);
    setenv("XDG_CONFIG_HOME", dir, 1);

    struct change change = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, NULL, -1, -1, 0};
    pthread_mutex_lock(&change.lock);
    CHECK(pw_watch_open(PW_PRECEDENCE_IGNORE, NULL, 0, on_change, &change, &change.watch) ==
          PW_OK);
    pw_context *context = NULL;
    pw_route *route = NULL;
    CHECK(pw_watch_current(change.watch, &context) == PW_OK);
    CHECK(pw_resolve(context, "http://a.example/", &route) == PW_OK);
    CHECK(pw_route_step_kind(route, 0) == PW_STEP_DIRECT);
    pw_route_free(route);
    pw_context_free(context);

    CHECK(write_kioslaverc(dir, "[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.corp:8080\n"));
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    while (change.calls == 0) {
        CHECK(pthread_cond_timedwait(&change.done, &change.lock, &deadline) == 0);
    }
    CHECK(change.status == PW_OK);
    CHECK(change.step == PW_STEP_HTTP);
    pthread_mutex_unlock(&change.lock);
    return 0;
}
#endif

int main(void) {
    /* First, while no other thread could be reading the environment it sets. */
#ifdef __linux__
    if (watch_a_change() != 0) return 1;
#endif
    const char *envp[] = {
        "https_proxy=http://user:secret@proxy.example:3128",
        "all_proxy=socks5h://socks.example:1080",
        NULL,
    };
    pw_context *context = NULL;
    pw_route *route = NULL;

#ifndef __ANDROID__
    CHECK(pw_android_init(NULL, NULL) == PW_ERR_UNSUPPORTED);
#endif
    CHECK(pw_context_open_with_env(PW_PRECEDENCE_BEFORE_SYSTEM, envp, &context) == PW_OK);
    CHECK(pw_context_os_readable(context) >= 0);

    CHECK(pw_resolve(context, "https://a.example/", &route) == PW_OK);
    CHECK(pw_route_kind(route) == PW_ROUTE_STEPS);
    CHECK(pw_route_len(route) == 1);
    CHECK(pw_route_step_kind(route, 0) == PW_STEP_HTTP);
    CHECK(strcmp(pw_route_uri(route, 0), "http://proxy.example:3128/") == 0);
    CHECK(strcmp(pw_route_password(route, 0), "secret") == 0);
    CHECK(strcmp(pw_route_username(route, 0), "user") == 0);
    CHECK(strcmp(pw_route_uri_with_auth(route, 0), "http://user:secret@proxy.example:3128/") == 0);
    CHECK(pw_route_pac(route) == NULL);
    CHECK(pw_route_uri(route, 1) == NULL);
    pw_route_free(route);

    CHECK(pw_resolve(context, "ftp://a.example/", &route) == PW_OK);
    CHECK(strcmp(pw_route_scheme(route, 0), "socks5h") == 0);
    pw_route_free(route);

    route = NULL;
    CHECK(pw_resolve(context, "not a url", &route) == PW_ERR_INVALID_URL);
    CHECK(route == NULL);
    CHECK(strlen(pw_last_error()) > 0);
    CHECK(pw_resolve_with_pac(context, "https://a.example/", 7, &route) == PW_ERR_INVALID_ARGUMENT);
    CHECK(pw_resolve_with_pac(context, "https://a.example/", PW_PAC_NATIVE, &route) == PW_OK);
    CHECK(strcmp(pw_route_uri(route, 0), "http://proxy.example:3128/") == 0);
    CHECK(pw_route_engine(route) == PW_ENGINE_NONE);
    pw_route_free(route);

    struct pw_route_options options;
    memset(&options, 0, sizeof options);
    options.size = sizeof options - 1;
    route = NULL;
    CHECK(pw_resolve_ex(context, "https://a.example/", &options, &route) == PW_ERR_INVALID_ARGUMENT);
    options.size = sizeof options;
    options.pac = PW_PAC_QUICKJS;
    options.wpad = 1;
    CHECK(pw_resolve_ex(context, "https://a.example/", &options, &route) == PW_ERR_INVALID_ARGUMENT);
    CHECK(route == NULL);
    options.pac = PW_PAC_AUTO;
    options.my_ip_address = "10.1.2.3";
    CHECK(pw_resolve_ex(context, "https://a.example/", &options, &route) == PW_OK);
    CHECK(strcmp(pw_route_uri(route, 0), "http://proxy.example:3128/") == 0);
    CHECK(pw_route_engine(route) == PW_ENGINE_NONE);
    pw_route_free(route);
    CHECK(pw_resolve_ex(context, "https://a.example/", NULL, &route) == PW_OK);
    pw_route_free(route);
    CHECK(pw_route_engine(NULL) == -1);

    CHECK(strstr(pw_describe(context), "secret") == NULL);
    CHECK(pw_rejected_text(context, pw_rejected_len(context)) == NULL);

    pw_context_free(context);

    CHECK(pw_context_open(PW_PRECEDENCE_IGNORE, &context) == PW_OK);
    pw_context_free(context);
    pw_context_free(NULL);
    pw_route_free(NULL);

    pw_watch *watch = NULL;
    CHECK(pw_watch_open(PW_PRECEDENCE_BEFORE_SYSTEM, envp, 50, NULL, NULL, &watch) == PW_OK);
    CHECK(pw_watch_current(watch, &context) == PW_OK);
    CHECK(pw_resolve(context, "https://a.example/", &route) == PW_OK);
    CHECK(strcmp(pw_route_uri(route, 0), "http://proxy.example:3128/") == 0);
    pw_route_free(route);
    pw_context_free(context);
    pw_watch_close(watch);
    pw_watch_close(NULL);

    puts("ok");
    return 0;
}
