import gc
import os
import select
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

import proxy_watch

ENV = {
    "https_proxy": "http://user:pass@proxy.example:3128",
    "all_proxy": "socks5h://socks.example:1080",
    "no_proxy": "internal.example",
}


class ReadTest(unittest.TestCase):
    def test_steps_carry_the_proxy_url_and_its_socks_hint(self):
        snapshot = proxy_watch.read(env=ENV)
        route = snapshot.route("https://a.example/")
        self.assertEqual(route.kind, "steps")
        self.assertEqual(route.steps, ["http://user:pass@proxy.example:3128/"])
        self.assertIsNone(route.pac_url)
        self.assertEqual(snapshot.route("ftp://a.example/").steps, ["socks5h://socks.example:1080"])
        self.assertEqual(snapshot.route("https://internal.example/").steps, ["direct"])
        self.assertEqual(route.engine, "none")
        for pac in ["native", "quickjs", "auto"]:
            routed = snapshot.route("https://a.example/", pac=pac)
            self.assertEqual((routed.steps, routed.engine), (route.steps, "none"), pac)

    def test_a_route_compares_by_value_and_its_repr_masks_the_password(self):
        snapshot = proxy_watch.read(env=ENV)
        route = snapshot.route("https://a.example/")
        self.assertEqual(route, snapshot.route("https://a.example/"))
        self.assertIn("user:***@proxy.example", repr(route))
        self.assertNotIn(":pass@", repr(route))
        self.assertNotIn('"pass"', repr(snapshot))

    def test_to_dict_holds_the_configuration_with_its_password(self):
        mode = proxy_watch.read(env=ENV).to_dict()["mode"]
        self.assertEqual(mode["kind"], "manual")
        self.assertEqual(mode["proxies"]["https"]["password"], "pass")
        self.assertEqual(mode["proxies"]["all"]["scheme"], "socks5h")
        self.assertEqual(mode["bypass"]["patterns"], ["internal.example"])

    def test_failures_carry_a_code(self):
        snapshot = proxy_watch.read(env={})
        with self.assertRaises(proxy_watch.ProxyWatchError) as raised:
            snapshot.route("not a url")
        self.assertEqual(raised.exception.code, "ERR_INVALID_URL")
        with self.assertRaises(proxy_watch.ProxyWatchError) as raised:
            proxy_watch.read(precedence="sideways")
        self.assertEqual(raised.exception.code, "ERR_INVALID_ARG_VALUE")

    def test_pac_options_with_nothing_to_run_them_or_out_of_range_are_refused(self):
        snapshot = proxy_watch.read(env={})
        script = "function FindProxyForURL(u, h) { return 'DIRECT'; }"
        refused = [
            lambda: snapshot.route("https://a.example/", pac="v8"),
            lambda: snapshot.route("https://a.example/", script=script),
            lambda: snapshot.route("https://a.example/", wpad=True),
            lambda: snapshot.route("https://a.example/", pac="quickjs", wpad=True),
            lambda: snapshot.route("https://a.example/", pac="quickjs", script=" " * ((1 << 20) + 1)),
            lambda: proxy_watch.PacPolicy(timeout=0),
            lambda: proxy_watch.PacPolicy(timeout=60.001),
            lambda: proxy_watch.PacPolicy(timeout=float("nan")),
            lambda: proxy_watch.PacPolicy(my_ip_address="corp.example"),
            lambda: proxy_watch.PacPolicy(utc_offset_seconds=-86_400),
        ]
        for index, call in enumerate(refused):
            with self.assertRaises(proxy_watch.ProxyWatchError, msg=index) as raised:
                call()
            self.assertEqual(raised.exception.code, "ERR_INVALID_ARG_VALUE", index)

    def test_an_entry_that_is_not_utf8_fails_nothing(self):
        # What `os.environ` holds for bytes that are not UTF-8: surrogates, in a name or a
        # value. Neither is one this read needs, so neither may fail it.
        env = {
            "JUNK": "\udcff\udcfe",
            "\udcffname": "http://never.example:1",
            "https_proxy": "http://proxy.example:3128",
        }
        route = proxy_watch.read(env=env).route("https://a.example/")
        self.assertEqual(route.steps, ["http://proxy.example:3128/"])
        proxy_watch.watch(lambda err, snapshot: None, env=env).close()

    # A malformed https_proxy alone does not win, so the route falls to the OS; the
    # dropped value is how the caller learns it was set and why it did not apply.
    def test_diagnostics_list_a_dropped_value_without_its_password(self):
        env = {"https_proxy": "http://user:hunter2@proxy.example:99999"}
        rejected = proxy_watch.read(env=env).diagnostics().rejected
        self.assertEqual(len(rejected), 1, rejected)
        self.assertIn("https_proxy", rejected[0])
        self.assertNotIn("hunter2", rejected[0])
        self.assertEqual(proxy_watch.read(env=ENV).diagnostics().rejected, [])

    def test_diagnostics_name_the_environment_as_a_source(self):
        diagnostics = proxy_watch.read(env=ENV).diagnostics()
        self.assertIsInstance(diagnostics.os_readable, bool)
        self.assertTrue(any("Env" in source for source in diagnostics.sources), diagnostics.sources)
        ignored = proxy_watch.read(env=ENV, precedence="ignore").diagnostics()
        self.assertFalse(any("Env" in source for source in ignored.sources), ignored.sources)


class WatchTest(unittest.TestCase):
    def test_current_layers_the_captured_environment_until_closed(self):
        with proxy_watch.watch(lambda err, snapshot: None, env=ENV) as watcher:
            route = watcher.current().route("https://a.example/")
            self.assertEqual(route.steps, ["http://user:pass@proxy.example:3128/"])
        with self.assertRaises(proxy_watch.ProxyWatchError) as raised:
            watcher.current()
        self.assertEqual(raised.exception.code, "ERR_WATCHER_CLOSED")
        watcher.close()

    def test_a_dropped_watcher_stops_without_blocking(self):
        started = time.monotonic()
        proxy_watch.watch(lambda err, snapshot: None, env={}, poll_interval=0.05)
        gc.collect()
        self.assertLess(time.monotonic() - started, 5.0)

    # KDE's store is a file, so a private XDG_CONFIG_HOME makes the change hermetic.
    @unittest.skipUnless(sys.platform.startswith("linux"), "the KDE backend is Linux only")
    def test_a_change_reaches_on_change_which_may_close_the_watcher(self):
        script = textwrap.dedent(
            """
            import os, threading, proxy_watch
            done = threading.Event()
            def on_change(err, snapshot):
                print(err.code if err else snapshot.route("http://a.example/").steps, flush=True)
                watcher.close()
                done.set()
            watcher = proxy_watch.watch(on_change, precedence="ignore")
            print(watcher.current().route("http://a.example/").steps, flush=True)
            with open(os.environ["XDG_CONFIG_HOME"] + "/kioslaverc", "w") as f:
                f.write("[Proxy Settings]\\nProxyType=1\\nhttpProxy=http://proxy.corp:8080\\n")
            if not done.wait(5):
                print("no change within 5 s")
            """
        )
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "kioslaverc"), "w") as f:
                f.write("[Proxy Settings]\nProxyType=0\n")
            env = dict(os.environ, XDG_CURRENT_DESKTOP="KDE", XDG_CONFIG_HOME=home)
            out = subprocess.run(
                [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=30
            )
        self.assertEqual(out.stdout, "['direct']\n['http://proxy.corp:8080/']\n", out.stderr)
        # A crash while the interpreter finalizes comes after both lines are printed.
        self.assertEqual(out.returncode, 0, out.stderr)

    # Removing the watched directory costs the watch its route: a snapshot arrives with the
    # configuration unchanged and only the health different. That is no change of the
    # settings, so on_change hears the failed re-read and nothing that reads as a change.
    @unittest.skipUnless(sys.platform.startswith("linux"), "kioslaverc is the Linux store")
    def test_losing_the_route_is_not_reported_as_a_change(self):
        script = textwrap.dedent(
            """
            import os, shutil, time, proxy_watch
            heard = []
            watcher = proxy_watch.watch(
                lambda err, snapshot: heard.append(err.code if err else "change"),
                precedence="ignore",
            )
            shutil.rmtree(os.environ["XDG_CONFIG_HOME"])
            time.sleep(1.5)
            watcher.close()
            print(sorted(set(heard)), flush=True)
            """
        )
        home = tempfile.mkdtemp()
        with open(os.path.join(home, "kioslaverc"), "w") as f:
            f.write("[Proxy Settings]\nProxyType=1\nhttpProxy=http://proxy.corp:8080\n")
        env = dict(
            os.environ, XDG_CURRENT_DESKTOP="KDE", XDG_CONFIG_HOME=home, XDG_CONFIG_DIRS="/nonexistent"
        )
        out = subprocess.run(
            [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=30
        )
        # The failed re-read only: the health-only snapshot that comes with it is not a change
        # (deliver it anyway and "change" joins this list).
        self.assertEqual(out.stdout, "['ERR_UNSUPPORTED']\n", out.stderr)
        self.assertEqual(out.returncode, 0, out.stderr)

    # A PAC URL from the OS with the body the caller fetched: QuickJS runs it under the
    # policy, and the defaults place the script off every network.
    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and os.uname().machine in ("x86_64", "aarch64", "armv7l", "armv8l"),
        "kioslaverc is the Linux store, and QuickJS is built for x86-64, AArch64 and ARMv7",
    )
    def test_quickjs_runs_a_fetched_script_under_the_policy(self):
        script = textwrap.dedent(
            """
            import proxy_watch
            body = ("function FindProxyForURL(u, h) { return isInNet(myIpAddress(), "
                    "'10.0.0.0', '255.0.0.0') ? 'PROXY corp.example:8080' : 'DIRECT'; }")
            snapshot = proxy_watch.read(precedence="ignore")
            inside = proxy_watch.PacPolicy(my_ip_address="10.1.2.3")
            for kwargs in [{}, {"pac": "quickjs", "script": body},
                           {"pac": "quickjs", "script": body, "policy": inside}, {"pac": "auto"}]:
                r = snapshot.route("http://a.example/", **kwargs)
                print(r.kind, r.steps, r.pac_url, r.engine)
            try:
                snapshot.route("http://a.example/", pac="native", script=body)
            except proxy_watch.ProxyWatchError as error:
                print(error.code)
            """
        )
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "kioslaverc"), "w") as f:
                f.write("[Proxy Settings]\nProxyType=2\nProxy Config Script=http://wpad.example/proxy.pac\n")
            env = dict(
                os.environ, XDG_CURRENT_DESKTOP="KDE", XDG_CONFIG_HOME=home, XDG_CONFIG_DIRS="/nonexistent"
            )
            out = subprocess.run(
                [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=30
            )
        left = "pac None http://wpad.example/proxy.pac none"
        self.assertEqual(
            out.stdout,
            f"{left}\nsteps ['direct'] None quickjs\n"
            "steps ['http://corp.example:8080/'] None quickjs\n"
            f"{left}\nERR_PAC_ENGINE_UNAVAILABLE\n",
            out.stderr,
        )

    # Each shape a route takes from the OS, under each precedence: the environment outranks
    # the OS before it, the OS outranks the environment after it, and ignore leaves it out.
    @unittest.skipUnless(sys.platform.startswith("linux"), "kioslaverc is the Linux store")
    def test_each_os_mode_reaches_the_route_in_its_own_shape_under_each_precedence(self):
        script = textwrap.dedent(
            """
            import proxy_watch
            env = {"https_proxy": "http://env.example:3128"}
            for precedence in ["ignore", "before-system", "after-system"]:
                r = proxy_watch.read(env=env, precedence=precedence).route("https://a.example/")
                print(precedence, r.kind, r.steps, r.pac_url, r.script)
            """
        )
        from_env = "steps ['http://env.example:3128/'] None None"
        os_modes = {
            "ProxyType=2\nProxy Config Script=http://wpad.example/proxy.pac\n":
                "pac None http://wpad.example/proxy.pac None",
            "ProxyType=3\n": "wpad None None None",
            "ProxyType=1\nhttpsProxy=http://os.example:8080\n":
                "steps ['http://os.example:8080/'] None None",
        }
        for settings, from_os in os_modes.items():
            with tempfile.TemporaryDirectory() as home:
                with open(os.path.join(home, "kioslaverc"), "w") as f:
                    f.write("[Proxy Settings]\n" + settings)
                env = dict(
                    os.environ,
                    XDG_CURRENT_DESKTOP="KDE",
                    XDG_CONFIG_HOME=home,
                    XDG_CONFIG_DIRS="/nonexistent",
                )
                out = subprocess.run(
                    [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=30
                )
            self.assertEqual(
                out.stdout,
                f"ignore {from_os}\nbefore-system {from_env}\nafter-system {from_os}\n",
                out.stderr,
            )

    def test_watch_reads_os_environ_as_it_was_at_the_call(self):
        saved = os.environ.get("https_proxy")
        try:
            os.environ["https_proxy"] = "http://a.example:1"
            with proxy_watch.watch(lambda err, snapshot: None) as watcher:
                os.environ["https_proxy"] = "http://b.example:2"
                steps = watcher.current().route("https://x.example/").steps
            self.assertEqual(steps, ["http://a.example:1/"])
        finally:
            if saved is None:
                os.environ.pop("https_proxy", None)
            else:
                os.environ["https_proxy"] = saved

    # The common shape of a cycle: an object holds its watcher and hands it a bound method.
    # The collector has to see on_change to free the pair, and freeing it stops the thread.
    @unittest.skipUnless(sys.platform.startswith("linux"), "counts threads in /proc")
    def test_a_watcher_in_a_cycle_with_on_change_is_collected_and_stops(self):
        script = textwrap.dedent(
            """
            import gc, os, time, proxy_watch
            def threads():
                return sum(
                    open(f"/proc/self/task/{task}/comm").read().startswith("proxy-watch")
                    for task in os.listdir("/proc/self/task")
                )
            class Owner:
                def __init__(self):
                    self.watcher = proxy_watch.watch(self.on_change, precedence="ignore")
                def on_change(self, err, snapshot):
                    pass
            owner = Owner()
            print(threads() > 0)
            del owner
            gc.collect()
            time.sleep(0.5)
            print(threads())
            """
        )
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, "kioslaverc"), "w") as f:
                f.write("[Proxy Settings]\nProxyType=0\n")
            env = dict(
                os.environ, XDG_CURRENT_DESKTOP="KDE", XDG_CONFIG_HOME=home, XDG_CONFIG_DIRS="/nonexistent"
            )
            out = subprocess.run(
                [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=30
            )
        self.assertEqual(out.stdout, "True\n0\n", out.stderr)

    def test_env_accepts_os_environ(self):
        proxy_watch.read(env=os.environ)
        proxy_watch.watch(lambda err, snapshot: None, env=os.environ).close()

    # The child has none of the parent's threads: `current()` refuses and `close()` returns
    # rather than waiting for a thread that is not there.
    @unittest.skipUnless(hasattr(os, "fork"), "fork is POSIX only")
    def test_a_forked_child_is_refused_the_parents_watcher(self):
        with proxy_watch.watch(lambda err, snapshot: None, env=ENV) as watcher:
            read_end, write_end = os.pipe()
            pid = os.fork()
            if pid == 0:
                # Whatever happens, the child must not go on to run the rest of the suite.
                try:
                    try:
                        watcher.current()
                        code = "answered"
                    except proxy_watch.ProxyWatchError as raised:
                        code = raised.code
                    watcher.close()
                    os.write(write_end, code.encode())
                finally:
                    os._exit(0)
            os.close(write_end)
            try:
                ready, _, _ = select.select([read_end], [], [], 10)
                out = os.read(read_end, 64).decode() if ready else "no answer within 10 s"
            finally:
                os.close(read_end)
                if not ready:
                    os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            self.assertEqual(out, "ERR_FORKED")
            self.assertEqual(
                watcher.current().route("https://a.example/").steps,
                ["http://user:pass@proxy.example:3128/"],
            )

    def test_poll_interval_rejects_a_negative_value(self):
        with self.assertRaises(ValueError):
            proxy_watch.watch(lambda err, snapshot: None, poll_interval=-1.0)

    def test_on_change_must_be_callable(self):
        with self.assertRaises(TypeError):
            proxy_watch.watch(5)

    def test_a_cgi_environment_holding_http_proxy_is_refused(self):
        env = {"REQUEST_METHOD": "GET", "http_proxy": "http://attacker.example:1"}
        with self.assertRaises(proxy_watch.ProxyWatchError) as raised:
            proxy_watch.read(env=env)
        self.assertEqual(raised.exception.code, "ERR_CGI_HTTP_PROXY")
        with self.assertRaises(proxy_watch.ProxyWatchError) as raised:
            proxy_watch.watch(lambda err, snapshot: None, env=env)
        self.assertEqual(raised.exception.code, "ERR_CGI_HTTP_PROXY")


if __name__ == "__main__":
    unittest.main()
