from types import TracebackType
from typing import Any, Callable, ClassVar, Literal, Mapping, Optional, Type

Precedence = Literal["before-system", "after-system", "ignore"]

class ProxyWatchError(Exception):
    code: str
    """An ``ERR_*`` code.

    ``ERR_CGI_HTTP_PROXY`` from ``read``/``watch`` when ``env`` is a CGI request's (a non-empty
    ``REQUEST_METHOD``) holding ``http_proxy``, unless ``precedence="ignore"``, which does not
    layer it -- though on Linux a KDE setting that names environment variables
    (``ProxyType=4``) still reads the process's own.

    ``ERR_PROXY_ENTRY_UNUSABLE`` from ``route`` when the entry for the URL's scheme was
    dropped, so the request goes nowhere rather than direct.
    """

Pac = Literal["none", "native", "quickjs", "auto"]

class Route:
    """Where a request to one URL goes: ``kind``, the one field that kind carries, and the
    engine that answered it. Compares and hashes by value.

    ``steps`` holds "direct" or proxy URLs with their credentials, so do not log it.
    ``repr()`` shows a step's password as ``***``.
    """

    kind: Literal["steps", "pac", "pac-inline", "wpad"]
    steps: Optional[list[str]]
    pac_url: Optional[str]
    script: Optional[str]
    engine: Literal["none", "native", "quickjs"]
    """Who answered: "native" the OS's PAC engine, "quickjs" QuickJS in this process, "none"
    no PAC engine. Two engines can answer one script differently."""

class PacPolicy:
    """What QuickJS runs a script under; each argument left out keeps its default.

    The defaults answer a script that asks where it runs as if off every network --
    ``myIpAddress()`` is 127.0.0.1, ``dnsResolve`` answers None, local time is UTC -- so a
    script that chooses a proxy by network goes direct unless these say where the machine is.

    ``timeout`` is in seconds, above 0 and up to 60 (default 5); ``utc_offset_seconds`` is
    east of UTC, within a day. A value out of range raises ``ProxyWatchError`` with
    ``ERR_INVALID_ARG_VALUE``. The OS's engine takes none of these. Two policies compare equal
    when every setting is; a policy is not hashable.
    """

    __hash__: ClassVar[None] = None  # type: ignore[assignment]

    def __init__(
        self,
        *,
        my_ip_address: Optional[str] = None,
        resolve_dns: Optional[bool] = None,
        allow_internal_addresses: Optional[bool] = None,
        utc_offset_seconds: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> None: ...

class Diagnostics:
    """Where a snapshot's answer came from, without the proxy addresses or credentials.
    Compares and hashes by value."""

    os_readable: bool
    sources: list[str]
    fallbacks: list[str]
    rejected: list[str]

class Snapshot:
    """One reading of the proxy configuration."""

    def route(
        self,
        url: str,
        *,
        pac: Pac = "none",
        script: Optional[str] = None,
        wpad: bool = False,
        policy: Optional[PacPolicy] = None,
    ) -> Route:
        """Where a request to ``url`` goes.

        ``pac`` names who runs a PAC configuration. "none" (the default): nobody, and the
        route is "pac", "pac-inline" or "wpad". "native": the OS's engine -- WinHTTP,
        CFNetwork, Android's PAC service -- with real DNS; it downloads a PAC URL, runs a body
        only on macOS and iOS, and runs WPAD only with ``wpad`` on Windows, macOS and iOS.
        "quickjs": QuickJS in this process under ``policy``, for a body -- the configuration's
        own or ``script``; built for x86-64 and AArch64 Windows, Linux and macOS and for ARMv7
        Linux with glibc, ``ERR_PAC_ENGINE_UNAVAILABLE`` elsewhere. "auto": the OS's engine
        where it has one for the mode, else QuickJS, else the caller's route; chosen before
        anything runs, so an engine's failure is raised, not retried on the other.

        ``script`` is a PAC body the caller fetched, up to 1 MiB, run in place of the
        configuration's; one no engine here can run raises ``ERR_PAC_ENGINE_UNAVAILABLE``.
        ``wpad`` lets the OS discover a script (Windows, macOS, iOS); WinHTTP remembers a miss
        for the life of the process, answering direct until it restarts. ``script`` with
        "none", and ``wpad`` with "none" or "quickjs", raise ``ERR_INVALID_ARG_VALUE``.

        The GIL is released while an engine runs. QuickJS's ``Date`` can read ``TZ`` through
        the C library then, which an ``os.environ`` write from another thread can race on a C
        library older than glibc 2.41.
        """

    def diagnostics(self) -> Diagnostics:
        """Which sources the snapshot came from."""

    def to_dict(self) -> dict[str, Any]:
        """The whole configuration as plain dicts and lists::

            {"mode": <mode>, "sources": [{"source": str, "mode": <mode>}, ...],
             "fallbacks": [str], "rejected": [str], "os_readable": bool}

        <mode> is {"kind": "direct"}, {"kind": "wpad"}, {"kind": "pac", "url", "rejected"},
        {"kind": "pac-inline", "script", "rejected"}, or {"kind": "manual", "proxies",
        "bypass", "rejected"}. "proxies" maps "http", "https", "ftp", "socks" or "all" to
        {"kind": "use", "scheme", "host", "port", "username", "password", "password_state"},
        {"kind": "disabled"}, or {"kind": "unusable", "rejected"}. A proxy's password is in it
        as the value; "password_state" is "Present", "Absent", "NotRead" (GNOME's stored
        password, which is not read) or "InKeychain" (macOS). "bypass" holds "patterns" (each
        rule in the form it parses back from), "implicit" ("Broad", "WinInet", "CfNetwork" or
        "Empty"), five flags and "rejected". "rejected" values are masked text. Every
        enumeration is open: a later release can add a value.
        """

class Watcher:
    """A running watch. Use it as a context manager, or call ``close()``."""

    def current(self) -> Snapshot:
        """The latest configuration, layered with the environment captured at the start. In a
        child of ``fork`` it raises with ``code`` ``ERR_FORKED``."""

    def close(self) -> None:
        """Stop watching and wait for the watch thread. Safe to call more than once, and from
        ``on_change``."""

    def __enter__(self) -> "Watcher": ...
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None: ...

def read(
    *, env: Optional[Mapping[str, str]] = None, precedence: Optional[Precedence] = None
) -> Snapshot:
    """Read the OS settings and the environment once.

    ``env`` is the mapping to read ``*_proxy`` from, ``os.environ`` when omitted.
    ``precedence`` is "before-system" (the default), "after-system" or "ignore".
    """

def watch(
    on_change: Callable[[Optional[ProxyWatchError], Optional[Snapshot]], object],
    *,
    env: Optional[Mapping[str, str]] = None,
    precedence: Optional[Precedence] = None,
    poll_interval: Optional[float] = None,
) -> Watcher:
    """Watch the OS settings, calling ``on_change(err, snapshot)`` after each change on a
    thread of the watcher's own. A watch that stops on its own calls it a last time with
    ``ERR_PROXY_WATCH``.

    ``env`` and ``precedence`` are as for ``read()``, captured once. ``poll_interval``
    (seconds) also re-reads on that interval; it is required where the OS gives no change
    notification (a Flatpak or Snap sandbox, iOS, Android below API 26 or where in-memory
    code loading is refused, or a Linux session without a D-Bus session bus). Anything under
    0.2, zero included, is raised to 0.2; ``None`` turns the timer off. A negative, infinite
    or NaN value raises ``ValueError``, and an ``on_change`` that is not callable
    ``TypeError``. ``on_change`` can run before this returns.
    """
