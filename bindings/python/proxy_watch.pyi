from types import TracebackType
from typing import Callable, Literal, Mapping, Optional, Type

Precedence = Literal["before-system", "after-system", "ignore"]

class ProxyWatchError(Exception):
    # An ``ERR_*`` code: ``ERR_CGI_HTTP_PROXY`` from ``read``/``watch`` when ``env`` is a CGI
    # request's (a non-empty ``REQUEST_METHOD``) holding ``http_proxy``, unless
    # ``precedence="ignore"``, which does not layer it -- though on Linux a KDE setting
    # that names environment variables (``ProxyType=4``) still reads the process's own;
    # ``ERR_PROXY_ENTRY_UNUSABLE`` from ``route`` when the entry for the URL's scheme was
    # dropped, so the request goes nowhere rather than direct.
    code: str

Pac = Literal["none", "native", "quickjs", "auto"]

class Route:
    kind: Literal["steps", "pac", "pac-inline", "wpad"]
    steps: Optional[list[str]]
    pac_url: Optional[str]
    script: Optional[str]
    # Who answered: "native" the OS's PAC engine, "quickjs" QuickJS in this process, "none"
    # no PAC engine. Two engines can answer one script differently.
    engine: Literal["none", "native", "quickjs"]

class PacPolicy:
    # What QuickJS runs a script under; each argument left out keeps its default. The
    # defaults answer a script that asks where it runs as if off every network --
    # ``myIpAddress()`` is 127.0.0.1, ``dnsResolve`` answers None, local time is UTC -- so a
    # script that chooses a proxy by network goes direct unless these say where the machine
    # is. ``timeout`` is in seconds, above 0 and up to 60 (default 5);
    # ``utc_offset_seconds`` is east of UTC, within a day. A value out of range raises
    # ``ProxyWatchError`` with ``ERR_INVALID_ARG_VALUE``. The OS's engine takes none of
    # these.
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
    os_readable: bool
    sources: list[str]
    fallbacks: list[str]
    rejected: list[str]

class Snapshot:
    # ``pac`` names who runs a PAC configuration. "none" (the default): nobody, and the
    # route is "pac", "pac-inline" or "wpad". "native": the OS's engine -- WinHTTP,
    # CFNetwork, Android's PAC service -- with real DNS; it downloads a PAC URL, runs a body
    # only on macOS and iOS, and runs WPAD only with ``wpad`` on Windows, macOS and iOS.
    # "quickjs": QuickJS in this process under ``policy``, for a body -- the
    # configuration's own or ``script``; built for x86-64 and AArch64 Windows, Linux and
    # macOS, ``ERR_PAC_ENGINE_UNAVAILABLE`` elsewhere. "auto": the OS's engine where it has
    # one for the mode, else QuickJS, else the caller's route; chosen before anything runs,
    # so an engine's failure is raised, not retried on the other.
    #
    # ``script`` is a PAC body the caller fetched, up to 1 MiB, run in place of the
    # configuration's; one no engine here can run raises ``ERR_PAC_ENGINE_UNAVAILABLE``.
    # ``wpad`` lets the OS discover a script (Windows, macOS, iOS); WinHTTP remembers a
    # miss for the life of the process, answering direct until it restarts. ``script``
    # with "none", and ``wpad`` with "none" or "quickjs", raise ``ERR_INVALID_ARG_VALUE``.
    #
    # The GIL is released while an engine runs. QuickJS's ``Date`` can read ``TZ`` through
    # the C library then, which an ``os.environ`` write from another thread can race on a
    # C library older than glibc 2.41.
    def route(
        self,
        url: str,
        *,
        pac: Pac = "none",
        script: Optional[str] = None,
        wpad: bool = False,
        policy: Optional[PacPolicy] = None,
    ) -> Route: ...
    def diagnostics(self) -> Diagnostics: ...

class Watcher:
    def current(self) -> Snapshot: ...
    def close(self) -> None: ...
    def __enter__(self) -> "Watcher": ...
    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None: ...

def read(
    *, env: Optional[Mapping[str, str]] = None, precedence: Optional[Precedence] = None
) -> Snapshot: ...
def watch(
    on_change: Callable[[Optional[ProxyWatchError], Optional[Snapshot]], object],
    *,
    env: Optional[Mapping[str, str]] = None,
    precedence: Optional[Precedence] = None,
    poll_interval: Optional[float] = None,
) -> Watcher: ...
