"""Daemon orchestration: load config, build the engine, run it, handle signals.

Ties the pieces together:
  config file -> detect format -> legacy parse -> merge settings (CLI > file > defaults)
  -> Scheduler (with SMTP notifier + periodic status publishing) -> run loop.

Signals (POSIX): SIGTERM/SIGINT stop the loop gracefully; SIGHUP reloads the config,
preserving live up/down state for hosts that still exist. Backgrounding is a minimal fork
(matching the original); per the deploy decision the process runs as root for raw-ICMP ping
rather than dropping privileges (privilege.drop_privileges remains available — see issue #2).
"""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
import signal
import sys
from pathlib import Path

from psysmon.checks.ping import PingService
from psysmon.config.detect import ConfigFormat, detect
from psysmon.config.legacy import parse as parse_legacy
from psysmon.config.model import CheckType, Node
from psysmon.config.settings import Settings, cli_overrides, merge
from psysmon.engine.scheduler import Scheduler
from psysmon.notify.email_smtp import SmtpNotifier
from psysmon.output.statuspage import render_and_publish

logger = logging.getLogger("psysmon")

# Upper bound between status publishes when nothing changes — a floor so elapsed-time displays
# stay fresh. Real state changes publish immediately (the scheduler's dirty event), so steady
# state writes the file at most this often instead of every few seconds.
RENDER_MAX_INTERVAL_S = 60.0


def load_roots(settings: Settings) -> tuple[list[Node], dict, list[str]]:
    """Read + parse the config file named by ``settings.config_path``."""
    text = Path(settings.config_path).read_text(encoding="utf-8", errors="replace")
    if detect(text) is not ConfigFormat.LEGACY:
        raise ValueError("only the legacy sysmon.conf format is supported yet (see issue #3)")
    result = parse_legacy(text, numfailures=settings.numfailures)
    return result.roots, result.overrides, result.warnings


def build(argv: list[str] | None = None) -> tuple[Scheduler, Settings]:
    """Parse CLI + config into effective settings and a ready-to-run Scheduler."""
    cli = cli_overrides(argv)
    bootstrap = merge(cli_overrides=cli)  # defaults + CLI -> config path & numfailures baseline
    roots, overrides, warnings = load_roots(bootstrap)
    for warning in warnings:
        logger.warning("config: %s", warning)
    settings = merge(overrides, cli)  # CLI > config file > defaults
    notifier = SmtpNotifier(settings) if settings.notify_enabled else None
    ping = PingService(settings.source_ip)
    scheduler = Scheduler(roots, settings, ping_service=ping, notifier=notifier)
    for warning in scheduler.warnings:
        logger.warning("schedule: %s", warning)
    return scheduler, settings


async def _render_loop(scheduler: Scheduler, settings: Settings) -> None:
    """Publish the status file on state changes (plus a periodic floor), off the event loop.

    Waits on the scheduler's dirty signal so an unchanged steady state isn't re-rendered and
    re-written every few seconds; the floor still publishes periodically so relative timestamps
    don't go stale.
    """
    while True:
        await scheduler.wait_until_dirty(RENDER_MAX_INTERVAL_S)
        if settings.status_path:
            try:
                await asyncio.to_thread(render_and_publish, scheduler.node_states(), settings)
            except Exception:
                logger.exception("status render failed")


async def _reload_loop(
    scheduler: Scheduler, settings: Settings, reload_flag: asyncio.Event
) -> None:
    """Reload the config (and preserve live state) whenever SIGHUP sets ``reload_flag``."""
    while True:
        await reload_flag.wait()
        reload_flag.clear()
        try:
            roots, _overrides, warnings = load_roots(settings)
            for warning in warnings:
                logger.warning("reload: %s", warning)
            scheduler.reload(roots)
            logger.info("configuration reloaded (%d nodes)", len(scheduler.node_states()))
        except Exception:
            logger.exception("config reload failed; keeping the current configuration")


def _install_signals(loop: asyncio.AbstractEventLoop, scheduler: Scheduler,
                     reload_flag: asyncio.Event) -> None:
    def add(sig: int, callback) -> None:
        try:
            loop.add_signal_handler(sig, callback)
        except (NotImplementedError, RuntimeError, ValueError):
            pass  # non-POSIX loop (Windows) — signals unsupported; the deploy target is Linux

    for name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is not None:
            add(sig, scheduler.stop)
    hup = getattr(signal, "SIGHUP", None)  # absent on Windows
    if hup is not None:
        add(hup, reload_flag.set)


async def serve(scheduler: Scheduler, settings: Settings) -> None:
    """Run the scheduler with periodic status publishing and signal handling until stopped."""
    loop = asyncio.get_running_loop()
    reload_flag = asyncio.Event()
    _install_signals(loop, scheduler, reload_flag)

    run_task = asyncio.create_task(scheduler.run())
    helpers = [
        asyncio.create_task(_render_loop(scheduler, settings)),
        asyncio.create_task(_reload_loop(scheduler, settings, reload_flag)),
    ]
    try:
        await run_task  # returns once scheduler.stop() is called (it drains in-flight checks)
    finally:
        for task in helpers:
            task.cancel()
        await asyncio.gather(*helpers, return_exceptions=True)
        if settings.status_path:
            try:
                render_and_publish(scheduler.node_states(), settings)  # final snapshot
            except Exception:
                logger.exception("final status render failed")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _has_ping(scheduler: Scheduler) -> bool:
    return any(node.check_type is CheckType.PING for node, _ in scheduler.node_states())


def _setup_syslog(settings: Settings) -> None:
    """Route logging to syslog using the configured facility (for the backgrounded daemon).

    In the foreground we keep logging to stderr (``logging.basicConfig`` in :func:`main`).
    But once the daemon detaches and redirects stdio to ``/dev/null`` (see :func:`_daemonize`),
    stderr logging would vanish — so when backgrounding we add a :class:`SysLogHandler` and drop
    the stderr handler. A facility of ``None`` / ``"none"`` disables syslog (matching the legacy
    ``config logging none``), in which case a backgrounded daemon simply has no log destination.
    """
    facility_name = (settings.syslog_facility or "none").lower()
    if facility_name == "none":
        return
    facility = logging.handlers.SysLogHandler.facility_names.get(facility_name)
    if facility is None:
        logger.warning("unknown syslog facility %r; logging stays on stderr",
                       settings.syslog_facility)
        return
    address = "/dev/log" if os.path.exists("/dev/log") else ("localhost", 514)
    try:
        handler = logging.handlers.SysLogHandler(address=address, facility=facility)
    except OSError as exc:
        logger.warning("could not connect to syslog (%s); logging stays on stderr", exc)
        return
    handler.setFormatter(
        logging.Formatter("psysmon[%(process)d]: %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.addHandler(handler)
    # After backgrounding, stderr is redirected to /dev/null, so the stderr handler that
    # basicConfig() installed would write nowhere — drop it now that syslog is wired up.
    for existing in list(root.handlers):
        if type(existing) is logging.StreamHandler:
            root.removeHandler(existing)


def _daemonize() -> None:
    """Detach into the background with a single fork (POSIX only; matches the original).

    After detaching there is no controlling terminal, so the standard streams are redirected
    to ``/dev/null``: anything still writing to stdout/stderr would otherwise be lost (or, on a
    full pipe, block the daemon). Configure syslog *before* calling this (see
    :func:`_setup_syslog`) so log output survives the redirect.
    """
    if not hasattr(os, "fork"):
        logger.warning("fork() unavailable here; staying in the foreground")
        return
    if os.fork() > 0:
        os._exit(0)  # parent exits; the child keeps running
    os.setsid()  # detach from the controlling terminal
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    if devnull > 2:
        os.close(devnull)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    try:
        scheduler, settings = build(argv)
    except FileNotFoundError as exc:
        print(f"psysmon: config file not found: {exc.filename}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"psysmon: {exc}", file=sys.stderr)
        return 1

    if _has_ping(scheduler):
        if _is_root():
            # Open the raw ICMP socket up front, while privileged and before we fork/loop;
            # the reply reader is attached lazily once the loop runs (see PingService).
            try:
                scheduler.ping_service.prepare()
            except OSError as exc:
                logger.warning("could not open the raw ICMP socket up front: %s", exc)
        else:
            logger.warning("not running as root: ICMP ping needs raw sockets and will fail")
    if not settings.foreground:
        # Only switch logging to syslog when we can actually detach; otherwise keep stderr so
        # _daemonize()'s "staying in the foreground" warning is still visible.
        if hasattr(os, "fork"):
            _setup_syslog(settings)  # wire syslog before stdio is sent to /dev/null
        _daemonize()
    try:
        asyncio.run(serve(scheduler, settings))
    except KeyboardInterrupt:
        pass
    return 0
