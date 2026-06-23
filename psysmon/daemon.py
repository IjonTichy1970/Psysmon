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

RENDER_INTERVAL_S = 5.0  # how often the status file is refreshed while running


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
    """Publish the status file periodically (off-thread so it never blocks the loop)."""
    while True:
        if settings.status_path:
            try:
                await asyncio.to_thread(render_and_publish, scheduler.node_states(), settings)
            except Exception:
                logger.exception("status render failed")
        await asyncio.sleep(RENDER_INTERVAL_S)


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


def _daemonize() -> None:
    """Detach into the background with a single fork (POSIX only; matches the original)."""
    if not hasattr(os, "fork"):
        logger.warning("fork() unavailable here; staying in the foreground")
        return
    if os.fork() > 0:
        os._exit(0)  # parent exits; the child keeps running
    os.setsid()  # detach from the controlling terminal


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
        _daemonize()
    try:
        asyncio.run(serve(scheduler, settings))
    except KeyboardInterrupt:
        pass
    return 0
