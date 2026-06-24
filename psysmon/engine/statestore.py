"""On-disk persistence of live monitoring state across restarts/upgrades (#21).

The scheduler carries per-node runtime state (last status code, consecutive-failure count,
whether the operator was already contacted, outage timestamps) across a *SIGHUP reload* in
memory, but a full process restart — a crash, a reboot, or the case sysmon's wishlist calls
out, a software upgrade — reconstructs every node from scratch. A node that was already DOWN
and already paged then looks brand-new and re-trips its threshold, re-paging an outage the
operator already knows about, and the outage timing is lost.

:class:`StateStore` is the disk half of the round trip the original C sysmon never finished
(it shipped only a debug-only write side, no restore). It serializes the same fields the
scheduler already carries across a reload (``Scheduler._CARRIED``) to an atomically-written
JSON file, and reads them back on startup. The scheduler owns *which* fields move and *how*
they merge (by ``(hostname, type, port)`` — the same key SIGHUP uses); this module only owns
the envelope, the durable write, and the validity gating (schema version + staleness), so a
stale or unrecognized file degrades to a clean fresh start rather than a crash.

Persistence is opt-in: with no state-file path configured the daemon never touches disk and
behavior is exactly as before.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile

log = logging.getLogger("psysmon.statestore")

# Bump when the persisted record shape changes incompatibly. A file written by a different
# schema is ignored (logged) on load rather than misread — an upgrade that changes the layout
# degrades to a fresh start instead of a startup crash.
SCHEMA_VERSION = 1

# Refuse to read an implausibly large state file. A real file is a few hundred bytes per node
# (the production scope is ~1200 nodes ~= 300 KB); this cap (32 MiB) is far above any sane
# deployment but bounds memory if the file is corrupt or hostile. Over the cap -> fresh start.
_MAX_FILE_BYTES = 32 * 1024 * 1024


class StateStore:
    """Reads/writes the monitoring-state file for a configured path (opt-in persistence)."""

    def __init__(self, path: str, *, max_age_s: int = 86400) -> None:
        self._path = path
        self._max_age_s = max_age_s  # ignore a file older than this (0 disables the check)

    @property
    def path(self) -> str:
        return self._path

    def save(self, records: list[dict], *, now_wall: float) -> None:
        """Atomically write ``records`` (the scheduler's exported node state) to the file.

        Raises ``OSError`` on a write/replace failure so the caller can log it; a failed save
        never leaves a partial file (temp + ``os.replace``) nor a stray temp behind.
        """
        payload = {
            "schema_version": SCHEMA_VERSION,
            "saved_at": now_wall,
            "nodes": records,
        }
        self._atomic_write(json.dumps(payload, indent=2).encode("utf-8"))

    def load(self, *, now_wall: float) -> list[dict]:
        """Return the persisted node records, or ``[]`` if the file is absent/invalid/stale.

        Every failure mode — missing file, unreadable, malformed JSON, wrong ``schema_version``,
        or older than ``max_age_s`` — is logged and turns into an empty result (a fresh start),
        never an exception. Trusting an old up/down snapshot after a long downtime is riskier
        than re-confirming, so staleness is treated as "no state".
        """
        try:
            raw = self._read()
        except FileNotFoundError:
            return []  # first run / persistence not yet written — silent, expected
        except OSError as exc:
            log.warning("could not read state file %s (%s); starting fresh", self._path, exc)
            return []

        try:
            payload = json.loads(raw)
        except ValueError as exc:
            log.warning("state file %s is not valid JSON (%s); starting fresh", self._path, exc)
            return []
        if not isinstance(payload, dict):
            log.warning("state file %s has an unexpected shape; starting fresh", self._path)
            return []

        version = payload.get("schema_version")
        if version != SCHEMA_VERSION:
            log.warning(
                "state file %s schema_version %r != %d; ignoring it and starting fresh",
                self._path, version, SCHEMA_VERSION,
            )
            return []

        saved_at = payload.get("saved_at")
        if self._max_age_s > 0 and isinstance(saved_at, (int, float)):
            age = now_wall - saved_at
            if age > self._max_age_s:
                log.warning(
                    "state file %s is %.0fs old (> %ds max age); ignoring it as stale",
                    self._path, age, self._max_age_s,
                )
                return []

        nodes = payload.get("nodes")
        if not isinstance(nodes, list):
            log.warning("state file %s has no node list; starting fresh", self._path)
            return []
        if not all(isinstance(node, dict) for node in nodes):
            # A list whose elements aren't records is corrupt; reject the whole file rather than
            # let a non-dict entry crash the consumer (record.get(...) on an int). Per-field type
            # validation of the dicts themselves happens in Scheduler.import_state.
            log.warning("state file %s has malformed node entries; starting fresh", self._path)
            return []
        return nodes

    def _read(self) -> str:
        size = os.path.getsize(self._path)  # FileNotFoundError here -> load()'s silent fresh start
        if size > _MAX_FILE_BYTES:
            raise OSError(f"state file {self._path} is {size} bytes (> {_MAX_FILE_BYTES} max)")
        with open(self._path, encoding="utf-8") as handle:
            return handle.read()

    def _atomic_write(self, data: bytes) -> None:
        """Write ``data`` to a private temp file in the target dir, then rename it into place.

        ``mkstemp`` creates the temp ``0o600`` (the state file may carry hostnames, so it is not
        world-readable, unlike the web-served status file). ``os.replace`` is atomic on POSIX
        and Windows; on a mid-write error the temp file is removed so none is left behind.
        """
        directory = os.path.dirname(self._path) or "."
        fd, tmp = tempfile.mkstemp(
            dir=directory, prefix=os.path.basename(self._path) + ".", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, self._path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
