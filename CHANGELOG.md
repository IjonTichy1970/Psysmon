# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Optional on-disk persistence of live monitoring state, so a restart or software upgrade no
  longer forgets what was already down and re-pages outages the operator already knows about.
  Enable it with `config savestate "<path>"` or `--state-file <path>` (off when unset); the file
  is written atomically on a periodic flush (`--state-save-interval`, default 60s) and on a
  graceful stop, and merged back in on startup by `(hostname, type, port)`. A node that was DOWN
  and already paged stays that way without re-paging; the re-page timer restarts fresh. A
  missing, unreadable, wrong-schema, or stale (`--state-max-age`, default 24h) file is ignored
  with a log line and the daemon starts clean
  ([#21](https://github.com/IjonTichy1970/Psysmon/issues/21)).

### Fixed
- A POP3 server that answers the initial greeting with a non-`+OK` line (e.g. an `-ERR`
  "temporarily unavailable") is now reported as `Bad Resp` rather than `No Srvr Resp`, matching
  the SMTP check and the `USER`/`PASS` reply handling — a server that *responded* is no longer
  labelled silent. An empty/dropped greeting still reports `No Srvr Resp`
  ([#55](https://github.com/IjonTichy1970/Psysmon/issues/55)).

## [0.1.3] — 2026-06-23 — logo auto-deploy + operational logging

### Added
- The daemon now ships its status-page logo and writes it next to the HTML status file on first
  publish, so a fresh deploy renders the logo without a manual copy step. An existing
  `psysmon-logo.png` in the status directory is left untouched, so a custom logo is preserved
  ([#58](https://github.com/IjonTichy1970/Psysmon/issues/58)).
- Operational syslog logging at selectable levels of detail. Verbosity is set with
  `config loglevel <warning|info|debug>` (or `--log-level` / `-v` / `-vv`): `info` — the default —
  logs host down/recovery and pages, a periodic `monitoring N hosts - U up, D down, S suppressed`
  heartbeat, periodic DNS-cache stats (`dnscache periodic - … hits … misses … expired`), and
  slow-check durations (`Check of <host> of <type> ran for N seconds`); `debug` adds a per-check
  result line. The heartbeat interval (`config heartbeat <sec>` / `--heartbeat`, default 300,
  `0` disables), the DNS-stats interval (`config dnslog <sec>`), and the slow-check threshold
  (`--slow-check <sec>`, default 30) are all configurable
  ([#59](https://github.com/IjonTichy1970/Psysmon/issues/59)).

## [0.1.2] — 2026-06-23 — ping false-DOWN + POP3 status accuracy

### Fixed
- Ping no longer reports a healthy host as `Unpingable` when its ICMP echo reply legitimately
  arrives from a different source address than the one pinged — common for routers (which often
  source the reply from their egress interface), NAT, and asymmetric routing. Replies are now
  authenticated by a per-probe random nonce echoed in the payload instead of a strict source-IP
  match, which preserves and strengthens the previous release's anti-forgery protection while
  accepting these valid replies. Because ping targets gate their dependents, this also unblocks
  the whole monitored subtree behind such a host
  ([#53](https://github.com/IjonTichy1970/Psysmon/issues/53)).
- The POP3 check now reports a connection dropped mid-authentication as `No Srvr Resp` instead of
  the misleading `Bad Resp`, and flags a username rejected at `USER` (not only at `PASS`) as
  `Bad Auth`. A drop after a successful login is deliberately *not* reported as `Bad Auth`, since
  a correct login can also be cut short by a post-authentication server fault — so the status no
  longer points operators at credentials when auth may have succeeded
  ([#54](https://github.com/IjonTichy1970/Psysmon/issues/54)).
- `psysmon --version` and the status-page footer now report the actual release version; they had
  been pinned to the placeholder `0.1.0.dev0` because `psysmon.__version__` was not bumped along
  with the packaging version in the 0.1.0 and 0.1.1 releases.

## [0.1.1] — 2026-06-23 — audit cleanup + parser fix

### Fixed
- The legacy config parser no longer silently truncates the rest of the file on a stray
  top-level `}`; it warns and continues so trailing stanzas still parse
  ([#42](https://github.com/IjonTichy1970/Psysmon/issues/42)).

## [0.1.0] — 2026-06-23 — initial release

### Added
- Initial project scaffold: package layout, packaging (`pyproject.toml`), CI, and the
  monitoring-engine architecture (config parser, async scheduler, checks, notifier, output).
- README describing the rewrite, its dependency-aware monitoring model, and how it differs
  from the original C `sysmon`.
- `INSTALL.md` step-by-step setup guide: venv install (from a release artifact or source),
  configuration with a sample config, running in the foreground / backgrounded / under systemd,
  and operate/upgrade/uninstall notes.
- Status-code definitions and display mappings ported from the original `lib.c`.
- Core data model (`Node`, `NodeState`) ported from the original `struct hostinfo`.
- Licensed under GPL-2.0-or-later (continuing the original sysmon's GNU GPL licensing).
- Runtime settings with **CLI > config-file > defaults** precedence: a `Settings` model and
  command-line flags for the values that were hardcoded in the original (outbound source IP,
  alert/status hostname, SMTP settings, status path/format, intervals, concurrency, thresholds,
  DNS-cache timers). Unset CLI flags fall through to the config file, then to defaults.
- Legacy `sysmon.conf` parser: builds the dependency tree (`{ }` nesting), honors the
  position-dependent `config numfailures`, parses all in-scope check types, warns-and-skips
  dropped types, and surfaces `config` globals as settings overrides. DNS is resolved at run
  time, not parse time, so unresolvable hosts are no longer silently dropped. Plus config
  format auto-detection (legacy today; reserved for a future modern format).
- Per-node up/down state machine reproducing the original's failure-counting and paging
  logic: threshold-based page-once, recovery notification, error-change handling, a NO_DNS
  state that records the outage without paging, and a re-page timer — all pure and
  exhaustively unit-tested.
- Check engine foundation: a common async check contract (resolve + connect + a timeout/
  error-mapping wrapper) and an in-process DNS cache with TTL expiry, single-flight, and
  hit/miss stats. DNS is resolved at check time so transient failures self-heal.
- Service checks: TCP connect, UDP/DNS reachability, SMTP banner, POP3 authentication,
  authoritative DNS (via dnspython), and HTTP/HTTPS content (via httpx, certificate
  verification on by default).
- ICMP ping via a shared raw socket with concurrent reply demultiplexing, plus a privilege-
  drop helper so the daemon can shed root after opening the raw socket.
- Async monitoring scheduler that ties checks, the state machine, and the DNS cache into a
  concurrent per-host loop: bounded concurrency, dependency suppression (a host behind a down
  parent isn't checked and its state freezes), stale-result discarding when a parent fails
  mid-check, and threshold/recovery/re-page notification.
- Email notifier (SMTP) with a pluggable interface: renders the original PMESG-style alert
  template, sends down/recovery/re-page emails via a bounded, non-blocking SMTP send, and
  degrades safely (a missing contact or disabled notifications dedup without sending; delivery
  failures retry; malformed addresses are rejected, not crash the loop).
- Status output: a modern dark-themed HTML "Bad Hosts" page (logo header, the original
  columns, browser auto-refresh, down-only by default with suppressed hosts hidden) plus a flat
  text variant and a JSON endpoint (all nodes, with a suppressed flag). Published atomically so
  readers never see a partial file. All dynamic content is HTML-escaped.
- Runnable daemon: the `psysmon` command loads the config, builds the engine, and runs it —
  publishing the status file periodically, handling SIGTERM/SIGINT (graceful stop) and SIGHUP
  (config reload that preserves live up/down state for hosts that still exist), and backgrounding
  itself unless `--no-fork`.

### Fixed
- Ping checks no longer go silent when a target can't be resolved or has no route: a failed
  DNS resolution or send now yields a concrete status (`No DNS` / `Net Unreachable` /
  `Host Down` / `Unpingable`) instead of an unhandled error that left the host — and, because
  ping targets gate their dependents, its whole downstream subtree — unmonitored with no alert
  ([#25](https://github.com/IjonTichy1970/Psysmon/issues/25)).
- DNS and UDP/DNS checks now report a malformed or unexpected-source reply as `Bad Response`
  rather than letting it escape and produce no verdict, so a reachable-but-misbehaving server is
  still flagged ([#26](https://github.com/IjonTichy1970/Psysmon/issues/26)).
- A `SIGHUP` config reload no longer races an in-flight check: a result that completes after the
  reload is discarded instead of being applied to the just-replaced state, preventing a
  duplicate page or a lost state change ([#27](https://github.com/IjonTichy1970/Psysmon/issues/27)).
- The backgrounded daemon now keeps its logs: the configured syslog facility is wired to an
  actual syslog handler, and the standard streams are redirected to `/dev/null` on detach, so
  log output is no longer silently lost once the daemon forks
  ([#30](https://github.com/IjonTichy1970/Psysmon/issues/30),
  [#31](https://github.com/IjonTichy1970/Psysmon/issues/31)).
- The legacy config parser no longer mishandles a stray `{`: a trailing brace is split off
  before the 7-field cap and before field parsing, so an over-long stanza that opens a block no
  longer drops the brace (which detached the subtree and silently truncated the rest of the
  file), and a stray `{` on a service line is no longer stored as the contact or label
  ([#32](https://github.com/IjonTichy1970/Psysmon/issues/32),
  [#35](https://github.com/IjonTichy1970/Psysmon/issues/35)).
- A pathologically deep config now fails with a clean configuration error instead of an uncaught
  `RecursionError` at startup — `{` nesting is capped (default 64)
  ([#36](https://github.com/IjonTichy1970/Psysmon/issues/36)).
- A node whose dependency parent goes down mid-check is now marked suppressed immediately when
  its stale result is discarded, so the status page and JSON no longer show it as a stale "up"
  host for up to one interval ([#37](https://github.com/IjonTichy1970/Psysmon/issues/37)).

### Security
- The status-file writer no longer follows a symlink at a predictable temp path: the temp file
  is created with an unguessable name via `tempfile.mkstemp` (`O_CREAT | O_EXCL`, plus
  `O_NOFOLLOW` where the platform defines it) in the target directory, and the pre-rename
  `chmod` of the target is restricted to Windows. This closes a symlink race that let a local
  user with write access to a world-/group-writable status directory redirect the privileged
  writer onto an arbitrary root-owned file ([#28](https://github.com/IjonTichy1970/Psysmon/issues/28)).
- ICMP echo replies are now accepted only from the address that was actually pinged, and the
  per-probe identifier/sequence is seeded from a per-process random value. Previously any host
  emitting a reply with a matching, predictable id/sequence on the shared raw socket could forge
  a host-is-up result — masking an outage and, because ping nodes gate their dependents,
  silencing alerts for a whole subtree ([#29](https://github.com/IjonTichy1970/Psysmon/issues/29)).

[Unreleased]: https://github.com/IjonTichy1970/Psysmon/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/IjonTichy1970/Psysmon/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/IjonTichy1970/Psysmon/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/IjonTichy1970/Psysmon/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/IjonTichy1970/Psysmon/releases/tag/v0.1.0
