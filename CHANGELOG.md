# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project scaffold: package layout, packaging (`pyproject.toml`), CI, and the
  monitoring-engine architecture (config parser, async scheduler, checks, notifier, output).
- README describing the rewrite, its dependency-aware monitoring model, and how it differs
  from the original C `sysmon`.
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

[Unreleased]: https://github.com/IjonTichy1970/Psysmon/commits/main
