# Glossary & security notes

This chapter collects the vocabulary used throughout the guide, then sets out the security
posture an operator needs to understand before deploying PSYSMON: running as root for raw ICMP,
how the control channel is locked down, and where cleartext credentials live. For the operational
side of running the daemon, see [Operating PSYSMON](07-operating.md); for the meaning of each
status code, see [Status codes](08-status-codes.md).

## Glossary

**Object**
: A single monitored thing — a host or a service on a host. Every object has an identity of
**hostname + check type [+ port]** (e.g. `web.example.net` / `https` / `443`). That identity is
how an object is addressed everywhere: on the status page, in the JSON, in the saved state file,
and in `psysmonctl ack` / `note` commands. A bare host being pinged uses port `0`.

**dep**
: A *dependency edge* in the modern `object{}` config — a named link from a child object to the
parent it sits behind. In the legacy config the same relationship is expressed by `{ }` nesting.
A `dep` is the mechanism that drives dependency suppression (below). Each object currently has at
most a **single** `dep` edge (one parent). Named multi-parent dependencies (an object behind two
upstreams) are *planned* and tracked as issue #62; they are not yet implemented. See
[Configuration](04-configuration.md).

**Dependency suppression**
: Monitored objects form a tree. A child is only checked while its parent (a ping target,
typically the upstream router) is reachable. When the parent goes down you get **one** alert for
the parent instead of a storm for everything behind it; the children freeze in place and are
shown as *suppressed*. Suppression keys on **reachability**, not strict up-ness: a parent that is
fully down (e.g. `Unpingable`) suppresses its subtree, but a `Degraded` (lossy but answering)
parent does **not** — a router that still forwards packets shouldn't mask real outages behind it.

**root**
: The top of the monitoring tree in a modern config — the single object (or objects) that have no
parent. Everything else hangs off a `root` via `dep` edges. See
[Configuration](04-configuration.md).

**group**
: An optional label attached to an object (the modern config's `group "NAME"` attribute, or a
`group "NAME" { … }` scope block that applies a default to everything inside it). Groups drive the
status views: the HTML "Bad Hosts" page lists objects under per-group headings (with an
"Ungrouped" bucket), and the JSON carries a `group` field per host for dashboards to filter on.
Groups are presentational; they do **not** affect dependency suppression.

**reachable vs up**
: Two different bars. *Up* means a check fully succeeded (status `up`). *Reachable* means the host
answered well enough to forward traffic to its dependents — which includes both `up` **and**
`Degraded`. Dependency suppression uses *reachable*; the status page and "did the service pass"
logic use *up*. A `Degraded` host is reachable but not up.

**Degraded**
: A PSYSMON-only status (added in #22) with no equivalent in the original sysmon. It comes only
from a **loss-tolerant ping**: the host replied to some echoes but fewer than the required
`min_pings`, so it is reachable but lossy. `Degraded` is **not** counted as up, does **not**
suppress the objects behind it, and is **informational by default** (it does not page unless you
set `page_on_degraded` / `--page-on-degraded`). See [Status codes](08-status-codes.md).

**Loss-tolerant ping**
: A ping check that sends `send_pings` echoes and requires `min_pings` replies to count the host
up. Some-but-fewer replies report `Degraded`; zero replies report `Unpingable`. The defaults
(`send_pings 1` / `min_pings 1`) reproduce the historical first-reply-wins behavior, so nothing
changes unless you raise them. See [Configuration](04-configuration.md) and the
[feature tour](06-feature-tour.md).

**Status code**
: The result of a single check — `up` plus a set of distinct failure reasons (`Conn Ref`,
`Net Unrch`, `Host Down`, `Unpingable`, `Bad Auth`, `Degraded`, and more). Codes and their display
strings are defined in code and rendered into the table in [Status codes](08-status-codes.md);
don't memorize them from here.

**Gate**
: Informal term for the suppression relationship — a ping parent "gates" its dependents. While the
gate is closed (parent unreachable), the children behind it are not checked. This is why getting
ping targets right matters: a forged or false-positive "up" on a gate would silence its whole
subtree (the kind of bug closed in #29 and #53).

**Re-page interval**
: How often the daemon re-alerts about an object that is *still* down, after the initial page.
Controlled by `config pageinterval` / `--pageinterval` (minutes). You are paged once when an
object crosses its failure threshold, re-paged on this interval while it stays down, and notified
again on recovery (subject to `contact_on`). See [Operating PSYSMON](07-operating.md).

**Notifier**
: The component that delivers alerts. Email (SMTP) ships out of the box; the notifier is a
pluggable interface so webhook/SMS/chat transports can be added. Notifications can be disabled
globally with `-n` / `--no-notify`.

**source (auto)**
: The outbound bind address for an object's probes, set per object (`source "203.0.113.5";`) or for
a whole group (introduced in #70). Precedence is **per-object > group default > global
`config source_ip`**. `source auto` forces the target to stay **unbound** (the kernel picks the
route) even when a group default or `source_ip` would otherwise bind it — useful for hosts reached
over a VPN or a dynamic interface. Note: **ping is unbound by default** and ignores the global
`source_ip`; only an explicit per-object/group `source` binds ping. Connection checks
(tcp/udp/smtp/pop3/dns) default to `source_ip`. The `source` value is **IPv4-only**, and HTTP/HTTPS
checks are always unbound. See [Configuration](04-configuration.md).

**savestate**
: Optional on-disk persistence of live monitoring state, so a restart or upgrade doesn't forget
what was already down and re-page known outages. Enabled with `config savestate "<path>"` or
`--state-file <path>` (off when unset). The file is written atomically, merged back in on startup
by `(hostname, type, port)`, and a missing/unreadable/stale file is ignored with a log line.
Operator `ack` flags and `note` text ride along in this state. See
[Operating PSYSMON](07-operating.md).

## Security notes

These are operator-facing notes. The control channel's full design lives in
[docs/control-channel.md](control-channel.md); this section is what you need to deploy safely.

### Running as root

Raw ICMP ping requires a raw socket, which on Linux requires elevated privilege. PSYSMON is
therefore started **as root** (there is no setuid binary). It opens the raw ICMP socket(s) while
privileged at startup and then **keeps root for the process lifetime** — it does *not* currently
drop to an unprivileged user. A privilege-drop helper exists in the code (it would drop to an
unprivileged uid/gid such as `nobody`/`nogroup` while keeping the already-open socket descriptors),
but it is **not wired in** today; tightening the run-as-root posture is tracked as security issue
#2.

A few practical consequences:

- **Linux + root (or `CAP_NET_RAW`).** Opening the raw ICMP socket needs root or the `CAP_NET_RAW`
  capability on Linux; the non-ping checks need neither. Privilege handling is POSIX-oriented.
- **New ping sources need a restart.** Because raw sockets are opened at startup while privileged,
  a brand-new `source` address introduced by a later `SIGHUP` reload can't open a fresh socket — it
  falls back to unbound (and logs that) until you restart the daemon.
- **Narrowing the posture** — dropping privilege after the sockets open, or running with only
  `CAP_NET_RAW` instead of full root — is tracked as security issue #2; today the daemon runs as
  root throughout.

### The control / query channel

The control channel is an **opt-in** TCP service for querying live status and performing runtime
actions (acknowledge an alert, attach a note, trigger a reload) without editing the config. It is a
deliberate, security-first replacement for sysmon 0.93's always-on cleartext protocol. Its model,
at an operator level:

- **Off by default.** Nothing listens unless you enable it with `config control` / `--control`.
- **Loopback by default.** When enabled it binds `127.0.0.1:2026`. It **refuses to start on a
  non-loopback address unless TLS is configured** (`control_tls_cert` + `control_tls_key`), so you
  cannot accidentally expose a plaintext control channel — a missing/broken cert means the daemon
  declines to start rather than listening in the clear.
- **Reads are token-free; mutations are token-gated.** `status` and `version` need no token.
  `ack`, `note`, and `reload` require a **bearer token** compared in constant time. With **no token
  file configured the channel still serves reads but all mutations are disabled** (fail closed).
- **Sanitized output.** `status` returns the same sanitized output as the status page — **stored
  credentials are never exposed**, and there is no raw-config or secret dump (the 0.93 mistake).
- **No remote kill.** There is deliberately no remote shutdown/kill command. The channel is also
  bounded (max request size, read/write deadlines, a concurrent-connection cap) so it can't starve
  the monitoring loop, and errors return a fixed short code on the wire with detail only in the
  daemon log.

For confidentiality beyond loopback, TLS provides the transport security and the bearer token
provides authentication; client certificates / mTLS are out of scope for now. See the
[CLI reference](05-cli-reference.md) and [docs/control-channel.md](control-channel.md).

### The control token file

Generate the token with the bundled `psysmon-token` command — the daemon never auto-creates it:

```bash
psysmon-token /etc/psysmon/control.token          # writes a random token, mode 0600
psysmon-token /etc/psysmon/control.token --force  # rotate (overwrite) an existing one
```

Point `--control-token-file` / `config control_token_file` at that file. **The token file must be
`0600`** — the daemon refuses a group- or world-readable token file on POSIX. The same file is
read by `psysmonctl` (via `--token-file`) when you run a mutating command, so it needs to be
readable by the operator account that drives the client, and by no one else.

### Cleartext credentials in config files

The POP3 service check authenticates with a username and password, and those credentials are
stored **in cleartext in the config file** (the modern config's `username` / `password`
attributes). There is no secret store or encryption-at-rest today.

Practical guidance:

- **Treat the config file as a secret.** Restrict its permissions (e.g. owned by the root account
  that starts the daemon, not group/world-readable) so the stored POP3 credentials aren't exposed
  to other local users.
- Prefer a dedicated, low-privilege mailbox account for monitoring rather than a credential that
  grants access to anything sensitive.
- Note that the **status output never exposes these credentials** — neither the status page nor the
  control channel's `status` reply includes them. The exposure surface is the config file on disk,
  not the wire. The fact that these credentials live in the config in cleartext is tracked as
  issue #2.

### State file permissions

If you enable `savestate`, the state file records each object's up/down state plus operator `ack`
flags and `note` text. It does not contain credentials, but it does reveal your monitoring topology
and current outage state. Put it somewhere only the daemon account can read and write (e.g. under a
dedicated `/var/lib/psysmon/` directory), and don't place it in a world-writable directory — the
daemon hardens against a symlink race on the *status* file (#28), but you should still own the
directories holding both the state file and the control token.

### What was removed from the original

For completeness: this rewrite removes two long-standing exposures from the original line — the
phone-home heartbeat, and the always-on cleartext control protocol that sent stored
passwords/SNMP communities over the network and exposed an unauthenticated remote `KILLIT`. The
modern control channel above is the clean-break replacement. See
[Introduction](01-introduction.md) and [docs/control-channel.md](control-channel.md) for the
history.
