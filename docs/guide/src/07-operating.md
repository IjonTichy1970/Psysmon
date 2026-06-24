# Operating PSYSMON

This chapter covers day-to-day operation once PSYSMON is installed and a config is in
place: how to run it, how to read what it tells you, how to reload or restart it safely,
what survives a restart, and how to acknowledge or annotate alerts at runtime without
touching the config file.

If you haven't installed it yet, start with [Installation](03-installation.md) (including
the systemd service unit) and [Configuration](04-configuration.md). For the full flag
list see [Appendix A](90-appendices.md); for the meaning of each status code see
[Status codes](08-status-codes.md).

## Running it

PSYSMON runs as a long-lived daemon. ICMP ping needs a raw socket, so it must run **as
root** on Linux (via `sudo` or a service manager); the non-ping checks
(TCP/UDP/SMTP/POP3/DNS/HTTP) work without it.

### Foreground (`--no-fork`)

For a first test, or any time you want to watch it work, run it attached to your terminal:

```bash
sudo psysmon -f /etc/psysmon.conf --no-fork
```

`--no-fork` (also `-d`) keeps the process in the foreground and sends log output to
**stderr** instead of syslog. This is the way to validate a config — a parse error prints
and the daemon exits — and to watch checks happen live. Add `--no-notify` (`-n`) to
suppress email while you experiment. `Ctrl-C` stops it (a clean SIGINT — see *Stopping*
below).

This is also the form to run under a service manager that supervises the process itself
(see *systemd*, below).

### Backgrounded (daemonized)

For normal standalone use, run without `--no-fork`:

```bash
sudo psysmon -f /etc/psysmon.conf
```

It detaches from the terminal and logs to **syslog** — the `daemon` facility by default.
Change the facility with `--syslog-facility <fac>`, or turn syslog off entirely with
`config logging none`. After it backgrounds, your terminal goes quiet; the logs are in
syslog (`journalctl` or `/var/log/...`), not on screen. If you need to see output
directly, run it foreground instead.

### Under systemd

The recommended production setup is a systemd unit running PSYSMON with `--no-fork`, so
systemd supervises the process directly and journald captures the logs. PSYSMON doesn't
ship a unit file — [Installation](03-installation.md) has a complete, working
`psysmon.service` to copy. The key lines are:

```ini
ExecStart=/usr/local/bin/psysmon -f /etc/psysmon.conf --no-fork
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
User=root
```

With that in place, the everyday commands are:

```bash
sudo systemctl enable --now psysmon    # start now and on boot
sudo systemctl status psysmon          # is it running?
sudo systemctl reload psysmon          # re-read the config (SIGHUP) — no downtime
sudo systemctl restart psysmon         # full restart (see "Reload vs restart")
sudo systemctl stop psysmon            # graceful stop
journalctl -u psysmon -f               # follow the logs
```

## Reading the status output

PSYSMON publishes a **status file** — HTML or flat text, selected by `config statusfile`
(the directive sets both the path and the format) or by `--status-file <path>` plus
`--status-format <html|text>`. Point a browser or web server at the path you configured.
HTML is the default format.

By default the view is **down-only** — the "Bad Hosts" page. Hosts that are up don't
appear, and children suppressed behind a down parent are omitted (so a router outage
doesn't fill the page with everything behind it). Pass `--show-up` to list up hosts too.
The HTML page auto-refreshes on an interval (`--status-refresh`, default 30s).

If any objects carry a `group` label (set in the modern config — see
[Configuration → Group scopes](04-configuration.md#group-scopes)), the page lists them under
per-group headings, with
an "Ungrouped" bucket for the rest; the JSON view (below) carries a `group` field per host
so a dashboard can filter on it. With no groups in use the page renders flat.

### The columns

Both the HTML table and the text table use the same eight columns (carried over from the
original sysmon):

| Column | Meaning |
| --- | --- |
| **HostName** | The monitored object's hostname. An `ACK` badge appears here when the outage has been acknowledged, and any operator note is shown beneath it. |
| **Type** | The check type — `ping`, `tcp`, `smtp`, `pop3`, `dns`, `http`, etc. |
| **Port** | The port checked (shown as `—` when not applicable, e.g. for ping). |
| **Count** | Consecutive-failure count for this object. |
| **Notified** | `Yes` once an alert has been sent for the current outage, `No` otherwise. |
| **Status** | The current status code (e.g. `up`, `Conn Ref`, `Host Down`, `Degraded`). See [Status codes](08-status-codes.md). |
| **Time Failed** | Wall-clock time the object went down (its "death time"); `Never` if it has never been seen down. |
| **Last Outage** | Elapsed time since the object was last seen up, or `Never` if it has never been up. |

The **Status** cell is colour-coded on the HTML page: green for up, red for down, and a
distinct yellow badge for **Degraded** — a partial-packet-loss ping result (reachable but
lossy), a PSYSMON-only status that does *not* suppress the objects behind it. See
[Status codes](08-status-codes.md) for `Degraded` and the rest.

### The ACK badge and notes

When you acknowledge an outage (see *Acknowledging and annotating*, below), the object
still shows as down but gains an **`ACK`** badge next to its hostname — paging is
suppressed while it stays down, but the status code is unchanged. An operator **note**, if
set, appears as italic text under the hostname (HTML) or after the row (text). Both are
HTML-escaped on the page.

### The JSON view

PSYSMON also exposes a **JSON view** of every monitored object. It is **not** written as a
file next to the status page — it is served live by the optional **control channel**
(`psysmonctl status`, see *Acknowledging and annotating*, below), which returns the same
sanitized JSON. Unlike the HTML page, the JSON lists **every** monitored object (up, down,
and suppressed) so the blast radius of an outage is queryable. The top level is:

```
{
  "generated": <unix time>,
  "down":  <count of down, non-suppressed hosts>,
  "total": <total monitored objects>,
  "hosts": [ ... ]
}
```

Each entry in `hosts` carries:

| Field | Meaning |
| --- | --- |
| `hostname`, `type`, `port`, `label`, `contact` | The object's identity and configured contact. |
| `group` | Operator group label, or `null` when unset. |
| `up` | `true` if the last check was a healthy "up" result. |
| `degraded` | `true` for a partial-loss ping (reachable but lossy). |
| `status` | The numeric status code. |
| `status_text` | The human-readable status string (the same text the page shows). |
| `count` | Consecutive-failure count. |
| `notified` | Whether an alert has been sent for the current outage. |
| `acked` | `true` if the outage is operator-acknowledged. |
| `note` | The operator note, or `null` when unset. |
| `suppressed` | `true` if the object is suppressed behind a down parent. |
| `deathtime` | When it went down (or `null`). |
| `last_up` | When it was last seen up (or `null`). |

The status file is published **atomically** — written to an unguessable temp file and
renamed into place — so a reader, dashboard, or web server never sees a half-written file.

## Logging

When backgrounded, PSYSMON logs to syslog (`daemon` facility by default); under systemd
with `--no-fork`, journald captures stderr. Verbosity is set with `config loglevel` or
`--log-level <warning|info|debug>` (or the shorthand `-v` = info, `-vv` = debug; an
explicit `--log-level` wins over `-v`). The default is **info**.

| Level | What it logs |
| --- | --- |
| `warning` | Problems only. |
| `info` (default) | Host down / recovery transitions and pages; a periodic heartbeat (`monitoring N hosts - U up, D down, S suppressed`); periodic DNS-cache stats (`dnscache periodic - … hits … misses … expired`); and slow-check durations (`Check of <host> of <type> ran for N seconds`). |
| `debug` | Everything in `info`, plus a per-check result line. |

Three of those have their own knobs:

- **Heartbeat** interval — `config heartbeat <sec>` / `--heartbeat`, default 300s; `0`
  disables it.
- **DNS-stats** interval — `config dnslog <sec>` / `--dnslog`.
- **Slow-check** threshold — `--slow-check <sec>`, default 30s; `0` disables the
  slow-check log line.

If you backgrounded the daemon and see no logs, they're in syslog — not your terminal.
Check `journalctl` / `/var/log`, or re-run with `--no-fork` to log to stderr. See
[Troubleshooting](09-troubleshooting.md).

## Reload vs restart

PSYSMON reloads its config on **SIGHUP** with no downtime:

```bash
sudo systemctl reload psysmon     # or: sudo kill -HUP <pid>
```

A reload re-reads the config file and re-applies the **monitored tree** (objects,
dependency nesting, contacts). Live up/down state is preserved for hosts that still exist
after the reload, so a SIGHUP doesn't re-page known outages or forget what's already down.
(An in-flight check that completes after the reload is discarded rather than applied to the
just-replaced state, so a reload never causes a duplicate page or a lost transition.)
Operator acks and notes also survive a reload.

Some changes need a **full restart** (`systemctl restart`) to take effect:

- **Global runtime settings** — anything in the `Settings` layer, such as the source IP,
  status path/format, SMTP settings, intervals, thresholds, and the logging knobs
  (`loglevel` / `heartbeat` / `dnslog`) and the control-channel options. These are read at
  startup and merged from CLI over config over defaults; a reload re-applies the
  *monitored tree*, not the daemon-level settings, so apply these with a restart.
- **A brand-new raw-ping bind source.** Raw ping sockets are opened at startup while the
  process is privileged, keyed by source address (see the per-object/group `source`
  in [Configuration](04-configuration.md)). If a SIGHUP reload introduces a *new* `source`
  address that wasn't bound at startup, ping for that target falls back to **unbound**
  (routing by destination), and the fallback is logged. To actually bind ping to a new
  source you must **restart** so the socket can be opened. (Ping is unbound by default
  regardless of the global `source_ip`; only an explicit per-object/group `source` binds
  it.)

When in doubt, a restart applies everything — at the cost of re-running each object's first
check. With state persistence enabled (below), a restart still won't re-page outages you
already know about.

## Stopping

A graceful stop is **SIGTERM** (or SIGINT / `Ctrl-C` in the foreground):

```bash
sudo systemctl stop psysmon     # or: sudo kill -TERM <pid>
```

On a graceful stop the daemon drains in-flight checks, writes a final status snapshot, and
(if state persistence is enabled) flushes the saved state so the next start picks up where
it left off.

## State persistence across restarts and upgrades

By default, PSYSMON starts with a clean slate each time it launches — which means a restart
or an upgrade would re-discover existing outages and page you again for hosts you already
know are down. Enable **savestate** to avoid that:

```
config savestate "/var/lib/psysmon/state.json"
```

(or `--state-file <path>`; off when unset). With it enabled:

- The state file is written atomically on a periodic flush
  (`--state-save-interval`, default 60s; `0` saves only on a graceful shutdown) and again
  on a clean stop.
- On startup the saved state is merged back in by `(hostname, type, port)`. An object that
  was **down and already paged stays that way without re-paging**; its re-page timer
  restarts fresh.
- Operator **acks and notes** are carried with the saved state, so they survive a restart
  too.
- A missing, unreadable, wrong-schema, or **stale** state file (older than
  `--state-max-age`, default 24h; `0` disables the age check) is ignored with a log line,
  and the daemon starts clean.

This is what makes the upgrade procedure below safe: with savestate on, an upgrade restart
doesn't flood you with re-pages for outages already in progress.

## Acknowledging and annotating alerts at runtime {#control-channel}

You can acknowledge an outage or attach an operator note **without editing the config**,
via the opt-in **control channel** and the bundled `psysmonctl` client. This is the runtime
equivalent of "I've seen it, stop paging me" and "here's the ticket number," and it's the
recommended way to manage an active incident.

The channel is **off by default**. When enabled it binds **`127.0.0.1:2026`** (loopback
only) and refuses to start on a non-loopback address without TLS. Mutating actions (`ack`,
`note`, `reload`) require a **bearer token**; reads (`status`, `version`) don't. Generate
the token once with `psysmon-token`, then enable the channel:

```bash
psysmon-token /etc/psysmon/control.token
sudo psysmon -f /etc/psysmon.conf \
     --control --control-token-file /etc/psysmon/control.token
```

Then drive it with `psysmonctl`:

```bash
psysmonctl status                                    # sanitized status (JSON) — no token
psysmonctl ack  router.example.net ping              # silence paging while down (needs token)
psysmonctl note web.example.net https 443 "vendor ticket 4711"
psysmonctl note web.example.net https 443 ""         # empty text clears the note
psysmonctl reload                                    # same as SIGHUP
```

- **`ack`** suppresses paging while the object stays down — both the initial page and the
  periodic re-pages — and **auto-clears when the object recovers**, so a *future* outage
  pages normally. It does not change the status code; the object still shows DOWN, with the
  `ACK` badge on the status page.
- **`note`** attaches operator free-text, shown next to the object on the status page
  (escaped) and in the JSON. It persists until cleared.

Both are live state and survive a SIGHUP reload and a restart (carried with the saved
state). Objects are addressed by **hostname + type [+ port]**; the port defaults to `0`
(ping). `psysmonctl reload` is exactly equivalent to a SIGHUP.

For the full setup — config directives, the `0600` token-file permission requirement,
exposing the channel beyond localhost with TLS, and the security model — see
[the control channel reference](docs/control-channel.md) and the
[security notes](10-glossary-security.md).

## Upgrading

To upgrade an installed PSYSMON:

```bash
/opt/psysmon-venv/bin/pip install --upgrade ./psysmon-<new-version>-py3-none-any.whl
sudo systemctl restart psysmon
```

With **savestate** enabled (above), the restart preserves in-progress outage state, so the
upgrade won't re-page hosts that were already down. If you run from source or a different
install layout, adjust the `pip` path accordingly — see [Installation](03-installation.md)
and [Getting it](02-getting-it.md). Always confirm the running version afterward:

```bash
psysmon --version
```

The version also appears in the status-page footer, so you can verify a remote instance
upgraded by reloading its status page.
