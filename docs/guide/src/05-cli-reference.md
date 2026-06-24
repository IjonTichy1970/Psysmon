# Command-line reference

This chapter orients you to PSYSMON's command-line interface: the console-script commands it
installs, how the daemon's flags are grouped, and — most importantly — the precedence rule that
decides which value wins when the command line and the config file disagree.

This is a map, not an inventory. The complete, alphabetised flag list (with every default) is
generated straight from `psysmon --help` into [Appendix A](90-appendices.html), so it never drifts
from the code. Reach for that when you need the exact spelling of an option; reach for this chapter
when you want to understand what the options *do* and how they layer.

## The commands

Installing PSYSMON puts four console scripts on your `PATH`:

| Command | What it is |
| --- | --- |
| `psysmon` | The monitoring daemon itself — the subject of this chapter. |
| `psysmon-convert` | Converts a legacy `sysmon.conf` to the modern `object{}` format. |
| `psysmonctl` | Client for the opt-in runtime control channel (query status, acknowledge alerts). |
| `psysmon-token` | Generates a bearer token file for the control channel. |

`psysmon-convert` can also be invoked as `python -m psysmon.config.convert`. The control-channel
tools (`psysmonctl`, `psysmon-token`) are covered with the feature itself in the
[feature tour](06-feature-tour.html) and [operating](07-operating.html) chapters; the rest of this
chapter is about the `psysmon` daemon.

Two flags short-circuit everything else:

```bash
psysmon --version      # print the version and exit
psysmon --help         # print the full flag list and exit
```

`--help` is the authoritative source for flags — Appendix A is just its rendered output.

## How the flags are grouped

Every daemon flag overrides a single runtime setting. Most of those settings were *hardcoded* in
the original C `sysmon` (the source IP, the org hostname, the mail transport, ports,
intervals, thresholds); PSYSMON lifts them into the config file and the command line. They fall
into eight logical groups.

### Files and output

Where PSYSMON reads its config and writes its status page.

- `-f` / `--config PATH` — config file path (default `/etc/psysmon.conf`).
- `--status-file PATH` — where to write the status page.
- `--status-format html|text` — status file format (HTML by default).
- `--status-refresh SECONDS` — auto-refresh interval baked into the HTML page.
- `--show-up` — list *up* hosts too; by default the page shows only down hosts ("Bad Hosts").

```bash
psysmon -f /etc/psysmon.conf --status-file /var/www/psysmon/status.html --show-up
```

### Identity and network

How PSYSMON identifies itself and sources its outbound traffic.

- `--source-ip IP` — outbound bind source for connection checks (the address your firewall ACLs
  see). This is IPv4 and applies to TCP/UDP/SMTP/POP3/DNS/HTTP checks; **ping is unbound by
  default** and ignores it. The source can also be set per object or group in the modern config
  (`source`); see [Configuration](04-configuration.html).
- `--hostname NAME` — the hostname shown in alert emails and the status-page title.

```bash
psysmon --source-ip 203.0.113.10 --hostname monitor.example.net
```

### Scheduling and thresholds

How often hosts are checked, how many checks run at once, and when a failure becomes a page.

- `--interval SEC` — default per-host check interval.
- `--max-concurrency N` — cap on concurrent checks.
- `--numfailures N` — consecutive failures before a host is reported.
- `--pageinterval MIN` — re-page interval while a host stays down (minutes).
- `--slow-check SEC` — log any check that runs at least this long (`0` disables).
- `--send-pings N` / `--min-pings M` — loss-tolerant ping: send `N` echoes, require `M` replies to
  count up. The default `1`/`1` is the historical first-reply-wins behaviour; a non-zero reply
  count below `--min-pings` reports *Degraded* (a PSYSMON-only status — see
  [Status codes](08-status-codes.html)).
- `--page-on-degraded` — page on a degraded (partial-loss) ping instead of treating it as
  informational.
- `--contact-on down|up|both|none` — which transitions page (default `both`: down *and* recovery).
  Overridable per object in the modern config.

```bash
psysmon --interval 60 --numfailures 5 --pageinterval 15 \
        --send-pings 5 --min-pings 3 --page-on-degraded
```

### Alerting (SMTP)

Where email alerts are relayed and whether they're sent at all.

- `--smtp-host HOST` (default `localhost`) and `--smtp-port PORT` (default `25`).
- `--mail-from ADDR` — the alert `From:` address.
- `-n` / `--no-notify` — disable all paging (handy while testing a new config).

```bash
psysmon --smtp-host smtp.example.net --smtp-port 25 --mail-from noc@example.net
```

### DNS cache

Tuning for the resolver cache PSYSMON keeps for monitored hostnames.

- `--dnsexpire SEC` — cache TTL (default `900`).
- `--dnslog SEC` — interval for periodic DNS-cache statistics logging (default `600`).

```bash
psysmon --dnsexpire 1800 --dnslog 300
```

### State persistence

On-disk up/down state so a restart or upgrade doesn't re-page outages you already know about.

- `--state-file PATH` — persist state here. State persistence is **off** when this is unset.
- `--state-save-interval SEC` — how often to flush the file (`0` saves only on shutdown).
- `--state-max-age SEC` — ignore a state file older than this on load (`0` disables the check;
  default `86400`).

```bash
psysmon --state-file /var/lib/psysmon/state.json --state-save-interval 60
```

The same path can be set in the config with `config savestate "<path>"`; see
[Operating](07-operating.html).

### Logging and process

Verbosity, the periodic heartbeat summary, and whether the daemon forks.

- `--syslog-facility FAC` — syslog facility (default `daemon`; `none` disables syslog).
- `--log-level warning|info|debug` — logging verbosity (default `info`).
- `-v` / `-vv` — shorthand for verbosity: `-v` sets `info`, `-vv` sets `debug`. This sets an
  *absolute* level and is overridden by an explicit `--log-level`.
- `--heartbeat SEC` — interval for the periodic "monitoring N hosts" summary (`0` disables;
  default `300`).
- `-d` / `--no-fork` — run in the foreground (logs to stderr instead of detaching). Use this for a
  first test run and when supervising under systemd.

```bash
psysmon --no-fork -vv --heartbeat 600
```

### Control channel

The opt-in JSON-over-TLS query/control channel, **off by default**. Full setup is in the
[feature tour](06-feature-tour.html).

- `--control` — enable the channel.
- `--control-bind ADDR` (default `127.0.0.1`) and `--control-port PORT` (default `2026`). A
  non-loopback bind requires TLS.
- `--control-token-file PATH` — file holding the bearer token required for mutating actions.
- `--control-tls-cert PATH` / `--control-tls-key PATH` — TLS certificate and key.

```bash
psysmon --control --control-token-file /etc/psysmon/control.token
```

## Precedence: command line > config file > built-in defaults

PSYSMON builds its effective configuration in three layers, each overriding the one before:

1. **Built-in defaults** — the values baked into the daemon (e.g. `numfailures` is `2`, the SMTP
   host is `localhost`, the check interval is `30` seconds).
2. **Config file** — any `config <directive>` lines in your `psysmon.conf` override the matching
   defaults.
3. **Command line** — any flag you pass overrides both the file and the defaults.

Only options you *explicitly set* participate. A flag you don't pass is genuinely absent — it does
not silently re-assert a default over a value your config file set. So the command line is purely
additive: it changes exactly the settings you name and leaves everything else to the file (or the
defaults).

This makes the command line the right place for deployment-specific values that you don't want to
hardcode into a shared config file — the outbound source IP, the monitor's hostname, SMTP details
— and for temporary overrides while testing.

Note that not every flag has a matching `config` directive: the legacy config file recognises a
fixed set of `config` globals (such as `statusfile`, `pageinterval`, `numfailures`, `dnsexpire`,
`dnslog`, `heartbeat`, `logging`, `loglevel`, and `savestate`). Settings without a legacy
directive — the SMTP host, the source IP, the daemon hostname — come from the command line (or the
modern config). See [Configuration](04-configuration.html) for the full directive list.

### Worked examples

**Override the page threshold for one run.** The config file sets `config numfailures 5`, but
tonight you want to be paged faster:

```bash
# psysmon.conf has:  config numfailures 5
psysmon -f /etc/psysmon.conf --numfailures 2
```

The effective threshold is `2` — the CLI wins. Drop the flag and it reverts to the file's `5`.

**Suppress alerts while validating a config.** Test a new config in the foreground with paging off,
without editing the file:

```bash
psysmon -f /etc/psysmon.conf --no-fork --no-notify
```

`--no-fork` and `--no-notify` win over whatever the file says; everything else (status path, SMTP
host, intervals) still comes from the file.

**Layer all three sources at once.** Suppose the file sets `config pageinterval 18` and nothing
about the SMTP host or the source IP:

```bash
psysmon -f /etc/psysmon.conf --pageinterval 5 --smtp-host smtp.example.net --source-ip 203.0.113.10
```

The effective settings come from all three layers: `pageinterval` is `5` minutes (CLI overrides the
file's `18`), `smtp-host` is `smtp.example.net` and `source-ip` is `203.0.113.10` (both CLI, since
the file has no directive for either), and the check interval is still the built-in `30` seconds
(no one overrode the default).

**Verbosity is order-independent, not last-wins.** `--log-level` always beats `-v`/`-vv`, no matter
which comes first on the line:

```bash
psysmon -vv --log-level warning      # effective level: warning
```

## See also

- [Configuration](04-configuration.html) — the config-file directives these flags override, and
  the per-object `source` / `contact-on` overrides.
- [Operating](07-operating.html) — running the daemon, reloading, and state persistence in
  practice.
- [Status codes](08-status-codes.html) — the meaning of `Degraded` and the other check results.
- [Appendix A](90-appendices.html) — the full, generated `--help` flag list with all defaults.
