# PSYSMON

**PSYSMON** (Python Sysmon) is a modern reimplementation of **sysmon**, a network-monitoring
daemon that pings hosts, checks services, and alerts you when things break — with
**dependency-aware** monitoring so an upstream outage raises one alert instead of a flood.

> **Status: early development.** This is a from-scratch Python 3.11+ rewrite of the original C
> `sysmon` by **Jared Mauch** — the network monitor he developed from **1996** to its final
> release, **0.93** (2014) — based on that 0.93 release. It preserves sysmon's battle-tested
> monitoring and alerting behavior while modernizing the engine, fixing long-standing bugs, making
> the historically hardcoded bits configurable, and adding new capabilities: loss-tolerant ping,
> on-disk state persistence, and an opt-in modern `object{}` config format with per-object
> intervals and a legacy→modern converter.

## What it does

- **Pings** hosts (ICMP) and checks **TCP**, **UDP/DNS**, **SMTP**, and **POP3** services, plus
  clean **DNS** (authoritative) and **HTTP/HTTPS-content** checks.
- **Dependency suppression:** monitored objects form a tree. A child host/service is only checked
  while its parent (a ping target — typically the upstream router) is up. When the parent goes
  down you get *one* alert for the parent, not a storm for everything behind it.
- **Threshold alerting:** after *N* consecutive failures a host is reported; you're paged once,
  re-paged on an interval while it stays down, and notified again when it recovers.
- **Pluggable notifications:** email (SMTP) out of the box; the notifier interface makes
  webhook/SMS/chat transports easy to add.
- **At-a-glance status:** an auto-refreshing **"Bad Hosts"** HTML page (down hosts only) plus a
  JSON endpoint for dashboards and automation.

## How it's different from the original

|                                          | Original C `sysmon`            | This rewrite                                                  |
| ---------------------------------------- | ------------------------------ | ------------------------------------------------------------ |
| Concurrency                              | single-threaded serial sweep   | **asyncio**, concurrent per-host scheduling                  |
| ICMP privilege                           | whole daemon suid root         | raw socket opened as root; runs as a root process (no setuid binary) |
| Config                                   | legacy `sysmon.conf` only      | **legacy `sysmon.conf` (drop-in)** + auto-detect; opt-in modern `object{}` format + converter |
| Hardcoded source IP / hostnames / paths  | compiled in                    | **config file + CLI** (CLI wins)                             |
| Status page                              | malformed legacy HTML          | **HTML5 + CSS**, plus JSON                                   |
| Known bugs                               | fd leaks, silent host drops    | fixed                                                         |
| Phone-home heartbeat / cleartext creds   | present                        | **removed**                                                  |

Your existing `sysmon.conf` keeps working unchanged.

## Monitoring model

```
core-router            ping        ← if this is DOWN …
  ├─ web-server        ping        ← … these are not checked (suppressed) …
  │    ├─ https        http        ← … and neither are their services
  │    └─ ssh          tcp 22
  └─ mail-server       ping
       ├─ smtp         smtp
       └─ pop3         pop3
```

Nesting (`{ }` in the config) encodes "reachable only if the parent is up."

## Configuration (legacy format)

```
config statusfile html /var/www/psysmon/status.html
config pageinterval 18        ; minutes between re-pages while down
config numfailures 5          ; consecutive failures before alerting
config savestate "/var/lib/psysmon/state.json"   ; remember up/down across restarts (optional)

router.example.net ping router.example.net noc@example.net {
    web.example.net ping web.example.net noc@example.net {
        web.example.net tcp 443 https noc@example.net
    }
}
```

Settings can also be given on the command line, which **overrides** the config file — e.g. the
outbound source IP (used for firewall ACLs), the hostname shown in alerts and the status page,
and SMTP settings.

psysmon also supports an **opt-in modern `object{}` config format** (auto-detected per file) with
named objects, `dep` dependency edges, `set`/`$var` reuse, and per-object overrides. See
[docs/modern-config.md](docs/modern-config.md) for the full reference and a migration guide — the
legacy format above keeps working unchanged.

## Requirements

- Python **3.11+**
- Linux (raw ICMP ping needs a raw socket, i.e. running as root)
- Dependencies: [`dnspython`](https://www.dnspython.org/), [`httpx`](https://www.python-httpx.org/)

## Install & run

```bash
pip install .
sudo psysmon --config /etc/psysmon.conf        # CLI flags override config values
```

See [INSTALL.md](INSTALL.md) for step-by-step setup (venv install, configuration, and running
under systemd).

## Documentation

The full **User Guide** — install, both config formats with worked examples, every CLI flag, a
feature tour, status codes, and troubleshooting — is published to **GitHub Pages**
(<https://ijontichy1970.github.io/Psysmon/>) and ships as a plain-text copy at
[docs/guide/psysmon-guide.txt](docs/guide/psysmon-guide.txt). It's generated from one Markdown
source (`docs/guide/src/`) by `python tools/build_guide.py`. `README.md` and `INSTALL.md` are the
getting-started level; the guide is the complete reference. The modern config format also has a
focused reference at [docs/modern-config.md](docs/modern-config.md) and the control channel at
[docs/control-channel.md](docs/control-channel.md).

## Project status & roadmap

The core daemon is feature-complete (config parser, check engine, async scheduler, notifier, and
HTML/JSON status output) and shipping releases — see the
[issue tracker](https://github.com/IjonTichy1970/Psysmon/issues). A modern `object{}` config
format with a legacy→modern converter has landed
([#3](https://github.com/IjonTichy1970/Psysmon/issues/3); see
[docs/modern-config.md](docs/modern-config.md)); planned enhancements include operator annotations
([#20](https://github.com/IjonTichy1970/Psysmon/issues/20)) and IPv6 ping
([#24](https://github.com/IjonTichy1970/Psysmon/issues/24)).

## Heritage

A faithful-but-modernized descendant of the original sysmon by Jared Mauch
([puck.nether.net/sysmon](http://www.sysmon.org/)). Thanks to that project for ~25 years of prior
art.

## License

GPL-2.0-or-later, continuing the original sysmon's GNU GPL licensing. See [LICENSE](LICENSE).
