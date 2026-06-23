# PSYSMON

**PSYSMON** (Python Sysmon) is a modern reimplementation of **sysmon**, a network-monitoring
daemon that pings hosts, checks services, and alerts you when things break — with
**dependency-aware** monitoring so an upstream outage raises one alert instead of a flood.

> **Status: early development.** This is a from-scratch Python 3.11+ rewrite of the original
> 1998 C `sysmon` (v0.78.3.2 by Jared Mauch), preserving its battle-tested monitoring and
> alerting behavior while modernizing the engine, fixing long-standing bugs, and making the
> historically hardcoded bits configurable.

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
| ICMP privilege                           | whole daemon suid root         | raw socket opened as root, **privileges dropped**            |
| Config                                   | legacy `sysmon.conf` only      | **legacy `sysmon.conf` (drop-in)** + auto-detect; modern format planned |
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

router.example.net ping router.example.net noc@example.net {
    web.example.net ping web.example.net noc@example.net {
        web.example.net tcp 443 https noc@example.net
    }
}
```

Settings can also be given on the command line, which **overrides** the config file — e.g. the
outbound source IP (used for firewall ACLs), the hostname shown in alerts and the status page,
and SMTP settings.

## Requirements

- Python **3.11+**
- Linux (raw ICMP via setuid root)
- Dependencies: [`dnspython`](https://www.dnspython.org/), [`httpx`](https://www.python-httpx.org/)

## Install & run

```bash
pip install -e .
sudo psysmon --config /etc/psysmon.conf        # CLI flags override config values
```

## Project status & roadmap

Under active development — see the [issue tracker](https://github.com/IjonTichy1970/Psysmon/issues).
Near-term milestones: config parser, check engine, async scheduler, notifier, and status output.
Deferred enhancements include a modern config format with a converter
([#3](https://github.com/IjonTichy1970/Psysmon/issues/3)) and an authenticated control/query API
([#1](https://github.com/IjonTichy1970/Psysmon/issues/1)).

## Heritage

A faithful-but-modernized descendant of the original sysmon by Jared Mauch
([puck.nether.net/sysmon](http://www.sysmon.org/)). Thanks to that project for ~25 years of prior
art.

## License

GPL-2.0-or-later, continuing the original sysmon's GNU GPL licensing. See [LICENSE](LICENSE).
