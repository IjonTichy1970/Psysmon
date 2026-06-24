# Introduction

PSYSMON is a **dependency-aware network monitoring daemon** — a modern Python rewrite of Jared
Mauch's C `sysmon`. It periodically checks hosts and services (ping, TCP, UDP, SMTP, POP3, DNS, HTTP/HTTPS),
pages you when something goes down and again when it recovers, and writes a live status page.

## The core idea: dependency suppression

A flat monitor floods you: when an edge router dies, every host behind it also fails its check, and
you get fifty pages for one outage. PSYSMON models the topology instead. You declare that a host
**depends on** another (it's only reachable when its parent ping is up), and PSYSMON checks a
subtree only while its gate is up.

> One alert for the router, not a flood for everything behind it.

When the router recovers, its dependents resume checking. A host whose parent is down is *frozen*,
not failed — its state doesn't change and it doesn't page.

## Heritage, and what this rewrite changes

The original `sysmon` — Jared Mauch's network monitor, developed from 1996 to its final 0.93
release in 2014 ([puck.nether.net/sysmon](http://www.sysmon.org/)) — was a single-threaded C daemon
driven by a positional config file and a cleartext TCP control port. PSYSMON is based on that final
0.93 release; it keeps the observable behavior — the check types, the status codes, the dependency
model, the status page — but rebuilds the internals:

- **Async, concurrent checks** on an `asyncio` scheduler instead of a serial sweep.
- **Two config formats:** the original positional **legacy** grammar (still the default, for drop-in
  compatibility) and a richer **modern `object{}`** grammar with named dependencies, variables, and
  per-object settings. See [Configuration](04-configuration.md).
- **Modern safety:** no cleartext credential dump; an opt-in, token-gated, loopback-default control
  channel; raw-socket privilege dropped after startup.
- **New capabilities:** loss-tolerant ping, per-object check intervals, per-object/group outbound
  source binding, operator acknowledge/notes, and JSON status output for dashboards.

## Who it's for

System and network administrators who want **topology-aware** alerting without the weight of a
full observability stack — a single daemon, a config file, a status page, and email paging. It runs
on Linux (root or `CAP_NET_RAW` for ICMP), needs Python 3.11+, and depends only on `dnspython` and
`httpx`.

If you want to understand *how it works inside* rather than how to operate it, that's the
developer/architecture documentation (a separate guide), not this one.
