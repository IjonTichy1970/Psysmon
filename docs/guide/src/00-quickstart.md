# 5-Minute Quickstart

Get PSYSMON watching a router — and the services behind it — in five minutes. The rest of this
guide explains everything in depth; this is the shortest path to a running monitor.

## Install

```bash
python3 -m venv /opt/psysmon-venv
/opt/psysmon-venv/bin/pip install ./psysmon-0.4.0-py3-none-any.whl
```

Python 3.11+ is required. See [Getting it](02-getting-it.md) and [Installation](03-installation.md)
for wheels vs. source, dependencies, and a systemd unit.

## A first config

Save this as `/etc/psysmon.conf` (the modern `object{}` format):

```
config statusfile html "/var/www/html/status.html";
root = "gw";

object gw  { ip "192.0.2.1";  type ping; desc "edge router"; contact "noc@example.net"; }
object web { ip "192.0.2.10"; type tcp; port 443; dep "gw"; contact "noc@example.net"; }
```

`web` depends on `gw`, so it is only checked while `gw` is up — **one alert for the router, not a
flood for everything behind it.** That dependency suppression is the whole idea; see the
[Feature tour](06-feature-tour.md).

## Run it

```bash
sudo /opt/psysmon-venv/bin/psysmon -f /etc/psysmon.conf --no-fork
```

Ping uses a raw ICMP socket, so the daemon needs root (or `CAP_NET_RAW`). Point a web server or
browser at the `statusfile` path you set. To page by email, configure the SMTP notifier
(see [Configuration](04-configuration.md)).

Next: the [Introduction](01-introduction.md) explains what PSYSMON is and where it came from.
