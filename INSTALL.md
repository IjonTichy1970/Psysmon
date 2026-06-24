# Installing PSYSMON

Step-by-step setup for the PSYSMON monitoring daemon. For what it does and the config-file
format, see [README.md](README.md); for the full option list run `psysmon --help`.

## 1. Requirements

- **Python 3.11 or newer.**
- **Linux.** ICMP ping uses a raw socket, which requires running as **root** (see step 4).
  The non-ping checks (TCP/UDP/SMTP/POP3/DNS/HTTP) work without root.
- Network egress to the hosts you monitor, and — if you want email alerts — an SMTP server to
  relay through.

The Python dependencies (`dnspython`, `httpx`) are installed automatically by `pip`.

## 2. Install

Install into a dedicated virtual environment so PSYSMON's dependencies don't mix with the
system Python.

### Option A — from a release artifact (recommended)

Download the wheel (`.whl`) or source tarball (`.tar.gz`) from the
[Releases page](https://github.com/IjonTichy1970/Psysmon/releases), then:

```bash
python3 -m venv /opt/psysmon-venv
/opt/psysmon-venv/bin/pip install ./psysmon-0.1.0-py3-none-any.whl
# (or the sdist:)  /opt/psysmon-venv/bin/pip install ./psysmon-0.1.0.tar.gz
```

The `psysmon` command lands at `/opt/psysmon-venv/bin/psysmon`. Symlink it onto `PATH` if you
like:

```bash
sudo ln -s /opt/psysmon-venv/bin/psysmon /usr/local/bin/psysmon
```

### Option B — from source

```bash
git clone https://github.com/IjonTichy1970/Psysmon.git
cd Psysmon
python3 -m venv .venv
./.venv/bin/pip install .          # add  -e ".[dev]"  for an editable dev install + test tools
```

### Verify the install

```bash
psysmon --version
```

## 3. Configure

PSYSMON reads `/etc/psysmon.conf` by default (override with `-f/--config`). It uses the legacy
`sysmon.conf` format — an existing sysmon config works unchanged. A minimal starting point:

```
# where to write the status page (and its format)
config statusfile html /var/www/psysmon/status.html
config pageinterval 18        ; minutes between re-pages while a host stays down
config numfailures 5          ; consecutive failures before alerting
# optional: persist up/down state so a restart/upgrade doesn't re-page known outages
config savestate "/var/lib/psysmon/state.json"

# a router, and a couple of things that depend on it being reachable
core-router.example.net ping core-router.example.net noc@example.net {
    web.example.net ping web.example.net noc@example.net {
        web.example.net tcp 443 https noc@example.net
    }
    mail.example.net ping mail.example.net noc@example.net {
        mail.example.net smtp smtp noc@example.net
    }
}
```

Nesting (`{ }`) means "only checked while the parent ping is up" — so a router outage pages once
for the router instead of flooding you for everything behind it. See the README for the full
field layout per check type.

Any setting can also be passed on the command line, which **overrides** the file — most usefully
the outbound source IP (for firewall ACLs), the hostname shown in alerts/status, and SMTP:

```bash
psysmon -f /etc/psysmon.conf \
        --source-ip 203.0.113.10 \
        --hostname monitor.example.net \
        --smtp-host smtp.example.net --mail-from psysmon@example.net
```

If you publish the HTML status page, the daemon automatically places its logo next to the status
file on first publish (the page references it by a relative path), so there's nothing to copy. To
use your own logo instead, drop a `psysmon-logo.png` into the status-file's directory beforehand —
the daemon won't overwrite an existing one.

A few other useful flags: `--state-file <path>` (or `config savestate "<path>"`) persists up/down
state so a restart or upgrade doesn't re-page known outages; `--send-pings N --min-pings M` turn
ping into a loss-tolerant check that reports a distinct *Degraded* status on partial packet loss
instead of flapping (add `--page-on-degraded` to alert on it; the default 1/1 is unchanged).

## 4. Run

ICMP ping needs a raw socket, so run PSYSMON **as root**. (Unlike the original C `sysmon`, which
was a setuid binary, the Python daemon is simply run as a root process — via `sudo` or a service
manager. It opens the raw socket at startup and, per the current deploy choice, keeps root for
the process lifetime; see issue
[#2](https://github.com/IjonTichy1970/Psysmon/issues/2).)

**Foreground (for a first test):**

```bash
sudo psysmon -f /etc/psysmon.conf --no-fork
```

`--no-fork` keeps it attached to your terminal and logs to stderr — handy while you confirm the
config. Add `--no-notify` to suppress email while testing. `Ctrl-C` to stop.

**Backgrounded (normal use):**

```bash
sudo psysmon -f /etc/psysmon.conf
```

It detaches and logs to **syslog** (the `daemon` facility by default; change with
`--syslog-facility`, or disable with `config logging none`).

### Run it as a service (systemd)

PSYSMON doesn't ship a unit file; here is a working one. Use `--no-fork` so systemd supervises
the process directly and journald captures the logs:

```ini
# /etc/systemd/system/psysmon.service
[Unit]
Description=PSYSMON network monitoring daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/psysmon -f /etc/psysmon.conf --no-fork
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now psysmon
sudo systemctl status psysmon
journalctl -u psysmon -f          # follow the logs
```

## 5. Operate

- **Status page:** point a browser (or web server) at the `statusfile` path you configured. By
  default it lists only hosts that are **down** ("Bad Hosts"); a JSON view of every host is
  written alongside it for dashboards.
- **Reload config without downtime:** `sudo systemctl reload psysmon` (or `kill -HUP <pid>`).
  Live up/down state is preserved for hosts that still exist.
- **Stop:** `sudo systemctl stop psysmon` (or `kill -TERM <pid>`) — it drains in-flight checks
  and writes a final status snapshot.
- **Control channel (optional):** to query status and acknowledge/annotate alerts at runtime,
  enable the opt-in control channel. Generate a token once — `psysmon-token
  /etc/psysmon/control.token` — then run with `--control --control-token-file
  /etc/psysmon/control.token` (or the `config control` directives). It binds `127.0.0.1:2026` and
  is driven by `psysmonctl` (`psysmonctl status`, `psysmonctl ack <host> <type>`). See
  [docs/control-channel.md](docs/control-channel.md) — including how to expose it beyond localhost
  with TLS.

## 6. Upgrade

```bash
/opt/psysmon-venv/bin/pip install --upgrade ./psysmon-<new-version>-py3-none-any.whl
sudo systemctl restart psysmon
```

## 7. Uninstall

```bash
sudo systemctl disable --now psysmon
sudo rm /etc/systemd/system/psysmon.service /usr/local/bin/psysmon
sudo rm -rf /opt/psysmon-venv
```

## Troubleshooting

- **`psysmon: ...` config error on start** — the config file couldn't be parsed; the message
  names the problem. Validate a config without starting the daemon by running it foreground:
  `sudo psysmon -f /etc/psysmon.conf --no-fork`.
- **Pings always report hosts down / "needs raw sockets" warning** — you're not running as root.
  Raw ICMP requires it.
- **No alerts arriving** — check `--smtp-host`/`--mail-from` and that each host has a contact in
  the config; test with `--no-fork` to see send errors on stderr.
- **No logs after backgrounding** — they go to syslog (`daemon` facility), not your terminal;
  see `journalctl` / `/var/log`, or run with `--no-fork` to log to stderr.
