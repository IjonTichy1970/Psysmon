# Installation

This chapter walks you through installing PSYSMON, verifying the install, running it as a daemon (including a working systemd unit), and upgrading. It folds in and supersedes the repository's `INSTALL.md`.

If you just want the fastest path from zero to a running monitor, start with [00-quickstart.md](00-quickstart.md) and come back here for the details. For where to obtain the release artifacts, see [02-getting-it.md](02-getting-it.md).

## Requirements

- **Python 3.11 or newer.**
- **Linux.** ICMP ping uses a raw socket, which requires **root** (or the `CAP_NET_RAW` capability). The non-ping checks (TCP, UDP, DNS, SMTP, POP3, HTTP/HTTPS) work without root.
- **Network egress** to the hosts you intend to monitor, and — if you want email alerts — an SMTP server to relay through.

The two runtime Python dependencies, [`dnspython`](https://www.dnspython.org/) and [`httpx`](https://www.python-httpx.org/), are pulled in automatically by `pip`. There are no other runtime dependencies.

## Console commands installed

Installing the `psysmon` package puts four commands on `PATH` (inside the virtual environment's `bin/` directory):

| Command | What it does |
| --- | --- |
| `psysmon` | The monitoring daemon itself. |
| `psysmon-convert` | Converts a legacy `sysmon.conf` to the modern `object{}` format. Also runnable as `python -m psysmon.config.convert`. |
| `psysmonctl` | Client for the optional runtime control channel (query status, acknowledge alerts). |
| `psysmon-token` | Generates a control-channel auth token. |

The control-channel tools (`psysmonctl`, `psysmon-token`) are only needed if you enable the opt-in control channel; see [07-operating.md](07-operating.md). The converter is covered in [04-configuration.md](04-configuration.md).

## Install into a virtual environment

Always install PSYSMON into a dedicated virtual environment so its dependencies don't mix with the system Python.

### Method A — from a release wheel (recommended)

Download the wheel (`.whl`) from the [Releases page](https://github.com/IjonTichy1970/Psysmon/releases) (see [02-getting-it.md](02-getting-it.md)), create a venv, and install into it:

```bash
python3 -m venv /opt/psysmon-venv
/opt/psysmon-venv/bin/pip install ./psysmon-<version>-py3-none-any.whl
```

The `psysmon` command then lives at `/opt/psysmon-venv/bin/psysmon`. To put it on `PATH`, symlink it:

```bash
sudo ln -s /opt/psysmon-venv/bin/psysmon /usr/local/bin/psysmon
```

(Substitute the actual version number from the file you downloaded.)

### Method B — from the sdist or a source checkout

You can install the same way from a source tarball (`.tar.gz`) downloaded from the Releases page:

```bash
python3 -m venv /opt/psysmon-venv
/opt/psysmon-venv/bin/pip install ./psysmon-<version>.tar.gz
```

Or from a Git checkout of the repository:

```bash
git clone https://github.com/IjonTichy1970/Psysmon.git
cd Psysmon
python3 -m venv .venv
./.venv/bin/pip install .
```

For a development install with the test tooling (pytest, pytest-asyncio, ruff), add the `dev` extra and the `-e` (editable) flag instead:

```bash
./.venv/bin/pip install -e ".[dev]"
```

The `dev` extra is for contributors — end users do not need it. (Building this guide separately uses the `docs` extra; that, too, is not a runtime requirement.)

### Method C — manual virtualenv setup

If you prefer to manage the environment by hand — for example to activate it in your shell — the steps are the same venv plus pip install, with the environment activated first:

```bash
python3 -m venv /opt/psysmon-venv
source /opt/psysmon-venv/bin/activate     # prepends the venv's bin/ to PATH
pip install ./psysmon-<version>-py3-none-any.whl
psysmon --version                         # now resolves inside the active venv
deactivate                                # leave the venv when done
```

Activating the venv is convenient for interactive use, but a service manager should call the venv's `psysmon` by its full path (or via the symlink) rather than relying on an activated shell.

## Verify the install

Confirm the command resolves and reports its version:

```bash
psysmon --version
```

If you installed without the symlink, run it by full path (`/opt/psysmon-venv/bin/psysmon --version`). For the complete list of flags, run `psysmon --help` or see Appendix A in [90-appendices.md](90-appendices.md).

## Running as root for ICMP

ICMP ping opens a raw socket, so the daemon must run **as root**. Unlike the original C `sysmon`, which was a setuid binary, the Python daemon is simply launched as a root process — via `sudo` or a service manager. It opens the raw socket at startup and, per the current deploy choice, keeps root for the process lifetime (a privilege-drop option is planned but not yet enabled).

The non-ping checks (TCP, UDP, DNS, SMTP, POP3, HTTP/HTTPS) do not need root — only ICMP ping does. If pings always report hosts as down, the usual cause is not running as root; see [09-troubleshooting.md](09-troubleshooting.md).

### Foreground (first test)

For a first run, keep the daemon attached to your terminal with `--no-fork` so it logs to stderr where you can watch it:

```bash
sudo psysmon -f /etc/psysmon.conf --no-fork
```

Add `--no-notify` to suppress email while you confirm the config. Press `Ctrl-C` to stop. (This is also the simplest way to validate a config file — a parse error is printed and the daemon exits.)

### Backgrounded

Without `--no-fork`, the daemon detaches and logs to **syslog** (the `daemon` facility by default; change it with `--syslog-facility`):

```bash
sudo psysmon -f /etc/psysmon.conf
```

For day-to-day operation, run it under a service manager instead, as shown next.

## Run it as a service (systemd)

PSYSMON does not ship a unit file. Here is a working one. Use `--no-fork` so systemd supervises the process directly (it stays in the foreground) and journald captures its logs:

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

Adjust `ExecStart` to the path where `psysmon` actually lives (e.g. `/opt/psysmon-venv/bin/psysmon` if you didn't create the symlink). Then enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now psysmon
sudo systemctl status psysmon
journalctl -u psysmon -f          # follow the logs
```

`ExecReload` wires `systemctl reload psysmon` to a `SIGHUP`, which reloads the config without downtime; live up/down state is preserved for hosts that still exist. Stopping the service (`systemctl stop psysmon`) sends `SIGTERM`, on which the daemon drains in-flight checks and writes a final status snapshot. Reloading, stopping, and the status page are covered in [07-operating.md](07-operating.md).

## Upgrade

To upgrade, install the new artifact over the old one in the same venv and restart the service:

```bash
/opt/psysmon-venv/bin/pip install --upgrade ./psysmon-<new-version>-py3-none-any.whl
sudo systemctl restart psysmon
```

If you configured on-disk state persistence (`config savestate` / `--state-file`), an upgrade-and-restart won't re-page outages that were already known. For the full operational picture — reloads, state persistence, and rolling upgrades — see [07-operating.md](07-operating.md).

## Uninstall

```bash
sudo systemctl disable --now psysmon
sudo rm /etc/systemd/system/psysmon.service /usr/local/bin/psysmon
sudo rm -rf /opt/psysmon-venv
```

This removes the service, the symlink, and the virtual environment. Your config file (`/etc/psysmon.conf`) and any state file are left in place; delete them separately if you no longer need them.

## Next steps

With PSYSMON installed, continue to [04-configuration.md](04-configuration.md) to write your config file, then [05-cli-reference.md](05-cli-reference.md) for the flags that override it. If something doesn't work, [09-troubleshooting.md](09-troubleshooting.md) covers the common install-time problems.
