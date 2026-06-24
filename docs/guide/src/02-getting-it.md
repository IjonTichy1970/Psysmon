# Getting it

This chapter tells you where PSYSMON comes from and what your system needs before you install it. It's short and orienting — the step-by-step install (virtual environment, configuration, running under systemd) lives in [Installation](03-installation.md).

## Where to get it

PSYSMON is published on its GitHub **Releases** page:

<https://github.com/IjonTichy1970/Psysmon/releases>

Each release attaches two build artifacts. They contain the same code — you only need one.

| Artifact | What it is | When to use it |
| --- | --- | --- |
| `psysmon-<version>-py3-none-any.whl` | A **wheel** — a pre-built, ready-to-install package. | The normal choice. `pip` installs it directly, no build step. |
| `psysmon-<version>.tar.gz` | A **source distribution** (sdist) — the source tree packaged for installation. | When you want the source, or your tooling/policy prefers building from sdist. `pip` builds it on install. |

Both install the same way with `pip` (see [Installation](03-installation.md)):

```bash
pip install ./psysmon-<version>-py3-none-any.whl
# or the sdist:
pip install ./psysmon-<version>.tar.gz
```

If you'd rather work from a git checkout instead of a release artifact — for development, or to track the latest commit — clone the repository and install from source. That path is covered in [Installation](03-installation.md).

## What you need

### Platform

PSYSMON targets **Linux**. ICMP ping uses a **raw socket**, which on Linux means the daemon must run as **root** (or with the `CAP_NET_RAW` capability). This is required only for ping; every other check type — TCP, UDP/DNS, SMTP, POP3, authoritative DNS, and HTTP/HTTPS-content — works without root. So a PSYSMON instance that does no ICMP pinging can run as an ordinary user.

How root is actually granted (via `sudo`, a systemd unit, etc.) is covered in [Installation](03-installation.md) and [Operating](07-operating.md).

### Python

Python **3.11 or newer**. PSYSMON is a pure-Python application; there is nothing to compile.

### Dependencies

Just two runtime dependencies:

- [`dnspython`](https://www.dnspython.org/) — DNS resolution and the authoritative DNS check.
- [`httpx`](https://www.python-httpx.org/) — the HTTP/HTTPS-content check.

You don't install these by hand. `pip` reads them from the package metadata and pulls them in automatically when you install the wheel or the sdist. Installing into a dedicated virtual environment (so these don't mix with your system Python) is the recommended approach — see [Installation](03-installation.md).

## What you get after installing

Installing PSYSMON puts four commands on your `PATH`:

- **`psysmon`** — the monitoring daemon itself.
- **`psysmon-convert`** — converts a legacy `sysmon.conf` to the modern `object{}` config format (also runnable as `python -m psysmon.config.convert`).
- **`psysmonctl`** — the client for the optional runtime control channel (query status, acknowledge alerts).
- **`psysmon-token`** — generates a token for that control channel.

These are introduced in the [CLI reference](05-cli-reference.md); the full flag list is in [Appendix A](90-appendices.md).

## Next steps

- New to PSYSMON? Start with the [Quickstart](00-quickstart.md).
- Ready to install? Go to [Installation](03-installation.md).
- Want the background first? See the [Introduction](01-introduction.md).
