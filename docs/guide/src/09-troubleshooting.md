# Troubleshooting & FAQ

This chapter collects the questions operators hit most often, framed as "symptom → cause →
fix." Each answer points to the chapter with the full detail. For the meaning of a specific
status word on the page, see [Status codes](08-status-codes.md); for the complete flag list, see
[the CLI reference](05-cli-reference.md) and Appendix A in the [appendices](90-appendices.md).

## Ping and reachability

### Every ping fails / a host reads "Unpingable" / I get a permission error at startup

Raw ICMP needs privilege. psysmon opens its raw sockets at startup, which requires **root or the
`CAP_NET_RAW` capability** on Linux; without it the daemon can't open the unbound ping socket and
surfaces a clean startup error. (Ping is a Linux feature — raw ICMP demux relies on the event
loop's `add_reader`, which isn't available on the Windows event loop.)

Fixes:

- Run the daemon as root, or grant the capability to the interpreter, e.g.
  `setcap cap_net_raw+ep /path/to/venv/bin/python` (see [Installation](03-installation.md)).
- What matters is opening the raw socket *as* root (or with `CAP_NET_RAW`) at startup. The daemon
  currently keeps root for the rest of its run; a privilege-drop option exists in the code but is
  not enabled (planned).

If a *single* host reads `Unpingable` while others ping fine, that's a real result: no echo reply
came back within the retry budget. A host that answers *some* but fewer than the required number
of probes reads `Degraded`, not `Unpingable` (see the loss-tolerant ping question below).

### A VPN-reached host reads "Unpingable" even though I set a global source IP

This is expected, and it changed in 0.4.0. **Ping is now unbound by default** and ignores the
global `config source_ip` — the kernel routes each ICMP probe by destination. `source_ip` still
binds the *connection* checks (tcp/udp/smtp/pop3/dns) for firewall-ACL egress, but no longer
binds ping.

If pings to a VPN host were succeeding before only because `source_ip` pinned them to the right
local address, set that address explicitly on the object (or its group):

```
object vpn-gw {
    ip      "198.51.100.1";
    type    ping;
    source  "203.0.113.5";    # pin ping to this local (VPN) address
}
```

The note in [Configuration](04-configuration.md) applies: a *literal* per-VPN IP is fragile if
that address changes across reboots or VPN restarts. For a host that should simply route freely,
use `source auto;` (the explicit "stay unbound" opt-out) rather than binding a fixed address.

### I added a per-object ping `source` and reloaded with SIGHUP, but it isn't binding

psysmon opens its raw ping sockets **at startup, while privileged**, and keeps them across the
later privilege drop. A *brand-new* source introduced by a SIGHUP reload can't open a new bound
raw socket after privilege is gone, so probes for it fall back to the **unbound** socket (logged
once as a `cannot bind source ... routing affected checks unbound until restart` warning).

Fix: **restart the daemon** to bind a newly-added `source`. Other reload changes to the host tree
(adding objects, editing `dep` edges, per-object `queuetime` / `numfailures`) apply on SIGHUP as
usual — see the reload notes in [Operating](07-operating.md) and
[Configuration](04-configuration.md).

## Alerting and paging

### A host shows "Degraded" on the status page but never pages

That's the default. `Degraded` is a loss-tolerant-ping result — the host answered some echoes but
fewer than `min_pings`, so it's reachable but lossy. It is deliberately **not treated as "down":**
it shows with its own badge and is informational only, so a flapping-but-up router doesn't wake
anyone.

To make a degraded result page like a normal outage, set `--page-on-degraded` (or
`config page_on_degraded;`). Loss-tolerant ping only kicks in when you raise `send_pings` above 1
(with `min_pings` between 1 and `send_pings`); the defaults of 1/1 reproduce the old
first-reply-wins behavior, where a host is simply up or `Unpingable`. See
[Configuration](04-configuration.md) and the [feature tour](06-feature-tour.md).

A related consequence: because a degraded (lossy-but-answering) router still forwards packets,
psysmon does **not** suppress the hosts behind it. Only a fully-down ancestor suppresses its
subtree.

### SMTP / email alerts never fire

Walk these in order:

1. **Notifier configured?** Alerts go out over SMTP. Check `config sender` / `config from` (the
   `From:` address, also settable with `--mail-from`) and the SMTP target (`smtp_host` defaults to
   `localhost`, `smtp_port` to `25`). Confirm notifications aren't globally disabled — `-n` /
   `--no-notify` turns paging off.
2. **A contact on the object?** An object with **no contact address never pages**, regardless of
   anything else (it's still monitored and shown — syslog only). For `dns` objects a non-empty
   contact is required; for other types an absent contact means "syslog only."
3. **Does `contact_on` cover this transition?** `contact_on` selects which transitions page:
   `both` (default — down and recovery), `down` (outages only), `up` (recovery only), or `none`
   (never). If you set it to `down`, recovery e-mails won't fire; `none` silences the object
   entirely. It can be set globally (`config contact_on …` / `--contact-on`) or per object, with
   the per-object value winning.
4. **Acknowledged?** If you ran `psysmonctl ack <host> <type>`, paging is suppressed while the
   object stays down (it auto-clears on recovery). See the control-channel section below.

Details and examples are in [Configuration](04-configuration.md); the alert lifecycle is in
[Operating](07-operating.md).

### A host behind a down parent isn't being checked at all

This is **dependency suppression working as designed**, not a bug. An object with `dep "parent"`
is checked only while every ancestor ping is reachable; when the parent goes down, psysmon stops
checking the children and freezes their state, so an upstream outage raises **one** alert instead
of a flood. When the parent recovers, checking of the subtree **resumes automatically**.

Notes:

- Suppression is gated on the ancestor being *reachable*, which includes `Degraded` — a lossy
  router still forwards, so its subtree keeps being checked. Only a fully-down ancestor suppresses.
- Each object has a **single** parent today (one `dep` edge). Listing more than one `dep` warns
  and keeps the first; true multi-parent (DAG) dependencies are planned.

See the dependency model in [Configuration](04-configuration.md) and the
[feature tour](06-feature-tour.md).

## Status file and output

### The status file isn't updating

The daemon publishes the status file periodically and writes it **atomically** (it renders to an
unguessable temp file in the target directory and renames it into place), so a reader never sees a
partial file — and a stale file usually means the write itself isn't landing. Check:

- **Path** — `config statusfile html "/path"` (or `text`), or `--status-file` / `--status-format`.
  No status path set means no status file is written at all.
- **Permissions** — the daemon must be able to create a temp file in, and rename within, the
  **target directory**. A directory it can't write to, or a path under a directory that doesn't
  exist, blocks the publish.
- **Process** — confirm the daemon is actually running and hasn't exited (check syslog). The
  page also carries a browser auto-refresh (`--status-refresh`, default 30s); if the file is
  current but your browser shows old data, that's just the refresh interval.

See [Operating](07-operating.md) for the publish cycle and [Configuration](04-configuration.md)
for the status directives.

## Control channel

### The control channel refuses to start

By design, so you can't accidentally expose it:

- **Non-loopback bind needs TLS.** The channel binds `127.0.0.1:2026` by default. If you set
  `control_bind` to a non-loopback address, you **must** also provide `control_tls_cert` and
  `control_tls_key`; if they're missing or fail to load, the daemon **refuses to start** rather
  than expose a plaintext control channel.
- **Not enabled.** The channel is off by default — enable it with `config control;` / `--control`.

### `psysmonctl ack` / `note` / `reload` are rejected

Mutating actions require a **bearer token**; reads (`status`, `version`) do not. Generate a token
file with `psysmon-token <path>` (it writes a random token at mode `0600`; the daemon never
auto-creates it), point `--control-token-file` / `config control_token_file` at it, and pass
`--token-file` to `psysmonctl`. With **no** token file configured the channel still serves reads
but **all mutations are disabled** (fail closed). The token file must be `0600` — the daemon
refuses a group- or world-readable file on POSIX.

Full setup, the security model, and the `psysmonctl` command list are in
[Operating](07-operating.md).

## Configuration loading

### My config uses `include` and the daemon won't load it

`include` is **not yet supported** — a config using it is rejected at load. It's reserved for a
future release (with proper `$var`-across-include scoping); for now, keep your configuration in a
single file. See the "what's not adopted" notes in [Configuration](04-configuration.md).

### The first directive or hostname in my file looks mangled

If the file was saved with a UTF-8 byte-order mark (BOM), older builds glued the BOM onto the
first line. Current psysmon strips a leading BOM on load (for both the daemon and
`psysmon-convert`), so re-saving under a recent version resolves it.

### A whole block of objects didn't load, or a `type` was skipped

psysmon **warns and skips** rather than failing the whole load when an object is malformed or
unsupported, so the rest of the config still comes up. Check syslog (raise verbosity with
`config loglevel debug` / `-vv`) for the specific warning. Common causes:

- An object missing a **required field** for its type (e.g. a `tcp`/`udp` object with no `port`,
  an `http`/`https` object without `url` + `urltext`) is warned and skipped.
- A **dropped check type** (`imap`, `nntp`, `pop2`, `umichx500`, `radius`, `bootp`, `snmp`) warns
  and skips — these aren't in scope for the rewrite.
- **IPv6 ping** types (`ping6` / `pingv6` / `icmp6`) warn and skip; IPv6 is deferred
  ([tracked on GitHub](https://github.com/IjonTichy1970/Psysmon/issues/24)). An IPv6 `source` is likewise
  rejected at load.
- An **unknown `dep` target**, a **dependency cycle**, or a **duplicate object name** each warn
  and degrade gracefully (the object becomes a root, or the duplicate is skipped).

The full required-fields and check-type tables are in [Configuration](04-configuration.md).

### I changed a global `config` setting and reloaded, but nothing happened

File-level `config` globals — intervals, paths, logging knobs (`loglevel` / `heartbeat` /
`dnslog`), and the global `queuetime` / `numfailures` baselines — take effect only **at startup**.
SIGHUP re-applies the **host tree** (objects, `dep` edges, per-object attributes) but does **not**
re-merge global overrides. **Restart the daemon** to change a global. (Per-object `queuetime` /
`numfailures` *do* reload, because they live on the objects.) This is detailed in
[Configuration](04-configuration.md) and [Operating](07-operating.md).

## See also

- [Status codes](08-status-codes.md) — the meaning of every status word on the page.
- [CLI reference](05-cli-reference.md) and [appendices](90-appendices.md) — the full flag list.
- [Configuration](04-configuration.md) — directives, per-object overrides, dependencies, reload.
- [Operating](07-operating.md) — running the daemon, the alert lifecycle, and the control channel.
