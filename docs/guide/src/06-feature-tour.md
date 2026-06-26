# Feature tour

This chapter walks through the main features of psysmon, each with a minimal snippet and an
availability badge so you can see at a glance where it works. The badges are:

- **(all formats)** — available in the legacy positional `sysmon.conf`, the modern `object{}`
  config, *and* on the command line.
- **(modern config only)** — only expressible in the modern `object{}` config format.

For the full configuration grammar see [Configuration](04-configuration.md) and the modern-format
reference; for every CLI flag see [Appendix A](90-appendices.md); for the meaning of each status
string see [Status codes](08-status-codes.md). This chapter shows representative snippets, not the
exhaustive reference tables (those are generated from the code).

Examples use only the RFC-5737 documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), `*.example.net` hostnames, and `noc@example.net` contacts.

---

## Dependency suppression **(all formats)**

Monitored objects form a tree: a child is checked only while its parent (a ping target, typically
the upstream router) is reachable. When the parent goes down you get **one** alert for the parent
instead of a storm for everything behind it.

In the **legacy** format, nesting with `{ }` encodes the dependency:

```
router.example.net ping router.example.net noc@example.net {
    web.example.net ping web.example.net noc@example.net {
        web.example.net tcp 443 https noc@example.net
    }
}
```

In the **modern** format, the same structure is named `dep` edges:

```
object edge-rtr {
    host "192.0.2.1"; type ping; contact "noc@example.net";
};
object web {
    host "192.0.2.10"; type https; url "/health"; urltext "OK";
    contact "noc@example.net";
    dep "edge-rtr";          # only checked while edge-rtr is up
};
```

An object can list **several `dep` edges** to sit behind multiple parents at once. Suppression is
then **any-path**: it keeps being checked while *any* parent path is up, and is suppressed only when
*every* path is down — so a server reachable through two upstream routers stays monitored until both
uplinks fail. An unknown `dep` target or a cycle (including a self-`dep`) warns and that edge is
dropped; an object left with no surviving edge is a root.

A *degraded* (lossy-but-answering) parent still counts as a live path and does **not** suppress its
dependents — a router that still forwards packets shouldn't mask real outages behind it. A node is
suppressed only when every one of its paths is fully down.

---

## Threshold alerting, re-page, and recovery notices **(all formats)**

After *N* consecutive failures an object is reported down and you are paged once; while it stays
down you are re-paged on an interval; and you get a notice again when it recovers.

```
config numfailures 5         ; consecutive failures before alerting (default 2)
config pageinterval 18       ; minutes between re-pages while down (default 10)
```

These are also CLI flags: `--numfailures N` and `--pageinterval MIN`. In the **modern** format
they are `config numfailures` / `config pageinterval` directives, and the modern format adds a
**per-object** `numfailures` override (see below).

You can also control *which* transitions page, with `contact_on`. Globally it's a **modern-config**
directive (`config contact_on …`) or the `--contact-on` CLI flag — the flag is the only way to set
it for a legacy config (the legacy parser has no `contact_on` directive). **Per object** it's
modern-format only:

```
config contact_on down;      ; page on outages only; suppress recovery pages
```

The values are `down`, `up`, `both`, and `none`; the default is **`both`** (page on down *and* on
recovery), which preserves psysmon's historical behavior. An object with no `contact` address
never pages regardless of `contact_on`.

---

## The SMTP email notifier **(all formats)**

Email is the built-in notification transport. The contact address comes from the object's
`contact`; the SMTP transport, sender, and the org hostname shown in alerts are settings:

```bash
sudo psysmon --config /etc/psysmon.conf \
  --smtp-host mail.example.net --smtp-port 25 \
  --mail-from noc@example.net --hostname noc.example.net
```

In the **modern** format these can also come from the config file (`config sender` / `config from`
for the `From:` address, `config hostname` for the org hostname); a **legacy** config sets them only
via the CLI flags above (it has no such directives). The SMTP host/port have no config directive in
either format — they are CLI-only. An object with an absent or empty
contact logs to syslog only — it does not page. Use `-n` / `--no-notify` to suppress paging
entirely (results still show on the status page).

---

## Status output: HTML, text, and JSON **(all formats)**

psysmon publishes a status file atomically (readers never see a partial file). Choose the format
and path with `config statusfile <html|text> "path"`, `--status-file PATH`, and
`--status-format {html,text}`:

```
config statusfile html "/var/www/psysmon/status.html";
```

- **HTML "Bad Hosts" page** — a dark-themed page listing down hosts (the default view), with a
  browser auto-refresh (`--status-refresh SECONDS`). Suppressed hosts are hidden by default; use
  `--show-up` to add a collapsed **"Healthy hosts"** section below (the down hosts stay on top). All
  dynamic content is HTML-escaped.
- **Text table** — a flat variant (`--status-format text`).
- **JSON** — all nodes, each with a `suppressed` flag and a `down_parents` list (which of a node's
  dependency parents are currently down — empty when fully healthy), for dashboards and automation.

When objects have a [`group`](04-configuration.md#group-scopes) set (modern format), the HTML page
lists them under per-group headings (with an "Ungrouped" bucket) and the JSON carries a `group`
field per host. See
[Operating](07-operating.md) for how to publish and serve the status file.

---

## Loss-tolerant ping and the Degraded status **(all formats)**

A normal ping counts a host up on the first reply. Loss-tolerant ping sends several echoes and
requires a minimum number of replies:

```bash
sudo psysmon --config /etc/psysmon.conf --send-pings 5 --min-pings 3
```

- `--send-pings N` — echoes sent per ping check.
- `--min-pings M` — replies required to count the host up.

The `config send_pings` / `config min_pings` directives set these globally in the **modern** format;
a **legacy** config has no such directives, so set them with the CLI flags above. (The modern format
also adds **per-object** `send_pings` / `min_pings` — see below.)

With **fewer than `M` but more than zero** replies, the host reports the psysmon-only **`Degraded`**
status — reachable but lossy — instead of flapping between up and `Unpingable`. Zero replies still
reads `Unpingable`. The defaults are `1`/`1`, exactly the previous first-reply-wins behavior, so
nothing changes unless you opt in.

A degraded host shows with its own badge on the status page and does **not** suppress its
dependents (a lossy router still forwards). It is **informational by default** — to make a degraded
result page like a normal outage, add `--page-on-degraded` (or `config page_on_degraded`).

`send_pings` / `min_pings` can also be set **per object** in the modern format (see below).

---

## State persistence (savestate) **(all formats)**

By default a restart forgets what was already down and could re-page outages the operator already
knows about. On-disk state persistence avoids that:

```
config savestate "/var/lib/psysmon/state.json";
```

Equivalent CLI flags: `--state-file PATH` (off when unset), `--state-save-interval SEC` (how often
to flush; default 60, `0` saves only on shutdown), and `--state-max-age SEC` (ignore a state file
older than this on load; default 86400). The file is written atomically and merged back on startup
by `(hostname, type, port)`. A node that was down and already paged stays that way without
re-paging; the re-page timer restarts fresh. A missing, unreadable, wrong-schema, or stale file is
ignored with a log line and the daemon starts clean.

---

## Leveled syslog logging **(all formats)**

psysmon logs operational detail to syslog at selectable verbosity:

```
config loglevel info;        ; warning | info | debug (default info)
config heartbeat 300;        ; "monitoring N hosts" summary interval, seconds (0 disables)
config dnslog 600;           ; DNS-cache stats interval, seconds
```

- `info` (the default) logs host down/recovery and pages, a periodic
  `monitoring N hosts - U up, D down, S suppressed` heartbeat, periodic DNS-cache stats, and
  slow-check durations.
- `debug` adds a per-check result line.

CLI equivalents: `--log-level {warning,info,debug}`, and `-v` / `-vv` as an absolute level
(`-v` = info, `-vv` = debug; `--log-level` wins if both are given). The heartbeat interval is
`--heartbeat SEC` (default 300, `0` disables), the DNS-stats interval is `--dnslog SEC`, and the
slow-check threshold is `--slow-check SEC` (default 30, `0` disables — logs any check that runs at
least that long). The syslog facility itself is `config logging` / `--syslog-facility`
(default `daemon`; `none` disables syslog).

---

## Auto-deployed status-page logo **(all formats)**

On its first publish, the daemon writes its status-page logo (`psysmon-logo.png`) next to the HTML
status file, so a fresh deploy renders the logo without a manual copy step. An existing
`psysmon-logo.png` in the status directory is left untouched, so a custom logo is preserved.
Nothing to configure — it follows wherever `statusfile` points.

---

## Per-object check cadence — `queuetime` / `interval` **(modern config only)**

The global check interval is `config queuetime <sec>` (default 30; CLI `--interval SEC`). The
modern format adds a **per-object** `queuetime` so a critical router can be polled faster than the
long tail:

```
object edge-rtr {
    host "192.0.2.1"; type ping; contact "noc@example.net";
    queuetime 10;            # poll this object every 10s
};
```

A per-object value greater than zero overrides the global default for that object only.

---

## Per-object loss-tolerant ping — `send_pings` / `min_pings` **(modern config only)**

Beyond the global ping tolerance shown earlier, the modern format lets you tune it per object:

```
object edge-rtr {
    host "192.0.2.1"; type ping; contact "noc@example.net";
    send_pings 5;
    min_pings  3;            # this host alone: 5 echoes, 3 replies = up
};
```

Both must be integers ≥ 1 with `min_pings ≤ send_pings`; an invalid pair is warned and falls back
to the globals.

---

## Per-object paging policy — `contact_on` **(modern config only)**

The `contact_on` setting exists globally in all formats (above). The modern format adds a
per-object override that wins over the global value:

```
object noisy-link {
    host "192.0.2.50"; type ping; contact "noc@example.net";
    contact_on down;         # page on outages only for this object
};
```

Values are `down`, `up`, `both`, `none`. An object with no `contact` never pages regardless.

---

## IPv6 ping — `ping6`

Monitor a host over IPv6 with `type ping6`, an ICMPv6 echo. It behaves exactly like `ping` — it
gates dependent children, honors loss-tolerant `send_pings` / `min_pings`, needs the same
raw-socket privilege (root or `CAP_NET_RAW`), and pages the same way — but it resolves the host's
**AAAA** record and sends ICMPv6 echoes:

```
object v6-gw {
    host "gw.example.net"; type ping6; contact "noc@example.net";
};
```

`ping6` is **AAAA-only**: a host with no AAAA record reads `No dns entry` (a resolution failure)
rather than silently falling back to IPv4. The two families are independent — give the same host
both a `ping` and a `ping6` object to watch each separately. A per-object `source` for a `ping6`
check must be an **IPv6** address (`source "2001:db8::5";`); `pingv6` and `icmp6` are accepted
aliases for the type keyword.

> The legacy `sysmon.conf` format accepts `ping6` too — write it positionally
> (`host ping6 label [contact]`), like any other legacy check.

---

## Mail-service checks — `imap`, `pop3s`, `imaps`

Beyond plaintext `pop3` and `smtp`, psysmon adds an IMAP greeting check and the implicit-TLS
variants of POP3 and IMAP:

- **`imap`** reads the server's IMAP greeting and is *up* on a ready `* OK` (or an
  already-authenticated `* PREAUTH`). Add `username`/`password` and it also performs a `LOGIN`,
  reporting a rejected credential as `Bad Auth`. Credentials are optional for `imap`/`imaps`
  (a banner check without them); `pop3`/`pop3s` require them.
- **`pop3s`** and **`imaps`** speak their protocol over **implicit TLS** (TLS from connect). These
  are *reachability* checks — the TLS handshake must succeed, but the certificate is **not**
  verified, so a self-signed or near-expiry cert still reads up.

```
object mail-imaps {
    host "198.51.100.2"; type imaps; contact "noc@example.net";
    # username/password optional — add them to also LOGIN
};
```

Default ports: `pop3s` 995, `imap` 143, `imaps` 993.

> The legacy `sysmon.conf` format accepts these too, positionally: `host pop3s user pass label`,
> `host imaps user pass label`, and `host imap label` (banner) or `host imap user pass label`
> (authenticated) — credentials are optional for `imap`/`imaps`, required for `pop3s`.

---

## Grouping — `group` and the `group { }` scope **(modern config only)**

A `group "name"` attribute labels an object; the status views then list objects under per-group
headings (with an "Ungrouped" bucket) and add a `group` field to the JSON. The full grammar and
precedence are in [Configuration → Group scopes](04-configuration.md#group-scopes).

A top-level `group "NAME" { … }` block additionally gives every member shared default settings:
`source`, `contact`, `contact_on`, `numfailures`, `queuetime`, and the ping pair
`send_pings`/`min_pings` (object-identity attributes like `host`/`type`/`port` stay out — they name
one object). A per-object value always wins over the group default; `send_pings`/`min_pings`
inherit as an atomic pair. The membership attribute works with or without a matching block (a
block-less group is just a display label), and declaration order doesn't matter — defaults are
resolved after the whole file is read.

```
group "dmz" {
    source "192.0.2.9";      # bind DMZ checks to this egress address
}

object mail {
    host "198.51.100.2"; type smtp; port 25;
    group "dmz";             # inherits source "192.0.2.9"
};
```

---

## Clean DNS checks — `dns-query` **(modern config only)**

A `dns` (authoritative) check looks up a name against the target server. In the modern format the
name to query is the `dns-query` attribute (a required field for `dns`, along with a non-empty
`contact`):

```
object auth-ns {
    host "192.0.2.53"; type dns;
    dns-query "www.example.net";
    contact "noc@example.net";
};
```

(`authdns` is accepted as an alias for `type dns`.)

---

## Per-object / per-group outbound source — `source` **(modern config only)**

`source` controls which local address a check's probes go out from. Resolution per object is:
**per-object `source` › the object's group `source` › the per-type default › unbound.** The
source's family must match the check — a `ping6` object takes an IPv6 source, every other check an
IPv4 one.

The per-type default differs:

- **Ping and ping6 (ICMP/ICMPv6) are unbound by default** — they route each probe by destination
  and **ignore the global `config source_ip`** (which is IPv4 anyway). This is the right behavior
  for hosts reached over a VPN or a dynamic interface, and it matches a plain `ping`/`ping6` with
  no `-I`.
- **All other checks** (tcp/udp/smtp/pop3/dns) default to the global `config source_ip` (the
  ACL-egress address), or unbound if none is set.

Set `source` to:

- an **IP address** (`source "203.0.113.5";`) — bind this object's probes to that local address;
  works for ping too (e.g. to pin a stable VPN local address) and for the connection checks. The
  family must match the check: a `ping6` object takes an IPv6 source (`source "2001:db8::5";`),
  every other check an IPv4 one.
- **`auto`** (`source auto;`) — keep this object **unbound** (route by destination) even when a
  group default or `config source_ip` would otherwise bind it. This is the explicit opt-out.

```
object vpn-gw {
    host "198.51.100.1"; type ping;
    source auto;             # route freely (unbound) even if a group default would bind
};
object dmz-mail {
    host "198.51.100.2"; type smtp; port 25;
    source "203.0.113.5";    # bind this connection check to a fixed egress address
};
```

`source` is **not** applied to http/https checks (the underlying HTTP client offers no per-request
source bind); those remain unbound.

---

## The control / query channel — `psysmonctl` / `psysmon-token` **(opt-in)**

psysmon can expose an **opt-in** TCP channel for querying live status and performing runtime
actions — acknowledge an alert, attach a note, trigger a reload — without editing the config. It is
**off by default**; when enabled it binds **`127.0.0.1:2026`** (loopback only) and **refuses to
start on a non-loopback address unless TLS is configured**.

Enable it (CLI for either config format):

```bash
psysmon --config /etc/psysmon.conf --control \
  --control-token-file /etc/psysmon/control.token
```

or in the modern config:

```
config control;                               # enable (off by default)
config control_token_file "/etc/psysmon/control.token";
```

Mutating actions (`ack`, `note`, `reload`) require a **bearer token**; reads (`status`, `version`)
do not. Generate the token with `psysmon-token` (a `0600` file; the daemon never auto-creates it).
With no token file configured, the channel still serves reads but all mutations are disabled
(fail closed). The bundled `psysmonctl` client drives it:

```bash
psysmonctl status                              # sanitized status (JSON) — no token needed
psysmonctl ack  router.example.net ping        # silence paging while this object is down
psysmonctl note web.example.net https 443 "vendor ticket 4711"
psysmonctl reload                              # re-read the config (same as SIGHUP)
```

`ack` suppresses paging while the object stays down (initial page *and* re-pages) and auto-clears
on recovery; `note` attaches operator free-text shown on the status page and in the JSON. Both
survive a reload and a restart. The `status` read serves the same sanitized output as the status
page — stored credentials are never exposed, and there is no remote shutdown command.

Full operational details and the security model are in [Operating](07-operating.md) and the
control-channel documentation.

---

## Availability matrix

| Feature | Legacy | Modern | CLI |
|---|---|---|---|
| Dependency suppression | Yes (`{ }` nesting) | Yes (`dep`) | — (structure is config-only) |
| Multi-parent dependencies (any-path) | — (single parent) | Yes (multiple `dep`) | — (structure is config-only) |
| IPv6 ping + mail checks (`ping6` / `imap` / `pop3s` / `imaps`) | Yes | Yes | — (config-only) |
| Threshold alerting (`numfailures`) | Yes | Yes | `--numfailures` |
| Re-page interval (`pageinterval`) | Yes | Yes | `--pageinterval` |
| Recovery notices | Yes | Yes | — |
| Paging policy (`contact_on`) — global | Yes (`config contact_on`) | Yes (`config contact_on`) | `--contact-on` |
| Paging policy (`contact_on`) — per object | No | Yes | No |
| SMTP email notifier | Yes | Yes | `--smtp-host` / `--smtp-port` / `--mail-from` / `-n` |
| Status output (HTML / text / JSON) | Yes | Yes | `--status-file` / `--status-format` / `--show-up` / `--status-refresh` |
| Status-page logo auto-deploy | Yes | Yes | — (follows `statusfile`) |
| Object grouping on status views | No | Yes (`group`) | No |
| Loss-tolerant ping + Degraded — global | Yes (`config send_pings` / `min_pings`) | Yes (`config send_pings` / `min_pings`) | `--send-pings` / `--min-pings` |
| Loss-tolerant ping — per object | No | Yes (`send_pings` / `min_pings`) | No |
| Page on degraded | Yes (`config page_on_degraded`) | Yes (`config page_on_degraded`) | `--page-on-degraded` |
| State persistence (savestate) | Yes | Yes | `--state-file` / `--state-save-interval` / `--state-max-age` |
| Leveled syslog logging | Yes | Yes | `--log-level` / `-v` / `-vv` / `--heartbeat` / `--dnslog` / `--slow-check` / `--syslog-facility` |
| Per-object check cadence (`queuetime`) | No (global only) | Yes | `--interval` (global only) |
| Per-object page threshold (`numfailures`) | No (global only) | Yes | `--numfailures` (global only) |
| DNS check query name (`dns-query`) | Yes (positional) | Yes (`dns-query`) | — |
| Per-object / per-group `source` | No | Yes | No (global `--source-ip` only) |
| Control channel (`psysmonctl` / `psysmon-token`) | Enable via `config control` or CLI | Enable via `config control` or CLI | `--control` / `--control-bind` / `--control-port` / `--control-token-file` / `--control-tls-cert` / `--control-tls-key` |

See [CLI reference](05-cli-reference.md) and [Appendix A](90-appendices.md) for the complete flag
list, [Configuration](04-configuration.md) for the full directive set, and
[Status codes](08-status-codes.md) for every status string including `Degraded`.
