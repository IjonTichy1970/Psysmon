# Modern config format

This is the reference for psysmon's **modern `object{}` configuration format** — the documented
sysmon 0.93 grammar (a single `root`, named `object NAME { ... };` blocks, `dep` edges, `config`
globals, and `set`/`$var` reuse), extended with a few psysmon-specific keys.

The modern format is **opt-in and auto-detected per file**: the classic positional `sysmon.conf`
stays the default and keeps working unchanged. A file is treated as modern when it contains an
`object NAME {`, a `root = ...`, or a `set NAME = ...` signal; an ambiguous file (e.g. only
`config` lines, which both formats share) is parsed as legacy. The two formats are never mixed in
one file.

> Accurate as of psysmon 0.7.0. To migrate an existing config,
> see [Migrating from the legacy format](#migrating-from-the-legacy-format).

## A quick example

```
# Globals
config statusfile html "/var/www/psysmon/status.html";
config pageinterval 18;          # minutes between re-pages while down
set noc = "noc@example.net";     # reuse a value with $noc below

# An edge router and the services that depend on it
object edge-rtr {
    host    "192.0.2.1";
    type    ping;
    desc    "edge router";
    contact $noc;
};

object web {
    host    "192.0.2.10";
    type    https;
    url     "/health";
    urltext "OK";
    desc    "web health";
    contact $noc;
    dep     "edge-rtr";          # only checked while edge-rtr is up
};
```

## Lexical rules

- **Statements** end with `;`. Object bodies are delimited by `{ ... }`.
- **Strings** are double-quoted: `"a value"`. There are **no escape sequences** — a string cannot
  contain a `"` or span a newline.
- **Barewords** are unquoted runs used for keywords, hostnames, and numbers (`ping`, `192.0.2.1`,
  `443`). A bareword ends at whitespace or one of `" { } = ; #`. Quoting any value is always safe;
  quote it whenever it might contain one of those characters.
- **Comments**: `#` starts a comment to end-of-line anywhere outside a string. A `;` at the start
  of a statement (file start, or right after a `{` or `;`) also starts a comment, matching the
  legacy `;`/`#` convention.
- `=` is **optional** in object attributes — `host "h";` and `host = "h";` are equivalent — but
  **required** in `set NAME = "...";` and `root = "...";`.

## Globals — `config` directives

Top-level `config <directive> <value>;` lines set runtime options. Each maps to a setting that
the command line can still override (**precedence: CLI > config file > built-in default**). An
unknown directive is warned and skipped.

| Directive | Value | Default | Meaning |
|---|---|---|---|
| `config queuetime` | seconds | `30` | Default per-host check interval |
| `config numfailures` | integer | `2` | Default consecutive-failure threshold before paging (see note) |
| `config pageinterval` | minutes | `10` | Re-page interval while a host stays down |
| `config statusfile` | `html`\|`text` `"path"` | (off) | Status output format + path |
| `config savestate` | `"path"` | (off) | Persist live state to survive restarts |
| `config statesave_interval` | seconds | `60` | How often to flush the state file (0 = only on exit) |
| `config state_max_age` | seconds | `86400` | Ignore a state file older than this (0 disables) |
| `config logging` | facility \| `none` | `daemon` | Syslog facility (`none` disables syslog) |
| `config loglevel` | `warning`\|`info`\|`debug` | `info` | Logging verbosity |
| `config heartbeat` | seconds | `300` | "Monitoring N hosts" summary interval (0 disables) |
| `config noheartbeat` | (no value) | — | Shorthand for `heartbeat 0` |
| `config dnsexpire` | seconds | `900` | DNS cache TTL |
| `config dnslog` | seconds | `600` | DNS-stats log interval |
| `config send_pings` | integer | `1` | Global echoes per ping check (loss-tolerant ping) |
| `config min_pings` | integer | `1` | Global replies required to count a host up |
| `config page_on_degraded` | (no value) | off | Page on a degraded (partial-loss) ping |
| `config contact_on` | `down`\|`up`\|`both`\|`none` | `both` | Default transitions that page (per-object override; see below) |
| `config maxqueued` | integer | `50` | Cap on concurrent checks |
| `config source_ip` | `"ip"` | (auto) | Default outbound bind source for the **connection** checks (firewall ACLs). Ping ignores it — ping is unbound by default; see the per-object `source` below |
| `config hostname` | `"name"` | (auto) | Org hostname shown in alerts / status page |
| `config sender` / `config from` | `"addr"` | (none) | Alert `From:` address |

`config sleeptime` is obsolete and ignored with a warning (use `queuetime` / `--interval`).

> **`config numfailures` is a global default only.** Unlike the legacy positional format — where
> `config numfailures` is *position-dependent* and snapshots into every subsequently-parsed host —
> the modern global sets the baseline default. To give one object a different threshold, use the
> per-object `numfailures` attribute (below). The converter relies on this distinction.

### Variables — `set` / `$var`

```
set noc = "noc@example.net";
set fast = "10";
```

`set NAME = "value";` defines a variable. `$NAME` is then expanded **anywhere** it appears in a
later value (a string or a bareword), including as a substring (`"$noc and a note"`). A reference
to an undefined variable is left literal with a warning. Variables must be defined before use.

## Objects — `object NAME { ... };`

Each monitored host/service is an `object` with a unique `NAME` (used only to wire `dep` edges).
Inside the block, attributes are `key value;` pairs.

### Structural attributes

| Attribute | Value | Applies to | Notes |
|---|---|---|---|
| `host` | `"host"` | all (**required**) | Hostname or IP to check (`ip` is an accepted synonym) |
| `type` | keyword | all (**required**) | One of the check types below |
| `port` | integer | tcp/udp (**required**); others optional | 1–65535; omitted ⇒ the type default |
| `desc` | `"text"` | optional | Display label |
| `contact` | `"addr"` | dns (**required**, non-empty); others optional | Notification address; where optional, an absent/empty contact ⇒ syslog only (no page) |
| `url` + `urltext` | `"path"`, `"substring"` | http/https (**required**) | Path to GET, and a substring the body must contain |
| `username` + `password` | `"u"`, `"p"` | pop3 (**required**) | POP3 credentials |
| `dns-query` | `"name"` | dns (**required**) | The DNS name to look up |
| `dep` | `"object-name"` | optional | Parent for dependency suppression; **repeatable** for multiple parents (OR / any-path) |

**Check types** (the `type` keyword): `ping`, `ping6`, `tcp`, `udp`, `smtp`, `pop3`, `pop3s`,
`imap`, `imaps`, `dns`, `http`, `https`, `ssh`, `mysql`. `ping` is an ICMP (IPv4) echo and
**`ping6`** an ICMPv6 (IPv6) echo over the host's **AAAA** record (`pingv6`/`icmp6` are accepted
aliases). **`imap`** is an IMAP greeting check (with an optional LOGIN — see below); **`pop3s`/`imaps`**
are the implicit-TLS variants of POP3/IMAP (TLS from connect). **`ssh`** reads the server's `SSH-`
identification banner and **`mysql`** reads the MySQL/MariaDB handshake packet — both protocol-aware
reachability checks (not logins). For legacy familiarity, `authdns` is an alias for `dns` and `www`
for `http`. Default ports: smtp `25`, pop3 `110`, pop3s `995`, imap `143`, imaps `993`, dns `53`,
http `80`, https `443`, ssh `22`, mysql `3306` (ping and ping6 have none; tcp/udp require an explicit
`port`).

**Required fields per type** — an object missing a required field is warned and skipped; the rest
of the config still loads:

| Type | Required attributes |
|---|---|
| `ping`, `ping6`, `smtp`, `imap`, `imaps`, `ssh`, `mysql` | `host`, `type` |
| `tcp`, `udp` | `host`, `type`, `port` |
| `http`, `https` | `host`, `type`, `url`, `urltext` |
| `pop3`, `pop3s` | `host`, `type`, `username`, `password` |
| `dns` | `host`, `type`, `dns-query`, `contact` |

**Mail checks.** `imap` reads the IMAP greeting and is *up* on a ready server; set
`username`/`password` and it also performs a `LOGIN`, reporting a rejected credential as `Bad Auth`.
`pop3s` and `imaps` speak their protocol over **implicit TLS** (TLS from connect). These TLS checks
are *reachability* checks — the handshake must succeed, but the certificate is **not** verified, so
a self-signed or soon-to-expire cert still reads up (certificate-*expiry* monitoring is a separate,
planned check). `pop3`/`pop3s` require `username`/`password`; `imap`/`imaps` take them optionally.

### Per-object overrides (psysmon extensions)

These override the global defaults for a single object. An invalid value is warned and ignored
(the object still loads with the global default).

| Attribute | Value | Notes |
|---|---|---|
| `queuetime` | seconds (> 0) | Per-object check interval — poll a critical host faster than the long tail |
| `numfailures` | integer (≥ 1) | Per-object page threshold |
| `send_pings` / `min_pings` | integers (≥ 1, `min ≤ send`) | Per-object loss-tolerant ping; an invalid pair falls back to the globals |
| `group` | `"name"` | Operator grouping label — groups objects under headings on the status page and adds a `group` field to the JSON. A matching `group "name" { … }` block (below) can also give the group default settings |
| `contact_on` | `down` \| `up` \| `both` \| `none` | Which transitions page this object (overrides the global `config contact_on`; see below) |
| `source` | `"ip"` \| `auto` | Outbound bind source for this object's check (overrides the group default and `config source_ip`; see below) |

Any other attribute (a typo) is warned and ignored.

**`contact_on`** selects which state transitions send a page — for one object (the attribute) or
globally (`config contact_on …` / `--contact-on`); a per-object value overrides the global:

- `both` *(default)* — page on a host going **down** and on its **recovery** (psysmon's historical
  behavior; nothing changes unless you set this).
- `down` — page on outages only; suppress recovery pages.
- `up` — page on recovery only; stay quiet on the way down.
- `none` — never page this object (it's still monitored and shown on the status page).

An object with no `contact` address never pages regardless of `contact_on`.

### Outbound bind source — `source`

`source` controls which local address a check's probes go out from. The resolution, per object, is:

**per-object `source` › the object's group `source` › the per-type default › unbound.**

The per-type default differs:

- **ping and ping6 (ICMP/ICMPv6) are unbound by default** — the kernel routes each probe by
  destination, *regardless of `config source_ip`* (which is IPv4 anyway). This is the right
  behavior for hosts reached over a VPN or a dynamic interface (nothing to track when the local
  address changes), and it matches a plain `ping`/`ping6` with no `-I`.
- **all other checks** (e.g. tcp/udp/smtp/pop3/imap/dns/ssh/mysql) default to the global **`config source_ip`** (the
  ACL-egress address), or unbound if none is set.

Set `source` to:

- an **IP address** (`source "203.0.113.5";`) — bind this object's probes to that local address.
  Works for ping (pin a stable VPN local address) and the connection checks. The source's family
  must match the check: a `ping6` object takes an **IPv6** source (`source "2001:db8::5";`), every
  other check an IPv4 one. A source of the wrong family is warned and the object is left unbound.
- **`auto`** (`source auto;`) — keep this object **unbound** (route by destination) even when a
  group default or `config source_ip` would otherwise bind it. This is the explicit opt-out.

> **HTTP/HTTPS exception:** `source` is not applied to http/https checks — httpx offers no
> per-request source bind. (Production configs use no http checks, so this is documented rather
> than worked around.)

> **Note:** binding a *literal* per-VPN IP is fragile if that address changes across reboots/VPN
> restarts — prefer `auto` (unbound) for such hosts.

### Group scopes — `group "NAME" { ... }`

A top-level `group "NAME" { … }` block gives every object that joins the group (via the
`group "NAME"` attribute) shared default settings: `source`, `contact`, `contact_on`,
`numfailures`, `queuetime`, and the ping pair `send_pings`/`min_pings`. Object-*identity*
attributes (`host`/`ip`, `type`, `port`, `url`/`urltext`, `username`/`password`, `dns-query`,
`desc`) name a single object, so they aren't group defaults — they warn and are ignored inside a
block. A per-object value always wins over the group default; `send_pings`/`min_pings` inherit as
an atomic pair (a member that sets either keeps its own ping-count config). The per-object
`group "NAME"` membership attribute keeps working with or without a matching block (a block-less
group is just a display label), and group/object declaration order doesn't matter — defaults
are resolved after the whole file is read. (One wrinkle: a `dns` object's *required* `contact` must
be set on the object itself — the required-field check runs at parse time, before group defaults
are applied, so a group `contact` won't satisfy it.)

```
group "vpn-sites" {
    source auto;              # these hosts route freely (unbound)
}
group "dmz" {
    source "192.0.2.9";       # bind DMZ checks to this egress address
    contact "noc@example.net";  # shared on-call for every member
    numfailures 3;              # ... and a shared down threshold
}

object gw {
    host "198.51.100.1"; type ping;
    group "vpn-sites";       # inherits: source auto
}
object mail {
    host "198.51.100.2"; type smtp; port 25;
    group "dmz";
    source "203.0.113.5";    # per-object source WINS over the dmz default
}
```

## Dependencies and the monitored graph

The config builds a directed acyclic **graph** of objects linked by `dep` edges — it reproduces the
legacy `{ }` nesting as a named graph and generalizes it to multiple parents:

- An object with **no `dep`** is a top-level **root**.
- `dep "parent"` makes the object a **child** of `parent`: it is checked only while it is *reachable*
  through that parent (**dependency suppression** — an upstream outage raises one alert, not a flood).
- An object may list **multiple `dep` edges**, sitting behind several parents at once. Suppression is
  **OR / any-path**: the object keeps being checked while *any* of its parent paths is up, and is
  suppressed only when *every* path is down. This models a host reachable through redundant upstreams
  (e.g. dual-homed behind two routers) — it stays monitored until both uplinks fail.
- Reachability is transitive and counts a degraded-but-answering parent as a live path; a parent that
  is not a `ping` provides no reachability path of its own.
- `root = "name";` is an **optional, informational** hint. It does not change the structure (roots are
  determined purely by the absence of a resolved `dep`); naming an object that doesn't exist just warns.

A server dual-homed behind two upstream routers — suppressed only if *both* uplinks are down:

```
object rtr-a  { host "rtr-a.example.net"; type ping; };
object rtr-b  { host "rtr-b.example.net"; type ping; };
object server {
    host "server.example.net"; type tcp; port 443;
    dep  "rtr-a";
    dep  "rtr-b";                # reachable via either uplink
};
```

Recoverable problems warn and degrade gracefully rather than failing the load:

- An **unknown `dep` target** warns and that edge is dropped; an object left with no surviving edge
  becomes a root.
- A **cycle** (including a self-`dep`) warns and the offending edge is dropped, keeping the graph acyclic.
- A **duplicate object name** warns and the duplicate is skipped.

## Migrating from the legacy format

A converter turns an existing positional `sysmon.conf` into the equivalent modern config:

```
psysmon-convert /etc/psysmon.conf -o psysmon.conf.new
# or, to stdout:
psysmon-convert /etc/psysmon.conf
```

`psysmon-convert` installs alongside the `psysmon` daemon command. If it isn't on your `PATH` —
e.g. you installed into a virtualenv you haven't activated — use the module form with the **same**
Python that has psysmon installed (the venv's interpreter, not the system one):

```
/path/to/venv/bin/python -m psysmon.config.convert /etc/psysmon.conf -o psysmon.conf.new
```

It parses the legacy file through psysmon's own parser and re-emits it, so the output reflects
psysmon's semantics and round-trips to the same monitoring tree:

- `{ }` nesting becomes named `dep` edges.
- The position-dependent `config numfailures` is resolved onto each object as a per-object
  `numfailures` (emitted only where it differs from the assumed default).
- Default ports are dropped; only tcp/udp ports (which have no default) are kept.
- The legacy `authdns` query name is emitted as `dns-query`.
- Object names are derived deterministically from hostnames, de-duplicated with a `-N` suffix.

Use `-n N` (`--numfailures`) to tell the converter which default threshold the legacy config
assumed (default `2`). The converter warns — rather than silently dropping coverage — when the
legacy file uses something the modern grammar can't represent faithfully (a port outside 1–65535,
a `numfailures` below 1, or a value containing a `"`), and when a globals-only file is produced
(an objectless file auto-detects as *legacy*, so force the modern parser or add an object).

## What psysmon does *not* adopt from sysmon 0.93

psysmon adopts the 0.93 grammar and the keywords that map onto its model, and extends it; it does
**not** chase byte-for-byte 0.93 fidelity. The following are intentionally not supported (each is a
clean warning or a clear refusal, never a silent surprise):

- **`include`** — not yet supported; a config using it is **rejected at load**. (A follow-up,
  M2b, will add it with proper `$var`-across-include scoping.)
- **Dropped check types** — `nntp`, `pop2`, `umichx500`, `radius`, `bootp`, `snmp` warn and skip
  (they were unused in practice and are out of scope for the rewrite). `imap`, `imaps`, `pop3s`, and
  `ping6` are **supported in both formats** (modern and legacy) — see the check types above.
- **The 0.93 control/query protocol, client tooling interop, and the phone-home heartbeat** — these
  were removed from psysmon entirely (the original's unauthenticated control server dumped stored
  credentials in cleartext), and the modern grammar carries no keywords for them.

## Differences from sysmon 0.93 defaults

psysmon keeps its own default values rather than 0.93's — converted and newly-written configs
behave like psysmon, not like 0.93:

| Setting | psysmon | sysmon 0.93 |
|---|---|---|
| Check interval (`queuetime`) | **30s** | 60s |
| Failure threshold (`numfailures`) | **2** | 4 |

`contact_on` defaults to **`both`** — psysmon's own historical page-on-down-and-recovery
behavior — so adopting it changes nothing by default. Its values (`down` / `up` / `both` /
`none`) are covered in the per-object overrides section above.

## Reloading (SIGHUP)

On `SIGHUP`, psysmon re-reads the config and re-applies the **host tree** — objects, `dep` edges,
and per-object attributes — preserving the live up/down state of hosts that still exist.

**File-level `config` globals are not re-applied on reload.** Intervals, paths, the logging knobs
(`loglevel` / `heartbeat` / `dnslog`), and the global `queuetime` / `numfailures` baselines take
effect only at startup; changing one and sending `SIGHUP` has no effect — **restart the daemon**.
(Per-object `queuetime` / `numfailures` *do* reload, because they live on the objects.) Re-merging
global overrides on reload is a possible future enhancement.

## See also

- `README.md` — overview and getting started.
- `INSTALL.md` — installation and a systemd unit.
- The legacy positional format remains fully supported and documented in those files; this
  document covers only the modern format.
