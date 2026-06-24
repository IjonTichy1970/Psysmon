# Configuration

PSYSMON reads a single configuration file (default `/etc/psysmon.conf`, overridable with
`-f/--config`). One daemon understands **two configuration formats**:

- **Legacy positional** — the original `sysmon.conf` grammar. This is the **default**: an
  existing `sysmon.conf` keeps working unchanged.
- **Modern `object{}`** — an opt-in, named-block grammar that is more readable and
  order-independent.

The format is **auto-detected per file**, and the two are never mixed in one file. A file is read
as **modern** when it contains an `object NAME {`, a `root = ...`, or a `set NAME = ...` signal;
anything else — including a file that has only `config` lines, which both formats share — is read
as **legacy**.

This chapter is the canonical reference for both formats and for migrating between them. The CLI
flags that override any of these file settings live in [Appendix A](90-appendices.md) (generated
from the source); precedence is always **CLI > config file > built-in default**. For what the
checks actually do at runtime, see the [feature tour](06-feature-tour.md); for how to run and
reload the daemon, see [Operating PSYSMON](07-operating.md).

> All examples below use RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`,
> `203.0.113.0/24`) and `*.example.net` names. Replace them with your own.

---

## 1. Legacy positional format

The legacy format is **line-oriented and whitespace-tokenized**. Each non-blank, non-comment line
is split into up to seven fields. The first token of a line decides what it is:

- A line whose first token starts with `;` or `#` is a **comment**; blank lines are skipped.
- A line beginning with `config` sets a **global** option (see [config directives](#config-directives-legacy)).
- Any other line is a **host/service stanza**: `hostname  type  <fields...>`.
- A line that is just `}` closes the current dependency block (see [dependency nesting](#dependency-nesting--)).

Check-type keywords are **prefix-matched** (as in the original C `strncmp`), so `tcpfoo` still
matches `tcp`. The historical legacy types that PSYSMON dropped (`imap`, `nntp`, `radius`,
`umichx500`, …) produce a warning and are skipped — they never abort the load. In general the
legacy parser **warns and skips** a bad stanza rather than failing; check the daemon log on startup
for `line N: ...` warnings.

### Field-by-field reference per check type

Every stanza starts with the **hostname** (field 1) and the **type** keyword (field 2). The
remaining positional fields depend on the type. `contact` is the notification address; an absent
contact means **syslog only, no page**.

| Type | Positional fields after `hostname` |
|---|---|
| `ping` | `ping  label  [contact]` |
| `smtp` | `smtp  label  [contact]` |
| `tcp` | `tcp  port  label  [contact]` |
| `udp` | `udp  port  label  [contact]` |
| `www` (HTTP) | `www  url  url_text  label  [contact]` |
| `https` | `https  url  url_text  label  [contact]` |
| `pop3` | `pop3  username  password  label  [contact]` |
| `authdns` (DNS) | `authdns  name  contact` |

Notes confirmed from the parser:

- **`label`** is the original "message" field — a human-readable description.
- **`tcp`/`udp`** require a numeric `port` (a non-numeric or non-positive port skips the stanza).
- **`www`/`https`** take a `url` (the path to GET) and `url_text` (a substring that must appear in
  the response body), then the `label`.
- **`pop3`** takes a `username` and `password`, then the `label`.
- **`authdns`** is special: it takes the DNS `name` to look up and then a **required** `contact` —
  a legacy authdns stanza with no contact is rejected. It has **no** `label` field.
- Default ports are applied automatically where they exist (smtp `25`, pop3 `110`, authdns/DNS
  `53`, www/http `80`, https `443`); ping has none, and tcp/udp require an explicit port.

A trailing `{` opens a dependency block (next section).

```
# hostname          type    fields...                       contact
router.example.net  ping    edge-router                     noc@example.net
mx.example.net      smtp    mail-relay                      noc@example.net
db.example.net      tcp     5432 postgres                   dba@example.net
api.example.net     https   /health OK api-health           noc@example.net
ns1.example.net     authdns example.net                     noc@example.net
```

> Because fields are whitespace-split, a legacy `label` or `url_text` **cannot contain spaces**.
> If you need spaces in a label, that's one good reason to move to the modern format.

### Dependency nesting `{ }`

A stanza followed by a trailing `{` opens a **child block**: the hosts inside it are checked only
while the parent is up. This is **dependency suppression** — when an upstream router goes down, you
get one alert for the router, not a flood for everything behind it. A line that is just `}` closes
the block.

In the legacy grammar **only ping-like parents** (`ping` and `smtp`) may open a `{` block — that
matches the original parser. A `{` on any other type is warned about and its block discarded.
Nesting deeper than 64 levels is rejected with a clean config error.

```
router.example.net  ping  edge-router  noc@example.net  {
    web.example.net    https /health OK  web-health  noc@example.net
    db.example.net     tcp   5432         postgres    dba@example.net
    sw.example.net     ping  access-switch  noc@example.net  {
        host1.example.net  ping  host-1  noc@example.net
    }
}
```

Here `web`, `db`, and `sw` are suppressed when `router` is down; `host1` is additionally suppressed
when `sw` is down.

### `config numfailures` is position-dependent

`config numfailures N` sets how many consecutive failed checks a host must accumulate before it
pages. In the **legacy** format this directive is **position-dependent**: its current value is
snapshotted into every stanza parsed **after** it. It is a running value, not last-wins — change it
again partway down the file and only the stanzas below the second change get the new value.

```
config numfailures 2

router.example.net  ping  edge-router  noc@example.net        # threshold 2

config numfailures 5

flaky.example.net   ping  flaky-link    noc@example.net        # threshold 5
host2.example.net   ping  host-2        noc@example.net        # threshold 5 (still)
```

> This positional behavior is unique to the legacy format. In the modern format `config numfailures`
> is a plain global default and you set per-object thresholds with a `numfailures` attribute — the
> converter relies on this distinction (see [migration](#3-legacy-vs-modern-and-migration)).

### `config` directives (legacy) {#config-directives-legacy}

The legacy parser's `config` line is `config <directive> <value...>`. The directive is
prefix-matched. The complete set the legacy parser accepts:

| Directive | Value | Effect |
|---|---|---|
| `config pageinterval` | minutes | Re-page interval while a host stays down |
| `config numfailures` | integer | Failure threshold (position-dependent — see above) |
| `config logging` | facility \| `none` | Syslog facility; `none` disables syslog |
| `config loglevel` | `warning`\|`info`\|`debug` | Logging verbosity |
| `config dnslog` | seconds | DNS-stats log interval |
| `config dnsexpire` | seconds | DNS cache TTL |
| `config heartbeat` | seconds | "Monitoring N hosts" summary interval |
| `config savestate` | `"path"` | Persist live state to survive restarts (quoted or bare path) |
| `config statusfile` | `html`\|`text` `path` | Status-output format and path |
| `config sleeptime` | — | **Obsolete; ignored** with a warning (use `--interval`) |

Valid syslog facilities are the usual set (`kern`, `user`, `mail`, `daemon`, `auth`, `syslog`,
`lpr`, `news`, `uucp`, `cron`, `authpriv`, `local0`–`local7`); an unknown one warns and falls back
to `daemon`. An unknown `loglevel` falls back to `info`. `config statusfile` needs exactly the two
arguments `<html|text> <path>`.

Anything the legacy format can't express on a line (source-IP binding, per-object intervals,
loss-tolerant ping, control channel, `contact_on`, …) must come from the **command line** with a
legacy config — or you move to the modern format, which has directives for all of them.

---

## 2. Modern `object{}` format

The modern format describes the same monitoring tree as named blocks instead of positions. It is
**order-independent**: declare objects in any order and wire them together by name. A modern file
is recognized by an `object NAME {`, `root = ...`, or `set NAME = ...`.

A minimal example:

```
# Globals
config statusfile html "/var/www/psysmon/status.html";
config pageinterval 18;              # minutes between re-pages while down
set noc = "noc@example.net";         # reuse a value with $noc below

object edge-rtr {
    ip      "192.0.2.1";
    type    ping;
    desc    "edge router";
    contact $noc;
};

object web {
    ip      "192.0.2.10";
    type    https;
    url     "/health";
    urltext "OK";
    desc    "web health";
    contact $noc;
    dep     "edge-rtr";              # only checked while edge-rtr is up
};
```

### Lexical rules

- **Statements end with `;`.** Object and [group](#group-scopes) bodies are delimited by `{ ... }`.
- **Strings are double-quoted** (`"a value"`) with **no escape sequences** — a string cannot
  contain a `"` or span a newline.
- **Barewords** are unquoted runs used for keywords, hostnames, and numbers (`ping`, `192.0.2.1`,
  `443`). A bareword ends at whitespace or one of `" { } = ; #`. Quoting any value is always safe;
  quote it whenever it might contain one of those characters.
- **Comments:** `#` starts a comment to end-of-line anywhere outside a string. A `;` at the start
  of a statement (file start, or right after a `{` or another `;`) also begins a comment, matching
  the legacy `;`/`#` convention — so `;`, `;;`, and `; like this` are comment lines.
- `=` is **optional** in object attributes — `ip "h";` and `ip = "h";` are equivalent — but
  **required** in `set NAME = "...";` and `root = "...";`.
- An **unterminated string** is the one lexical error that aborts the load with a clear message; a
  missing `;` only warns.

### `root` and the object graph

- `root = "name";` is an **optional, informational** hint. It does **not** change the structure
  (roots are determined purely by which objects have no `dep`); naming a nonexistent object just
  warns.
- `object NAME { ... };` defines one monitored host/service. `NAME` is used only to wire `dep`
  edges; it must be unique (a duplicate name warns and is skipped).

### Structural attributes

Inside an object body, attributes are `key value;` pairs:

| Attribute | Value | Applies to | Notes |
|---|---|---|---|
| `ip` | `"host"` | all (**required**) | Hostname or IP to check |
| `type` | keyword | all (**required**) | A check type (below) |
| `port` | integer | tcp/udp (**required**); others optional | 1–65535; omitted ⇒ the type default |
| `desc` | `"text"` | optional | Display label (the legacy `label`) |
| `contact` | `"addr"` | dns (**required**); others optional | Notification address; absent/empty ⇒ syslog only, no page |
| `url` + `urltext` | `"path"`, `"substring"` | http/https (**required**) | Path to GET, and a substring the body must contain |
| `username` + `password` | `"u"`, `"p"` | pop3 (**required**) | POP3 credentials |
| `dns-query` | `"name"` | dns (**required**) | The DNS name to look up |
| `dep` | `"object-name"` | optional | Parent object for dependency suppression |

This table covers the **structural** attributes. An object body can also carry **per-object
override** attributes — `queuetime`, `numfailures`, `send_pings` / `min_pings`, `group`,
`contact_on`, and `source` — documented under [Per-object overrides](#per-object-overrides) below.

**Check types** (`type` keyword): `ping`, `tcp`, `udp`, `smtp`, `pop3`, `dns`, `http`, `https`. For
legacy familiarity, `authdns` is accepted as an alias for `dns` and `www` for `http`. Default
ports: smtp `25`, pop3 `110`, dns `53`, http `80`, https `443` (ping has none; tcp/udp require an
explicit `port`).

**Required fields per type** — an object missing a required field is warned and skipped; the rest
of the config still loads:

| Type | Required attributes |
|---|---|
| `ping`, `smtp` | `ip`, `type` |
| `tcp`, `udp` | `ip`, `type`, `port` |
| `http`, `https` | `ip`, `type`, `url`, `urltext` |
| `pop3` | `ip`, `type`, `username`, `password` |
| `dns` | `ip`, `type`, `dns-query`, `contact` |

### Dependencies and the forest

The config builds a **forest** linked by `dep` edges, reproducing the legacy `{ }` nesting as a
named graph:

- An object with **no `dep`** is a top-level **root**.
- `dep "parent"` makes the object a **child** of `parent`: it is checked only while every ancestor
  ping is up.

Recoverable problems warn and degrade gracefully rather than failing the load:

- **One parent only** (single-`dep` MVP). Listing more than one `dep` warns and keeps the first.
  True named multi-parent (DAG) dependencies are **planned** and not yet implemented.
- An **unknown `dep` target** warns and the object becomes a root.
- A **cycle** warns and the object becomes a root (the forest is kept acyclic).

### Variables — `set` / `$var`

```
set noc  = "noc@example.net";
set fast = "10";
```

`set NAME = "value";` defines a variable. `$NAME` is then expanded **anywhere** it later appears in
a value — a string or a bareword, including as a substring (`"$noc and a note"`). A reference to an
undefined variable is left literal with a warning. Variables must be defined before use.

> **`include` is reserved, not yet supported.** A config that uses `include` is **rejected at load**
> with an error — it's a planned feature, not yet implemented. Do not rely on it working today.

### Per-object overrides

These override the global defaults for one object. An invalid value is warned and ignored (the
object still loads with the global default).

| Attribute | Value | Notes |
|---|---|---|
| `queuetime` | seconds (> 0) | Per-object check interval — poll a critical host faster than the tail |
| `numfailures` | integer (≥ 1) | Per-object page threshold |
| `send_pings` / `min_pings` | integers (≥ 1, `min ≤ send`) | Per-object loss-tolerant ping; an invalid pair falls back to the globals |
| `group` | `"name"` | Operator grouping label (status-page headings + a JSON field); a matching `group "name" { … }` block can give the group default settings — see [Group scopes](#group-scopes) |
| `contact_on` | `down`\|`up`\|`both`\|`none` | Which transitions page this object (overrides global) |
| `source` | `"ip"` \| `auto` | Outbound bind source for this object's check (see below) |

Any other attribute (a typo, or a not-yet-supported key) is warned about and ignored.

**`contact_on`** selects which state transitions send a page — for one object (the attribute) or
globally (`config contact_on …` / `--contact-on`); the per-object value wins:

- `both` *(default)* — page on a host going **down** and on its **recovery**.
- `down` — page on outages only; suppress recovery pages.
- `up` — page on recovery only.
- `none` — never page this object (still monitored and shown on the status page).

An object with no `contact` address never pages regardless of `contact_on`.

### Outbound bind source — `source`

`source` controls which local address a check's probes go out from. The per-object resolution is
**per-object `source` › the object's group `source` › the per-type default › unbound.** The
per-type default differs by check type, and this is a common source of confusion:

- **ping (ICMP) is unbound by default.** The kernel routes each probe by destination, **regardless
  of `config source_ip`**. This matches a plain `ping` with no `-I` and is right for hosts reached
  over a VPN or a dynamic interface.
- **All other checks** (tcp/udp/smtp/pop3/dns) default to the global **`config source_ip`** (the
  ACL-egress address), or unbound if none is set.

Set `source` to:

- an **IPv4 address** (`source "203.0.113.5";`) — bind this object's probes to that local address.
  Works for ping too. (IPv6 source binding is rejected at load; that's planned.)
- **`auto`** (`source auto;`) — keep this object **unbound** (route by destination) even when a
  group default or `config source_ip` would otherwise bind it. This is the explicit opt-out.

> **HTTP/HTTPS exception:** `source` is not applied to http/https checks (the HTTP client offers no
> per-request source bind).

### Group scopes — `group "NAME" { ... }` {#group-scopes}

A top-level `group "NAME" { … }` block gives every object that joins the group (via the
`group "NAME"` attribute) shared default settings. Today it carries `source`; it's a scope, so
future per-group defaults slot in the same way. A per-object value always wins over the group
default, and the membership attribute works with or without a matching block (a block-less group is
just a display label). Group/object declaration order doesn't matter.

```
group "vpn-sites" {
    source auto;            # these hosts route freely (unbound)
};
group "dmz" {
    source "192.0.2.9";     # bind DMZ checks to this egress address
};

object gw {
    ip "198.51.100.1"; type ping;
    group "vpn-sites";      # inherits: source auto
};
object mail {
    ip "198.51.100.2"; type smtp; port 25;
    group "dmz";
    source "203.0.113.5";   # per-object source WINS over the dmz default
};
```

### `config` directives (modern)

Top-level `config <directive> <value>;` lines set runtime options. Each maps to a setting the CLI
can still override (CLI > config file > default). An unknown directive warns and is skipped.

| Directive | Value | Default | Meaning |
|---|---|---|---|
| `config queuetime` | seconds | `30` | Default per-host check interval |
| `config numfailures` | integer | `2` | Default failure threshold (a global baseline — see note) |
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
| `config contact_on` | `down`\|`up`\|`both`\|`none` | `both` | Default transitions that page (per-object override) |
| `config maxqueued` | integer | `50` | Cap on concurrent checks |
| `config source_ip` | `"ip"` | (auto) | Default outbound bind source for **connection** checks. Ping ignores it (ping is unbound by default; see `source`) |
| `config hostname` | `"name"` | (auto) | Org hostname shown in alerts / status page |
| `config sender` / `config from` | `"addr"` | (none) | Alert `From:` address |

`config sleeptime` is obsolete and ignored with a warning (use `queuetime` / `--interval`).

> **Several of these globals have a matching per-object override.** `queuetime`, `numfailures`,
> `send_pings` / `min_pings`, `contact_on`, and `source` can each be set on an individual object to
> override the global default (see [Per-object overrides](#per-object-overrides)). `numfailures` is
> the only one whose *legacy* behavior also differs — it is position-dependent in the legacy format
> (see above), but a plain global default here.

**Control / query channel.** The opt-in control channel ([control channel docs](07-operating.md))
is configured with these directives; it is **off by default** and binds loopback `127.0.0.1:2026`
when enabled, refusing to start on a non-loopback address without TLS:

```
config control;                                       # enable (off by default)
config control_bind "127.0.0.1";                      # default; non-loopback requires TLS
config control_port 2026;                             # default
config control_token_file "/etc/psysmon/control.token";
# config control_tls_cert "/etc/psysmon/control.crt"; # required for a non-loopback bind
# config control_tls_key  "/etc/psysmon/control.key";
```

Generate the bearer token with `psysmon-token`; reads (`status`, `version`) need no token, but
mutations (`ack`, `note`, `reload`) do, and with no token file configured all mutations are
disabled. See the [CLI reference](05-cli-reference.md) for `psysmonctl` and `psysmon-token`.

> **Legacy configs** have no control directives — enable the channel via the CLI flags
> (`--control`, `--control-token-file`, …) instead.

### Reloading (SIGHUP)

On `SIGHUP`, PSYSMON re-reads the config and re-applies the **host tree** — objects, `dep` edges,
and per-object attributes (`queuetime` / `numfailures` and friends) — preserving the live up/down
state of hosts that still exist. **File-level `config` globals are not re-applied on reload**:
intervals, paths, the logging knobs, and the global `queuetime` / `numfailures` baselines take
effect only at startup. To change a global, restart the daemon. See
[Operating PSYSMON](07-operating.md).

---

## 3. Legacy vs. modern, and migration

### Side-by-side

| | Legacy positional | Modern `object{}` |
|---|---|---|
| Default? | **Yes** (and auto-detected) | Opt-in (auto-detected by `object`/`root`/`set`) |
| Structure | Position; `{ }` nesting | Named objects + `dep` edges |
| Spaces in values | No (whitespace-split) | Yes (quoted strings) |
| Dependency parents | ping/smtp only | any type via `dep` |
| `numfailures` | Position-dependent | Global default + per-object attribute |
| Per-object interval / ping counts / `source` / `contact_on` | Not expressible (CLI only) | Per-object attributes |
| Variables / reuse | No | `set` / `$var` |
| Control channel in file | No (CLI only) | `config control_*` |
| Org identity / mail-from in file | No (CLI only) | `config hostname` / `sender` |

### Legacy field ↔ modern attribute mapping (canonical)

This is the canonical mapping table ([Appendix C](90-appendices.md) points here).

| Legacy positional field | Modern attribute | Notes |
|---|---|---|
| `hostname` (field 1) | `ip "host";` | |
| `type` keyword (field 2) | `type keyword;` | `www` → `http`, `authdns` → `dns` (aliases accepted either way) |
| `port` (tcp/udp) | `port N;` | Default ports omitted in modern; kept only for tcp/udp |
| `label` / "message" | `desc "text";` | |
| `contact` | `contact "addr";` | |
| `url`, `url_text` (www/https) | `url "path";`, `urltext "substring";` | |
| `username`, `password` (pop3) | `username "u";`, `password "p";` | |
| `name` (authdns) | `dns-query "name";` | |
| `{ … }` child nesting | `dep "parent";` on the child | Legacy ping/smtp parents become named edges |
| `config numfailures N` (positional) | per-object `numfailures N;` | Resolved onto each object, not replayed as a global |
| `config savestate "path"` | `config savestate "path";` | |
| `config statusfile html /p` | `config statusfile html "/p";` | |
| `config pageinterval/logging/loglevel/dnslog/dnsexpire/heartbeat` | same `config <name>` | Direct equivalents |
| `config sleeptime` | — | Obsolete in both; ignored |

### The converter — `psysmon-convert`

`psysmon-convert` turns an existing positional `sysmon.conf` into the equivalent modern config. It
installs alongside the `psysmon` daemon command:

```bash
psysmon-convert /etc/psysmon.conf -o psysmon.conf.new   # write a file
psysmon-convert /etc/psysmon.conf                       # or print to stdout
psysmon-convert - -o out.conf                           # read legacy from stdin
```

If the command isn't on your `PATH` (for example, you installed into a virtualenv you haven't
activated), use the module form with the **same** Python that has PSYSMON installed:

```bash
/path/to/venv/bin/python -m psysmon.config.convert /etc/psysmon.conf -o psysmon.conf.new
```

It parses the legacy file through PSYSMON's own parser and re-emits it, so the output reflects
PSYSMON's semantics and round-trips to the same monitoring tree:

- `{ }` nesting becomes named `dep` edges.
- The position-dependent `config numfailures` is resolved onto each object as a per-object
  `numfailures` (emitted only where it differs from the assumed default).
- Default ports are dropped; only tcp/udp ports are kept.
- The legacy `authdns` query name is emitted as `dns-query`.
- Object names are derived from hostnames, de-duplicated with a `-N` suffix.

Use `-n N` (`--numfailures`) to tell the converter which default threshold the legacy config
assumed (default `2`). The converter **warns rather than silently dropping coverage** when the
legacy file uses something the modern grammar can't represent faithfully (a port outside 1–65535, a
`numfailures` below 1, or a value containing a `"`). It also warns if the result is **globals-only
with no objects**: an objectless file auto-detects as *legacy*, so add an object or force the
modern parser.

---

## 4. Worked examples

Each check type below is shown in **both formats**. The two columns describe the same check.

### ping

```
# legacy
router.example.net  ping  edge-router  noc@example.net
```

```
# modern
object router {
    ip      "192.0.2.1";
    type    ping;
    desc    "edge router";
    contact "noc@example.net";
};
```

### tcp

```
# legacy  — port is required
db.example.net  tcp  5432  postgres  dba@example.net
```

```
# modern
object db {
    ip      "192.0.2.20";
    type    tcp;
    port    5432;
    desc    "postgres";
    contact "dba@example.net";
};
```

### udp

```
# legacy
ntp.example.net  udp  123  ntp  noc@example.net
```

```
# modern
object ntp {
    ip      "192.0.2.21";
    type    udp;
    port    123;
    desc    "ntp";
    contact "noc@example.net";
};
```

### smtp

```
# legacy  — smtp uses the default port 25
mx.example.net  smtp  mail-relay  noc@example.net
```

```
# modern
object mx {
    ip      "192.0.2.25";
    type    smtp;
    desc    "mail relay";
    contact "noc@example.net";
};
```

### pop3

```
# legacy  — user, password, label  (note: values can't contain spaces)
pop.example.net  pop3  probeuser  probepass  pop3-login  noc@example.net
```

```
# modern
object pop {
    ip       "192.0.2.26";
    type     pop3;
    username "probeuser";
    password "probepass";
    desc     "pop3 login";
    contact  "noc@example.net";
};
```

### authdns / dns

```
# legacy  — name to look up, then the REQUIRED contact (no label field)
ns1.example.net  authdns  example.net  noc@example.net
```

```
# modern  — dns requires both dns-query AND contact
object ns1 {
    ip        "192.0.2.53";
    type      dns;
    dns-query "example.net";
    contact   "noc@example.net";
};
```

### www / http and https

```
# legacy  — url, match-text, label  (no spaces in url_text)
api.example.net  https  /health  OK  api-health  noc@example.net
```

```
# modern  — url + urltext required for http/https
object api {
    ip      "192.0.2.10";
    type    https;
    url     "/health";
    urltext "OK";
    desc    "api health";
    contact "noc@example.net";
};
```

### Topology: a router with dependents

```
# legacy  — only the ping parent opens a { } block
router.example.net  ping  edge-router  noc@example.net  {
    web.example.net  https /health OK  web-health  noc@example.net
    db.example.net   tcp   5432         postgres    dba@example.net
}
```

```
# modern  — flat objects joined by dep
set noc = "noc@example.net";

object router {
    ip "192.0.2.1"; type ping; desc "edge router"; contact $noc;
};
object web {
    ip "192.0.2.10"; type https; url "/health"; urltext "OK";
    desc "web health"; contact $noc;
    dep "router";
};
object db {
    ip "192.0.2.20"; type tcp; port 5432; desc "postgres";
    contact "dba@example.net";
    dep "router";
};
```

`web` and `db` are checked only while `router` is up — one alert for the router, not three.

### Topology: a mail server with SMTP + POP3

```
# legacy
mail.example.net  smtp  mail-submit  noc@example.net
mail.example.net  pop3  probeuser probepass  mail-retrieve  noc@example.net
```

```
# modern  — two objects, same host, distinct names
object mail-smtp {
    ip "198.51.100.2"; type smtp; desc "mail submit"; contact "noc@example.net";
};
object mail-pop3 {
    ip "198.51.100.2"; type pop3;
    username "probeuser"; password "probepass";
    desc "mail retrieve"; contact "noc@example.net";
};
```

### Topology: an HTTP health check with `url` + `urltext`

A health endpoint that must return a known marker string, polled faster than the default and not
re-paged too often:

```
object health {
    ip        "203.0.113.10";
    type      https;
    url       "/healthz";
    urltext   "ready";       # this substring must appear in the response body
    desc      "service health";
    contact   "noc@example.net";
    queuetime 10;            # poll every 10s instead of the 30s default
    numfailures 3;          # require 3 consecutive failures before paging
};
```

---

## See also

- [CLI reference](05-cli-reference.md) and [Appendix A](90-appendices.md) — every command-line flag
  (generated from the source), which overrides any file setting.
- [Feature tour](06-feature-tour.md) — what each check type actually does and the dependency model.
- [Status codes](08-status-codes.md) — the result states a check can report, including PSYSMON's
  `Degraded`.
- [Operating PSYSMON](07-operating.md) — starting, reloading (SIGHUP), and the control channel.
- [Troubleshooting](09-troubleshooting.md) — reading the `line N: ...` config warnings.
