# Control / query channel

psysmon can expose an **opt-in** network channel for querying live status and performing runtime
actions — acknowledge an alert, attach a note, trigger a reload — without editing the config. It
is a security-first replacement for sysmon 0.93's cleartext tcp/1345 protocol (which leaked stored
credentials and had auth-bypass bugs); see issue #69 for the history.

> **Off by default.** Nothing listens unless you enable it. When enabled it binds **`127.0.0.1`**
> (loopback only) on port **`2026`**, and **refuses to start on a non-loopback address unless TLS
> is configured** — so you can't accidentally expose it.

## Enabling it

CLI:

```
psysmon --config /etc/psysmon.conf --control --control-token-file /etc/psysmon/control.token
```

or in a modern config:

```
config control;                               # enable (off by default)
config control_bind "127.0.0.1";              # default; a non-loopback value requires TLS
config control_port 2026;                     # default
config control_token_file "/etc/psysmon/control.token";
# config control_tls_cert "/etc/psysmon/control.crt";   # required for a non-loopback bind
# config control_tls_key  "/etc/psysmon/control.key";
```

(Legacy positional configs enable it via the CLI flags.)

## The token

Mutating actions (`ack`, `note`, `reload`) require a **bearer token**; reads (`status`, `version`)
do not. Generate one with the bundled command (the daemon never auto-creates it):

```
psysmon-token /etc/psysmon/control.token      # writes a random token, mode 0600
psysmon-token /etc/psysmon/control.token --force   # rotate (overwrite) an existing one
```

Point `--control-token-file` / `config control_token_file` at that file. With **no** token file
configured, the channel still serves reads but **all mutations are disabled** (fail closed). The
token file must be `0600` (the daemon refuses a group/world-readable file on POSIX).

## Binding beyond localhost

A non-loopback bind (e.g. to reach the channel from another host) **requires TLS** — set
`control_tls_cert` + `control_tls_key`. If they're missing or fail to load, the daemon refuses to
start rather than exposing a plaintext control channel. TLS provides confidentiality/integrity; the
bearer token is the authentication (client certificates / mTLS are out of scope for now).

## Using `psysmonctl`

```
psysmonctl status                              # the sanitized status (JSON) — no token needed
psysmonctl version
psysmonctl ack  router.example.net ping        # acknowledge an outage (needs --token-file)
psysmonctl note web.example.net  https 443 "vendor ticket 4711"
psysmonctl note web.example.net  https 443 ""  # empty text clears the note
psysmonctl reload                              # re-read the config (same as SIGHUP)

# global options: --host (default 127.0.0.1) --port (2026) --token-file PATH --tls-ca PATH
psysmonctl --token-file /etc/psysmon/control.token ack router.example.net ping
```

Objects are addressed by **hostname + type [+ port]** (the same identity used elsewhere); the port
defaults to `0` (ping). `ack`/`note` report how many objects matched (`not_found` if none).

## What `ack` / `note` do

- **`ack`** sets a per-object flag that **suppresses paging while the object is down** — both the
  initial page and the periodic re-pages. It **auto-clears when the object recovers**, so a *future*
  outage pages normally. It does not change the status code (the object still shows DOWN, with an
  `ACK` badge on the status page). Whether the recovery itself pages still follows `contact_on`.
- **`note`** attaches operator free-text, shown next to the object on the status page (escaped) and
  in the JSON. It persists until cleared.

Both are live state: they survive a SIGHUP reload and a restart (carried with the saved state).

## Security model (summary)

- Loopback-default bind; non-loopback requires TLS or the daemon refuses to start.
- Reads are token-free; mutations require a constant-time-compared bearer token; **no token file ⇒
  mutations disabled**.
- `status` serves the same sanitized output as the status page — **stored credentials are never
  exposed**, and there is no raw-config/secret dump (the 0.93 mistake).
- Bounded: a max request size, per-connection read/write deadlines, and a concurrent-connection cap
  (reject-when-full) so the channel can't starve the monitoring loop.
- Deny-by-default command dispatch; errors return a fixed short code (detail goes to the daemon log
  only, never the wire). **There is no remote shutdown/kill command.**

## Differences from sysmon 0.93

psysmon does **not** revive 0.93's wire protocol or its Java client. The 0.93 channel was
always-on, bound all interfaces, sent stored passwords/SNMP-communities in cleartext (`CONF`/
`SHOWOBJ`), had unauthenticated `SHOWOBJ`/`TRACE`/`ACK`, and exposed remote `KILLIT`/`ABORT`. This
is a clean break: opt-in, loopback-default, token-gated, sanitized output, no remote kill.
