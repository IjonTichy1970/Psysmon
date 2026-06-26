# Status codes

Every check returns one **status code**. Code `0` (`up`) means the service is fully up; every
nonzero code is a distinct failure reason. The code's short text appears in the **Status** column
of the HTML status page and the text status file; the JSON output carries both the integer code
(the `status` field) and that short text (the `status_text` field).

The table below is generated from the daemon's own `psysmon.status` module, so it always matches
the running code.

<!--GEN:status-->

## Up, degraded, and reachable

Two distinctions matter for how a code affects the rest of your monitoring:

- **`up` vs. not** — only code `0` resets an outage and stops paging. A **`Degraded`** host (a
  loss-tolerant ping that got *some* replies but fewer than `min_pings`) is **not** up: it stays
  visible as a problem and does not clear an outage. It pages only if you set `--page-on-degraded`.
- **Reachable (for dependency gating)** — a host's dependents are checked only while the host is
  *reachable*, which means **up _or_ degraded**. A lossy-but-answering router still forwards
  packets, so PSYSMON does not suppress everything behind it; only a fully-down ancestor freezes
  its subtree. See [Feature tour → dependency suppression](06-feature-tour.md) and
  [Troubleshooting](09-troubleshooting.md).

Which codes a given check can produce depends on the check type — e.g. `Unpingable` comes only
from a ping check (`ping` or `ping6`), `Bad Auth` only from POP3, and `Bad Resp` from DNS
(malformed/wrong-source reply) or
HTTP (body missing the expected text). See the [Feature tour](06-feature-tour.md) for what each
check verifies.
