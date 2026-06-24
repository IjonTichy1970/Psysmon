"""Status page render + atomic publish.

Renders the "Bad Hosts" view — by default only nodes that are down (``lastcheck != OK``),
suppressed children omitted (owner choice) — as a modern dark-themed HTML5 page with the
psysmon logo header, or as a flat text table. Columns match the original: HostName, Type, Port,
Count, Notified, Status, Time Failed, Last Outage.

Atomic publish is preserved from ``textfile.c``: write to a temp file, make it read-only, then
rename it over the target so readers never see a partial file. (The old target's read-only bit
is cleared first so the replace also works on Windows.)

Input is the scheduler's ``node_states()`` — a list of ``(Node, NodeState)``.
"""

from __future__ import annotations

import html
import logging
import os
import tempfile
import time
from importlib import resources

from psysmon import __version__, timefmt
from psysmon.config.model import Node, NodeState, type_to_name
from psysmon.config.settings import Settings
from psysmon.status import Status, errtostr, is_up

NodeStates = list[tuple[Node, NodeState]]

log = logging.getLogger("psysmon.output")

# Bundled in psysmon/assets/; the daemon deploys a copy next to the HTML status file it writes.
_LOGO_NAME = "psysmon-logo.png"

# Palette sampled from the logo: navy background, teal glow, logo green/yellow, alert red.
_CSS = """
:root {
  --bg:#15254A; --panel:#1F3158; --border:#2E4470; --text:#E6ECF7; --muted:#93A4C4;
  --glow:#1D708C; --green:#4CD137; --yellow:#F4D03F; --down:#E84118;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; }
.header { display:flex; align-items:center; gap:22px; padding:18px 26px;
  background:linear-gradient(180deg,#1C2E58,#101D3C); border-bottom:2px solid var(--border); }
.header .glow { display:grid; place-items:center; border-radius:14px;
  background:radial-gradient(circle at center, var(--glow) 0%, transparent 68%); }
.header img.logo { height:104px; width:104px; image-rendering:auto; display:block; }
.header h1 { margin:0; font-size:30px; letter-spacing:1px; }
.header .sub { margin:3px 0 0; color:var(--muted); font-size:14px; }
.bar { display:flex; justify-content:space-between; align-items:center;
  padding:12px 26px; font-size:14px; color:var(--muted); }
.bar .count { font-weight:700; }
.bar .count.down { color:var(--down); }
.bar .count.ok { color:var(--green); }
.wrap { padding:0 26px 26px; }
h2.group { margin:24px 0 8px; font-size:14px; text-transform:uppercase; letter-spacing:.6px;
  color:var(--muted); }
.wrap > table { margin-bottom:6px; }
table { width:100%; border-collapse:collapse; background:var(--panel);
  border:1px solid var(--border); border-radius:10px; overflow:hidden; }
th { text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.6px;
  color:var(--muted); padding:11px 14px; background:#1A2C54;
  border-bottom:1px solid var(--border); }
td { padding:10px 14px; border-bottom:1px solid var(--border); font-size:14px; }
tr:last-child td { border-bottom:none; }
td.host { font-weight:600; }
.badge { display:inline-block; padding:2px 9px; border-radius:999px;
  font-size:12px; font-weight:700; }
.badge.down { background:rgba(232,65,24,.18); color:#FF7A5C; }
.badge.up { background:rgba(76,209,55,.16); color:var(--green); }
.badge.degraded { background:rgba(244,208,63,.18); color:var(--yellow); }
.badge.acked { background:rgba(147,164,196,.20); color:var(--muted); }
.note { margin-top:4px; font-size:12px; color:var(--muted); font-style:italic; }
.mono { font-variant-numeric:tabular-nums; color:var(--muted); }
.ok-panel { background:var(--panel); border:1px solid var(--border); border-radius:10px;
  padding:40px; text-align:center; }
.ok-panel .big { font-size:42px; color:var(--green); margin-bottom:6px; }
.footer { padding:14px 26px 26px; color:var(--muted); font-size:12px; }
"""

_COLUMNS = ("HostName", "Type", "Port", "Count", "Notified", "Status", "Time Failed", "Last Outage")


def _visible(node_states: NodeStates, show_up_also: bool) -> NodeStates:
    """Rows to show: down (or all, if show_up_also), never suppressed children."""
    out: NodeStates = []
    for node, state in node_states:
        if state.suppressed:
            continue
        if is_up(state.lastcheck) and not show_up_also:
            continue
        out.append((node, state))
    return out


def _grouped(rows: NodeStates) -> list[tuple[str, NodeStates]]:
    """Partition visible rows by ``Node.group`` (#20). With no groups in use, returns a single
    unlabelled section so the page renders flat exactly as before; otherwise named groups come
    first (alphabetical), then an "Ungrouped" bucket for objects with no group."""
    buckets: dict[str, NodeStates] = {}
    for node, state in rows:
        buckets.setdefault(node.group, []).append((node, state))
    if set(buckets) <= {""}:
        return [("", rows)]
    no_group = buckets.pop("", [])
    if no_group and "Ungrouped" in buckets:
        buckets["Ungrouped"].extend(no_group)  # operator already named a group "Ungrouped" -> merge
        no_group = []
    sections = [(g, buckets[g]) for g in sorted(buckets)]
    if no_group:
        sections.append(("Ungrouped", no_group))  # synthetic bucket for objects with no group, last
    return sections


def _esc(value: object) -> str:
    return html.escape(str(value))


def _port(node: Node) -> str:
    return str(node.port) if node.port else "—"


def _last_outage(state: NodeState, now_wall: float) -> str:
    """Elapsed time since the node was last up, or "Never" if it has never been seen up.

    A node that is down at first sight keeps ``last_up == 0``; ``elapsed(0, now)`` would
    otherwise render the meaningless span since the Unix epoch.
    """
    if not state.last_up:
        return "Never"
    return timefmt.elapsed(state.last_up, now_wall)


def render_html(
    node_states: NodeStates,
    *,
    org_hostname: str,
    refresh_s: int,
    show_up_also: bool,
    logo_url: str,
    now_wall: float,
) -> str:
    rows = _visible(node_states, show_up_also)
    down = sum(1 for _, s in rows if not is_up(s.lastcheck))

    if rows:
        headers = "".join(f"<th>{h}</th>" for h in _COLUMNS)
        sections = []
        for label, grp in _grouped(rows):
            body = "\n".join(_html_row(node, state, now_wall) for node, state in grp)
            heading = f'<h2 class="group">{_esc(label)}</h2>\n' if label else ""
            sections.append(f"{heading}<table><tr>{headers}</tr>\n{body}\n</table>")
        content = f'<div class="wrap">{"".join(sections)}</div>'
    else:
        content = (
            '<div class="wrap"><div class="ok-panel"><div class="big">✓</div>'
            "<div>All systems operational</div></div></div>"
        )

    if down:
        summary = f'<span class="count down">{down}</span> host{"s" if down != 1 else ""} down'
    else:
        summary = '<span class="count ok">All clear</span>'

    footer = f"psysmon {__version__} · auto-refresh {int(refresh_s)}s"

    return "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en"><head><meta charset="utf-8">',
            f'<meta http-equiv="refresh" content="{int(refresh_s)}">',
            f"<title>Network Status — {_esc(org_hostname)}</title>",
            f"<style>{_CSS}</style></head><body>",
            '<div class="header">'
            f'<div class="glow"><img class="logo" src="{_esc(logo_url)}" alt="psysmon logo"></div>'
            "<div><h1>PSYSMON</h1>"
            f'<p class="sub">Network status for {_esc(org_hostname)}</p></div></div>',
            f'<div class="bar"><div>{summary}</div>'
            f'<div>Updated {_esc(timefmt.clock_time(now_wall))}</div></div>',
            content,
            f'<div class="footer">{_esc(footer)}</div>',
            "</body></html>",
        ]
    )


def _html_row(node: Node, state: NodeState, now_wall: float) -> str:
    if is_up(state.lastcheck):
        badge = "up"
    elif state.lastcheck == Status.DEGRADED:
        badge = "degraded"  # reachable but lossy — its own colour, not the red down badge (#22)
    else:
        badge = "down"
    host = _esc(node.hostname)
    if state.acked:  # operator-acknowledged outage (#68)
        host += ' <span class="badge acked">ACK</span>'
    if state.note:  # operator note (#68) — escaped: it's set via the authenticated control channel
        host += f'<div class="note">{_esc(state.note)}</div>'
    cells = [
        f'<td class="host">{host}</td>',
        f"<td>{_esc(type_to_name(node.check_type))}</td>",
        f'<td class="mono">{_esc(_port(node))}</td>',
        f'<td class="mono">{state.downct}</td>',
        f'<td>{"Yes" if state.contacted else "No"}</td>',
        f'<td><span class="badge {badge}">{_esc(errtostr(state.lastcheck))}</span></td>',
        f'<td class="mono">{_esc(timefmt.clock_time(state.deathtime, never_if_zero=True))}</td>',
        f'<td class="mono">{_esc(_last_outage(state, now_wall))}</td>',
    ]
    return "<tr>" + "".join(cells) + "</tr>"


def render_text(
    node_states: NodeStates, *, org_hostname: str, show_up_also: bool, now_wall: float
) -> str:
    rows = _visible(node_states, show_up_also)
    lines = [
        f"Network status for {org_hostname} — {timefmt.clock_time(now_wall)}",
        f"{'Hostname':<28}{'Type':<8}{'Port':<6}{'Cnt':<5}{'Noti':<5}"
        f"{'Status':<16}{'Time Failed':<16}Last Outage",
    ]
    for label, grp in _grouped(rows):
        if label:
            lines.append(f"== {label} ==")
        for node, state in grp:
            extra = "  [ACK]" if state.acked else ""  # #68
            if state.note:
                extra += f"  note: {state.note}"
            lines.append(
                f"{node.hostname:<28}{type_to_name(node.check_type):<8}{_port(node):<6}"
                f"{state.downct:<5}{'Yes' if state.contacted else 'No':<5}"
                f"{errtostr(state.lastcheck):<16}"
                f"{timefmt.clock_time(state.deathtime, never_if_zero=True):<16}"
                f"{_last_outage(state, now_wall)}{extra}"
            )
    if not rows:
        lines.append("All systems operational.")
    return "\n".join(lines) + "\n"


def publish(content: str, path: str) -> None:
    """Atomically write ``content`` to ``path`` (unguessable temp file -> read-only -> rename).

    The temp file is created with :func:`tempfile.mkstemp` in the target's own directory: an
    unpredictable name opened ``O_CREAT | O_EXCL`` (and ``O_NOFOLLOW`` where the platform
    defines it). This closes a predictable-temp-name / symlink-follow race for the privileged
    writer when the status file lives in a world- or group-writable (e.g. web-served) directory:
    an attacker can neither guess the temp name nor pre-create it as a symlink for the root
    process to follow and overwrite. On any failure before the rename completes the temp file is
    removed, so a mid-write error (disk full, encoding error) never leaves a stray temp behind.
    """
    _atomic_write(path, content.encode("utf-8"))


def _atomic_write(path: str, data: bytes) -> None:
    """Write ``data`` bytes to ``path`` atomically and symlink-safely (see :func:`publish`).

    Shared by the status-file writer and the logo deploy so both get the same unguessable-temp ->
    ``0o444`` -> ``os.replace`` guarantees and the same mid-write cleanup.
    """
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, 0o444)
        if os.name == "nt" and os.path.exists(path):
            try:  # Windows refuses os.replace onto a read-only file; clear the bit first.
                os.chmod(path, 0o644)  # POSIX rename needs no such chmod (and chmod follows
            except OSError:            # a symlink at `path`, so we skip it off Windows).
                pass
        os.replace(tmp, path)
    except BaseException:
        _unlink_quietly(tmp)
        raise


def _unlink_quietly(path: str) -> None:
    """Remove ``path`` if present, clearing a read-only bit first (Windows refuses otherwise)."""
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass
    try:
        os.remove(path)
    except OSError:
        pass


def _ensure_logo(status_path: str) -> None:
    """Drop the bundled logo next to the HTML status file if it isn't already there.

    The page references the logo by a relative ``src``, so it must live in the same directory to
    render. We write it once when missing and never overwrite an existing file (so an operator's
    custom logo is preserved), using the same atomic, symlink-safe write as the status file. Any
    failure is logged and swallowed — a missing or unreadable logo must never stop the status page
    from publishing.
    """
    target = os.path.join(os.path.dirname(status_path) or ".", _LOGO_NAME)
    if os.path.exists(target):
        return
    try:
        data = resources.files("psysmon.assets").joinpath(_LOGO_NAME).read_bytes()
    except (ModuleNotFoundError, OSError) as exc:  # FileNotFoundError is an OSError subclass
        log.warning("psysmon: bundled logo unavailable; status page will lack it (%s)", exc)
        return
    try:
        _atomic_write(target, data)
    except OSError as exc:
        log.warning("psysmon: could not deploy logo to %s (%s)", target, exc)


def render_and_publish(
    node_states: NodeStates, settings: Settings, *, now_wall: float | None = None
) -> None:
    """Render the configured status file (html or text) and publish it atomically."""
    if not settings.status_path:
        return
    now = time.time() if now_wall is None else now_wall
    org = settings.org_hostname or "psysmon"
    if settings.status_html:
        content = render_html(
            node_states,
            org_hostname=org,
            refresh_s=settings.status_refresh_s,
            show_up_also=settings.show_up_also,
            logo_url=_LOGO_NAME,
            now_wall=now,
        )
    else:
        content = render_text(
            node_states, org_hostname=org, show_up_also=settings.show_up_also, now_wall=now
        )
    publish(content, settings.status_path)
    if settings.status_html:
        _ensure_logo(settings.status_path)
