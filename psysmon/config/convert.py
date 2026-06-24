"""Legacy ``sysmon.conf`` -> modern ``object{}`` converter (#3 milestone 5).

This is a :class:`ParseResult` *serializer*, not a port of upstream ``misc/convert-old-to-new.pl``:
it parses a legacy positional config through psysmon's own :func:`psysmon.config.legacy.parse`
and re-emits the resulting node forest + globals in the modern grammar, so the output reflects
psysmon's semantics. The contract is a round-trip: ``parse_legacy(text)`` and
``parse_modern(to_modern(...))`` produce an equivalent forest.

Key transforms (the modern format is order-independent, so a legacy ``{}`` tree becomes a flat
list of objects joined by named ``dep`` edges):

* ``{}`` nesting          -> named ``dep "<parent>";`` edges
* position-dependent      -> per-object ``numfailures N;`` (only where a node's resolved
  ``config numfailures``     ``max_down`` differs from the assumed default; the legacy global is
                             NOT replayed, since modern's ``config numfailures`` is a Settings
                             override, not a per-node baseline. The legacy file's last value also
                             lives in ``overrides['numfailures']``; dropping it is lossless — the
                             engine reads only per-node ``max_down``.)
* default ports           -> omitted (emitted only for tcp/udp, which have no default)
* legacy ``authdns name`` -> ``dns-query`` (the name lives in ``Node.username``)

Run it as ``python -m psysmon.config.convert <legacy.conf> [-o out.conf]`` (stdout by default).
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .legacy import ParseResult
from .legacy import parse as parse_legacy
from .model import DEFAULT_PORT, CheckType, Node

# CheckType -> the modern `type` keyword to emit (the aliases www/authdns are input-only).
_TYPE_KW: dict[CheckType, str] = {
    CheckType.PING: "ping",
    CheckType.TCP: "tcp",
    CheckType.UDP: "udp",
    CheckType.SMTP: "smtp",
    CheckType.POP3: "pop3",
    CheckType.DNS: "dns",
    CheckType.HTTP: "http",
    CheckType.HTTPS: "https",
}

# Settings field -> (modern `config` keyword, emit-kind), in a fixed output order. `numfailures`
# is intentionally absent: it is resolved into per-object attributes, never a global.
_GLOBAL_ORDER: list[tuple[str, str, str]] = [
    ("source_ip", "source_ip", "str"),
    ("org_hostname", "hostname", "str"),
    ("mail_from", "sender", "str"),
    ("pageinterval_min", "pageinterval", "int"),
    ("interval_s", "queuetime", "num"),
    ("send_pings", "send_pings", "int"),
    ("min_pings", "min_pings", "int"),
    ("dnsexpire_s", "dnsexpire", "int"),
    ("dnslog_s", "dnslog", "int"),
    ("heartbeat_s", "heartbeat", "int"),
    ("statesave_s", "statesave_interval", "int"),
    ("state_max_age_s", "state_max_age", "int"),
    ("max_concurrency", "maxqueued", "int"),
    ("state_path", "savestate", "str"),
    ("log_level", "loglevel", "bareword"),
    ("page_on_degraded", "page_on_degraded", "flag"),
]

# Object names are barewords; anything the tokenizer would treat as special/whitespace is unsafe.
_NAME_BAD = re.compile(r'["{}=;#\s]')


def _fmt_num(value: object) -> str:
    """Render a number without a trailing ``.0`` (``30.0`` -> ``30``)."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


class _Serializer:
    def __init__(self, default_numfailures: int) -> None:
        self._seed = default_numfailures
        self._lines: list[str] = []
        self._warnings: list[str] = []
        self._used: set[str] = set()
        self._names: dict[int, str] = {}

    def run(self, result: ParseResult) -> tuple[str, list[str]]:
        self._header()
        self._emit_globals(result.overrides)
        if self._lines[-1] != "":
            self._line("")
        for root in result.roots:
            self._walk(root, None)
        if not result.roots and any(line.startswith("config ") for line in self._lines):
            self._warn("output has globals but no objects; detect() routes an objectless file to "
                       "the legacy parser — force the modern parser or add an object")
        text = "\n".join(self._lines).rstrip("\n") + "\n"
        return text, self._warnings

    # --- emission helpers -------------------------------------------------------------
    def _line(self, text: str) -> None:
        self._lines.append(text)

    def _warn(self, message: str) -> None:
        self._warnings.append(message)

    def _quote(self, value: str) -> str:
        """The modern string grammar has no escapes — a value cannot contain ``"`` or a newline.
        These never occur in a whitespace-tokenized legacy field, but strip + warn defensively."""
        if '"' in value or "\n" in value or "\r" in value:
            self._warn(f"value {value!r} contains a quote/newline (unrepresentable); stripped")
            value = value.replace('"', "").replace("\n", " ").replace("\r", " ")
        return value

    def _attr(self, key: str, value: str) -> None:
        self._line(f'  {key} "{self._quote(value)}";')

    def _header(self) -> None:
        self._line("# Converted from a legacy sysmon.conf by psysmon.config.convert (#3).")
        self._line("# Per-object 'numfailures' is emitted only where it differs from the assumed")
        self._line(f"# default of {self._seed}; '{{}}' nesting becomes named 'dep' edges.")
        self._line("")

    def _emit_globals(self, overrides: dict[str, object]) -> None:
        o = dict(overrides)
        # statusfile is a (format, path) pair across two override keys.
        if "status_path" in o:
            fmt = "html" if o.get("status_html", True) else "text"
            self._line(f'config statusfile {fmt} "{self._quote(str(o["status_path"]))}";')
        o.pop("status_path", None)
        o.pop("status_html", None)
        if "syslog_facility" in o:
            fac = o.pop("syslog_facility")
            self._line(f"config logging {fac if fac is not None else 'none'};")
        # numfailures is resolved per-object, never a global; drop it before the leftover check.
        o.pop("numfailures", None)
        for field, kw, kind in _GLOBAL_ORDER:
            if field not in o:
                continue
            val = o.pop(field)
            if kind == "flag":
                if val:
                    self._line(f"config {kw};")
            elif kind == "str":
                self._line(f'config {kw} "{self._quote(str(val))}";')
            elif kind == "num":
                self._line(f"config {kw} {_fmt_num(val)};")
            elif kind == "bareword":
                self._line(f"config {kw} {val};")
            else:  # int
                self._line(f"config {kw} {int(val)};")
        for leftover in o:
            self._warn(f"global override '{leftover}' has no modern directive; omitted")

    # --- forest -----------------------------------------------------------------------
    def _assign(self, node: Node) -> str:
        base = _NAME_BAD.sub("_", node.hostname) or "obj"
        name, n = base, 2
        while name in self._used:
            name = f"{base}-{n}"
            n += 1
        self._used.add(name)
        self._names[id(node)] = name
        return name

    def _walk(self, node: Node, parent_name: str | None) -> None:
        name = self._assign(node)  # parent is named before its children (dep targets resolve)
        self._emit_object(node, name, parent_name)
        for child in node.children:
            self._walk(child, name)

    def _emit_object(self, node: Node, name: str, parent_name: str | None) -> None:
        self._line(f"object {name} {{")
        self._attr("ip", node.hostname)
        self._line(f"  type {_TYPE_KW[node.check_type]};")
        if node.port and node.port != DEFAULT_PORT.get(node.check_type):
            if node.check_type in (CheckType.TCP, CheckType.UDP) and not 1 <= node.port <= 65535:
                self._warn(f"object '{name}': port {node.port} is outside 1..65535; the modern "
                           "parser will reject this object on load")
            self._line(f"  port {node.port};")
        if node.check_type in (CheckType.HTTP, CheckType.HTTPS):
            self._attr("url", node.url)
            self._attr("urltext", node.url_text)
        elif node.check_type is CheckType.POP3:
            self._attr("username", node.username)
            self._attr("password", node.password)
        elif node.check_type is CheckType.DNS:
            self._attr("dns-query", node.username)  # legacy stores the query name in `username`
        if node.label:
            self._attr("desc", node.label)
        if node.contact:
            self._attr("contact", node.contact)
        if node.group:
            self._attr("group", node.group)
        if node.contact_on:
            self._attr("contact_on", node.contact_on)
        if node.max_down != self._seed:
            if node.max_down < 1:
                self._warn(f"object '{name}': numfailures {node.max_down} < 1 is not representable "
                           "in modern; on load the threshold falls back to the default")
            self._line(f"  numfailures {node.max_down};")
        if node.interval is not None:
            self._line(f"  queuetime {_fmt_num(node.interval)};")
        if node.send_pings is not None:
            self._line(f"  send_pings {node.send_pings};")
        if node.min_pings is not None:
            self._line(f"  min_pings {node.min_pings};")
        if parent_name is not None:
            self._attr("dep", parent_name)
        self._line("};")
        self._line("")


def to_modern(result: ParseResult, *, default_numfailures: int = 2) -> tuple[str, list[str]]:
    """Serialize a parsed forest + globals to modern ``object{}`` text. Returns (text, warnings)."""
    return _Serializer(default_numfailures).run(result)


def convert(text: str, *, numfailures: int = 2) -> tuple[str, list[str]]:
    """Parse a legacy config and return its modern equivalent + all warnings (parse + serialize)."""
    result = parse_legacy(text, numfailures=numfailures)
    modern, warns = to_modern(result, default_numfailures=numfailures)
    return modern, list(result.warnings) + warns


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m psysmon.config.convert",
        description="Convert a legacy positional sysmon.conf to the modern object{} format.",
    )
    ap.add_argument("input", help="legacy config path (use '-' for stdin)")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    ap.add_argument(
        "-n", "--numfailures", type=int, default=2,
        help="default failure threshold the legacy config assumes (default: 2)",
    )
    args = ap.parse_args(argv)
    try:
        if args.input == "-":
            text = sys.stdin.read()
        else:
            text = Path(args.input).read_text(encoding="utf-8-sig")  # strips a leading BOM
        text = text.removeprefix("\ufeff")  # utf-8-sig covers files; this covers a BOM on stdin
        modern, warnings = convert(text, numfailures=args.numfailures)
        if args.output:
            Path(args.output).write_text(modern, encoding="utf-8")
    except (OSError, ValueError) as e:  # ParseError subclasses ValueError; OSError = bad path/write
        print(f"psysmon: {e}", file=sys.stderr)
        return 1
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not args.output:
        sys.stdout.write(modern)
    return 0


if __name__ == "__main__":  # python -m psysmon.config.convert
    sys.exit(main())
