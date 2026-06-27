"""Parser for the original ``sysmon.conf`` grammar.

Faithfully reproduces ``loadconfig.c``/``parseline``:

* Lines are whitespace-tokenized (up to 7 fields, like ``sscanf("%s"*7)``).
* A line whose first token starts with ``;`` or ``#`` is a comment; blank lines are skipped.
* ``}`` closes the current block; a trailing ``{`` opens a recursive **child block** (only on
  the ping-like branch — ping/smtp — as in the original).
* ``config <directive> ...`` sets globals: the original ``statusfile``, ``pageinterval``
  (minutes), ``logging``, ``dnslog``, ``dnsexpire``, ``numfailures``, ``savestate``,
  ``sleeptime`` — plus the post-rewrite globals (``contact_on``, ``source_ip``, ``queuetime``,
  ``send_pings``/``min_pings``, ``page_on_degraded``, the ``control*`` family, ...) which reuse
  the modern parser's directive tables so both formats accept the same set (#93).
* **``numfailures`` is position-dependent** — its current value snapshots into each
  subsequently-parsed node's ``max_down`` (a running value, not last-wins).
* Per-type field positions exactly as in C (ping/ping6/smtp: label[,contact][,``{``];
  tcp/udp: port,label[,contact]; www/https: url,label[,contact] (reachability) or
  url,url_text,label[,contact] (content); pop3/pop3s/imap/imaps: label[,contact] (banner) or
  user,pass,label[,contact] (auth); authdns: name,contact).
* Dropped legacy types (nntp, radius, umichx500, ...) -> warn and skip; never hard-fail.
* Keyword matching is prefix-based, like the original ``strncmp`` (so ``tcpfoo`` matches
  ``tcp``).

Deliberate departures from the C, all fixes/hardening:

* DNS resolution is **deferred to runtime** — unresolvable hosts still produce a node (the C
  silently dropped them, and a ping parent dropped its already-parsed subtree).
* A trailing ``{`` is split off *before* field parsing and the 7-field cap, so it can never be
  mistaken for a positional field (contact/label) nor dropped by truncation — either of which
  would detach a subtree and unbalance the rest of the file. A non-ping line's stray block is
  still consumed and discarded with a warning.
* ``{`` nesting is capped at :data:`_MAX_NESTING_DEPTH`; a deeper config raises
  :class:`ParseError` (a clean config error) instead of an uncaught ``RecursionError``.

``parse`` returns a :class:`ParseResult` carrying the root nodes, a dict of config-file
settings overrides (to feed :func:`psysmon.config.settings.merge`), and collected warnings.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass, field

from psysmon.config.model import CONTACT_ON_CHOICES, DEFAULT_PORT, SOURCE_AUTO, CheckType, Node

# Valid syslog facilities (from match_facility in loadconfig.c); "none" disables logging.
_FACILITIES = frozenset(
    "kern user mail daemon auth syslog lpr news uucp cron authpriv "
    "local0 local1 local2 local3 local4 local5 local6 local7".split()
)

# Post-rewrite string globals whose value is a filesystem path that may be quoted / contain
# spaces — join the remaining tokens and strip a surrounding quote pair, the same way savestate
# does, so a whitespace-split quoted path survives (#93). Other string globals take one token.
_PATH_STR_GLOBALS = frozenset({"control_token_file", "control_tls_cert", "control_tls_key"})

# Check-type keywords in the original dispatch order, prefix-matched like the C strncmp.
# A None value marks a type the legacy parser does not handle (warn + skip). ORDER MATTERS: a
# longer keyword sharing a prefix MUST precede the shorter one or it gets swallowed — the v6 ping
# keywords before "ping", and "pop3s"/"imaps" before "pop3"/"imap" (else "pop3s" would silently
# become plaintext "pop3"). ping6 + the mail types (imap/imaps/pop3s) are accepted natively (#94);
# imap was an original legacy type (loadconfig.c type 7), the rest are post-rewrite additions.
_TYPE_KEYWORDS: tuple[tuple[str, CheckType | None], ...] = (
    ("ping6", CheckType.PING6), ("pingv6", CheckType.PING6),  # before "ping"!
    ("icmp6", CheckType.PING6),
    ("ping", CheckType.PING),
    ("pop3s", CheckType.POP3S), ("imaps", CheckType.IMAPS),  # before "pop3"/"imap"! (TLS)
    ("pop3", CheckType.POP3),
    ("imap", CheckType.IMAP),
    ("tcp", CheckType.TCP),
    ("udp", CheckType.UDP),
    ("nntp", None),
    ("smtp", CheckType.SMTP),
    ("umichx500", None),
    ("www", CheckType.HTTP),
    ("authdns", CheckType.DNS),
    ("radius", None),
    ("https", CheckType.HTTPS),
    ("ssh", CheckType.SSH),        # #96
    ("mysql", CheckType.MYSQL),    # #97
    ("ftps", CheckType.FTPS),      # before "ftp"! (TLS) (#102)
    ("ftp", CheckType.FTP),
    ("telnet", CheckType.TELNET),  # #106
)

# Types whose stanza may open a `{` child block: the original's ping-like branch (ping, smtp) plus
# ping6 — an ICMPv6 ping that can gate a dependency subtree exactly like ping (#94).
_PING_LIKE = frozenset({CheckType.PING, CheckType.PING6, CheckType.SMTP})

# Hard cap on `{` nesting depth. Real dependency trees are only a handful deep; anything past
# this is malformed/pathological, and recursing further risks Python's RecursionError surfacing
# as an uncaught startup crash. Past the cap we raise ParseError (see the daemon's handling).
_MAX_NESTING_DEPTH = 64


class ParseError(ValueError):
    """A config the parser refuses (e.g. nesting past :data:`_MAX_NESTING_DEPTH`).

    Subclasses ``ValueError`` so the daemon's startup handler reports it as a clean
    ``psysmon: ...`` config error rather than crashing with a traceback.
    """


@dataclass(slots=True)
class ParseResult:
    """Outcome of parsing a legacy config."""

    roots: list[Node]
    overrides: dict[str, object] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def parse(text: str, *, numfailures: int = 2) -> ParseResult:
    """Parse legacy config ``text`` into a forest of root :class:`Node`s.

    ``numfailures`` is the starting threshold (the caller passes the effective default — a CLI
    override or the built-in 2); ``config numfailures`` lines update it for subsequent nodes.
    """
    parser = _Parser(text.splitlines(), numfailures)
    roots = parser.parse_block()
    return ParseResult(roots=roots, overrides=parser.overrides, warnings=parser.warnings)


def _match_type(token: str) -> tuple[CheckType | None, str | None]:
    """Return (check type, matched keyword). type=None+keyword set => dropped; both None => bad."""
    for keyword, ctype in _TYPE_KEYWORDS:
        if token.startswith(keyword):
            return ctype, keyword
    return None, None


def _as_port(token: str) -> int | None:
    """``token`` as a port number if it is an integer in 1..65535, else None — used to detect the
    optional leading port for ssh/mysql (#96/#97); a non-numeric token is the label instead."""
    try:
        port = int(token)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


class _Parser:
    """Recursive-descent parser mirroring the original ``parseline`` recursion."""

    def __init__(self, lines: list[str], numfailures: int) -> None:
        self._lines = list(enumerate(lines, start=1))
        self._pos = 0
        self.numfailures = numfailures
        # Position-dependent ("sticky") per-object defaults (#95): each snapshots into every
        # subsequently-parsed node, exactly like numfailures. Seeded to each Node field's "unset"
        # sentinel so a node parsed before any such directive inherits the global default at check
        # time (the engine falls back to the Settings value when the per-node field is unset).
        self.contact_on = ""
        self.source: str | None = None
        self.send_pings: int | None = None
        self.min_pings: int | None = None
        self.interval: float | None = None
        self.overrides: dict[str, object] = {}
        self.warnings: list[str] = []

    def _warn(self, lineno: int, message: str) -> None:
        self.warnings.append(f"line {lineno}: {message}")

    def _next(self) -> tuple[int, str] | None:
        if self._pos >= len(self._lines):
            return None
        item = self._lines[self._pos]
        self._pos += 1
        return item

    def parse_block(self, depth: int = 0) -> list[Node]:
        """Parse sibling stanzas until a ``}`` closes this block (or EOF).

        ``depth`` is the current ``{`` nesting level; exceeding :data:`_MAX_NESTING_DEPTH`
        raises :class:`ParseError` instead of letting Python's recursion limit surface as an
        uncaught ``RecursionError`` during startup.
        """
        if depth > _MAX_NESTING_DEPTH:
            raise ParseError(
                f"configuration nesting exceeds the maximum depth of {_MAX_NESTING_DEPTH}"
            )
        siblings: list[Node] = []
        while True:
            item = self._next()
            if item is None:
                return siblings
            lineno, raw = item
            tokens = raw.split()

            if not tokens:
                continue
            if tokens[0][0] in ";#":
                continue
            if tokens[0] == "}":
                if depth > 0:
                    return siblings
                # A '}' with no open block would otherwise end parsing of the ENTIRE rest of the
                # file silently; warn and skip it so trailing stanzas still parse.
                self._warn(lineno, "unexpected '}' at top level; ignoring")
                continue

            # Split off a trailing block-open BEFORE the 7-field cap or any field parsing, so the
            # `{` can't be dropped by truncation (detaching a subtree + unbalancing the rest of
            # the file) nor land in a positional field such as contact or label.
            opens_block = tokens[-1] == "{"
            if opens_block:
                tokens = tokens[:-1]

            if len(tokens) > 7:
                self._warn(lineno, "too many fields; using the first 7")
                tokens = tokens[:7]

            # A line that is only a block-open (`{`) strips to an empty token list above; it has no
            # stanza or directive, so warn + drain it (keeping braces balanced) before any dispatch
            # that indexes tokens[0]. (Matches the original `< 3 fields` handling for this case.)
            if not tokens:
                self._warn(lineno, "not enough fields; skipping")
                if opens_block:
                    self.parse_block(depth + 1)  # drain the orphaned block; keep braces balanced
                continue
            # `config` is dispatched before the 3-field minimum: a valueless flag global (e.g.
            # `config control`, #93) is a legitimate 2-token line. `_handle_config` owns its own
            # arity checks; host lines still require >= 3 fields (the guard just below).
            if tokens[0] == "config":
                self._handle_config(lineno, tokens)
                if opens_block:
                    self._warn(lineno, "a config line cannot open a block; ignoring the '{'")
                    self.parse_block(depth + 1)
                continue
            if len(tokens) < 3:
                self._warn(lineno, "not enough fields; skipping")
                if opens_block:
                    self.parse_block(depth + 1)  # drain the orphaned block; keep braces balanced
                continue

            node = self._parse_host(lineno, tokens)
            if node is None:
                if opens_block:
                    self.parse_block(depth + 1)  # drain a skipped stanza's block
                continue
            siblings.append(node)
            if opens_block:
                if node.check_type in _PING_LIKE:
                    node.children = self.parse_block(depth + 1)
                else:
                    self._warn(lineno, f"{node.check_type} cannot have children; ignoring block")
                    self.parse_block(depth + 1)

    def _parse_host(self, lineno: int, tokens: list[str]) -> Node | None:
        host = tokens[0]
        ctype, keyword = _match_type(tokens[1])
        if ctype is None:
            if keyword is not None:  # recognized but unsupported (nntp/radius/umichx500)
                self._warn(lineno, f"unsupported check type {keyword!r}; skipping")
            else:
                self._warn(lineno, f"invalid check type {tokens[1]!r}; skipping")
            return None

        n = len(tokens)
        # Snapshot the position-dependent defaults in effect at this point in the file (#95) — the
        # numfailures precedent, generalized. Unset sentinels (default) leave each field inheriting
        # the global at check time, so a config with no sticky directives is byte-identical.
        node = Node(
            hostname=host,
            check_type=ctype,
            max_down=self.numfailures,
            contact_on=self.contact_on,
            send_pings=self.send_pings,
            min_pings=self.min_pings,
            interval=self.interval,
            source=self._source_for(ctype, lineno),
        )
        default_port = DEFAULT_PORT.get(ctype)
        if default_port is not None:
            node.port = default_port

        if ctype in (CheckType.TCP, CheckType.UDP):
            if n < 4:
                self._warn(lineno, f"{ctype} needs a port and label; skipping")
                return None
            try:
                port = int(tokens[2])
            except ValueError:
                self._warn(lineno, f"invalid port {tokens[2]!r}; skipping")
                return None
            if port <= 0:
                self._warn(lineno, f"invalid port {tokens[2]!r}; skipping")
                return None
            node.port = port
            node.label = tokens[3]
            if n >= 5:
                node.contact = tokens[4]
        elif ctype in (CheckType.HTTP, CheckType.HTTPS):
            # match-text (url_text) is OPTIONAL (#104). The 4-token form `host www url label` is a
            # reachability probe (no match text; url_text stays None). 5+ tokens keep the original
            # `url url_text label [contact]` meaning, so existing configs are unchanged — a
            # reachability check that also wants a contact isn't expressible positionally (a 5-token
            # line reads the middle field as url_text); use the modern format for that.
            if n < 4:
                self._warn(lineno, f"{ctype} needs a url and label; skipping")
                return None
            if n == 4:
                node.url, node.label = tokens[2], tokens[3]
            else:
                node.url, node.url_text, node.label = tokens[2], tokens[3], tokens[4]
                if n >= 6:
                    node.contact = tokens[5]
        elif ctype in (CheckType.POP3, CheckType.POP3S, CheckType.IMAP, CheckType.IMAPS,
                       CheckType.FTP, CheckType.FTPS):
            # The mail/ftp checks mirror each other: credentials are OPTIONAL (#88 imap, #101 pop3,
            # #102 ftp). A short line (`host ftp label [contact]`) is a banner-only check; a full
            # `host ftp user pass label [contact]` line adds an authenticated probe. The original
            # C pop3/imap required user/pass, so that always-auth form is the 5-/6-token case here
            # and parses identically.
            if n < 5:
                node.label = tokens[2]
                if n >= 4:
                    node.contact = tokens[3]
            else:
                node.username, node.password, node.label = tokens[2], tokens[3], tokens[4]
                if n >= 6:
                    node.contact = tokens[5]
        elif ctype is CheckType.DNS:  # authdns
            if n < 4:
                self._warn(lineno, "authdns needs a name and contact; skipping")
                return None
            node.username = tokens[2]  # name to look up
            node.contact = tokens[3]
        elif ctype in (CheckType.SSH, CheckType.MYSQL, CheckType.TELNET):
            # Optional leading numeric port (#96/#97/#106): `host ssh [PORT] label [contact]`. A
            # field after the type that parses as a port (1..65535) is the port; otherwise the label
            # (the default port from DEFAULT_PORT already applies). A purely-numeric label can't be
            # expressed here — use a descriptive label, or set the port in the modern format.
            idx = 2
            port = _as_port(tokens[2])
            if port is not None:
                node.port = port
                idx = 3
            if n <= idx:
                self._warn(lineno, f"{ctype} needs a label; skipping")
                return None
            node.label = tokens[idx]
            if n > idx + 1:
                node.contact = tokens[idx + 1]
        else:  # ping-like: ping, smtp (a trailing '{' was already stripped by parse_block)
            node.label = tokens[2]
            if n > 3:
                node.contact = tokens[3]
                if n >= 5:
                    self._warn(lineno, "unexpected fields after contact; ignoring")
        return node

    def _handle_config(self, lineno: int, tokens: list[str]) -> None:
        if len(tokens) < 2:
            self._warn(lineno, "config line needs a directive; skipping")
            return
        directive = tokens[1]
        # The post-rewrite globals reuse the modern parser's directive tables — the single source
        # of truth, so the legacy and modern formats accept the same `config` set (#93). Imported
        # lazily because modern imports this module (this breaks the import cycle).
        from psysmon.config.modern import (
            _FLAG_DIRECTIVES,
            _FLOAT_DIRECTIVES,
            _INT_DIRECTIVES,
            _STR_DIRECTIVES,
        )
        # Valueless flags (control / page_on_degraded / noheartbeat) may be a bare 2-token line;
        # every other directive needs tokens[2], so guard once here and the branches below can
        # assume the value is present. (A malformed value-directive with no value was skipped as
        # "not enough fields" before; it now skips with a more specific message — same outcome.)
        is_flag = directive in _FLAG_DIRECTIVES
        if len(tokens) < 3 and not is_flag:
            self._warn(lineno, f"config {directive} needs a value; skipping")
            return

        # --- original legacy directives (unchanged; prefix-matched like the C strncmp) ---
        if directive.startswith("pageinterval"):
            self._set_int(lineno, "pageinterval_min", tokens[2])
        elif directive.startswith("logging"):
            self._set_logging(lineno, tokens[2])
        elif directive.startswith("loglevel"):
            self._set_loglevel(lineno, tokens[2])
        elif directive.startswith("dnslog"):
            self._set_int(lineno, "dnslog_s", tokens[2])
        elif directive.startswith("dnsexpire"):
            self._set_int(lineno, "dnsexpire_s", tokens[2])
        elif directive.startswith("heartbeat"):
            self._set_int(lineno, "heartbeat_s", tokens[2])
        elif directive.startswith("savestate"):
            self._set_savestate(lineno, tokens)
        elif directive.startswith("statusfile"):
            self._set_statusfile(lineno, tokens)
        elif directive.startswith("numfailures"):
            value = self._to_int(lineno, tokens[2])
            if value is not None:
                self.numfailures = value
                self.overrides["numfailures"] = value
        elif directive.startswith("sleeptime"):
            self._warn(lineno, "config sleeptime is obsolete; ignored (use --interval)")
        # --- per-object "sticky" directives (#95): position-dependent, snapshotted into each
        # subsequently-parsed node (like numfailures above), NOT written to the global overrides.
        # Intercepted BEFORE the #93 global tables below, since send_pings/min_pings/queuetime also
        # live in those tables (for the *modern* format's global use). A node parsed before any of
        # these inherits the global Settings default at check time.
        elif directive == "contact_on":
            self._set_contact_on(lineno, self._one_value(lineno, "contact_on", tokens))
        elif directive == "source":
            self._set_sticky_source(lineno, self._one_value(lineno, "source", tokens))
        elif directive == "queuetime":
            value = self._to_float(lineno, self._one_value(lineno, "queuetime", tokens))
            if value is not None and self._valid_interval(lineno, value):
                self.interval = value
        elif directive == "send_pings":
            value = self._sticky_count(lineno, "send_pings", tokens)
            if value is not None:
                self.send_pings = value
        elif directive == "min_pings":
            value = self._sticky_count(lineno, "min_pings", tokens)
            if value is not None:
                self.min_pings = value
        # --- post-rewrite GLOBAL directives (#93): exact-match against the shared modern tables.
        # Exact (not prefix) match is deliberate so `control_bind`/`control_port`/... are never
        # swallowed by the `control` flag. Existing directives above are caught first.
        elif directive in _INT_DIRECTIVES:
            self._set_global_int(lineno, _INT_DIRECTIVES[directive], directive, tokens)
        elif directive in _FLOAT_DIRECTIVES:
            self._set_global_float(lineno, _FLOAT_DIRECTIVES[directive], directive, tokens)
        elif directive in _STR_DIRECTIVES:
            self._set_global_str(lineno, _STR_DIRECTIVES[directive], directive, tokens)
        elif is_flag:
            if len(tokens) > 2:
                self._warn(lineno, f"config {directive} takes no value; ignoring the rest")
            field, val = _FLAG_DIRECTIVES[directive]
            self.overrides[field] = val
        else:
            self._warn(lineno, f"unknown config directive {directive!r}; skipping")

    def _set_logging(self, lineno: int, facility: str) -> None:
        if facility == "none":
            self.overrides["syslog_facility"] = None
        elif facility in _FACILITIES:
            self.overrides["syslog_facility"] = facility
        else:
            self._warn(lineno, f"unknown logging facility {facility!r}; using daemon")
            self.overrides["syslog_facility"] = "daemon"

    def _set_loglevel(self, lineno: int, level: str) -> None:
        level = level.lower()
        if level in ("warning", "info", "debug"):
            self.overrides["log_level"] = level
        else:
            self._warn(lineno, f"unknown loglevel {level!r}; using info")
            self.overrides["log_level"] = "info"

    def _set_savestate(self, lineno: int, tokens: list[str]) -> None:
        """``config savestate "/path/to/state.json"`` — the legacy directive (#21).

        The original required a double-quoted path; we accept it quoted or bare and strip a
        surrounding pair of quotes, joining any whitespace-split remainder so a quoted path with
        single spaces survives. Enabling persistence from the legacy config keeps a drop-in
        ``sysmon.conf`` working unchanged.
        """
        path = " ".join(tokens[2:]).strip().strip('"')
        if not path:
            self._warn(lineno, "savestate needs a file path; skipping")
            return
        self.overrides["state_path"] = path

    def _set_statusfile(self, lineno: int, tokens: list[str]) -> None:
        if len(tokens) != 4:
            self._warn(lineno, "statusfile needs <html|text> <path>; skipping")
            return
        fmt = tokens[2]
        if fmt.startswith("html"):
            self.overrides["status_html"] = True
        elif fmt.startswith("text"):
            self.overrides["status_html"] = False
        else:
            self._warn(lineno, f"statusfile type {fmt!r} invalid (want html or text); skipping")
            return
        self.overrides["status_path"] = tokens[3]

    def _set_int(self, lineno: int, field_name: str, token: str) -> None:
        value = self._to_int(lineno, token)
        if value is not None:
            self.overrides[field_name] = value

    def _to_int(self, lineno: int, token: str) -> int | None:
        try:
            return int(token)
        except ValueError:
            self._warn(lineno, f"expected an integer, got {token!r}; skipping")
            return None

    def _to_float(self, lineno: int, token: str) -> float | None:
        try:
            return float(token)
        except ValueError:
            self._warn(lineno, f"expected a number, got {token!r}; skipping")
            return None

    def _one_value(self, lineno: int, name: str, tokens: list[str]) -> str:
        """The single config value token, warning on extra tokens like the modern parser."""
        if len(tokens) > 3:
            self._warn(lineno, f"config {name} takes one value; using the first")
        return tokens[2]

    def _set_global_int(self, lineno: int, field_name: str, name: str, tokens: list[str]) -> None:
        """Apply a post-rewrite int GLOBAL (#93), warning on extra tokens like the modern parser."""
        value = self._to_int(lineno, self._one_value(lineno, name, tokens))
        if value is not None:
            self.overrides[field_name] = value

    def _set_global_float(self, lineno: int, field_name: str, name: str, tokens: list[str]) -> None:
        """Apply a post-rewrite float GLOBAL from the shared tables (#93)."""
        value = self._to_float(lineno, self._one_value(lineno, name, tokens))
        if value is not None:
            self.overrides[field_name] = value

    def _set_contact_on(self, lineno: int, value: str) -> None:
        """``config contact_on`` is POSITION-DEPENDENT in legacy (#95): a running per-node default
        snapshotted into subsequently-parsed nodes (like numfailures), not a global. Validated like
        the modern parser (an unknown value falls back to ``both``)."""
        if value in CONTACT_ON_CHOICES:
            self.contact_on = value
        else:
            self._warn(lineno, f"unknown contact_on {value!r} "
                       f"(want {'/'.join(CONTACT_ON_CHOICES)}); using both")
            self.contact_on = "both"

    def _set_sticky_source(self, lineno: int, value: str) -> None:
        """``config source <ip|auto>`` (#95): a position-dependent per-node bind snapshotted into
        subsequently-parsed nodes. Syntax is validated here (an IP literal or ``auto``); the family
        is checked per node at snapshot time (:meth:`_source_for`). A bad value warns and leaves the
        running source unchanged."""
        val = value.strip().strip('"')
        if val.lower() == SOURCE_AUTO:
            self.source = SOURCE_AUTO
            return
        try:
            ipaddress.ip_address(val)
        except ValueError:
            self._warn(lineno, f"source must be an IP address or 'auto', got {value!r}; ignoring")
            return
        self.source = val

    def _source_for(self, ctype: CheckType, lineno: int) -> str | None:
        """The sticky ``source`` (#95) resolved for a node of this check type, family-checked here
        where the check type is known: a ``ping6`` node wants an IPv6 source, every other check an
        IPv4 one (``auto``/unset always pass). A mismatch warns and leaves the node unbound."""
        src = self.source
        if src is None or src == SOURCE_AUTO:
            return src
        want_version = 6 if ctype is CheckType.PING6 else 4
        if ipaddress.ip_address(src).version != want_version:
            self._warn(lineno, f"source {src!r} family does not match {ctype}; leaving unbound")
            return None
        return src

    def _valid_interval(self, lineno: int, value: float) -> bool:
        """``queuetime`` must be a positive, finite number — mirror the modern parser, since a
        non-finite or non-positive interval would poison the scheduler heap (#95)."""
        if value > 0 and math.isfinite(value):
            return True
        self._warn(lineno, f"config queuetime must be a positive number, got {value!r}; ignoring")
        return False

    def _sticky_count(self, lineno: int, name: str, tokens: list[str]) -> int | None:
        """A loss-tolerant ping count (send_pings/min_pings): a positive int, like modern (#95). The
        send/min relationship is clamped at check time, so only the >= 1 floor is enforced here."""
        value = self._to_int(lineno, self._one_value(lineno, name, tokens))
        if value is None:
            return None
        if value < 1:
            self._warn(lineno, f"config {name} must be >= 1, got {value}; ignoring")
            return None
        return value

    def _set_global_str(self, lineno: int, field_name: str, name: str, tokens: list[str]) -> None:
        """Apply a post-rewrite string global (#93). Path-like values join the remaining tokens and
        strip a surrounding quote pair (the savestate precedent, so a quoted path with spaces
        survives the whitespace split); other values take the first token only."""
        if name in _PATH_STR_GLOBALS:
            value = " ".join(tokens[2:]).strip().strip('"')
        else:
            if len(tokens) > 3:
                self._warn(lineno, f"config {name} takes one value; using the first")
            value = tokens[2].strip('"')
        if not value:
            self._warn(lineno, f"config {name} needs a value; skipping")
            return
        self.overrides[field_name] = value
