"""Parser for the original ``sysmon.conf`` grammar.

Faithfully reproduces ``loadconfig.c``/``parseline``:

* Lines are whitespace-tokenized (up to 7 fields, like ``sscanf("%s"*7)``).
* A line whose first token starts with ``;`` or ``#`` is a comment; blank lines are skipped.
* ``}`` closes the current block; a trailing ``{`` opens a recursive **child block** (only on
  the ping-like branch — ping/smtp — as in the original).
* ``config <directive> ...`` sets globals: ``statusfile``, ``pageinterval`` (minutes),
  ``logging``, ``dnslog``, ``dnsexpire``, ``numfailures``, ``sleeptime``.
* **``numfailures`` is position-dependent** — its current value snapshots into each
  subsequently-parsed node's ``max_down`` (a running value, not last-wins).
* Per-type field positions exactly as in C (ping/smtp: label[,contact][,``{``];
  tcp/udp: port,label[,contact]; www/https: url,url_text,label[,contact];
  pop3: user,pass,label[,contact]; authdns: name,contact).
* Dropped legacy types (imap, nntp, radius, umichx500, ...) -> warn and skip; never hard-fail.
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

from dataclasses import dataclass, field

from psysmon.config.model import DEFAULT_PORT, CheckType, Node

# Valid syslog facilities (from match_facility in loadconfig.c); "none" disables logging.
_FACILITIES = frozenset(
    "kern user mail daemon auth syslog lpr news uucp cron authpriv "
    "local0 local1 local2 local3 local4 local5 local6 local7".split()
)

# Check-type keywords in the original dispatch order, prefix-matched like the C strncmp.
# A None value marks a legacy type that is dropped in the rewrite (warn + skip).
_TYPE_KEYWORDS: tuple[tuple[str, CheckType | None], ...] = (
    ("ping", CheckType.PING),
    ("pop3", CheckType.POP3),
    ("imap", None),
    ("tcp", CheckType.TCP),
    ("udp", CheckType.UDP),
    ("nntp", None),
    ("smtp", CheckType.SMTP),
    ("umichx500", None),
    ("www", CheckType.HTTP),
    ("authdns", CheckType.DNS),
    ("radius", None),
    ("https", CheckType.HTTPS),
)

# Types whose stanza may open a `{` child block (the original's ping-like parse branch).
_PING_LIKE = frozenset({CheckType.PING, CheckType.SMTP})

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


class _Parser:
    """Recursive-descent parser mirroring the original ``parseline`` recursion."""

    def __init__(self, lines: list[str], numfailures: int) -> None:
        self._lines = list(enumerate(lines, start=1))
        self._pos = 0
        self.numfailures = numfailures
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

            if len(tokens) < 3:
                self._warn(lineno, "not enough fields; skipping")
                if opens_block:
                    self.parse_block(depth + 1)  # drain the orphaned block; keep braces balanced
                continue
            if tokens[0] == "config":
                self._handle_config(lineno, tokens)
                if opens_block:
                    self._warn(lineno, "a config line cannot open a block; ignoring the '{'")
                    self.parse_block(depth + 1)
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
            if keyword is not None:
                self._warn(lineno, f"unsupported check type {keyword!r}; skipping")
            else:
                self._warn(lineno, f"invalid check type {tokens[1]!r}; skipping")
            return None

        n = len(tokens)
        node = Node(hostname=host, check_type=ctype, max_down=self.numfailures)
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
            if n < 5:
                self._warn(lineno, f"{ctype} needs url, match-text and label; skipping")
                return None
            node.url, node.url_text, node.label = tokens[2], tokens[3], tokens[4]
            if n >= 6:
                node.contact = tokens[5]
        elif ctype is CheckType.POP3:
            if n < 5:
                self._warn(lineno, "pop3 needs user, password and label; skipping")
                return None
            node.username, node.password, node.label = tokens[2], tokens[3], tokens[4]
            if n >= 6:
                node.contact = tokens[5]
        elif ctype is CheckType.DNS:  # authdns
            if n < 4:
                self._warn(lineno, "authdns needs a name and contact; skipping")
                return None
            node.username = tokens[2]  # name to look up
            node.contact = tokens[3]
        else:  # ping-like: ping, smtp (a trailing '{' was already stripped by parse_block)
            node.label = tokens[2]
            if n > 3:
                node.contact = tokens[3]
                if n >= 5:
                    self._warn(lineno, "unexpected fields after contact; ignoring")
        return node

    def _handle_config(self, lineno: int, tokens: list[str]) -> None:
        directive = tokens[1]
        if directive.startswith("pageinterval"):
            self._set_int(lineno, "pageinterval_min", tokens[2])
        elif directive.startswith("logging"):
            self._set_logging(lineno, tokens[2])
        elif directive.startswith("dnslog"):
            self._set_int(lineno, "dnslog_s", tokens[2])
        elif directive.startswith("dnsexpire"):
            self._set_int(lineno, "dnsexpire_s", tokens[2])
        elif directive.startswith("statusfile"):
            self._set_statusfile(lineno, tokens)
        elif directive.startswith("numfailures"):
            value = self._to_int(lineno, tokens[2])
            if value is not None:
                self.numfailures = value
                self.overrides["numfailures"] = value
        elif directive.startswith("sleeptime"):
            self._warn(lineno, "config sleeptime is obsolete; ignored (use --interval)")
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
