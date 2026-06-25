"""Parser for the modern ``object{}`` config grammar (sysmon 0.93): tokenizer + globals.

This is the opt-in modern format adopted in issue #3 — the documented sysmon 0.93 grammar
(a single ``root``, named ``object NAME { ... };`` blocks with named attributes, ``dep``
edges, ``config`` globals, ``set``/``$var`` reuse), extended with psysmon-specific keys. The
legacy positional parser (:mod:`psysmon.config.legacy`) stays the default, and
:mod:`psysmon.config.detect` picks the format per file.

**Implemented so far (#3 milestones 1–3):** the *tokenizer* (:func:`tokenize`), the **global
directives**, and the **``object{}`` monitored graph**. :func:`parse` interprets top-level
``config <directive> ...;`` lines into a settings-``overrides`` dict (keyed by
:class:`~psysmon.config.settings.Settings` field names, exactly like the legacy parser),
``set NAME = "..."`` / ``$NAME`` substitution, and ``object NAME { ... };`` blocks into a
``Node`` forest (single ``dep`` edges resolved into ``Node.children``). Per-object *override*
attributes (``queuetime``/``send_pings``/``numfailures``/...) are M4; ``include`` is a follow-up
that still raises rather than silently dropping coverage. An empty / comment-only / globals-only
file yields a normal (objectless) result.

Lexical grammar (matches the 0.93 lexer's observable behavior):

* ``"``-delimited strings, no escapes — a string may not span a line or contain ``"``.
* ``;`` terminates a statement. A ``;`` (or ``#``) at the *start of a line* — or right after a
  previous ``;`` or a ``{`` — instead begins a comment to end of line, so ``;``, ``;;`` and
  ``; like this`` are comment/blank lines, mirroring the upstream ``[;#].*\n`` rule.
* ``#`` anywhere outside a string begins a comment to end of line.
* ``{`` ``}`` ``=`` are single-character punctuation tokens.
* Everything else (runs of non-special, non-whitespace characters) is a bareword ``WORD``
  (keywords, hostnames, numbers — the interpreter, not the lexer, tells them apart).
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from enum import Enum, auto

# Reuse the shared parse contract + error type (so the daemon consumes either parser uniformly)
# and the legacy facility allow-list (the single source of valid syslog facilities). These are
# format-neutral despite currently living in the legacy module — hoist to a shared module later.
from psysmon.config.legacy import _FACILITIES, ParseError, ParseResult
from psysmon.config.model import CONTACT_ON_CHOICES, DEFAULT_PORT, SOURCE_AUTO, CheckType, Node

# Characters that end a bareword (and are otherwise their own tokens or comment/string starts).
_SPECIAL = set('"{}=;#')


class TokenKind(Enum):
    WORD = auto()      # bareword: keyword, hostname, number, ...
    STRING = auto()    # "quoted value" (quotes stripped in .value)
    LBRACE = auto()    # {
    RBRACE = auto()    # }
    EQUALS = auto()    # =
    SEMI = auto()      # ; (statement terminator)


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    value: str  # the lexeme (string contents without quotes; "" for punctuation)
    line: int   # 1-based source line, for diagnostics


def tokenize(text: str) -> list[Token]:
    """Tokenize modern-format ``text`` into a flat list of :class:`Token`.

    Raises :class:`~psysmon.config.legacy.ParseError` on a lexical error (an unterminated
    string), reported with its line number, so the daemon surfaces it as a clean config error.
    """
    tokens: list[Token] = []
    line = 1
    i = 0
    n = len(text)
    # True where a statement could begin — file start, the start of a line, just after a ';',
    # or just after a '{' (a block body). A ';' here is a comment marker (a ';'/';;'/'; like
    # this' line), not a terminator — mirroring the upstream `[;#].*\n` line-start comment rule.
    at_boundary = True

    while i < n:
        ch = text[i]

        if ch == "\n":
            line += 1
            i += 1
            at_boundary = True  # a new line: a leading ';'/'#' begins a comment
            continue
        if ch in " \t\r":
            i += 1
            continue

        if ch == "#" or (ch == ";" and at_boundary):
            # Comment to end of line (the ';' form covers ';', ';;', '; like this').
            while i < n and text[i] != "\n":
                i += 1
            continue

        if ch == '"':
            start_line = line
            i += 1
            buf: list[str] = []
            while i < n and text[i] not in '"\n':
                buf.append(text[i])
                i += 1
            if i >= n or text[i] == "\n":
                raise ParseError(f"line {start_line}: unterminated string")
            i += 1  # consume the closing quote
            tokens.append(Token(TokenKind.STRING, "".join(buf), start_line))
            at_boundary = False
            continue

        if ch == ";":
            tokens.append(Token(TokenKind.SEMI, "", line))
            i += 1
            at_boundary = True
            continue
        if ch == "{":
            tokens.append(Token(TokenKind.LBRACE, "", line))
            i += 1
            at_boundary = True  # a block body opens: an attribute (or ';'-comment) follows
            continue
        if ch == "}":
            tokens.append(Token(TokenKind.RBRACE, "", line))
            i += 1
            at_boundary = False
            continue
        if ch == "=":
            tokens.append(Token(TokenKind.EQUALS, "", line))
            i += 1
            at_boundary = False
            continue

        # A bareword: run up to the next whitespace or special character.
        start = i
        while i < n and text[i] not in _SPECIAL and not text[i].isspace():
            i += 1
        tokens.append(Token(TokenKind.WORD, text[start:i], line))
        at_boundary = False

    return tokens


# --- global ``config <name> ...`` directive tables ----------------------------------------
# Each maps a modern directive keyword to the Settings field it overrides — the legacy parser's
# directives plus the psysmon extensions adopted in #3. Unknown names warn + skip. Keys land in
# ``overrides`` by Settings field name, so the daemon's ``merge`` accepts them unchanged.
_INT_DIRECTIVES = {
    "pageinterval": "pageinterval_min",
    "numfailures": "numfailures",
    "dnsexpire": "dnsexpire_s",
    "dnslog": "dnslog_s",
    "heartbeat": "heartbeat_s",
    "send_pings": "send_pings",
    "min_pings": "min_pings",
    "statesave_interval": "statesave_s",
    "state_max_age": "state_max_age_s",
    "maxqueued": "max_concurrency",   # 0.93's "max objects queued to check at once"
    "control_port": "control_port",   # control plane (#69)
}
_FLOAT_DIRECTIVES = {
    "queuetime": "interval_s",        # 0.93's per-poll cadence; interval_s/--interval are floats
}
_STR_DIRECTIVES = {
    "savestate": "state_path",
    "source_ip": "source_ip",
    "hostname": "org_hostname",
    "sender": "mail_from",
    "from": "mail_from",
    "control_bind": "control_bind",            # control plane (#69)
    "control_token_file": "control_token_file",
    "control_tls_cert": "control_tls_cert",
    "control_tls_key": "control_tls_key",
}
_FLAG_DIRECTIVES = {                   # value-less booleans
    "page_on_degraded": ("page_on_degraded", True),
    "noheartbeat": ("heartbeat_s", 0),
    "control": ("control_enabled", True),  # control plane (#69)
}
_LOGLEVELS = ("warning", "info", "debug")
_VAR_RE = re.compile(r"\$([A-Za-z_]\w*)")  # a $NAME reference (set / $var substitution)

# --- object `type <T>` keyword -> CheckType (M3) -------------------------------------------
_TYPE_KEYWORDS = {
    "ping": CheckType.PING,
    "tcp": CheckType.TCP,
    "udp": CheckType.UDP,
    "smtp": CheckType.SMTP,
    "pop3": CheckType.POP3,
    "dns": CheckType.DNS, "authdns": CheckType.DNS,
    "http": CheckType.HTTP, "www": CheckType.HTTP,
    "https": CheckType.HTTPS,
}
_DROPPED_TYPES = frozenset({"imap", "nntp", "pop2", "umichx500", "radius", "bootp", "snmp"})
_DEFERRED_TYPES = frozenset({"ping6", "pingv6", "icmp6"})  # IPv6 ping -> #24
# Object attributes the parser understands; anything else (a typo, or a not-yet-supported key)
# warns and is ignored. Structural fields (M3) + per-object overrides (M4) + contact_on + source.
_OBJECT_ATTRS = frozenset({
    "host", "ip", "type", "port", "desc", "contact", "url", "urltext", "username", "password",
    "dns-query", "dep",                              # structural (M3); `host` preferred, `ip` alias
    "queuetime", "send_pings", "min_pings", "numfailures", "group", "contact_on",  # overrides
    "source",                                                    # outbound bind source (#70)
})
# Settings a `group "NAME" { ... }` block may carry (#70). Today just `source`; the block is a
# scope so future per-group defaults slot in here. Unknown keys in a group block warn + ignore.
_GROUP_ATTRS = frozenset({"source"})


class _Parser:
    """Walks the token stream, interpreting global ``config``/``set`` (M2) + ``object{}`` (M3).

    Statements end at a ``;`` (or a ``{ ... }`` object body). ``config``/``set`` populate the
    overrides + variables; ``object NAME { ... };`` and ``root = "..."`` build the monitored
    ``Node`` forest (resolved from single ``dep`` edges); ``include`` raises (a follow-up).
    Unknown directives, malformed values, and objects that fail required-field validation warn
    and skip — matching the legacy parser's never-hard-fail-a-recoverable-config stance.
    """

    def __init__(self, tokens: list[Token], numfailures: int) -> None:
        self._toks = tokens
        self._i = 0
        self.numfailures = numfailures  # running default threshold; per-object override is M4
        self.vars: dict[str, str] = {}
        self.overrides: dict[str, object] = {}
        self.warnings: list[str] = []
        # objects in declaration order + a name index; deps resolved into a forest at the end.
        self._objects: list[tuple[str, Node, str | None, int]] = []
        self._object_index: dict[str, Node] = {}
        # per-group default settings from `group "NAME" { ... }` blocks (#70), resolved onto each
        # member object's fields after all statements parse (so group/object order is free).
        self._group_defaults: dict[str, dict[str, str]] = {}
        self.root_name: str | None = None
        self.root_line = 0

    def parse_top(self) -> ParseResult:
        while self._i < len(self._toks):
            self._statement()
        self._resolve_group_sources()
        roots = self._build_forest()
        return ParseResult(roots=roots, overrides=self.overrides, warnings=self.warnings)

    # --- low-level helpers ------------------------------------------------------------
    def _warn(self, line: int, message: str) -> None:
        self.warnings.append(f"line {line}: {message}")

    def _collect_to_semi(self) -> tuple[list[Token], bool]:
        """Consume tokens (and the closing ``;``) up to the next SEMI; ``(tokens, terminated)``."""
        collected: list[Token] = []
        while self._i < len(self._toks):
            tok = self._toks[self._i]
            self._i += 1
            if tok.kind is TokenKind.SEMI:
                return collected, True
            collected.append(tok)
        return collected, False  # EOF without a ';'

    def _subst(self, line: int, value: str) -> str:
        """Expand ``$NAME`` references from earlier ``set`` directives (undefined -> warn)."""
        def repl(match: re.Match) -> str:
            name = match.group(1)
            if name in self.vars:
                return self.vars[name]
            self._warn(line, f"undefined variable ${name}; left literal")
            return match.group(0)
        return _VAR_RE.sub(repl, value)

    # --- statements -------------------------------------------------------------------
    def _statement(self) -> None:
        tok = self._toks[self._i]
        if tok.kind is not TokenKind.WORD:
            self._warn(tok.line, f"unexpected {tok.kind.name.lower()} at statement start; skipping")
            self._collect_to_semi()
            return
        word = tok.value
        if word == "config":
            self._i += 1
            self._config(tok.line)
        elif word == "set":
            self._i += 1
            self._set(tok.line)
        elif word == "root":
            self._i += 1
            self._root(tok.line)
        elif word == "object":
            self._i += 1
            self._object(tok.line)
        elif word == "group":
            self._i += 1
            self._group(tok.line)
        elif word == "include":
            raise ParseError(
                f"line {tok.line}: `include` isn't supported yet (a follow-up milestone, #3)"
            )
        else:
            self._warn(tok.line, f"unknown statement '{word}'; skipping")
            self._collect_to_semi()

    def _set(self, line: int) -> None:
        args, terminated = self._collect_to_semi()
        if not terminated:
            self._warn(line, "statement missing a terminating ';'")
        if (len(args) >= 3 and args[0].kind is TokenKind.WORD
                and args[1].kind is TokenKind.EQUALS
                and args[2].kind in (TokenKind.STRING, TokenKind.WORD)):
            if len(args) > 3:
                self._warn(line, "'set' takes a single value; using the first")
            self.vars[args[0].value] = self._subst(line, args[2].value)
        else:
            # A missing '=', no value, or punctuation where the value should be (e.g.
            # `set x = = ;`) is malformed — warn rather than silently bind an empty var.
            self._warn(line, "malformed 'set' (expected: set NAME = \"value\";); skipping")

    def _config(self, line: int) -> None:
        args, terminated = self._collect_to_semi()
        if not terminated:
            self._warn(line, "statement missing a terminating ';'")
        if not args or args[0].kind is not TokenKind.WORD:
            self._warn(line, "config directive needs a name; skipping")
            return
        self._apply_config(line, args[0].value, args[1:])

    def _apply_config(self, line: int, name: str, values: list[Token]) -> None:
        if name in _INT_DIRECTIVES:
            self._set_int(line, _INT_DIRECTIVES[name], name, values)
        elif name in _FLOAT_DIRECTIVES:
            self._set_float(line, _FLOAT_DIRECTIVES[name], name, values)
        elif name in _STR_DIRECTIVES:
            self._set_str(line, _STR_DIRECTIVES[name], name, values)
        elif name in _FLAG_DIRECTIVES:
            if values:
                self._warn(line, f"config {name} takes no value; ignoring the rest")
            field, val = _FLAG_DIRECTIVES[name]
            self.overrides[field] = val
        elif name == "loglevel":
            self._set_loglevel(line, values)
        elif name == "logging":
            self._set_logging(line, values)
        elif name == "contact_on":
            self._set_contact_on(line, values)
        elif name == "statusfile":
            self._set_statusfile(line, values)
        elif name == "sleeptime":
            self._warn(line, "config sleeptime is obsolete; ignored (use queuetime / --interval)")
        else:
            self._warn(line, f"unknown config directive '{name}'; skipping")

    def _one_value(self, line: int, name: str, values: list[Token]) -> str | None:
        if not values:
            self._warn(line, f"config {name} needs a value; skipping")
            return None
        if len(values) > 1:
            self._warn(line, f"config {name} takes one value; using the first")
        return self._subst(line, values[0].value)

    def _set_int(self, line: int, field: str, name: str, values: list[Token]) -> None:
        raw = self._one_value(line, name, values)
        if raw is None:
            return
        try:
            self.overrides[field] = int(raw)
        except ValueError:
            self._warn(line, f"config {name} expects an integer, got '{raw}'; skipping")

    def _set_float(self, line: int, field: str, name: str, values: list[Token]) -> None:
        raw = self._one_value(line, name, values)
        if raw is None:
            return
        try:
            self.overrides[field] = float(raw)
        except ValueError:
            self._warn(line, f"config {name} expects a number, got '{raw}'; skipping")

    def _set_str(self, line: int, field: str, name: str, values: list[Token]) -> None:
        raw = self._one_value(line, name, values)
        if raw is not None:
            self.overrides[field] = raw

    def _set_loglevel(self, line: int, values: list[Token]) -> None:
        raw = self._one_value(line, "loglevel", values)
        if raw is None:
            return
        if raw.lower() in _LOGLEVELS:
            self.overrides["log_level"] = raw.lower()
        else:
            self._warn(line, f"unknown loglevel '{raw}'; using info")
            self.overrides["log_level"] = "info"

    def _set_logging(self, line: int, values: list[Token]) -> None:
        raw = self._one_value(line, "logging", values)
        if raw is None:
            return
        if raw == "none":
            self.overrides["syslog_facility"] = None
        elif raw in _FACILITIES:
            self.overrides["syslog_facility"] = raw
        else:
            self._warn(line, f"unknown logging facility '{raw}'; using daemon")
            self.overrides["syslog_facility"] = "daemon"

    def _set_contact_on(self, line: int, values: list[Token]) -> None:
        raw = self._one_value(line, "contact_on", values)
        if raw is None:
            return
        if raw in CONTACT_ON_CHOICES:
            self.overrides["contact_on"] = raw
        else:
            self._warn(line, f"unknown contact_on '{raw}' (want {'/'.join(CONTACT_ON_CHOICES)});"
                       " using both")
            self.overrides["contact_on"] = "both"

    def _set_statusfile(self, line: int, values: list[Token]) -> None:
        if len(values) != 2:
            self._warn(line, 'config statusfile needs <html|text> "<path>"; skipping')
            return
        fmt = values[0].value
        if fmt.startswith("html"):
            self.overrides["status_html"] = True
        elif fmt.startswith("text"):
            self.overrides["status_html"] = False
        else:
            self._warn(line, f"statusfile format '{fmt}' invalid (want html or text); skipping")
            return
        self.overrides["status_path"] = self._subst(line, values[1].value)

    # --- objects + dependency graph (M3) ----------------------------------------------
    def _root(self, line: int) -> None:
        args, terminated = self._collect_to_semi()
        if not terminated:
            self._warn(line, "statement missing a terminating ';'")
        if (len(args) >= 2 and args[0].kind is TokenKind.EQUALS
                and args[1].kind is TokenKind.STRING):
            self.root_name = self._subst(line, args[1].value)
            self.root_line = line
        else:
            self._warn(line, 'malformed root (expected: root = "name";); skipping')

    def _object(self, line: int) -> None:
        name = self._take_word()
        if name is None:
            self._warn(line, "object needs a name; skipping")
            if self._peek_kind() is TokenKind.LBRACE:
                self._skip_block()
            else:
                self._collect_to_semi()
            return
        if not self._take(TokenKind.LBRACE):
            self._warn(line, f"object '{name}' is missing '{{'; skipping")
            self._collect_to_semi()
            return
        attrs, closed = self._collect_block_attrs(name, "object")
        if not closed:
            self._warn(line, f"object '{name}' is missing its closing '}}' (reached end of file)")
        self._add_object(line, name, attrs)

    def _group(self, line: int) -> None:
        """Parse a top-level ``group "NAME" { attr value; ... };`` scope (#70).

        Defines per-group default settings (currently just ``source``) inherited by objects that
        join the group via the ``group "NAME"`` attribute. The per-object value always wins; group
        defaults are applied after all statements parse, so group/object declaration order is free.
        """
        name = self._take_name()
        if name is None:
            self._warn(line, "group needs a name; skipping")
            self._skip_block_or_semi()
            return
        # Expand $vars in the name exactly like the object-side `group "..."` membership attr
        # (else `group "$G" {...}` would key under the literal "$G" and never match its members).
        name = self._subst(line, name).strip()
        if not self._take(TokenKind.LBRACE):
            self._warn(line, f"group '{name}' is missing '{{'; skipping")
            self._collect_to_semi()
            return
        attrs, closed = self._collect_block_attrs(name or "?", "group")
        if not closed:
            self._warn(line, f"group '{name}' is missing its closing '}}' (reached end of file)")
        self._add_group(line, name, attrs)

    def _collect_block_attrs(
        self, name: str, kind: str
    ) -> tuple[dict[str, tuple[int, list[Token]]], bool]:
        """Collect ``key value;`` attrs inside a ``{ ... }`` body. Returns ``(attrs, closed)`` —
        ``closed`` is True if a matching ``}`` was consumed (and an optional trailing ``;``), False
        on EOF. Shared by ``object`` and ``group`` blocks (same body grammar)."""
        attrs: dict[str, tuple[int, list[Token]]] = {}
        while self._i < len(self._toks):
            tok = self._toks[self._i]
            if tok.kind is TokenKind.RBRACE:
                self._i += 1
                self._take(TokenKind.SEMI)  # optional trailing ';'
                return attrs, True
            if tok.kind is not TokenKind.WORD:
                self._warn(tok.line, f"unexpected token in {kind} '{name}'; skipping")
                self._collect_attr()
                continue
            self._i += 1
            values = self._collect_attr()
            if values and values[0].kind is TokenKind.EQUALS:
                values = values[1:]  # tolerate `key = value` (block attrs are `key value`)
            if len(values) > 1:
                self._warn(tok.line, f"'{tok.value}' takes one value (missing ';'?)")
            if tok.value in attrs:
                # Keep the first (matches the single-dep MVP decision for a repeated `dep`).
                self._warn(tok.line, f"duplicate '{tok.value}' in '{name}'; keeping the first")
            else:
                attrs[tok.value] = (tok.line, values)
        return attrs, False

    def _take_word(self) -> str | None:
        if self._peek_kind() is TokenKind.WORD:
            value = self._toks[self._i].value
            self._i += 1
            return value
        return None

    def _take_name(self) -> str | None:
        """Take the next token's value if it's a name (a quoted STRING or a bareword WORD)."""
        if self._peek_kind() in (TokenKind.WORD, TokenKind.STRING):
            value = self._toks[self._i].value
            self._i += 1
            return value
        return None

    def _skip_block_or_semi(self) -> None:
        """Recover from a malformed block header: skip a ``{ ... }`` body or run to the ``;``."""
        if self._peek_kind() is TokenKind.LBRACE:
            self._skip_block()
        else:
            self._collect_to_semi()

    def _take(self, kind: TokenKind) -> bool:
        if self._peek_kind() is kind:
            self._i += 1
            return True
        return False

    def _peek_kind(self) -> TokenKind | None:
        return self._toks[self._i].kind if self._i < len(self._toks) else None

    def _collect_attr(self) -> list[Token]:
        """Collect an attribute's value tokens up to ';' (consumed) or '}' (left for the caller).

        A modern object does not nest (``{}``-nesting is replaced by named ``dep`` edges), so an
        inner ``{ ... }`` in an attribute value is malformed: skip the balanced block + a trailing
        ';' and warn, rather than letting the inner ``}`` masquerade as the object's close and leak
        the rest of the body into top-level parsing.
        """
        collected: list[Token] = []
        while self._i < len(self._toks):
            tok = self._toks[self._i]
            if tok.kind is TokenKind.RBRACE:
                return collected  # don't consume; the object loop closes the block
            self._i += 1
            if tok.kind is TokenKind.SEMI:
                return collected
            if tok.kind is TokenKind.LBRACE:
                self._warn(tok.line, "unexpected '{' in object body; skipping the block")
                self._skip_balanced()
                self._take(TokenKind.SEMI)
                return collected
            collected.append(tok)
        return collected

    def _skip_block(self) -> None:
        """Skip a balanced ``{ ... }`` (and a trailing ';') after a malformed object header."""
        if self._take(TokenKind.LBRACE):
            self._skip_balanced()
            self._take(TokenKind.SEMI)

    def _skip_balanced(self) -> None:
        """Consume tokens through the ``}`` that matches an already-consumed ``{``."""
        depth = 1
        while self._i < len(self._toks) and depth > 0:
            kind = self._toks[self._i].kind
            self._i += 1
            if kind is TokenKind.LBRACE:
                depth += 1
            elif kind is TokenKind.RBRACE:
                depth -= 1

    def _add_object(self, line: int, name: str, attrs: dict[str, tuple[int, list[Token]]]) -> None:
        node, dep_name = self._build_node(line, name, attrs)
        if node is None:
            return  # required-field validation failed; the object was warned + skipped
        if name in self._object_index:
            self._warn(line, f"duplicate object name '{name}'; skipping the duplicate")
            return
        self._object_index[name] = node
        self._objects.append((name, node, dep_name, line))

    def _add_group(self, line: int, name: str, attrs: dict[str, tuple[int, list[Token]]]) -> None:
        """Record a ``group "NAME" { ... }`` block's default settings (#70)."""
        if not name:
            self._warn(line, "group has an empty name; skipping")
            return
        resolved = {key: self._subst(kl, toks[0].value) if toks else "" for key, (kl, toks) in
                    attrs.items()}
        settings: dict[str, str] = {}
        if "source" in resolved:
            src = self._parse_source(line, f"group '{name}'", resolved["source"])
            if src is not None:
                settings["source"] = src
        for key, (kl, _toks) in attrs.items():
            if key not in _GROUP_ATTRS:
                self._warn(kl, f"group '{name}': attribute '{key}' isn't supported yet; ignoring")
        if name in self._group_defaults:
            self._warn(line, f"duplicate group '{name}'; keeping the first")
            return
        self._group_defaults[name] = settings

    def _parse_source(self, line: int, who: str, raw: str) -> str | None:
        """Validate a ``source`` value: the literal ``auto`` (-> SOURCE_AUTO, stay unbound) or an IP
        literal (the bind address). Anything else warns and is ignored (returns ``None``)."""
        val = raw.strip()
        if val.lower() == SOURCE_AUTO:
            return SOURCE_AUTO
        try:
            addr = ipaddress.ip_address(val)
        except ValueError:
            self._warn(line, f"{who}: source must be an IPv4 address or 'auto', got '{raw}'; "
                       "ignoring")
            return None
        if addr.version != 4:
            # The whole bind stack is IPv4-only (raw AF_INET ping; IPv4 connection checks); an IPv6
            # source could never bind, so reject it at load with a clear warning rather than letting
            # it silently fail at probe time. IPv6 is #24.
            self._warn(line, f"{who}: IPv6 source binding isn't supported yet (#24), got '{raw}'; "
                       "ignoring")
            return None
        return val

    def _build_node(
        self, line: int, name: str, attrs: dict[str, tuple[int, list[Token]]]
    ) -> tuple[Node | None, str | None]:
        """Build a :class:`Node` from an object's attributes, or ``(None, None)`` if it fails the
        per-type required-field validation (mirroring the legacy parser, for converter parity)."""
        resolved = {key: self._subst(kl, toks[0].value) if toks else "" for key, (kl, toks) in
                    attrs.items()}

        # `host` is the preferred attribute; `ip` is a back-compat synonym (both -> Node.hostname,
        # which takes a hostname or an IP). If both are given and disagree, prefer `host` + warn.
        host = resolved.get("host") or resolved.get("ip")
        if "host" in resolved and "ip" in resolved and resolved["host"] != resolved["ip"]:
            self._warn(line, f"object '{name}': 'host' and 'ip' both set and differ; using 'host'")
        if not host:
            self._warn(line, f"object '{name}' has no 'host'; skipping")
            return None, None
        type_kw = resolved.get("type")
        ctype = _TYPE_KEYWORDS.get(type_kw) if type_kw is not None else None
        if ctype is None:
            self._warn(line, self._type_error(name, type_kw))
            return None, None

        node = Node(hostname=host, check_type=ctype, max_down=self.numfailures)
        default_port = DEFAULT_PORT.get(ctype)
        if default_port is not None:
            node.port = default_port

        if ctype in (CheckType.TCP, CheckType.UDP):
            port = self._port(line, name, resolved.get("port"))
            if port is None:
                return None, None
            node.port = port
        elif ctype in (CheckType.HTTP, CheckType.HTTPS):
            if not resolved.get("url") or not resolved.get("urltext"):
                self._warn(line, f"object '{name}': {type_kw} needs 'url' and 'urltext'; skipping")
                return None, None
            node.url, node.url_text = resolved["url"], resolved["urltext"]
        elif ctype is CheckType.POP3:
            if not resolved.get("username") or not resolved.get("password"):
                self._warn(line, f"object '{name}': pop3 needs 'username' and 'password'; skipping")
                return None, None
            node.username, node.password = resolved["username"], resolved["password"]
        elif ctype is CheckType.DNS:
            # Legacy authdns requires a name AND a contact (a DNS check that pages nobody is what
            # the legacy parser rejected at load) — keep parity.
            if not resolved.get("dns-query") or not resolved.get("contact"):
                self._warn(line, f"object '{name}': dns needs 'dns-query' and 'contact'; skipping")
                return None, None
            node.username = resolved["dns-query"]  # the name to look up (legacy convention)
        else:  # ping-like (ping, smtp): a port may still override the default
            if "port" in resolved:
                port = self._port(line, name, resolved.get("port"))
                if port is not None:
                    node.port = port

        # `desc`/`contact` are optional named attrs (legacy required a positional label); an empty
        # label is fine at runtime (display keys off check_type) — but the M5 converter must
        # synthesize a non-empty label (e.g. the hostname) when emitting back to legacy.
        if "desc" in resolved:
            node.label = resolved["desc"]
        if "contact" in resolved:
            node.contact = resolved["contact"]

        self._apply_overrides(line, name, node, resolved)

        for key, (kl, _toks) in attrs.items():
            if key not in _OBJECT_ATTRS:
                self._warn(kl, f"object '{name}': attribute '{key}' isn't supported yet; ignoring")

        dep_name = resolved.get("dep") or None
        return node, dep_name

    def _apply_overrides(self, line: int, name: str, node: Node, resolved: dict[str, str]) -> None:
        """Apply the per-object override attributes (#3 M4) onto ``node``; bad values warn + ignore.

        These map onto Node fields the engine already honors: ``queuetime``->``interval``
        (closes #23), ``send_pings``/``min_pings`` (validated; PingService also clamps at run
        time), ``numfailures``->``max_down``, ``group`` (display use is #20), ``contact_on``
        (which transitions page; "" = use the global default), and ``source`` (the per-object
        outbound bind address — an IP, or ``auto`` to stay unbound; #70).
        """
        if "queuetime" in resolved:
            interval = self._number(line, name, "queuetime", resolved["queuetime"], float)
            if interval is not None and interval <= 0:
                self._warn(line, f"object '{name}': queuetime must be > 0; ignoring")
            elif interval is not None:
                node.interval = interval
        if "numfailures" in resolved:
            nf = self._number(line, name, "numfailures", resolved["numfailures"], int)
            if nf is not None and nf < 1:
                self._warn(line, f"object '{name}': numfailures must be >= 1; ignoring")
            elif nf is not None:
                node.max_down = nf
        if "group" in resolved:
            node.group = resolved["group"].strip()  # blank/whitespace-only -> no group
        if "contact_on" in resolved:
            val = resolved["contact_on"]
            if val in CONTACT_ON_CHOICES:
                node.contact_on = val
            else:
                self._warn(line, f"object '{name}': contact_on must be one of "
                           f"{'/'.join(CONTACT_ON_CHOICES)}; ignoring")
        if "source" in resolved:
            src = self._parse_source(line, f"object '{name}'", resolved["source"])
            if src is not None:
                node.source = src  # wins over any group default (resolved later)
        self._apply_ping_counts(line, name, node, resolved)

    def _apply_ping_counts(
        self, line: int, name: str, node: Node, resolved: dict[str, str]
    ) -> None:
        send_given, min_given = "send_pings" in resolved, "min_pings" in resolved
        send = (self._number(line, name, "send_pings", resolved["send_pings"], int)
                if send_given else None)
        minp = (self._number(line, name, "min_pings", resolved["min_pings"], int)
                if min_given else None)
        if send is not None and send < 1:
            self._warn(line, f"object '{name}': send_pings must be >= 1; ignoring")
            send = None
        if minp is not None and minp < 1:
            self._warn(line, f"object '{name}': min_pings must be >= 1; ignoring")
            minp = None
        if send is not None and minp is not None and minp > send:
            self._warn(line, f"object '{name}': min_pings ({minp}) > send_pings ({send}); ignoring")
            send = minp = None
        # Atomic pair: if a *given* leg was rejected, drop its partner too — never combine a
        # per-object value with the global default for the other leg (a surprising/impossible mix).
        if (send_given and send is None) or (min_given and minp is None):
            send = minp = None
        if send is not None:
            node.send_pings = send
        if minp is not None:
            node.min_pings = minp

    def _number(self, line: int, name: str, key: str, raw: str, conv):
        """Parse ``raw`` as int/float; warn + return None on failure. Rejects '+'/'_' for ints and
        a non-finite float (``inf``/``nan`` would poison the scheduler heap as an interval)."""
        try:
            if conv is int and not raw.strip().lstrip("-").isdigit():
                raise ValueError
            value = conv(raw)
            if conv is float and not math.isfinite(value):
                raise ValueError
            return value
        except ValueError:
            self._warn(line, f"object '{name}': '{key}' expects a number, got '{raw}'; ignoring")
            return None

    def _port(self, line: int, name: str, raw: str | None) -> int | None:
        if raw is None:
            self._warn(line, f"object '{name}' needs a 'port'; skipping")
            return None
        # Plain digits only (reject the `+80`/`8_0` that Python int() would otherwise accept) and
        # a valid TCP/UDP range.
        canonical = raw.strip()
        if not canonical.isdigit() or not (0 < int(canonical) <= 65535):
            self._warn(line, f"object '{name}': invalid port '{raw}'; skipping")
            return None
        return int(canonical)

    @staticmethod
    def _type_error(name: str, type_kw: str | None) -> str:
        if type_kw is None:
            return f"object '{name}' has no 'type'; skipping"
        if type_kw in _DEFERRED_TYPES:
            return f"object '{name}': IPv6 ping ('{type_kw}') isn't supported yet (#24); skipping"
        if type_kw in _DROPPED_TYPES:
            return f"object '{name}': check type '{type_kw}' is not supported; skipping"
        return f"object '{name}': invalid type '{type_kw}'; skipping"

    def _resolve_group_sources(self) -> None:
        """Inherit each object's ``source`` from its ``group`` block's default when the object set
        none (#70). Per-object ``source`` (already on the node) wins; a group with no ``source``
        default, or membership in a group with no block (a plain display label, #20), leaves the
        object's source unset (it then falls back to the engine's per-type default)."""
        for _name, node, _dep, _line in self._objects:
            if node.source is None and node.group:
                grp = self._group_defaults.get(node.group)
                if grp and "source" in grp:
                    node.source = grp["source"]

    def _build_forest(self) -> list[Node]:
        """Resolve single ``dep`` edges into the ``Node.children`` forest (multi-dep is #62)."""
        if self.root_name is not None and self.root_name not in self._object_index:
            self._warn(self.root_line, f"root '{self.root_name}' names no object")
        roots: list[Node] = []
        for name, node, dep_name, line in self._objects:
            if dep_name is None:
                roots.append(node)
                continue
            parent = self._object_index.get(dep_name)
            if parent is None:
                self._warn(line, f"'{name}': dep '{dep_name}' names no object; making it a root")
                roots.append(node)
            elif self._reaches(node, parent):
                self._warn(line, f"'{name}': dep '{dep_name}' forms a cycle; making it a root")
                roots.append(node)
            else:
                parent.children.append(node)
        return roots

    @staticmethod
    def _reaches(start: Node, target: Node) -> bool:
        """True if ``target`` is ``start`` or in its subtree (so linking start->target cycles)."""
        stack, seen = [start], set()
        while stack:
            node = stack.pop()
            if node is target:
                return True
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(node.children)
        return False


def parse(text: str, *, numfailures: int = 2) -> ParseResult:
    """Parse modern-format ``text`` into a :class:`ParseResult` (#3 milestones 1–3).

    Interprets global ``config <directive> ...;`` lines into a settings-``overrides`` dict, ``set``
    / ``$var`` substitution, and ``object NAME { ... };`` blocks into a monitored ``Node`` forest
    (``dep`` edges resolved into ``Node.children``; single-dep MVP, the multi-parent DAG is #62).
    Per-object *override* attributes (``queuetime``/``send_pings``/``numfailures``/...) are M4, and
    ``include`` is a follow-up — both warn/raise rather than silently dropping coverage.

    ``numfailures`` (the caller's ``settings.numfailures``) seeds each object's ``max_down``; a
    top-level ``config numfailures`` also lands in ``overrides``. Malformed/invalid input warns and
    is skipped (never a hard failure), except a lexical error, which raises :class:`ParseError`.
    """
    return _Parser(tokenize(text), numfailures).parse_top()
