"""Parser for the modern ``object{}`` config grammar (sysmon 0.93): tokenizer + globals.

This is the opt-in modern format adopted in issue #3 — the documented sysmon 0.93 grammar
(a single ``root``, named ``object NAME { ... };`` blocks with named attributes, ``dep``
edges, ``config`` globals, ``set``/``$var`` reuse), extended with psysmon-specific keys. The
legacy positional parser (:mod:`psysmon.config.legacy`) stays the default, and
:mod:`psysmon.config.detect` picks the format per file.

**Implemented so far (#3 milestones 1–2):** the *tokenizer* (:func:`tokenize`) and the
**global directives**. :func:`parse` interprets top-level ``config <directive> ...;`` lines into
a settings-``overrides`` dict (keyed by :class:`~psysmon.config.settings.Settings` field names,
exactly like the legacy parser) plus ``set NAME = "..."`` / ``$NAME`` variable substitution. The
monitored graph — ``root`` and ``object{}`` blocks (M3/M4) — and ``include`` (a follow-up) are
not parsed yet: a config that uses them is *refused* with a clean :class:`ParseError` rather than
loaded as an empty monitor (and on SIGHUP the running config is kept). An empty / comment-only /
globals-only file yields a normal (objectless) result.

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

import re
from dataclasses import dataclass
from enum import Enum, auto

# Reuse the shared parse contract + error type (so the daemon consumes either parser uniformly)
# and the legacy facility allow-list (the single source of valid syslog facilities). These are
# format-neutral despite currently living in the legacy module — hoist to a shared module later.
from psysmon.config.legacy import _FACILITIES, ParseError, ParseResult

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
}
_FLAG_DIRECTIVES = {                   # value-less booleans
    "page_on_degraded": ("page_on_degraded", True),
    "noheartbeat": ("heartbeat_s", 0),
}
_LOGLEVELS = ("warning", "info", "debug")
_VAR_RE = re.compile(r"\$([A-Za-z_]\w*)")  # a $NAME reference (set / $var substitution)


class _Parser:
    """Walks the token stream, interpreting global ``config`` directives + ``set``/``$var`` (M2).

    Statements are sequences of tokens up to a ``;``. ``config`` and ``set`` are handled here;
    the monitored graph (``root`` / ``object{}``) and ``include`` raise a clean
    :class:`ParseError` (not parsed yet). Unknown directives / malformed values warn and skip,
    matching the legacy parser's never-hard-fail-a-recoverable-config stance.
    """

    def __init__(self, tokens: list[Token], numfailures: int) -> None:
        self._toks = tokens
        self._i = 0
        self.numfailures = numfailures  # running default threshold; used per-object in M4
        self.vars: dict[str, str] = {}
        self.overrides: dict[str, object] = {}
        self.warnings: list[str] = []

    def parse_top(self) -> ParseResult:
        while self._i < len(self._toks):
            self._statement()
        return ParseResult(roots=[], overrides=self.overrides, warnings=self.warnings)

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
        elif word in ("root", "object"):
            raise ParseError(
                f"line {tok.line}: monitored objects (`{word} ...`) aren't parsed yet — this "
                "milestone is in progress (#3); use the legacy format to monitor hosts for now"
            )
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


def parse(text: str, *, numfailures: int = 2) -> ParseResult:
    """Parse modern-format ``text`` into a :class:`ParseResult` (#3 milestones 1–2).

    Interprets top-level ``config <directive> ...;`` lines into a settings-``overrides`` dict and
    ``set`` / ``$var`` substitution. The monitored graph (``root`` / ``object{}``, M3/M4) and
    ``include`` (a follow-up) are not parsed yet — a config using them is refused with a clean
    :class:`ParseError` rather than loaded as an empty monitor (and SIGHUP keeps the running
    config). An empty / comment-only / globals-only file yields a normal (objectless) result.

    ``numfailures`` (the caller's ``settings.numfailures``) is the running default threshold; a
    top-level ``config numfailures`` lands in ``overrides`` here, while the per-object snapshot it
    feeds is interpreted with the objects in M4.
    """
    return _Parser(tokenize(text), numfailures).parse_top()
