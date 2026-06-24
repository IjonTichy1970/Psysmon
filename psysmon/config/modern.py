"""Parser for the modern ``object{}`` config grammar (sysmon 0.93), milestone 1: the tokenizer.

This is the opt-in modern format adopted in issue #3 — the documented sysmon 0.93 grammar
(a single ``root``, named ``object NAME { ... };`` blocks with named attributes, ``dep``
edges, ``config`` globals, ``set``/``$var`` reuse), extended with psysmon-specific keys. The
legacy positional parser (:mod:`psysmon.config.legacy`) stays the default, and
:mod:`psysmon.config.detect` picks the format per file.

**Milestone 1 scope (this module):** the *tokenizer* plus the dispatch wiring. :func:`tokenize`
turns config text into a flat token stream; :func:`parse` runs it and returns the shared
:class:`~psysmon.config.legacy.ParseResult`, but does **not** yet interpret directives or
objects — an empty/comment-only file yields an empty result, and a file that carries real
tokens yields an empty result plus a warning that modern parsing is still incomplete. Global
directives (M2), ``object{}`` blocks (M3), and the per-object attributes / converter (M4–5)
build on this token stream.

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

from dataclasses import dataclass
from enum import Enum, auto

# Reuse the shared parse contract + error type so the daemon/scheduler consume either parser
# uniformly (both produce the same ParseResult; ParseError is a ValueError the daemon reports
# cleanly). These are format-neutral despite currently living in the legacy module.
from psysmon.config.legacy import ParseError, ParseResult

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


def parse(text: str, *, numfailures: int = 2) -> ParseResult:
    """Parse modern-format ``text`` into a :class:`ParseResult` (milestone 1: skeleton).

    Tokenizes the input (surfacing any lexical error). An empty / comment-only file yields an
    empty result. A file that carries real tokens is *refused* with a clean :class:`ParseError`
    until the directive/object interpreter lands (M2+) — failing loudly is safer than starting a
    daemon that silently monitors nothing (and on SIGHUP the running config is kept rather than
    replaced by an empty one). ``numfailures`` (the caller's ``settings.numfailures``) is accepted
    for signature parity with the legacy parser and used once ``config numfailures`` / per-object
    overrides are interpreted.
    """
    tokens = tokenize(text)
    if tokens:
        raise ParseError(
            "modern object{} config support is not yet implemented (only the tokenizer is in "
            "place); use the legacy format for now — see issue #3"
        )
    return ParseResult(roots=[], overrides={}, warnings=[])
