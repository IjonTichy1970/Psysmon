"""Tests for the modern object{} config parser — milestone 1 (tokenizer + dispatch, #3)."""

from __future__ import annotations

import pytest

from psysmon.config.detect import ConfigFormat, detect
from psysmon.config.legacy import ParseError
from psysmon.config.modern import Token, TokenKind, parse, tokenize


def kinds(text: str) -> list[TokenKind]:
    return [t.kind for t in tokenize(text)]


# --- tokenizer: structure -------------------------------------------------------------

def test_tokenize_root_assignment():
    toks = tokenize('root = "gw";\n')
    assert [t.kind for t in toks] == [
        TokenKind.WORD, TokenKind.EQUALS, TokenKind.STRING, TokenKind.SEMI
    ]
    assert toks[0].value == "root" and toks[2].value == "gw"  # quotes stripped


def test_tokenize_object_block():
    text = 'object gw {\n  ip "192.0.2.1";\n  type ping;\n};\n'
    assert kinds(text) == [
        TokenKind.WORD, TokenKind.WORD, TokenKind.LBRACE,           # object gw {
        TokenKind.WORD, TokenKind.STRING, TokenKind.SEMI,           # ip "192.0.2.1";
        TokenKind.WORD, TokenKind.WORD, TokenKind.SEMI,             # type ping;
        TokenKind.RBRACE, TokenKind.SEMI,                          # };
    ]


def test_tokenize_dotted_bareword_is_one_word():
    # An object name / number bareword keeps its dots, digits and dashes as ONE word; only the
    # special chars { } = ; " # and whitespace split a bareword.
    toks = tokenize('object my.default.gw-1 {\n  port 8080;\n};\n')
    words = [t.value for t in toks if t.kind is TokenKind.WORD]
    assert words == ["object", "my.default.gw-1", "port", "8080"]


def test_token_line_numbers():
    toks = tokenize('root = "gw";\n\nobject x {\n};\n')
    by_kind = {t.kind: t.line for t in toks}
    assert by_kind[TokenKind.EQUALS] == 1
    assert tokenize('\n\nobject x {')[0].line == 3  # leading blank lines counted


# --- tokenizer: comments --------------------------------------------------------------

def test_comment_lines_hash_and_semicolon():
    # '#' and ';'-led lines (incl. ';', ';;', '; like this') are comments -> no tokens.
    text = "# a comment\n; another\n;;\n; like this\n"
    assert tokenize(text) == []


def test_trailing_hash_comment():
    assert kinds('type ping;  # trailing note\n') == [
        TokenKind.WORD, TokenKind.WORD, TokenKind.SEMI
    ]


def test_semicolon_terminator_vs_comment():
    # A ';' after statement content terminates it; a ';' at a boundary starts a comment.
    assert kinds('a;\n; b c\nd;\n') == [
        TokenKind.WORD, TokenKind.SEMI,   # a ;
        # '; b c' is a comment (boundary ';')
        TokenKind.WORD, TokenKind.SEMI,   # d ;
    ]


def test_double_semicolon_after_statement_is_empty_then_comment():
    # 'x;;' -> first ';' terminates, the second is a boundary ';' -> comment to EOL.
    assert kinds('x;;\n') == [TokenKind.WORD, TokenKind.SEMI]


def test_semicolon_led_line_is_comment_even_after_unterminated_line():
    # A ';'-led line is a comment regardless of whether the PREVIOUS line ended with ';'
    # (the upstream [;#].*\n rule keys on line start). Here `ip "1.2.3.4"` has no trailing ';'.
    text = 'object x {\n  ip "1.2.3.4"\n; note line\n};\n'
    toks = tokenize(text)
    assert all(t.value not in ("note", "line") for t in toks)  # the comment didn't leak as WORDs
    assert kinds(text) == [
        TokenKind.WORD, TokenKind.WORD, TokenKind.LBRACE,   # object x {
        TokenKind.WORD, TokenKind.STRING,                   # ip "1.2.3.4"   (no ';')
        TokenKind.RBRACE, TokenKind.SEMI,                   # };
    ]


def test_semicolon_led_line_is_comment_after_hash_comment():
    # ';'-led line is a comment even when the prior line was a '#' comment (boundary reset).
    assert kinds('a b  # note\n; c\nd;\n') == [
        TokenKind.WORD, TokenKind.WORD,   # a b   (unterminated, but tokenized)
        TokenKind.WORD, TokenKind.SEMI,   # d ;
    ]


def test_semicolon_right_after_open_brace_is_comment():
    assert kinds('object x { ; oops\n  ip "y";\n};\n') == [
        TokenKind.WORD, TokenKind.WORD, TokenKind.LBRACE,   # object x {  (; oops -> comment)
        TokenKind.WORD, TokenKind.STRING, TokenKind.SEMI,   # ip "y";
        TokenKind.RBRACE, TokenKind.SEMI,                   # };
    ]


def test_hash_and_semicolon_inside_string_are_literal():
    toks = tokenize('desc "a # b ; c";\n')
    assert toks[1].kind == TokenKind.STRING
    assert toks[1].value == "a # b ; c"  # the # and ; inside quotes are kept


# --- tokenizer: errors + edges --------------------------------------------------------

def test_unterminated_string_raises_with_line():
    with pytest.raises(ParseError) as exc:
        tokenize('object x {\n  ip "oops\n};\n')
    assert "line 2" in str(exc.value) and "unterminated string" in str(exc.value)


def test_unterminated_string_at_eof_raises():
    with pytest.raises(ParseError):
        tokenize('desc "no close')


def test_empty_and_whitespace_only_yield_no_tokens():
    assert tokenize("") == []
    assert tokenize("   \n\t\n  \n") == []


# --- parse() skeleton -----------------------------------------------------------------

def test_parse_empty_is_clean_empty_result():
    res = parse("")
    assert res.roots == [] and res.overrides == {} and res.warnings == []


def test_parse_comment_only_is_clean_empty_result():
    res = parse("# just comments\n; and more\n")
    assert res.roots == [] and res.overrides == {} and res.warnings == []


def test_parse_real_config_refused_until_implemented():
    # Until M2+ interprets directives/objects, a real modern file is REFUSED (fail loud) rather
    # than loaded as an empty monitor — so a daemon never silently watches nothing.
    with pytest.raises(ParseError) as exc:
        parse('root = "gw";\nobject gw {\n  ip "192.0.2.1";\n  type ping;\n};\n')
    assert "not yet implemented" in str(exc.value)


def test_parse_propagates_lexical_error():
    with pytest.raises(ParseError):
        parse('object x {\n  ip "unterminated\n};\n')


def test_parse_accepts_numfailures_kwarg():
    # Same signature as the legacy parser so the daemon can call either uniformly.
    assert parse("", numfailures=5).roots == []


# --- detect() routes the modern grammar -----------------------------------------------

def test_detect_modern_signals():
    assert detect('root = "gw";\n') is ConfigFormat.MODERN
    assert detect('set x = "y";\n') is ConfigFormat.MODERN
    assert detect('object gw {\n};\n') is ConfigFormat.MODERN
    assert detect('# c\nconfig queuetime 30;\nobject gw {\n};\n') is ConfigFormat.MODERN


def test_detect_legacy_and_ambiguous():
    assert detect("h.example.net ping h.example.net noc@x\n") is ConfigFormat.LEGACY
    assert detect('config savestate "/x";\n') is ConfigFormat.LEGACY  # config-only -> legacy
    assert detect("") is ConfigFormat.LEGACY


def test_detect_does_not_misroute_legacy_shapes():
    # A legacy www line whose URL field contains '=' has no STANDALONE '=' token -> LEGACY.
    assert detect("h.example.net www http://h/p?a=b OK lbl noc@x\n") is ConfigFormat.LEGACY
    # A legacy ping block line ends in '{' but its first token is a hostname -> LEGACY.
    assert detect("rtr.example.net ping rtr.example.net noc@x {\n") is ConfigFormat.LEGACY
    # Even a (pathological) host literally named 'object' stays legacy: the '{' isn't right
    # after the name, so it isn't the modern `object NAME {` shape.
    assert detect("object ping object noc@x {\n") is ConfigFormat.LEGACY


def test_token_is_hashable_frozen():
    # Token is a frozen dataclass (used in lists/comparisons); sanity-check equality.
    assert Token(TokenKind.WORD, "a", 1) == Token(TokenKind.WORD, "a", 1)
    assert Token(TokenKind.WORD, "a", 1) != Token(TokenKind.WORD, "a", 2)
