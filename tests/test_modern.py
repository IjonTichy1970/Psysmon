"""Tests for the modern object{} config parser — milestone 1 (tokenizer + dispatch, #3)."""

from __future__ import annotations

import pytest

from psysmon.config.detect import ConfigFormat, detect
from psysmon.config.legacy import ParseError
from psysmon.config.modern import Token, TokenKind, parse, tokenize
from psysmon.config.settings import merge


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


def test_parse_objects_refused_until_m3():
    # Globals parse now (M2), but the monitored graph (root/object) is refused until M3 — fail
    # loud rather than load a daemon that monitors nothing.
    with pytest.raises(ParseError) as exc:
        parse('root = "gw";\nobject gw {\n  ip "192.0.2.1";\n  type ping;\n};\n')
    assert "aren't parsed yet" in str(exc.value)


def test_parse_propagates_lexical_error():
    with pytest.raises(ParseError):
        parse('object x {\n  ip "unterminated\n};\n')


def test_parse_accepts_numfailures_kwarg():
    # Same signature as the legacy parser so the daemon can call either uniformly.
    assert parse("", numfailures=5).roots == []


# --- M2: global config directives + set/$var ------------------------------------------

def ov(text: str) -> dict:
    return parse(text).overrides


def test_config_int_directives():
    assert ov("config pageinterval 18;\n")["pageinterval_min"] == 18
    assert ov("config send_pings 3;\nconfig min_pings 2;\n") == {"send_pings": 3, "min_pings": 2}
    assert ov("config maxqueued 80;\n")["max_concurrency"] == 80
    assert ov("config heartbeat 120;\n")["heartbeat_s"] == 120


def test_config_queuetime_accepts_int_or_float():
    # queuetime -> interval_s, a float field (and --interval is type=float), so a fractional
    # cadence must parse rather than warn-skip.
    assert ov("config queuetime 30;\n")["interval_s"] == 30.0
    assert ov("config queuetime 2.5;\n")["interval_s"] == 2.5
    assert any("number" in w for w in parse("config queuetime nope;\n").warnings)


def test_config_str_directives():
    assert ov('config savestate "/var/lib/psysmon/state.json";\n')["state_path"] == (
        "/var/lib/psysmon/state.json")
    assert ov('config source_ip "203.0.113.9";\n')["source_ip"] == "203.0.113.9"
    assert ov('config hostname "mon1.example.net";\n')["org_hostname"] == "mon1.example.net"
    assert ov('config sender "noc@example.net";\n')["mail_from"] == "noc@example.net"
    assert ov('config from "ops@example.net";\n')["mail_from"] == "ops@example.net"


def test_config_flag_directives():
    assert ov("config page_on_degraded;\n")["page_on_degraded"] is True
    assert ov("config noheartbeat;\n")["heartbeat_s"] == 0


def test_config_loglevel_and_logging():
    assert ov("config loglevel debug;\n")["log_level"] == "debug"
    bad_level = parse("config loglevel bogus;\n")
    assert bad_level.overrides["log_level"] == "info" and any(
        "loglevel" in w for w in bad_level.warnings)
    assert ov("config logging local0;\n")["syslog_facility"] == "local0"
    assert ov("config logging none;\n")["syslog_facility"] is None
    bad_fac = parse("config logging nope;\n")
    assert bad_fac.overrides["syslog_facility"] == "daemon" and bad_fac.warnings


def test_config_statusfile():
    o = ov('config statusfile html "/var/www/status.html";\n')
    assert o["status_html"] is True and o["status_path"] == "/var/www/status.html"
    assert ov('config statusfile text "/tmp/s.txt";\n')["status_html"] is False
    assert parse('config statusfile bogus "/x";\n').warnings  # invalid format -> warn + skip


def test_config_unknown_invalid_obsolete_warn_skip():
    unknown = parse("config bogusdirective 5;\n")
    assert unknown.overrides == {}
    assert any("unknown config directive" in w for w in unknown.warnings)
    bad_int = parse("config heartbeat notanint;\n")
    assert bad_int.overrides == {} and any("integer" in w for w in bad_int.warnings)
    obsolete = parse("config sleeptime 30;\n")
    assert obsolete.overrides == {} and any("obsolete" in w for w in obsolete.warnings)


def test_set_and_var_substitution():
    res = parse('set on = "noc@example.net";\nconfig sender "$on";\n')
    assert res.overrides["mail_from"] == "noc@example.net" and res.warnings == []


def test_undefined_var_warns_and_stays_literal():
    res = parse('config sender "$missing";\n')
    assert res.overrides["mail_from"] == "$missing"
    assert any("undefined variable" in w for w in res.warnings)


def test_malformed_set_warns():
    assert any("malformed 'set'" in w for w in parse("set broken;\n").warnings)


def test_globals_only_config_parses_without_objects():
    res = parse('# header\nconfig queuetime 30;\nset x = "y";\nconfig hostname "$x";\n')
    assert res.roots == [] and res.overrides["interval_s"] == 30
    assert res.overrides["org_hostname"] == "y"  # $x substituted from `set`


def test_root_and_include_are_refused():
    for snippet in ('root = "gw";\n', 'include "other.conf";\n'):
        with pytest.raises(ParseError):
            parse(snippet)


def test_all_overrides_are_valid_settings_fields():
    # Every directive maps to a real Settings field, so merge() accepts the overrides unchanged
    # (the _FIELD_NAMES contract) — and no directive in this exhaustive config warns.
    text = (
        'config pageinterval 18;\nconfig numfailures 5;\nconfig queuetime 45;\n'
        'config send_pings 3;\nconfig min_pings 2;\nconfig page_on_degraded;\n'
        'config savestate "/x";\nconfig statesave_interval 30;\nconfig state_max_age 0;\n'
        'config source_ip "203.0.113.9";\nconfig hostname "mon";\nconfig maxqueued 80;\n'
        'config sender "noc@example.net";\nconfig loglevel debug;\nconfig logging local0;\n'
        'config dnsexpire 7200;\nconfig dnslog 600;\nconfig heartbeat 120;\n'
        'config statusfile html "/p";\n'
    )
    res = parse(text)
    assert res.warnings == []  # every directive recognized
    s = merge(file_overrides=res.overrides)  # must not raise "unknown setting"
    assert s.interval_s == 45 and s.send_pings == 3 and s.state_path == "/x"
    assert s.page_on_degraded is True and s.status_path == "/p" and s.max_concurrency == 80


# --- M2: parser-robustness regressions (review follow-ups) ----------------------------

def test_statement_walk_safety_on_garbage():
    # Stray punctuation / strings at statement start warn and skip — no crash, no infinite loop.
    res = parse('{ } = "x";\n= = =;\n"lonely";\n')
    assert res.overrides == {} and res.roots == []
    assert len(res.warnings) >= 3


def test_config_missing_semi_and_arity():
    no_semi = parse("config heartbeat 5\n")  # missing terminating ';'
    assert no_semi.overrides["heartbeat_s"] == 5
    assert any("terminating" in w for w in no_semi.warnings)
    assert any("needs a value" in w for w in parse("config heartbeat;\n").warnings)
    extra = parse("config heartbeat 1 2 3;\n")
    assert extra.overrides["heartbeat_s"] == 1 and any("one value" in w for w in extra.warnings)


def test_set_malformed_punctuation_value_warns():
    # `set x = = ;` is malformed -> warn, NOT a silent empty binding (review LOW).
    res = parse('set x = = ;\nconfig hostname "$x";\n')
    assert any("malformed 'set'" in w for w in res.warnings)
    assert res.overrides["org_hostname"] == "$x"  # x never bound -> $x left literal


def test_var_substitution_edge_cases():
    # used-before-set -> literal + warn; self-reference -> literal, no loop; non-identifier $1 ->
    # left literal silently (single-pass; a substituted value's own $ isn't re-expanded).
    res = parse('config hostname "$y";\nset y = "later";\nset z = "$z";\nset n = "a$1b";\n')
    assert res.overrides["org_hostname"] == "$y"  # $y used before it was set
    assert any("undefined variable $y" in w for w in res.warnings)


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
