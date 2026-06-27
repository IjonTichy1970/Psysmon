"""Tests for the modern object{} config parser — milestone 1 (tokenizer + dispatch, #3)."""

from __future__ import annotations

import pytest

from psysmon.config.detect import ConfigFormat, detect
from psysmon.config.legacy import ParseError
from psysmon.config.model import SOURCE_AUTO, CheckType
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


def test_parse_objects_build_a_node_forest():
    # M3: objects parse into a Node forest (root/object no longer raise).
    res = parse('root = "gw";\nobject gw {\n  ip "192.0.2.1";\n  type ping;\n};\n')
    assert res.warnings == []
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]
    assert res.roots[0].check_type is CheckType.PING


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


def test_include_is_refused():
    with pytest.raises(ParseError):
        parse('include "other.conf";\n')


def test_root_naming_missing_object_warns_not_raises():
    res = parse('root = "gw";\n')  # no object named gw
    assert res.roots == [] and any("names no object" in w for w in res.warnings)


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


# --- M3: object{} blocks + dependency forest ------------------------------------------

def test_object_per_type_fields():
    res = parse(
        'object gw { ip "192.0.2.1"; type ping; desc "gateway"; contact "noc@example.net"; };\n'
        'object web { ip "192.0.2.20"; type https; url "/health"; urltext "OK"; };\n'
        'object ns { ip "192.0.2.53"; type dns; dns-query "example.net"; '
        'contact "noc@example.net"; };\n'
        'object svc { ip "192.0.2.30"; type tcp; port 22; desc "ssh"; };\n'
        'object box { ip "192.0.2.40"; type pop3; username "u"; password "p"; };\n'
    )
    assert res.warnings == []
    by = {n.hostname: n for n in res.roots}
    assert by["192.0.2.1"].check_type is CheckType.PING and by["192.0.2.1"].label == "gateway"
    assert by["192.0.2.1"].contact == "noc@example.net"
    web = by["192.0.2.20"]
    assert web.check_type is CheckType.HTTPS and (web.url, web.url_text) == ("/health", "OK")
    assert web.port == 443  # type default
    assert by["192.0.2.53"].username == "example.net"  # dns-query -> the name to look up
    assert by["192.0.2.30"].port == 22 and by["192.0.2.30"].check_type is CheckType.TCP
    box = by["192.0.2.40"]
    assert (box.username, box.password, box.port) == ("u", "p", 110)


def test_dep_builds_children_tree():
    res = parse(
        'object gw { ip "192.0.2.1"; type ping; };\n'
        'object web { ip "192.0.2.20"; type tcp; port 443; dep "gw"; };\n'
    )
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]            # only gw is a root
    assert [c.hostname for c in res.roots[0].children] == ["192.0.2.20"]  # web nested under gw


def test_dep_can_reference_a_later_object():
    # Forward references work: deps resolve after all objects are parsed.
    res = parse(
        'object web { ip "192.0.2.20"; type tcp; port 443; dep "gw"; };\n'
        'object gw { ip "192.0.2.1"; type ping; };\n'
    )
    gw = next(n for n in res.roots if n.hostname == "192.0.2.1")
    assert [c.hostname for c in gw.children] == ["192.0.2.20"]


def test_object_missing_required_field_skipped():
    assert any("no 'host'" in w for w in parse('object x { type ping; };\n').warnings)
    assert any("needs a 'port'" in w for w in parse('object x { ip "h"; type tcp; };\n').warnings)
    assert any("'url' and 'urltext'" in w
               for w in parse('object x { ip "h"; type https; };\n').warnings)
    assert any("invalid type" in w
               for w in parse('object x { ip "h"; type frobnicate; };\n').warnings)
    # all of the above produced no node
    for cfg in ('object x { type ping; };\n', 'object x { ip "h"; type tcp; };\n'):
        assert parse(cfg).roots == []


# --- #76: `host` is the preferred synonym for `ip` -------------------------------------

def test_host_is_the_preferred_attribute():
    res = parse('object x { host "router.example.net"; type ping; };\n')
    assert res.roots[0].hostname == "router.example.net" and res.warnings == []


def test_ip_is_still_an_accepted_synonym():
    res = parse('object x { ip "192.0.2.1"; type ping; };\n')
    assert res.roots[0].hostname == "192.0.2.1" and res.warnings == []


def test_host_and_ip_both_set_same_is_fine():
    res = parse('object x { host "h"; ip "h"; type ping; };\n')
    assert res.roots[0].hostname == "h" and res.warnings == []


def test_host_and_ip_both_set_differ_warns_and_prefers_host():
    res = parse('object x { host "wins"; ip "loses"; type ping; };\n')
    assert res.roots[0].hostname == "wins"
    assert any("'host' and 'ip' both set" in w for w in res.warnings)


def test_neither_host_nor_ip_skips():
    res = parse('object x { type ping; };\n')
    assert res.roots == [] and any("no 'host'" in w for w in res.warnings)


def test_host_attr_not_unknown():
    res = parse('object x { host "h"; type ping; };\n')
    assert not any("isn't supported yet" in w for w in res.warnings)


def test_dropped_types_skip():
    dropped = parse('object x { ip "h"; type nntp; };\n')  # imap is no longer dropped (#88)
    assert dropped.roots == [] and any("not supported" in w for w in dropped.warnings)


def test_mail_tls_types_recognized():
    # imap / pop3s / imaps build the right node with the right default port (#88).
    res = parse(
        'object a { host "p3s.example.net"; type pop3s; username "u"; password "p"; };\n'
        'object b { host "im.example.net"; type imap; };\n'
        'object c { host "ims.example.net"; type imaps; };\n'
    )
    assert res.warnings == []
    by = {n.hostname: n for n in res.roots}
    assert by["p3s.example.net"].check_type is CheckType.POP3S and by["p3s.example.net"].port == 995
    assert by["im.example.net"].check_type is CheckType.IMAP and by["im.example.net"].port == 143
    assert by["ims.example.net"].check_type is CheckType.IMAPS and by["ims.example.net"].port == 993


def test_pop3_family_banner_only_builds_without_credentials():
    # pop3/pop3s now mirror imap/imaps: no credentials -> a banner-only check, not a skip (#101).
    res = parse(
        'object x { host "h.example.net"; type pop3; };\n'
        'object y { host "h2.example.net"; type pop3s; };\n'
    )
    assert len(res.roots) == 2 and res.warnings == []
    assert all(n.username == "" and n.password == "" for n in res.roots)


def test_pop3_partial_credentials_warn_and_ignored():
    # Only one of username/password -> warn + ignore both; the object still builds (banner) (#101).
    res = parse('object x { host "h.example.net"; type pop3; username "u"; };\n')
    assert len(res.roots) == 1 and res.roots[0].username == ""
    assert any("pop3 auth needs both" in w for w in res.warnings)


def test_imap_banner_only_builds_without_credentials():
    res = parse('object x { host "h.example.net"; type imap; };\n')
    assert len(res.roots) == 1 and res.warnings == []
    assert res.roots[0].username == "" and res.roots[0].password == ""


def test_imap_optional_credentials_applied():
    res = parse('object x { host "h.example.net"; type imaps; username "u"; password "p"; };\n')
    n = res.roots[0]
    assert n.username == "u" and n.password == "p"


def test_imap_partial_credentials_warn_and_ignored():
    # Only one of username/password -> warn + ignore both; the object still builds (banner check).
    res = parse('object x { host "h.example.net"; type imap; username "u"; };\n')
    assert len(res.roots) == 1 and res.roots[0].username == ""
    assert any("imap auth needs both" in w for w in res.warnings)


def test_ping6_type_recognized():
    # ping6 (and its pingv6/icmp6 aliases) build a PING6 node — no longer deferred (#24).
    for kw in ("ping6", "pingv6", "icmp6"):
        res = parse(f'object x {{ ip "h"; type {kw}; }};\n')
        assert res.warnings == []
        assert len(res.roots) == 1 and res.roots[0].check_type is CheckType.PING6


def test_unknown_object_attribute_warns_but_keeps_object():
    # A genuinely-unknown attribute is ignored with a warning; the object still builds, and a
    # recognized override (queuetime) is applied rather than warned.
    res = parse('object gw { ip "192.0.2.1"; type ping; queuetime 10; bogus "x"; };\n')
    assert res.roots[0].interval == 10.0  # queuetime applied (M4)
    assert any("bogus" in w for w in res.warnings)
    assert not any("queuetime" in w for w in res.warnings)


def test_multi_dep_builds_a_dag():
    # Multiple `dep`s put the child under EVERY named parent — a multi-parent DAG (#62), no warning.
    res = parse(
        'object a { ip "192.0.2.1"; type ping; };\n'
        'object b { ip "192.0.2.2"; type ping; };\n'
        'object c { ip "192.0.2.3"; type tcp; port 22; dep "a"; dep "b"; };\n'
    )
    a = next(n for n in res.roots if n.hostname == "192.0.2.1")
    b = next(n for n in res.roots if n.hostname == "192.0.2.2")
    assert [ch.hostname for ch in a.children] == ["192.0.2.3"]  # c under a ...
    assert [ch.hostname for ch in b.children] == ["192.0.2.3"]  # ... AND under b
    assert a.children[0] is b.children[0]  # the SAME shared Node, not a copy
    assert res.warnings == []  # no "duplicate 'dep'" warning anymore


def test_multi_dep_diamond_is_not_a_cycle():
    # a->b, a->c, b->d, c->d: d has two parents (b, c). A diamond is reached twice, but is acyclic.
    res = parse(
        'object a { ip "192.0.2.1"; type ping; };\n'
        'object b { ip "192.0.2.2"; type ping; dep "a"; };\n'
        'object c { ip "192.0.2.3"; type ping; dep "a"; };\n'
        'object d { ip "192.0.2.4"; type tcp; port 22; dep "b"; dep "c"; };\n'
    )
    assert not any("cycle" in w for w in res.warnings)  # a diamond is NOT a cycle
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]  # only a is a root
    b, c = res.roots[0].children
    assert b.children[0] is c.children[0]  # d is the same node under both b and c


def test_multi_dep_unknown_edge_dropped_others_kept():
    # c dep a (known) + ghost (unknown): the ghost edge warns + drops; c stays under a (not a root).
    res = parse(
        'object a { ip "192.0.2.1"; type ping; };\n'
        'object c { ip "192.0.2.3"; type tcp; port 22; dep "a"; dep "ghost"; };\n'
    )
    a = next(n for n in res.roots if n.hostname == "192.0.2.1")
    assert [ch.hostname for ch in a.children] == ["192.0.2.3"]  # c under a
    assert all(n.hostname != "192.0.2.3" for n in res.roots)  # c is NOT a root
    assert any("ghost" in w and "names no object" in w for w in res.warnings)


def test_self_dep_is_a_cycle_and_becomes_root():
    res = parse('object a { ip "192.0.2.1"; type ping; dep "a"; };\n')
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]  # self-dep dropped -> a is a root
    assert any("cycle" in w for w in res.warnings)


def test_duplicate_non_dep_attr_still_keeps_first():
    # The multi-dep special case must NOT leak: a repeated *non-dep* attr still warns + keeps first.
    res = parse('object a { ip "192.0.2.1"; type tcp; port 22; port 23; };\n')
    assert any("duplicate 'port'" in w for w in res.warnings)
    assert res.roots[0].port == 22  # the first value kept


def test_dependency_cycle_is_broken():
    res = parse(
        'object a { ip "192.0.2.1"; type ping; dep "b"; };\n'
        'object b { ip "192.0.2.2"; type ping; dep "a"; };\n'
    )
    assert any("cycle" in w for w in res.warnings)

    def assert_acyclic(nodes, seen):
        for n in nodes:
            assert id(n) not in seen  # no node reachable twice -> finite, acyclic
            seen.add(id(n))
            assert_acyclic(n.children, seen)

    assert_acyclic(res.roots, set())


def test_dep_to_unknown_object_becomes_root():
    res = parse('object x { ip "192.0.2.1"; type tcp; port 22; dep "ghost"; };\n')
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]
    assert any("names no object" in w for w in res.warnings)


def test_duplicate_object_name_skipped():
    res = parse(
        'object dup { ip "192.0.2.1"; type ping; };\n'
        'object dup { ip "192.0.2.2"; type ping; };\n'
    )
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]  # the second 'dup' is skipped
    assert any("duplicate object name" in w for w in res.warnings)


def test_malformed_object_header_recovers():
    # A missing name is warned + skipped (the block is drained) without derailing the next object.
    res = parse(
        'object { ip "192.0.2.9"; type ping; };\n'         # no name
        'object good { ip "192.0.2.1"; type ping; };\n'
    )
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]
    assert any("needs a name" in w for w in res.warnings)


# --- M3 review follow-ups -------------------------------------------------------------

def test_dns_requires_contact():
    # Parity with legacy authdns: a dns object with no contact is rejected.
    no_contact = parse('object ns { ip "192.0.2.53"; type dns; dns-query "x.example.net"; };\n')
    assert no_contact.roots == [] and any("dns needs" in w for w in no_contact.warnings)
    ok = parse('object ns { ip "192.0.2.53"; type dns; dns-query "x.example.net"; '
               'contact "noc@example.net"; };\n')
    assert [n.hostname for n in ok.roots] == ["192.0.2.53"] and ok.warnings == []


def test_inner_brace_in_object_body_is_skipped_not_leaked():
    # A user porting legacy {}-nesting (or any stray inner block) must not derail parsing: the
    # outer object still builds, the inner block is skipped + warned, nothing leaks to top level.
    res = parse(
        'object parent { ip "192.0.2.1"; type ping;\n'
        '  object child { ip "192.0.2.2"; type ping; };\n'   # nested object -> not supported
        '};\n'
        'object after { ip "192.0.2.9"; type ping; };\n'
    )
    hosts = [n.hostname for n in res.roots]
    assert "192.0.2.1" in hosts and "192.0.2.9" in hosts     # parent + after both build
    assert "192.0.2.2" not in hosts                          # nested child dropped (no {}-nesting)
    assert any("'{'" in w for w in res.warnings)             # the inner block was flagged
    assert not any("unknown statement" in w for w in res.warnings)  # no top-level leakage


def test_object_attr_tolerates_equals():
    # `ip = "h"` (legacy / set-style '=') is tolerated as `ip "h"`.
    res = parse('object x { ip = "192.0.2.1"; type = ping; };\n')
    assert [n.hostname for n in res.roots] == ["192.0.2.1"]


def test_object_port_range_validation():
    for bad in ("0", "70000", "+80", "8_0", "notaport"):
        res = parse(f'object x {{ ip "h"; type tcp; port {bad}; }};\n')
        assert res.roots == [] and any("invalid port" in w for w in res.warnings)
    assert parse('object x { ip "h"; type tcp; port 65535; };\n').roots[0].port == 65535


def test_missing_semicolon_between_attrs_warns():
    res = parse('object x { ip "192.0.2.1" type ping; };\n')  # missing ';' after ip's value
    assert any("missing ';'" in w for w in res.warnings)


# --- M4: per-object override attributes (closes #23) ----------------------------------

def test_per_object_override_attributes():
    res = parse(
        'object gw { ip "192.0.2.1"; type ping; queuetime 10; send_pings 5; min_pings 3; '
        'numfailures 4; group "core"; };\n'
    )
    assert res.warnings == []
    n = res.roots[0]
    assert n.interval == 10.0 and n.send_pings == 5 and n.min_pings == 3
    assert n.max_down == 4 and n.group == "core"


def test_per_object_overrides_no_longer_warn_as_unknown():
    # In M3 these warned "isn't supported yet"; M4 recognizes them.
    res = parse('object x { ip "h"; type ping; queuetime 30; group "g"; };\n')
    assert not any("isn't supported yet" in w for w in res.warnings)


def test_per_object_queuetime_accepts_float():
    assert parse('object x { ip "h"; type ping; queuetime 2.5; };\n').roots[0].interval == 2.5


def test_per_object_min_greater_than_send_rejected():
    res = parse('object x { ip "h"; type ping; send_pings 3; min_pings 5; };\n')
    n = res.roots[0]
    assert n.send_pings is None and n.min_pings is None  # both ignored, fall back to global
    assert any("min_pings" in w and "send_pings" in w for w in res.warnings)


def test_per_object_invalid_override_values_warn_and_ignore():
    res = parse('object x { ip "h"; type ping; queuetime nope; numfailures 0; send_pings 0; };\n')
    n = res.roots[0]
    assert n.interval is None       # bad queuetime ignored -> global default
    assert n.max_down == 2          # numfailures 0 ignored -> default
    assert n.send_pings is None     # send_pings 0 ignored
    assert len(res.warnings) >= 3


def test_group_whitespace_only_is_treated_as_no_group():
    # A blank/whitespace-only group must not become a distinct, empty-looking section.
    assert parse('object x { ip "h"; type ping; group "   "; };\n').roots[0].group == ""
    assert parse('object x { ip "h"; type ping; group " core "; };\n').roots[0].group == "core"


def test_contact_on_per_object():
    res = parse('object x { ip "h"; type ping; contact_on down; };\n')
    assert res.roots[0].contact_on == "down" and res.warnings == []


def test_contact_on_invalid_value_warns_and_ignores():
    res = parse('object x { ip "h"; type ping; contact_on sometimes; };\n')
    assert res.roots[0].contact_on == ""  # left at default; object still loads
    assert any("contact_on" in w for w in res.warnings)


def test_contact_on_global_directive():
    res = parse('config contact_on up;\nobject x { ip "h"; type ping; };\n')
    assert res.overrides.get("contact_on") == "up"
    res_bad = parse('config contact_on nope;\nobject x { ip "h"; type ping; };\n')
    assert res_bad.overrides.get("contact_on") == "both"  # unknown -> falls back to both + warns
    assert any("contact_on" in w for w in res_bad.warnings)


def test_control_plane_global_directives():
    res = parse(
        'config control;\n'
        'config control_bind "::1";\n'
        'config control_port 9443;\n'
        'config control_token_file "/etc/psysmon.token";\n'
        'config control_tls_cert "/c.pem";\n'
        'config control_tls_key "/k.pem";\n'
        'object x { ip "h"; type ping; };\n'
    )
    o = res.overrides
    assert o["control_enabled"] is True
    assert o["control_bind"] == "::1" and o["control_port"] == 9443
    assert o["control_token_file"] == "/etc/psysmon.token"
    assert o["control_tls_cert"] == "/c.pem" and o["control_tls_key"] == "/k.pem"
    assert res.warnings == []


def test_per_object_queuetime_rejects_non_finite():
    # A non-finite queuetime must NOT reach node.interval: inf -> never-due, nan -> heap corruption.
    for bad in ("inf", "nan", "-inf", "Infinity"):
        res = parse(f'object x {{ ip "h"; type ping; queuetime {bad}; }};\n')
        assert res.roots[0].interval is None  # rejected -> falls back to the global default
        assert any("queuetime" in w for w in res.warnings)


def test_per_object_invalid_ping_leg_drops_both():
    # A given-but-invalid leg drops its partner too — never mix a per-object value with the
    # global default for the other leg (which could form an impossible min > send pair).
    res = parse('object x { ip "h"; type ping; send_pings 0; min_pings 3; };\n')
    n = res.roots[0]
    assert n.send_pings is None and n.min_pings is None
    res2 = parse('object y { ip "h"; type ping; send_pings nope; min_pings 2; };\n')
    assert res2.roots[0].send_pings is None and res2.roots[0].min_pings is None


# --- #70: per-object `source` + `group { ... }` scope ---------------------------------

def test_per_object_source_ip():
    res = parse('object x { ip "h"; type ping; source "192.0.2.9"; };\n')
    assert res.roots[0].source == "192.0.2.9" and res.warnings == []


def test_per_object_source_auto():
    res = parse('object x { ip "h"; type ping; source auto; };\n')
    assert res.roots[0].source == SOURCE_AUTO and res.warnings == []


def test_per_object_source_auto_is_case_insensitive():
    assert parse('object x { ip "h"; type ping; source AUTO; };\n').roots[0].source == SOURCE_AUTO


def test_per_object_source_invalid_warns_and_ignores():
    res = parse('object x { ip "h"; type ping; source "not-an-ip"; };\n')
    assert res.roots[0].source is None  # bad value ignored -> inherit default
    assert any("source" in w for w in res.warnings)


def test_source_attr_no_longer_warns_as_unknown():
    res = parse('object x { ip "h"; type ping; source auto; };\n')
    assert not any("isn't supported yet" in w for w in res.warnings)


def test_source_via_variable_substitution():
    res = parse('set S = "203.0.113.5";\nobject x { ip "h"; type ping; source $S; };\n')
    assert res.roots[0].source == "203.0.113.5" and res.warnings == []


def test_group_block_source_inherited():
    res = parse(
        'group "dmz" { source "192.0.2.9"; }\n'
        'object x { ip "h"; type tcp; port 80; group "dmz"; };\n'
    )
    assert res.roots[0].source == "192.0.2.9" and res.warnings == []


def test_group_block_source_auto_inherited():
    res = parse(
        'group "vpn" { source auto; }\n'
        'object x { ip "h"; type ping; group "vpn"; };\n'
    )
    assert res.roots[0].source == SOURCE_AUTO


def test_per_object_source_wins_over_group_default():
    res = parse(
        'group "dmz" { source "192.0.2.9"; }\n'
        'object x { ip "h"; type smtp; port 25; group "dmz"; source "203.0.113.5"; };\n'
    )
    assert res.roots[0].source == "203.0.113.5"  # per-object wins


def test_group_source_resolution_is_order_independent():
    # An object declared BEFORE its group block still inherits (resolution is a deferred pass).
    res = parse(
        'object x { ip "h"; type ping; group "late"; };\n'
        'group "late" { source "198.51.100.7"; }\n'
    )
    assert res.roots[0].source == "198.51.100.7"


def test_object_in_group_without_block_has_no_source():
    # `group "x"` with no matching group{} block stays a plain display label (#20); source unset.
    res = parse('object x { ip "h"; type ping; group "display-only"; };\n')
    assert res.roots[0].source is None and res.roots[0].group == "display-only"


def test_group_block_unknown_attr_warns():
    res = parse('group "g" { source auto; frobnicate 7; }\n')
    assert any("frobnicate" in w and "isn't supported yet" in w for w in res.warnings)


def test_group_block_invalid_source_warns_and_drops():
    res = parse(
        'group "g" { source "bogus"; }\n'
        'object x { ip "h"; type ping; group "g"; };\n'
    )
    assert res.roots[0].source is None  # the bad group source was dropped
    assert any("source" in w for w in res.warnings)


def test_group_default_policy_settings_inherited():
    # A group can carry contact / contact_on / numfailures / queuetime as shared defaults (#82),
    # applied to a member that doesn't set them.
    res = parse(
        'group "core" {\n'
        '  contact "noc@example.net"; contact_on down; numfailures 4; queuetime 30;\n'
        '}\n'
        'object gw { ip "192.0.2.1"; type ping; group "core"; };\n'
    )
    assert res.warnings == []
    n = res.roots[0]
    assert n.contact == "noc@example.net"
    assert n.contact_on == "down"
    assert n.max_down == 4
    assert n.interval == 30.0


def test_group_default_ping_pair_inherited():
    res = parse(
        'group "lossy" { send_pings 5; min_pings 3; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "lossy"; };\n'
    )
    assert res.warnings == []
    n = res.roots[0]
    assert n.send_pings == 5 and n.min_pings == 3


def test_per_object_value_wins_over_group_policy_default():
    res = parse(
        'group "core" { numfailures 4; contact "noc@example.net"; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "core"; numfailures 9; };\n'
    )
    n = res.roots[0]
    assert n.max_down == 9                 # the per-object numfailures wins
    assert n.contact == "noc@example.net"  # the unset field still inherits


def test_group_ping_pair_inherits_atomically():
    # A member that sets EITHER ping-count leg keeps its own config — it does not mix in the
    # group's other leg (#82).
    res = parse(
        'group "lossy" { send_pings 5; min_pings 3; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "lossy"; send_pings 2; };\n'
    )
    n = res.roots[0]
    assert n.send_pings == 2 and n.min_pings is None  # object's send; group's min NOT inherited


def test_group_policy_default_order_independent():
    # An object declared before its group block still inherits a policy default (deferred pass).
    res = parse(
        'object gw { ip "192.0.2.1"; type ping; group "late"; };\n'
        'group "late" { numfailures 7; }\n'
    )
    assert res.roots[0].max_down == 7


def test_group_invalid_policy_value_warns_and_ignored():
    # A bad group default warns (naming the object by its DECLARED name, not its hostname) and the
    # member keeps the global default.
    res = parse(
        'group "core" { numfailures 0; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "core"; };\n'
    )
    assert res.roots[0].max_down == 2  # global default; the group's invalid value was ignored
    assert any("object 'gw'" in w and "numfailures" in w for w in res.warnings)
    assert not any("192.0.2.1" in w for w in res.warnings)  # named 'gw', not the IP


def test_group_ping_pair_single_leg_inherited():
    # A group that sets only send_pings applies that leg; min_pings stays at the global default.
    res = parse(
        'group "lossy" { send_pings 5; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "lossy"; };\n'
    )
    n = res.roots[0]
    assert n.send_pings == 5 and n.min_pings is None


def test_per_object_empty_contact_wins_over_group_contact():
    # Declaring contact "" explicitly opts out of paging even when the group sets a contact (#82).
    res = parse(
        'group "core" { contact "noc@example.net"; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "core"; contact ""; };\n'
    )
    assert res.roots[0].contact == ""  # the explicit empty wins; group default not applied


def test_group_identity_attrs_warn_and_ignored():
    # Object-identity attributes in a group make no sense as defaults — still warn + ignore (#82).
    res = parse(
        'group "core" { host "192.0.2.99"; type tcp; port 80; }\n'
        'object gw { ip "192.0.2.1"; type ping; group "core"; };\n'
    )
    n = res.roots[0]
    assert n.hostname == "192.0.2.1" and n.check_type is CheckType.PING and n.port == 0
    for attr in ("host", "type", "port"):
        assert any(attr in w and "isn't supported yet" in w for w in res.warnings)


def test_group_block_empty_is_harmless():
    res = parse(
        'group "g" { }\n'
        'object x { ip "h"; type ping; group "g"; };\n'
    )
    assert res.roots[0].source is None and not any("group" in w for w in res.warnings)


def test_duplicate_group_block_keeps_first():
    res = parse(
        'group "g" { source "192.0.2.1"; }\n'
        'group "g" { source "192.0.2.2"; }\n'
        'object x { ip "h"; type ping; group "g"; };\n'
    )
    assert res.roots[0].source == "192.0.2.1"  # first wins
    assert any("duplicate group" in w for w in res.warnings)


def test_group_block_missing_brace_recovers():
    # A malformed group header must warn and not derail the following object.
    res = parse(
        'group "g" source "192.0.2.1";\n'
        'object x { ip "h"; type ping; };\n'
    )
    assert any("group 'g' is missing" in w for w in res.warnings)
    assert res.roots and res.roots[0].hostname == "h"  # the object still parsed


def test_group_attribute_still_sets_display_label():
    # The per-object `group "x"` membership attribute keeps working unchanged (#20).
    res = parse('object x { ip "h"; type ping; group " core "; };\n')
    assert res.roots[0].group == "core"  # trimmed, as before


def test_group_block_name_is_var_substituted():
    # A $var in the group BLOCK name must expand the same as in the membership attr, else the
    # block keys under "$G" and its members (keyed under the expanded name) never match it.
    res = parse(
        'set G = "edge";\n'
        'group "$G" { source "192.0.2.9"; }\n'
        'object x { ip "h"; type tcp; port 80; group "$G"; };\n'
    )
    assert res.roots[0].source == "192.0.2.9" and res.warnings == []


def test_source_family_must_match_check():
    # A source of the wrong family for the check is warned + left unbound (#24): a v6 source on a
    # v4 check, or a v4 source on a ping6 check.
    for v6 in ("::1", "2001:db8::5"):
        res = parse(f'object x {{ ip "h"; type tcp; port 80; source "{v6}"; }};\n')
        assert res.roots[0].source is None
        assert any("wrong family" in w for w in res.warnings)
    res = parse('object x { ip "h"; type ping; source "2001:db8::5"; };\n')
    assert res.roots[0].source is None and any("wrong family" in w for w in res.warnings)
    res = parse('object x { ip "h"; type ping6; source "192.0.2.1"; };\n')
    assert res.roots[0].source is None and any("wrong family" in w for w in res.warnings)


def test_source_ipv6_accepted_for_ping6():
    # ping6 binds an IPv6 source — the v6 source the old code rejected outright is now valid (#24).
    for v6 in ("2001:db8::9", "::1"):
        res = parse(f'object x {{ ip "h"; type ping6; source "{v6}"; }};\n')
        assert res.roots[0].source == v6 and res.warnings == []


def test_group_source_family_must_match_member():
    # A group's source default is family-checked per member (#24): a v6 group source on a v4
    # (ping) member is warned + left unbound; a v4 group source on a ping6 member likewise.
    res = parse(
        'group "$G" { source "2001:db8::9"; }\n'
        'object x { ip "h"; type ping; group "$G"; };\n'
    )
    assert res.roots[0].source is None and any("wrong family" in w for w in res.warnings)

    res = parse(
        'group "$H" { source "192.0.2.9"; }\n'
        'object y { ip "h"; type ping6; group "$H"; };\n'
    )
    assert res.roots[0].source is None and any("wrong family" in w for w in res.warnings)


def test_source_rejects_non_ip_tokens():
    # ip_address() coerces a bare int, but the token is always a str, so "5"/"300" are rejected.
    for bad in ("5", "300", "10.0.0", "0x7f000001"):
        res = parse(f'object x {{ ip "h"; type ping; source "{bad}"; }};\n')
        assert res.roots[0].source is None and any("source" in w for w in res.warnings)


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
