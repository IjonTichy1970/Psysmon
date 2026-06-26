"""Tests for the legacy sysmon.conf parser and format detection."""

from __future__ import annotations

import pytest

from psysmon.config import legacy
from psysmon.config.detect import ConfigFormat, detect
from psysmon.config.legacy import ParseError, parse
from psysmon.config.model import CheckType


def _count(nodes) -> int:
    return sum(1 + _count(n.children) for n in nodes)


# --- golden test against the synthetic fixture ----------------------------------------

def test_sample_tree_shape(sample_config_text):
    res = parse(sample_config_text)
    # roots: core-rtr, ns1, edge-rtr  (the nntp line is dropped, not a root)
    assert [r.hostname for r in res.roots] == [
        "core-rtr.example.net",
        "ns1.example.net",
        "edge-rtr.example.net",
    ]
    core, ns1, edge = res.roots
    assert [c.hostname for c in core.children] == ["web.example.net", "mail.example.net"]
    web, mail = core.children
    assert [c.check_type for c in web.children] == [CheckType.TCP, CheckType.HTTP, CheckType.HTTPS]
    assert [c.check_type for c in mail.children] == [CheckType.SMTP, CheckType.POP3, CheckType.TCP]
    assert [c.check_type for c in ns1.children] == [CheckType.UDP, CheckType.DNS]
    assert edge.children == []
    assert _count(res.roots) == 13


def test_sample_field_parsing(sample_config_text):
    res = parse(sample_config_text)
    web = res.roots[0].children[0]
    tcp443, www, https = web.children
    assert (tcp443.port, tcp443.label, tcp443.contact) == (443, "https", "web-team@example.net")
    assert (www.url, www.url_text, www.label) == ("/health", "OK", "weblabel")
    assert www.port == 80 and https.port == 443

    mail = res.roots[0].children[1]
    smtp, pop3, tcp143 = mail.children
    assert smtp.check_type is CheckType.SMTP and smtp.port == 25
    assert smtp.label == "smtp" and smtp.contact == "mail-team@example.net"
    assert (pop3.username, pop3.password, pop3.port) == ("systest", "TESTPASS", 110)
    assert tcp143.port == 143 and tcp143.label == "imap"

    ns1 = res.roots[1]
    udp, authdns = ns1.children
    assert udp.check_type is CheckType.UDP and udp.port == 53
    assert authdns.check_type is CheckType.DNS and authdns.username == "example.net"
    assert authdns.port == 53

    edge = res.roots[2]
    assert edge.contact == ""  # ping with no contact (syslog-only)


def test_numfailures_is_position_dependent(sample_config_text):
    res = parse(sample_config_text)
    core, ns1, edge = res.roots
    # Everything before `config numfailures 8` keeps 3 (incl. nested children).
    assert core.max_down == 3
    assert all(c.max_down == 3 for c in core.children)
    assert core.children[0].children[0].max_down == 3
    # Everything after gets 8.
    assert ns1.max_down == 8
    assert all(c.max_down == 8 for c in ns1.children)
    assert edge.max_down == 8


def test_sample_overrides(sample_config_text):
    res = parse(sample_config_text)
    assert res.overrides == {
        "status_html": True,
        "status_path": "/var/www/psysmon/status.html",
        "pageinterval_min": 15,
        "syslog_facility": "local4",
        "dnslog_s": 180,
        "dnsexpire_s": 1200,
        "numfailures": 8,
    }


def test_sample_warns_on_dropped_type(sample_config_text):
    res = parse(sample_config_text)
    assert any("nntp" in w for w in res.warnings)


# --- focused grammar unit tests -------------------------------------------------------

def test_comments_and_blanks_skipped():
    res = parse("; a comment\n#another\n\n   \nhost.example.net ping host.example.net noc@x\n")
    assert [r.hostname for r in res.roots] == ["host.example.net"]


def test_starting_numfailures_used():
    res = parse("h.example.net ping h.example.net noc@x\n", numfailures=5)
    assert res.roots[0].max_down == 5


def test_tcp_invalid_port_skipped():
    res = parse("h.example.net tcp notaport ssh noc@x\n")
    assert res.roots == []
    assert any("invalid port" in w for w in res.warnings)


def test_dropped_types_skip_not_fail():
    res = parse(
        "a.example.net umichx500 dir c@x\n"  # still-dropped (imap/pop3s/etc. are accepted now, #94)
        "b.example.net nntp news c@x\n"
        "c.example.net radius u p s c@x\n"
        "d.example.net ping d.example.net c@x\n"
    )
    assert [r.hostname for r in res.roots] == ["d.example.net"]
    assert len(res.warnings) == 3


def test_invalid_type_warns():
    res = parse("h.example.net frobnicate x y\n")
    assert res.roots == []
    assert any("invalid check type" in w for w in res.warnings)


def test_legacy_ping6_accepted_and_can_parent():
    # ping6/pingv6/icmp6 are now native legacy types (#94); they must NOT prefix-match "ping".
    for kw in ("ping6", "pingv6", "icmp6"):
        res = parse(f"h.example.net {kw} v6-label noc@x\n")
        assert [n.check_type for n in res.roots] == [CheckType.PING6], kw
        assert res.warnings == []
    # plain "ping" still works — the v6 keywords didn't shadow it.
    ok = parse("h.example.net ping v4-label noc@x\n")
    assert [n.check_type for n in ok.roots] == [CheckType.PING]
    # ping6 can gate a dependency subtree, like ping.
    tree = parse("gw.example.net ping6 edge noc@x {\nweb.example.net ping6 web noc@x\n}\n")
    assert tree.roots[0].check_type is CheckType.PING6
    assert [c.hostname for c in tree.roots[0].children] == ["web.example.net"]


def test_legacy_pop3s_accepted_not_plaintext():
    # pop3s is POP3-over-TLS (port 995), NOT silently prefix-matched to plaintext pop3 (#94).
    n = parse("mail.example.net pop3s mu mp label noc@x\n").roots[0]
    assert n.check_type is CheckType.POP3S and n.port == 995
    assert (n.username, n.password, n.label, n.contact) == ("mu", "mp", "label", "noc@x")
    # plain pop3 still works and stays distinct (the prefix order didn't shadow it).
    ok = parse("mail.example.net pop3 mu mp label noc@x\n").roots[0]
    assert ok.check_type is CheckType.POP3 and ok.port == 110


def test_legacy_pop3_family_requires_credentials():
    # pop3/pop3s always authenticate (mirror modern): too few fields -> warn + skip.
    res = parse("mail.example.net pop3s onlylabel noc@x\n")  # 4 tokens, no user/pass
    assert res.roots == []
    assert any("needs user, password and label" in w for w in res.warnings)


def test_legacy_imap_optional_credentials():
    # imap/imaps mirror modern's optional credentials (#94): a short line is banner-only, a full
    # pop3-style line authenticates.
    minimal = parse("h.example.net imap just-a-label\n").roots[0]  # 3 tokens
    assert minimal.check_type is CheckType.IMAP and minimal.port == 143
    assert not minimal.username and not minimal.password and not minimal.contact
    assert minimal.label == "just-a-label"

    banner = parse("h.example.net imap banner-label noc@x\n").roots[0]  # 4 tokens: label + contact
    assert not banner.username and not banner.password
    assert banner.label == "banner-label" and banner.contact == "noc@x"

    auth = parse("h.example.net imap iuser ipass auth-label noc@x\n").roots[0]  # 6 tokens: auth
    assert (auth.username, auth.password, auth.label, auth.contact) == (
        "iuser", "ipass", "auth-label", "noc@x")

    # imaps is IMAP-over-TLS (port 993) with the same optional-cred rule.
    sbanner = parse("h.example.net imaps imaps-banner noc@x\n").roots[0]
    assert sbanner.check_type is CheckType.IMAPS and sbanner.port == 993
    assert not sbanner.username and not sbanner.password
    sauth = parse("h.example.net imaps iuser ipass label\n").roots[0]  # 5 tokens: auth
    assert sauth.check_type is CheckType.IMAPS
    assert (sauth.username, sauth.password) == ("iuser", "ipass")


def test_legacy_imap_matches_original_always_auth_form():
    # The original C imap (loadconfig.c type 7) was `host imap user pass message [contact]`; that
    # 5-/6-token form must parse to an authenticated check, byte-identical to the original layout.
    n = parse("h.example.net imap mailuser mailpass mylabel noc@x\n").roots[0]
    assert n.check_type is CheckType.IMAP
    assert (n.username, n.password, n.label, n.contact) == (
        "mailuser", "mailpass", "mylabel", "noc@x")


def test_legacy_new_types_round_trip_through_convert():
    from psysmon.config.convert import to_modern
    from psysmon.config.modern import parse as mparse

    def walk(nodes):
        for nn in nodes:
            yield nn
            yield from walk(nn.children)

    def sig(roots):
        return sorted((n.check_type.value, n.username, n.password, n.port) for n in walk(roots))

    cfg = (
        "gw.example.net ping6 edge noc@x {\n"
        "web.example.net ping6 web noc@x\n"
        "}\n"
        "m1.example.net pop3s mu mp p3s noc@x\n"
        "m2.example.net imap banner noc@x\n"
        "m3.example.net imap iu ip auth noc@x\n"
        "m4.example.net imaps iu ip i noc@x\n"
    )
    res = parse(cfg)
    text, warns = to_modern(res)
    assert warns == []
    mr = mparse(text)
    assert mr.warnings == []
    assert sig(res.roots) == sig(mr.roots)


def test_legacy_new_type_keyword_as_label_is_unaffected():
    # The new type keywords match only in the TYPE position (tokens[1]); a tcp check whose *label*
    # happens to be a new keyword is unchanged. production.conf relies on this (it has a tcp/143
    # check labelled "imap"), so this is the load-bearing back-compat invariant (#94).
    for label in ("imap", "imaps", "pop3s", "ping6"):
        n = parse(f"h.example.net tcp 143 {label} noc@x\n").roots[0]
        assert n.check_type is CheckType.TCP and n.port == 143
        assert n.label == label and n.contact == "noc@x"


def test_legacy_type_prefix_match_resolves_to_longer_keyword():
    # strncmp-style prefix match: a token starting with a longer keyword resolves to it, never the
    # shorter prefix — pop3s/imaps must never degrade to plaintext pop3/imap (the #88 ordering).
    assert parse("h.example.net pop3sx u p l\n").roots[0].check_type is CheckType.POP3S
    assert parse("h.example.net imapsx u p l\n").roots[0].check_type is CheckType.IMAPS
    assert parse("h.example.net ping6x label\n").roots[0].check_type is CheckType.PING6
    assert parse("h.example.net pop3x u p l\n").roots[0].check_type is CheckType.POP3


def test_legacy_imap_convert_emits_creds_only_when_authenticated():
    from psysmon.config.convert import to_modern

    auth_text, _ = to_modern(parse("h.example.net imap iu ip auth noc@x\n"))
    assert "username" in auth_text and "password" in auth_text
    banner_text, _ = to_modern(parse("h.example.net imap banner noc@x\n"))
    assert "username" not in banner_text and "password" not in banner_text


def test_legacy_imap_four_token_is_banner_not_auth():
    # Token count disambiguates (n<5 = banner): `host imap A B` is a banner check with label=A,
    # contact=B, NOT auth-without-label. The original C rejected <5 tokens, so nothing regresses.
    n = parse("h.example.net imap alice bob\n").roots[0]
    assert n.check_type is CheckType.IMAP
    assert n.label == "alice" and n.contact == "bob"
    assert not n.username and not n.password


def test_legacy_ping6_port_unset_and_numfailures_snapshots():
    res = parse("config numfailures 7\ngw.example.net ping6 edge noc@x\n", numfailures=2)
    n = res.roots[0]
    assert n.check_type is CheckType.PING6 and n.port == 0  # ping6 has no port
    assert n.max_down == 7  # position-dependent numfailures snapshots into ping6 like any node


def test_deferred_dns_keeps_unresolvable_host():
    # The parser never resolves DNS, so even a bogus name yields a node (the C dropped it).
    res = parse("does-not-exist.invalid ping does-not-exist.invalid noc@x\n")
    assert len(res.roots) == 1
    assert res.roots[0].hostname == "does-not-exist.invalid"


def test_nesting_depth_three():
    text = (
        "a.example.net ping a.example.net c@x {\n"
        "  b.example.net ping b.example.net c@x {\n"
        "    b.example.net tcp 22 ssh c@x\n"
        "  }\n"
        "}\n"
    )
    res = parse(text)
    assert res.roots[0].children[0].children[0].check_type is CheckType.TCP


def test_unbalanced_brace_on_service_line_is_contained():
    # A non-ping line cannot open children; its stray block is consumed + warned, so the
    # following top-level host still parses.
    text = (
        "a.example.net ping a.example.net c@x {\n"
        "  a.example.net tcp 22 ssh c@x {\n"
        "    a.example.net tcp 23 telnet c@x\n"
        "  }\n"
        "}\n"
        "b.example.net ping b.example.net c@x\n"
    )
    res = parse(text)
    assert [r.hostname for r in res.roots] == ["a.example.net", "b.example.net"]
    assert any("cannot have children" in w for w in res.warnings)


def test_overlong_stanza_with_brace_still_opens_block():
    # A stanza with >7 fields that ends in '{' must still open its child block: the brace is
    # split off before the 7-field cap, so the subtree isn't detached and the rest of the file
    # (here p2) isn't silently dropped (#32).
    text = (
        "p1 ping a b c d e f {\n"      # 9 tokens incl. the brace: over-long AND a block-open
        "   c1 tcp 22 ssh noc@x\n"
        "}\n"
        "p2 ping p2 noc@x\n"
    )
    res = parse(text)
    assert [r.hostname for r in res.roots] == ["p1", "p2"]        # p2 preserved, not dropped
    assert [c.hostname for c in res.roots[0].children] == ["c1"]  # c1 stayed nested under p1
    assert any("too many fields" in w for w in res.warnings)


def test_stray_brace_on_service_line_does_not_pollute_contact():
    # A tcp stanza whose '{' falls in the contact slot must NOT take '{' as the contact: the
    # brace is stripped first, the block is drained, and the next top-level host still parses
    # (#35). (The old code set contact = '{', so pages went nowhere.)
    text = (
        "h tcp 80 weblabel {\n"        # '{' would otherwise land in the contact field
        "   inner ping inner noc@x\n"
        "}\n"
        "after ping after noc@x\n"
    )
    res = parse(text)
    assert [r.hostname for r in res.roots] == ["h", "after"]
    h = res.roots[0]
    assert h.label == "weblabel"
    assert h.contact == ""             # not '{'
    assert h.children == []            # tcp can't have children
    assert any("cannot have children" in w for w in res.warnings)


def test_stray_top_level_brace_does_not_truncate_file():
    # A misplaced top-level '}' must NOT silently terminate parsing of the rest of the file;
    # it is warned and skipped so trailing stanzas still parse (#42).
    text = (
        "a.example.net ping a.example.net noc@x\n"
        "}\n"                          # stray close brace at the root
        "b.example.net ping b.example.net noc@x\n"     # must still be parsed, not dropped
    )
    res = parse(text)
    assert [r.hostname for r in res.roots] == ["a.example.net", "b.example.net"]
    assert any("unexpected '}'" in w for w in res.warnings)


def test_excessive_nesting_raises_clean_parse_error():
    # Nesting past the cap raises ParseError (a ValueError), not an uncaught RecursionError (#36).
    depth = legacy._MAX_NESTING_DEPTH + 5
    lines = [f"p{i} ping p{i} {{" for i in range(depth)]
    lines += ["inner ping inner"]
    lines += ["}"] * depth
    assert issubclass(ParseError, ValueError)
    with pytest.raises(ParseError):
        parse("\n".join(lines) + "\n")


def test_unknown_config_directive_warns():
    res = parse("config wibble 7\nh.example.net ping h.example.net c@x\n")
    assert [r.hostname for r in res.roots] == ["h.example.net"]
    assert any("unknown config directive" in w for w in res.warnings)


def test_logging_none_and_invalid():
    assert parse("config logging none\n").overrides["syslog_facility"] is None
    res = parse("config logging bogusfac\n")
    assert res.overrides["syslog_facility"] == "daemon"
    assert any("logging facility" in w for w in res.warnings)


def test_config_loglevel():
    res = parse("config loglevel debug\n")
    assert res.overrides["log_level"] == "debug"
    assert "syslog_facility" not in res.overrides  # disjoint from `config logging`
    bad = parse("config loglevel bogus\n")
    assert bad.overrides["log_level"] == "info"  # unknown level -> info
    assert any("loglevel" in w for w in bad.warnings)
    # ...and `config logging` must not be misrouted into log_level.
    assert "log_level" not in parse("config logging local4\n").overrides


def test_config_heartbeat():
    assert parse("config heartbeat 120\n").overrides["heartbeat_s"] == 120


def test_config_savestate():
    # The legacy directive takes a (optionally quoted) path; surrounding quotes are stripped.
    assert (parse('config savestate "/var/lib/psysmon/state.json"\n').overrides["state_path"]
            == "/var/lib/psysmon/state.json")
    assert parse("config savestate /tmp/state.json\n").overrides["state_path"] == "/tmp/state.json"
    # A bare directive with no path needs >= 3 tokens, so it is skipped, not stored empty.
    assert "state_path" not in parse("config savestate\n").overrides


# --- post-rewrite global directives backported to legacy (#93) ------------------------

def test_config_backport_globals():
    """The post-rewrite globals the legacy parser used to drop are now honored, landing in the
    same Settings fields as the modern parser (#93)."""
    cfg = (
        "config contact_on down\n"
        "config source_ip 192.0.2.10\n"
        "config queuetime 2.5\n"
        "config send_pings 3\n"
        "config min_pings 2\n"
        "config maxqueued 50\n"
        "config statesave_interval 30\n"
        "config state_max_age 600\n"
        "config control\n"
        "config control_port 2026\n"
        "config control_bind 192.0.2.1\n"
        'config control_token_file "/etc/psysmon/control.token"\n'
        "config page_on_degraded\n"
        "config noheartbeat\n"
        "config sender noc@example.net\n"
        "config hostname mon.example.net\n"
    )
    res = parse(cfg, numfailures=2)
    assert res.warnings == []
    assert res.overrides == {
        "contact_on": "down",
        "source_ip": "192.0.2.10",
        "interval_s": 2.5,
        "send_pings": 3,
        "min_pings": 2,
        "max_concurrency": 50,
        "statesave_s": 30,
        "state_max_age_s": 600,
        "control_enabled": True,
        "control_port": 2026,
        "control_bind": "192.0.2.1",
        "control_token_file": "/etc/psysmon/control.token",
        "page_on_degraded": True,
        "heartbeat_s": 0,  # set by `noheartbeat`
        "mail_from": "noc@example.net",
        "org_hostname": "mon.example.net",
    }


def test_config_backport_matches_modern():
    """The same global `config` line yields identical overrides in both parsers (#93)."""
    from psysmon.config.modern import parse as mparse

    cases = [
        ("contact_on up", "contact_on up;"),
        ("source_ip 198.51.100.5", "source_ip 198.51.100.5;"),
        ("queuetime 45", "queuetime 45;"),
        ("send_pings 4", "send_pings 4;"),
        ("control", "control;"),
        ("control_port 9999", "control_port 9999;"),
        ("page_on_degraded", "page_on_degraded;"),
        ("from alerts@example.net", "from alerts@example.net;"),
    ]
    for legacy_line, modern_line in cases:
        lr = parse(f"config {legacy_line}\n")
        mr = mparse(f"config {modern_line}\n")
        assert lr.overrides == mr.overrides, legacy_line
        assert lr.warnings == []


def test_config_every_global_matches_modern():
    """Drift guard: EVERY global in the modern directive tables yields identical overrides (and no
    warnings) in the legacy parser — so a future wrong-field mapping or type mismatch fails here,
    not silently (#93)."""
    from psysmon.config import modern
    from psysmon.config.modern import parse as mparse

    def value_for(name: str) -> str:
        if name in modern._FLAG_DIRECTIVES:
            return ""  # valueless
        if name in modern._INT_DIRECTIVES or name in modern._FLOAT_DIRECTIVES:
            return "5"
        if name == "contact_on":
            return "down"
        return "x.example.net"  # string globals

    names = (
        set(modern._INT_DIRECTIVES)
        | set(modern._FLOAT_DIRECTIVES)
        | set(modern._STR_DIRECTIVES)
        | set(modern._FLAG_DIRECTIVES)
        | {"contact_on"}
    )
    for name in sorted(names):
        line = f"config {name} {value_for(name)}".rstrip()
        lr = parse(line + "\n")
        mr = mparse(line + ";\n")
        assert lr.overrides == mr.overrides, f"{name}: {lr.overrides} != {mr.overrides}"
        assert lr.warnings == [], f"{name}: {lr.warnings}"


def test_config_numeric_extra_token_warns_like_modern():
    res = parse("config send_pings 3 4\n")  # int global with an extra token
    assert res.overrides["send_pings"] == 3
    assert any("takes one value" in w for w in res.warnings)


def test_config_numeric_invalid_value_skips():
    r1 = parse("config queuetime abc\n")  # float global, bad value
    assert "interval_s" not in r1.overrides
    assert any("number" in w for w in r1.warnings)
    r2 = parse("config send_pings xyz\n")  # int global, bad value
    assert "send_pings" not in r2.overrides
    assert any("integer" in w for w in r2.warnings)


def test_config_new_global_prefix_near_miss_warns_unknown():
    # Exact-match (not prefix): a near-miss of a new directive is NOT accepted (#93).
    for bad in ("control_por 9", "send_ping 3", "source_i 192.0.2.1"):
        res = parse(f"config {bad}\n")
        assert any("unknown config directive" in w for w in res.warnings), bad


def test_config_noheartbeat_vs_heartbeat_do_not_collide():
    assert parse("config heartbeat 120\n").overrides == {"heartbeat_s": 120}
    assert parse("config noheartbeat\n").overrides == {"heartbeat_s": 0}


def test_config_bare_brace_line_does_not_crash():
    """A lone `{` strips to no tokens; it must warn + skip (not crash), and still drain a following
    block so braces stay balanced — a regression guard for the #93 dispatch reorder."""
    res = parse("{\n")
    assert res.roots == []
    assert any("not enough fields" in w for w in res.warnings)
    res2 = parse(
        "h.example.net ping h c@x\n"
        "{\n"
        "child.example.net ping c c@x\n"
        "}\n"
        "after.example.net ping a c@x\n"
    )
    # the orphaned block is drained; parsing recovers and the trailing host still loads.
    assert [r.hostname for r in res2.roots] == ["h.example.net", "after.example.net"]


def test_config_old_style_block_unchanged():
    """The dispatch reorder must not change how a pre-#93 legacy config parses — #93 is additive."""
    cfg = (
        "config pageinterval 15\n"
        "config numfailures 4\n"
        "config logging local4\n"
        "config loglevel info\n"
        "config statusfile html /var/www/status.html\n"
        "config savestate /var/lib/psysmon/state.json\n"
        "config sleeptime 30\n"
        "router.example.net ping edge noc@example.net\n"
    )
    res = parse(cfg, numfailures=2)
    assert res.overrides == {
        "pageinterval_min": 15,
        "numfailures": 4,
        "syslog_facility": "local4",
        "log_level": "info",
        "status_html": True,
        "status_path": "/var/www/status.html",
        "state_path": "/var/lib/psysmon/state.json",
    }
    assert any("sleeptime is obsolete" in w for w in res.warnings)
    assert [r.hostname for r in res.roots] == ["router.example.net"]
    assert res.roots[0].max_down == 4  # numfailures snapshotted (position-dependent)


def test_config_contact_on_validates():
    assert parse("config contact_on none\n").overrides["contact_on"] == "none"
    bad = parse("config contact_on sometimes\n")
    assert bad.overrides["contact_on"] == "both"  # invalid -> both, like the modern parser
    assert any("contact_on" in w for w in bad.warnings)


def test_config_flag_extra_token_warns():
    res = parse("config control on\n")  # a flag takes no value
    assert res.overrides["control_enabled"] is True
    assert any("takes no value" in w for w in res.warnings)


def test_config_value_directive_missing_value_skips():
    res = parse("config source_ip\n")  # 2-token line; a value directive needs its value
    assert "source_ip" not in res.overrides
    assert any("needs a value" in w for w in res.warnings)


def test_config_control_paths_join_quoted_spaces():
    # path-like control globals follow the savestate join+strip precedent (#93).
    res = parse('config control_tls_cert "/etc/my certs/psysmon.pem"\n')
    assert res.overrides["control_tls_cert"] == "/etc/my certs/psysmon.pem"


def test_config_control_not_swallowed_by_prefix():
    """Exact-match (not prefix): control_bind/control_port aren't captured by the `control` flag."""
    res = parse("config control_bind 203.0.113.7\n")
    assert res.overrides == {"control_bind": "203.0.113.7"}
    assert res.warnings == []


# --- format detection -----------------------------------------------------------------

def test_detect_legacy(sample_config_text):
    assert detect(sample_config_text) == ConfigFormat.LEGACY
    assert detect("; comment\nhost ping host c@x\n") == ConfigFormat.LEGACY
    assert detect("") == ConfigFormat.LEGACY


def test_detect_modern():
    # The modern object{} grammar is detected by an object/root=/set= line — NOT by shared
    # `config` lines (both formats use those identically).
    assert detect('root = "gw";\n') == ConfigFormat.MODERN
    assert detect('set on = "x";\nroot = "gw";\n') == ConfigFormat.MODERN
    assert detect('object gw {\n  ip "192.0.2.1";\n};\n') == ConfigFormat.MODERN
    # leading comments + shared config lines, then an object block -> still modern
    assert detect('# c\nconfig queuetime 30;\nobject gw {\n};\n') == ConfigFormat.MODERN


def test_detect_ambiguous_config_only_is_legacy():
    # A file of only shared `config` lines can't be told apart (it parses identically either
    # way), so it defaults to LEGACY — the safe choice that never mis-routes a real legacy file.
    assert detect('config savestate "/x";\nconfig numfailures 2\n') == ConfigFormat.LEGACY
    # A positional host line is legacy even when `config` lines precede it.
    assert detect("config numfailures 5\nh.example.net ping h.example.net noc@x\n") == (
        ConfigFormat.LEGACY)


# --- production-config scale smoke (skipped if the local fixture is absent) ------------

def test_production_config_parses(production_config_text):
    res = parse(production_config_text, numfailures=5)
    # Sanity: the real config has hundreds of top-level stanzas and over a thousand nodes.
    assert len(res.roots) > 300
    assert _count(res.roots) > 1000
    # Every node has a hostname and an in-scope check type.
    def walk(nodes):
        for node in nodes:
            assert node.hostname
            assert isinstance(node.check_type, CheckType)
            walk(node.children)
    walk(res.roots)
