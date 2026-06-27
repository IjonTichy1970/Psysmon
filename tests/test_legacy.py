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


def test_legacy_pop3_family_optional_credentials():
    # pop3/pop3s now mirror imap/imaps (#101): a short line is banner-only, a full line auths.
    banner = parse("mail.example.net pop3s onlylabel noc@x\n").roots[0]  # 4 tokens: label + contact
    assert banner.check_type is CheckType.POP3S and banner.port == 995
    assert not banner.username and not banner.password
    assert banner.label == "onlylabel" and banner.contact == "noc@x"
    auth = parse("mail.example.net pop3 mu mp label noc@x\n").roots[0]  # 6 tokens: authenticated
    assert (auth.username, auth.password, auth.label) == ("mu", "mp", "label")


def test_legacy_telnet_optional_port_no_creds():
    # telnet mirrors ssh's positional form (#106): optional leading port, label, contact; no creds.
    n = parse("dev.example.net telnet console noc@x\n").roots[0]  # 4 tokens: label + contact
    assert n.check_type is CheckType.TELNET and n.port == 23
    assert not n.username and n.label == "console" and n.contact == "noc@x"
    alt = parse("dev.example.net telnet 2323 console noc@x\n").roots[0]  # optional leading port
    assert alt.port == 2323 and alt.label == "console" and alt.contact == "noc@x"


def test_legacy_ftp_optional_credentials():
    # ftp/ftps mirror the mail checks (#102): banner-only short line, authenticated full line; and
    # ftps is NOT prefix-shadowed by ftp (ordered like pop3s before pop3).
    banner = parse("ftp.example.net ftp control-banner noc@x\n").roots[0]  # 4 tokens: label+contact
    assert banner.check_type is CheckType.FTP and banner.port == 21
    assert not banner.username and banner.label == "control-banner" and banner.contact == "noc@x"
    auth = parse("ftp.example.net ftp ftpuser ftppass label noc@x\n").roots[0]  # 6 tokens: auth
    assert (auth.username, auth.password, auth.label) == ("ftpuser", "ftppass", "label")
    sec = parse("ftp.example.net ftps fu fp label\n").roots[0]  # 5 tokens: auth, over TLS
    assert sec.check_type is CheckType.FTPS and sec.port == 990
    assert (sec.username, sec.password) == ("fu", "fp")


def test_legacy_http_urltext_optional():
    # urltext is optional (#104): the 4-token `host www url label` form is a reachability probe
    # (no url_text); 5+ tokens keep the original url,url_text,label[,contact] meaning.
    reach = parse("web.example.net www /health webdesc\n").roots[0]  # 4 tokens: url + label
    assert reach.check_type is CheckType.HTTP and reach.url == "/health"
    assert reach.url_text is None and reach.label == "webdesc" and not reach.contact
    content = parse("web.example.net www /health OK weblabel noc@x\n").roots[0]  # 6 tokens: content
    assert (content.url, content.url_text, content.label, content.contact) == (
        "/health", "OK", "weblabel", "noc@x")


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
    """The post-rewrite GLOBAL directives land in the same Settings overrides as the modern parser
    (#93). contact_on / queuetime / send_pings / min_pings are position-dependent (sticky) in legacy
    now (#95), so they do NOT appear in overrides — they snapshot into nodes (tested separately)."""
    cfg = (
        "config contact_on down\n"  # sticky (#95) -> not in overrides
        "config source_ip 192.0.2.10\n"
        "config queuetime 2.5\n"  # sticky (#95)
        "config send_pings 3\n"  # sticky (#95)
        "config min_pings 2\n"  # sticky (#95)
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
        "source_ip": "192.0.2.10",
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
    """The same GLOBAL `config` line yields identical overrides in both parsers (#93). The sticky
    directives (contact_on/queuetime/send_pings/min_pings) are intentionally excluded — they are
    per-node in legacy but global in modern (#95)."""
    from psysmon.config.modern import parse as mparse

    cases = [
        ("source_ip 198.51.100.5", "source_ip 198.51.100.5;"),
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

    # contact_on / queuetime / send_pings / min_pings are POSITION-DEPENDENT (sticky) in legacy now
    # (#95) — per-node, not global — so they diverge from modern's top-level global and are excluded
    # from this global drift guard (their sticky behavior is covered separately).
    sticky = {"contact_on", "queuetime", "send_pings", "min_pings"}
    names = (
        set(modern._INT_DIRECTIVES)
        | set(modern._FLOAT_DIRECTIVES)
        | set(modern._STR_DIRECTIVES)
        | set(modern._FLAG_DIRECTIVES)
        | {"contact_on"}
    ) - sticky
    for name in sorted(names):
        line = f"config {name} {value_for(name)}".rstrip()
        lr = parse(line + "\n")
        mr = mparse(line + ";\n")
        assert lr.overrides == mr.overrides, f"{name}: {lr.overrides} != {mr.overrides}"
        assert lr.warnings == [], f"{name}: {lr.warnings}"


def test_config_sticky_extra_token_warns():
    # The sticky directives warn on extra tokens like the modern parser (#95); the first value
    # still snapshots into a subsequently-parsed node.
    res = parse("config send_pings 3 4\nh.example.net ping lbl noc@x\n")
    assert res.roots[0].send_pings == 3
    assert any("takes one value" in w for w in res.warnings)


def test_config_sticky_invalid_value_leaves_default():
    # A bad value warns; the running sticky default is unchanged (the next node stays unset).
    r1 = parse("config queuetime abc\nh.example.net ping a noc@x\n")
    assert r1.roots[0].interval is None
    assert any("number" in w for w in r1.warnings)
    r2 = parse("config send_pings xyz\nh.example.net ping b noc@x\n")
    assert r2.roots[0].send_pings is None
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
    # contact_on is sticky (#95): a valid value snapshots into a following node; bad -> "both".
    ok = parse("config contact_on none\nh.example.net ping a noc@x\n").roots[0]
    assert ok.contact_on == "none"
    bad = parse("config contact_on sometimes\nh.example.net ping b noc@x\n")
    assert bad.roots[0].contact_on == "both"  # invalid -> both, like the modern parser
    assert any("contact_on" in w for w in bad.warnings)


def test_config_sticky_directives_are_position_dependent():
    """source / contact_on / send_pings / min_pings / queuetime snapshot the running value into each
    subsequently-parsed node, like numfailures; a node before any directive stays unset (#95)."""
    cfg = (
        "before.example.net ping b noc@x\n"
        "config contact_on down\n"
        "config queuetime 45\n"
        "config send_pings 3\n"
        "config min_pings 2\n"
        "config source 192.0.2.10\n"
        "after.example.net ping a noc@x\n"
        "config contact_on up\n"
        "later.example.net ping l noc@x\n"
    )
    res = parse(cfg, numfailures=2)
    assert res.warnings == []
    nodes = {n.hostname: n for n in res.roots}
    before = nodes["before.example.net"]
    assert before.contact_on == "" and before.source is None and before.interval is None
    assert before.send_pings is None and before.min_pings is None
    after = nodes["after.example.net"]
    assert after.contact_on == "down" and after.interval == 45.0
    assert after.send_pings == 3 and after.min_pings == 2
    assert after.source == "192.0.2.10"
    # the running value retargets the hosts below the second directive
    assert nodes["later.example.net"].contact_on == "up"


def test_config_sticky_is_file_position_not_block_scoped():
    """The locked nesting rule (#95): the running value flows into nested {} children, and a value
    set inside a block is NOT restored on block close — file-position sticky, like numfailures."""
    cfg = (
        "config contact_on down\n"
        "parent.example.net ping p noc@x {\n"
        "config contact_on up\n"  # set INSIDE the block
        "child.example.net ping c noc@x\n"
        "}\n"
        "after.example.net ping a noc@x\n"
    )
    res = parse(cfg)
    parent = res.roots[0]
    assert parent.contact_on == "down"  # set before the block
    assert parent.children[0].contact_on == "up"  # the in-block change flows into the child
    assert res.roots[1].contact_on == "up"  # ...and is NOT restored when the block closes


def test_config_sticky_source_family_checked_per_node():
    """A sticky source is family-checked at each node (#95): a v4 source binds v4 checks but leaves
    a ping6 node unbound (with a warning); a v6 source binds ping6; `auto` always passes."""
    res = parse(
        "config source 192.0.2.5\n"
        "v4.example.net ping v4 noc@x\n"
        "v6.example.net ping6 v6 noc@x\n"
    )
    nodes = {n.hostname: n for n in res.roots}
    assert nodes["v4.example.net"].source == "192.0.2.5"
    assert nodes["v6.example.net"].source is None  # family mismatch -> unbound
    assert any("family" in w for w in res.warnings)
    assert parse("config source auto\nh.example.net ping6 v6 noc@x\n").roots[0].source == "auto"
    v6src = parse("config source 2001:db8::5\nh.example.net ping6 v6 noc@x\n").roots[0]
    assert v6src.source == "2001:db8::5"


def test_config_sticky_source_bad_value_ignored():
    res = parse("config source not-an-ip\nh.example.net ping a noc@x\n")
    assert res.roots[0].source is None  # bad source ignored
    assert any("source must be an IP" in w for w in res.warnings)


def test_config_no_sticky_directives_is_byte_identical():
    """Back-compat: a config using none of the sticky directives leaves every snapshotted field at
    its unset sentinel (#95 is additive)."""
    res = parse("a.example.net ping lbl noc@x\nb.example.net tcp 80 web noc@x\n")
    for n in res.roots:
        assert n.contact_on == "" and n.source is None
        assert n.send_pings is None and n.min_pings is None and n.interval is None


def test_config_sticky_numeric_validation():
    """Sticky numeric directives reject the values the modern parser does (#95) — a non-finite or
    non-positive queuetime would poison the scheduler heap; send_pings/min_pings need >= 1."""
    for bad in ("nan", "inf", "-5", "0"):
        res = parse(f"config queuetime {bad}\nh.example.net ping a noc@x\n")
        assert res.roots[0].interval is None, bad
        assert any("queuetime" in w for w in res.warnings), bad
    assert parse("config queuetime 30\nh.example.net ping a noc@x\n").roots[0].interval == 30.0
    for bad in ("0", "-3"):
        res = parse(f"config send_pings {bad}\nh.example.net ping a noc@x\n")
        assert res.roots[0].send_pings is None, bad
        assert any("send_pings must be >= 1" in w for w in res.warnings), bad


def test_config_sticky_contact_on_source_extra_token_warns():
    # every sticky directive warns on extra tokens (parity within the family) (#95)
    r1 = parse("config contact_on down up\nh.example.net ping a noc@x\n")
    assert r1.roots[0].contact_on == "down"
    assert any("takes one value" in w for w in r1.warnings)
    r2 = parse("config source 192.0.2.1 9.9.9.9\nh.example.net ping a noc@x\n")
    assert r2.roots[0].source == "192.0.2.1"
    assert any("takes one value" in w for w in r2.warnings)


def test_config_sticky_values_round_trip_through_convert():
    """Sticky source/contact_on/queuetime/send_pings/min_pings survive a to_modern round-trip
    (#95 — convert must emit node.source, not just the #93 global source_ip)."""
    from psysmon.config.convert import to_modern
    from psysmon.config.modern import parse as mparse

    res = parse(
        "config contact_on down\n"
        "config queuetime 45\n"
        "config send_pings 3\n"
        "config min_pings 2\n"
        "config source 192.0.2.10\n"
        "h.example.net tcp 80 web noc@x\n"
    )
    text, warns = to_modern(res)
    assert warns == []
    back = mparse(text).roots[0]
    assert back.contact_on == "down" and back.interval == 45.0
    assert back.send_pings == 3 and back.min_pings == 2
    assert back.source == "192.0.2.10"


def test_config_sticky_and_numfailures_coexist():
    # numfailures and the new sticky directives are independent running values.
    res = parse(
        "config numfailures 5\nconfig contact_on down\nh.example.net ping a noc@x\n", numfailures=2
    )
    n = res.roots[0]
    assert n.max_down == 5 and n.contact_on == "down"


def test_config_sticky_directives_do_not_leak_into_overrides():
    # a sticky directive sets per-node state, never the global overrides dict (#95).
    res = parse(
        "config contact_on down\nconfig send_pings 3\nconfig source 192.0.2.1\n"
        "h.example.net ping a noc@x\n"
    )
    for key in ("contact_on", "send_pings", "interval_s", "source"):
        assert key not in res.overrides


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


def test_legacy_ssh_mysql_optional_port():
    # ssh/mysql take an optional leading numeric port; the default applies otherwise (#96/#97).
    a = parse("a.example.net ssh edge noc@x\n").roots[0]
    assert a.check_type is CheckType.SSH and a.port == 22
    assert a.label == "edge" and a.contact == "noc@x"
    b = parse("b.example.net ssh 2222 alt noc@x\n").roots[0]
    assert b.check_type is CheckType.SSH and b.port == 2222 and b.label == "alt"
    c = parse("c.example.net mysql primary noc@x\n").roots[0]
    assert c.check_type is CheckType.MYSQL and c.port == 3306 and c.label == "primary"
    d = parse("d.example.net mysql 3307 alt-db noc@x\n").roots[0]
    assert d.port == 3307 and d.label == "alt-db"
    e = parse("e.example.net ssh just-label\n").roots[0]  # 3 tokens: default port, no contact
    assert e.port == 22 and e.label == "just-label" and e.contact == ""
    # numeric-label caveat: a bare-number first field (in range) is the PORT, not the label
    f = parse("f.example.net ssh 8080 mylabel\n").roots[0]
    assert f.port == 8080 and f.label == "mylabel"
    # an out-of-range "port" falls through to the label
    g = parse("g.example.net ssh 99999 noc@x\n").roots[0]
    assert g.port == 22 and g.label == "99999" and g.contact == "noc@x"


def test_legacy_ssh_port_without_label_skips():
    res = parse("h.example.net ssh 2222\n")  # a port but no label is incomplete
    assert res.roots == []
    assert any("needs a label" in w for w in res.warnings)


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
