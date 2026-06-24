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
    res = parse("; a comment\n#another\n\n   \nhost.net ping host.net noc@x\n")
    assert [r.hostname for r in res.roots] == ["host.net"]


def test_starting_numfailures_used():
    res = parse("h.net ping h.net noc@x\n", numfailures=5)
    assert res.roots[0].max_down == 5


def test_tcp_invalid_port_skipped():
    res = parse("h.net tcp notaport ssh noc@x\n")
    assert res.roots == []
    assert any("invalid port" in w for w in res.warnings)


def test_dropped_types_skip_not_fail():
    res = parse(
        "a.net imap u p l c@x\n"
        "b.net nntp news c@x\n"
        "c.net radius u p s c@x\n"
        "d.net ping d.net c@x\n"
    )
    assert [r.hostname for r in res.roots] == ["d.net"]
    assert len(res.warnings) == 3


def test_invalid_type_warns():
    res = parse("h.net frobnicate x y\n")
    assert res.roots == []
    assert any("invalid check type" in w for w in res.warnings)


def test_deferred_dns_keeps_unresolvable_host():
    # The parser never resolves DNS, so even a bogus name yields a node (the C dropped it).
    res = parse("does-not-exist.invalid ping does-not-exist.invalid noc@x\n")
    assert len(res.roots) == 1
    assert res.roots[0].hostname == "does-not-exist.invalid"


def test_nesting_depth_three():
    text = (
        "a.net ping a.net c@x {\n"
        "  b.net ping b.net c@x {\n"
        "    b.net tcp 22 ssh c@x\n"
        "  }\n"
        "}\n"
    )
    res = parse(text)
    assert res.roots[0].children[0].children[0].check_type is CheckType.TCP


def test_unbalanced_brace_on_service_line_is_contained():
    # A non-ping line cannot open children; its stray block is consumed + warned, so the
    # following top-level host still parses.
    text = (
        "a.net ping a.net c@x {\n"
        "  a.net tcp 22 ssh c@x {\n"
        "    a.net tcp 23 telnet c@x\n"
        "  }\n"
        "}\n"
        "b.net ping b.net c@x\n"
    )
    res = parse(text)
    assert [r.hostname for r in res.roots] == ["a.net", "b.net"]
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
        "a.net ping a.net noc@x\n"
        "}\n"                          # stray close brace at the root
        "b.net ping b.net noc@x\n"     # must still be parsed, not dropped
    )
    res = parse(text)
    assert [r.hostname for r in res.roots] == ["a.net", "b.net"]
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
    res = parse("config wibble 7\nh.net ping h.net c@x\n")
    assert [r.hostname for r in res.roots] == ["h.net"]
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


# --- format detection -----------------------------------------------------------------

def test_detect_legacy(sample_config_text):
    assert detect(sample_config_text) == ConfigFormat.LEGACY
    assert detect("; comment\nhost ping host c@x\n") == ConfigFormat.LEGACY
    assert detect("") == ConfigFormat.LEGACY


def test_detect_modern():
    assert detect("---\nhosts:\n  - a\n") == ConfigFormat.MODERN
    assert detect("# c\nhosts:\n  - a\n") == ConfigFormat.MODERN


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
