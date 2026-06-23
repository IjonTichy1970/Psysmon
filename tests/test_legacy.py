"""Tests for the legacy sysmon.conf parser and format detection."""

from __future__ import annotations

from sysmon.config.detect import ConfigFormat, detect
from sysmon.config.legacy import parse
from sysmon.config.model import CheckType


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
        "status_path": "/var/www/sysmon/status.html",
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


def test_unknown_config_directive_warns():
    res = parse("config wibble 7\nh.net ping h.net c@x\n")
    assert [r.hostname for r in res.roots] == ["h.net"]
    assert any("unknown config directive" in w for w in res.warnings)


def test_logging_none_and_invalid():
    assert parse("config logging none\n").overrides["syslog_facility"] is None
    res = parse("config logging bogusfac\n")
    assert res.overrides["syslog_facility"] == "daemon"
    assert any("logging facility" in w for w in res.warnings)


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
