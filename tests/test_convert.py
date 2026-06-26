"""Round-trip tests for the legacy -> modern config converter (#3 milestone 5).

The bar is round-trip equivalence: parsing the legacy config and parsing the converter's modern
output must yield the same node forest. Object *names* are synthesized, so the comparison is
name-independent — it canonicalizes each node by its fields + child structure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from psysmon.config.convert import convert, main, to_modern
from psysmon.config.detect import ConfigFormat, detect
from psysmon.config.legacy import ParseResult
from psysmon.config.legacy import parse as parse_legacy
from psysmon.config.model import CheckType, Node
from psysmon.config.modern import parse as parse_modern

FIXTURES = Path(__file__).parent / "fixtures"


def _canon(node) -> tuple:
    """A hashable, name-independent signature of a node and its subtree. Includes the
    modern-only fields (group/interval/send_pings/min_pings) so a future regression that
    drops them can't slip past the round-trip comparison."""
    return (
        node.hostname, str(node.check_type), node.port, node.label, node.contact,
        node.username, node.password, node.url, node.url_text, node.max_down,
        node.group, node.contact_on, node.interval, node.send_pings, node.min_pings,
        tuple(sorted(_canon(c) for c in node.children)),
    )


def _forest(roots) -> list:
    return sorted(_canon(r) for r in roots)


def _roundtrip(legacy_text: str, *, numfailures: int = 2):
    leg = parse_legacy(legacy_text, numfailures=numfailures)
    modern_text, warnings = convert(legacy_text, numfailures=numfailures)
    mod = parse_modern(modern_text, numfailures=numfailures)
    return leg, mod, modern_text, warnings


# --- per-type round trips -------------------------------------------------------------

PER_TYPE = (
    "core.example.net ping coredesc noc@example.net\n"
    "svc.example.net tcp 8080 svctcp ops@example.net\n"
    "dns.example.net udp 53 dnsudp ops@example.net\n"
    "mx.example.net smtp mxbanner mail@example.net\n"
    "pop.example.net pop3 user secret popdesc mail@example.net\n"
    "ns.example.net authdns zone.example.net dns@example.net\n"
    "web.example.net www /health OK webdesc web@example.net\n"
    "tls.example.net https /health OK tlsdesc web@example.net\n"
)


def test_every_type_round_trips_cleanly():
    leg, mod, text, warnings = _roundtrip(PER_TYPE)
    assert _forest(leg.roots) == _forest(mod.roots)
    assert warnings == [] and mod.warnings == []
    assert detect(text) is ConfigFormat.MODERN


def test_to_modern_emits_ping6():
    # A modern forest can carry a ping6 node even though the legacy parser never produces one; the
    # converter must serialize it (not KeyError) and the modern parser must read it back (#24).
    result = ParseResult(roots=[Node(hostname="h.example.net", check_type=CheckType.PING6)])
    text, warnings = to_modern(result)
    assert "type ping6;" in text and warnings == []
    reparsed = parse_modern(text)
    assert len(reparsed.roots) == 1 and reparsed.roots[0].check_type is CheckType.PING6


def test_to_modern_emits_mail_tls_types():
    # to_modern must serialize the new mail types (not KeyError) and round-trip through the modern
    # parser, carrying pop3s's required creds and imaps's optional creds (#88).
    roots = [
        Node(hostname="im.example.net", check_type=CheckType.IMAP),
        Node(hostname="ims.example.net", check_type=CheckType.IMAPS, username="u", password="p"),
        Node(hostname="p3s.example.net", check_type=CheckType.POP3S, username="u", password="p"),
    ]
    text, warnings = to_modern(ParseResult(roots=roots))
    assert warnings == []
    assert "type imap;" in text and "type imaps;" in text and "type pop3s;" in text
    reparsed = parse_modern(text)
    types = {n.hostname: n.check_type for n in reparsed.roots}
    assert types == {
        "im.example.net": CheckType.IMAP,
        "ims.example.net": CheckType.IMAPS,
        "p3s.example.net": CheckType.POP3S,
    }


def test_to_modern_emits_ssh_mysql():
    # to_modern must serialize the ssh/mysql types and round-trip a non-default port (#96/#97).
    roots = [
        Node(hostname="s.example.net", check_type=CheckType.SSH),
        Node(hostname="s2.example.net", check_type=CheckType.SSH, port=2222),
        Node(hostname="m.example.net", check_type=CheckType.MYSQL, port=3307),
    ]
    text, warnings = to_modern(ParseResult(roots=roots))
    assert warnings == []
    assert "type ssh;" in text and "type mysql;" in text
    assert "port 2222;" in text and "port 3307;" in text
    by_host = {n.hostname: n for n in parse_modern(text).roots}
    assert by_host["s.example.net"].check_type is CheckType.SSH
    assert by_host["s.example.net"].port == 22  # default omitted in text; modern reapplies it
    assert by_host["s2.example.net"].port == 2222
    assert by_host["m.example.net"].check_type is CheckType.MYSQL
    assert by_host["m.example.net"].port == 3307


def test_default_ports_omitted_tcp_udp_kept():
    _, _, text, _ = _roundtrip(PER_TYPE)
    # tcp/udp have no default port -> always emitted; smtp/pop3/dns/http/https default -> omitted.
    assert "port 8080;" in text and "port 53;" in text
    assert "port 25;" not in text and "port 110;" not in text and "port 443;" not in text
    assert "port 80;" not in text


def test_dns_query_name_emitted_not_username():
    _, _, text, _ = _roundtrip("ns.example.net authdns zone.example.net dns@example.net\n")
    assert 'dns-query "zone.example.net";' in text
    assert "username" not in text  # the legacy query name must NOT leak out as `username`


# --- nesting -> named dep edges -------------------------------------------------------

NESTED = (
    "rtr.example.net ping rtrdesc noc@example.net {\n"
    "    web.example.net tcp 443 webtls web@example.net\n"
    "    mail.example.net smtp mailbanner mail@example.net {\n"
    "        mail.example.net pop3 user secret mailpop mail@example.net\n"
    "    }\n"
    "}\n"
)


def test_nesting_becomes_dep_edges():
    leg, mod, text, warnings = _roundtrip(NESTED)
    assert _forest(leg.roots) == _forest(mod.roots)
    assert warnings == [] and mod.warnings == []
    # one root, the rest reached via dep; the modern format has no `{}` host nesting.
    assert len(mod.roots) == 1 and mod.roots[0].hostname == "rtr.example.net"
    assert text.count("dep ") == 3  # web, mail(smtp), mail(pop3)


def test_duplicate_hostnames_get_distinct_names():
    # web appears as both tcp and www under the same parent; names must not collide (or the
    # second object would be dropped as a duplicate on re-parse).
    leg, mod, text, warnings = _roundtrip(
        "rtr.example.net ping d noc@example.net {\n"
        "    web.example.net tcp 80 a web@example.net\n"
        "    web.example.net www /h OK b web@example.net\n"
        "}\n"
    )
    assert _forest(leg.roots) == _forest(mod.roots)
    assert mod.warnings == []
    assert "object web.example.net {" in text and "object web.example.net-2 {" in text


# --- position-dependent numfailures -> per-object -------------------------------------

def test_position_dependent_numfailures_resolves_per_object():
    text_in = (
        "config numfailures 3\n"
        "a.example.net ping a noc@example.net\n"
        "config numfailures 7\n"
        "b.example.net ping b noc@example.net\n"
    )
    leg, mod, modern_text, warnings = _roundtrip(text_in, numfailures=2)
    assert _forest(leg.roots) == _forest(mod.roots)
    by = {n.hostname: n.max_down for n in mod.roots}
    assert by["a.example.net"] == 3 and by["b.example.net"] == 7
    # the legacy positional global is NOT replayed; thresholds live on the objects.
    assert "config numfailures" not in modern_text
    assert modern_text.count("numfailures ") == 2


def test_default_threshold_not_emitted_per_object():
    # a node whose max_down equals the assumed default (2) needs no per-object numfailures.
    _, mod, modern_text, _ = _roundtrip("a.example.net ping a noc@example.net\n", numfailures=2)
    assert mod.roots[0].max_down == 2
    assert "  numfailures " not in modern_text  # no per-object attr (the header mentions the word)


# --- globals --------------------------------------------------------------------------

def test_globals_map_to_config_directives():
    text_in = (
        'config statusfile html /var/www/status.html\n'
        "config pageinterval 18\n"
        "config dnsexpire 1200\n"
        "config logging local0\n"
        "a.example.net ping a noc@example.net\n"
    )
    leg, mod, modern_text, _ = _roundtrip(text_in)
    assert 'config statusfile html "/var/www/status.html";' in modern_text
    assert "config pageinterval 18;" in modern_text
    assert "config dnsexpire 1200;" in modern_text
    assert "config logging local0;" in modern_text
    # the globals survive the round trip as Settings-field overrides.
    assert mod.overrides.get("pageinterval_min") == 18
    assert mod.overrides.get("status_path") == "/var/www/status.html"
    assert mod.overrides.get("syslog_facility") == "local0"
    # lock the globals round trip: identical overrides except numfailures (resolved per-object)
    assert mod.overrides == {k: v for k, v in leg.overrides.items() if k != "numfailures"}


# --- sample + production fixtures ------------------------------------------------------

def test_sample_fixture_round_trips():
    text = (FIXTURES / "legacy_sample.conf").read_text(encoding="utf-8")
    leg = parse_legacy(text, numfailures=2)
    modern_text, _ = convert(text, numfailures=2)
    mod = parse_modern(modern_text, numfailures=2)
    assert _forest(leg.roots) == _forest(mod.roots)
    assert mod.warnings == []


def test_production_fixture_round_trips():
    path = FIXTURES / "production.conf"
    if not path.exists():
        pytest.skip("production.conf not present (local-only fixture)")
    text = path.read_text(encoding="utf-8", errors="replace")
    leg = parse_legacy(text, numfailures=2)
    modern_text, _ = convert(text, numfailures=2)
    mod = parse_modern(modern_text, numfailures=2)
    assert _forest(leg.roots) == _forest(mod.roots)


# --- value-escaping edge + CLI --------------------------------------------------------

def test_special_chars_in_fields_survive_quoting():
    # legacy fields are whitespace-tokenized but may carry ; # = { } — these must round-trip
    # inside a quoted modern string, not derail the parser.
    leg, mod, _, _ = _roundtrip("h.example.net ping lab;e=l#x noc@example.net\n")
    assert _forest(leg.roots) == _forest(mod.roots)
    assert mod.roots[0].label == "lab;e=l#x"


def test_out_of_range_port_warns_not_silent():
    # legacy accepts any port > 0; modern rejects > 65535 and drops the object. The converter must
    # warn rather than silently lose the node on re-parse.
    _, _, _, warnings = _roundtrip("h.example.net tcp 70000 lbl noc@example.net\n")
    assert any("70000" in w and "65535" in w for w in warnings)


def test_sub_one_numfailures_warns_not_silent():
    # legacy allows numfailures 0/negative; modern requires >= 1. Warn rather than silently reset.
    _, _, _, warnings = _roundtrip(
        "config numfailures 0\nh.example.net ping lbl noc@example.net\n", numfailures=2
    )
    assert any("numfailures" in w and "representable" in w for w in warnings)


def test_globals_only_output_warns_about_detection():
    # an objectless converted file auto-detects as legacy; surface that rather than lose settings.
    _, _, _, warnings = _roundtrip("config pageinterval 9\n")
    assert any("no objects" in w and "legacy" in w for w in warnings)


def test_cli_bad_path_is_clean_error(capsys):
    rc = main(["does-not-exist.conf"])
    assert rc == 1
    assert "psysmon:" in capsys.readouterr().err  # clean error, not a traceback


def test_to_modern_accepts_parseresult_directly():
    leg = parse_legacy("a.example.net ping a noc@example.net\n", numfailures=2)
    text, warnings = to_modern(leg, default_numfailures=2)
    assert warnings == [] and "object a.example.net {" in text


def test_cli_writes_output(tmp_path):
    src = tmp_path / "old.conf"
    src.write_text("host.example.net ping label noc@example.net\n", encoding="utf-8")
    out = tmp_path / "new.conf"
    assert main([str(src), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert detect(text) is ConfigFormat.MODERN and "object host.example.net {" in text


def test_cli_handles_utf8_bom_input(tmp_path):
    # A legacy file saved with a UTF-8 BOM must not glue the BOM onto the first host (utf-8-sig).
    src = tmp_path / "old.conf"
    src.write_text("host.example.net ping label noc@example.net\n", encoding="utf-8-sig")
    out = tmp_path / "new.conf"
    assert main([str(src), "-o", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert 'host "host.example.net";' in text  # hostname clean, no leading BOM


def test_converter_emits_host_not_ip():
    # The converter writes the preferred `host` attribute (#76); the legacy `ip` keyword (still an
    # accepted synonym on input) is no longer emitted.
    text, _ = convert("router.example.net ping edge noc@example.net\n")
    assert 'host "router.example.net";' in text
    assert '  ip "' not in text
