"""Tests for the core data model."""

from __future__ import annotations

from psysmon.config.model import DEFAULT_PORT, CheckType, Node, NodeState, type_to_name


def test_node_defaults():
    n = Node(hostname="rtr.example.net", check_type=CheckType.PING)
    assert n.port == 0
    assert n.children == []
    assert n.contact == ""
    assert n.max_down == 2


def test_children_are_independent_lists():
    a = Node(hostname="a", check_type=CheckType.PING)
    b = Node(hostname="b", check_type=CheckType.PING)
    a.children.append(Node(hostname="c", check_type=CheckType.TCP, port=22))
    assert a.children and not b.children  # no shared mutable default


def test_default_ports():
    assert DEFAULT_PORT[CheckType.SMTP] == 25
    assert DEFAULT_PORT[CheckType.POP3] == 110
    assert DEFAULT_PORT[CheckType.HTTPS] == 443
    assert DEFAULT_PORT[CheckType.TCP] is None  # explicit in config


def test_type_to_name_matches_legacy():
    assert type_to_name(CheckType.HTTP) == "www"
    assert type_to_name(CheckType.DNS) == "authdns"
    assert type_to_name(CheckType.PING) == "ping"


def test_nodestate_defaults():
    s = NodeState()
    assert s.lastcheck == 0
    assert s.downct == 0
    assert s.contacted is False
    assert s.suppressed is False
