from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1574.snmp_extension import SnmpExtensionAgent

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    node = make_node(values={"1": r"SOFTWARE\Evil\SNMP\CurrentVersion\Agent"})
    p = make_plugin(SnmpExtensionAgent, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) >= 1
    assert any("Evil" in f.value for f in findings)


def test_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(SnmpExtensionAgent, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    assert p.run() == []
