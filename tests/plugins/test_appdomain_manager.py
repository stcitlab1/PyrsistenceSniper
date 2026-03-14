from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1574.appdomain_manager import (
    AppDomainManagerInjection,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    node = make_node(values={"APPDOMAIN_MANAGER_ASM": "EvilAssembly, Version=1.0.0.0"})
    p = make_plugin(AppDomainManagerInjection, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) >= 1
    assert any("EvilAssembly" in f.value for f in findings)


def test_type_value(tmp_path: Path) -> None:
    node = make_node(values={"APPDOMAIN_MANAGER_TYPE": "Evil.Manager"})
    p = make_plugin(AppDomainManagerInjection, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) >= 1
    assert any("Evil.Manager" in f.value for f in findings)


def test_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(AppDomainManagerInjection, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SYSTEM")
    assert p.run() == []
