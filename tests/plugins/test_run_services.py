from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1547.run_services import (
    RunServices,
    RunServicesOnce,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_run_services_happy(tmp_path: Path) -> None:
    node = make_node(values={"EvilSvc": r"C:\evil_svc.exe"})
    p = make_plugin(RunServices, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_svc.exe" in f.value for f in findings)


def test_run_services_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(RunServices, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    assert p.run() == []


def test_run_services_once_happy(tmp_path: Path) -> None:
    node = make_node(values={"EvilOnce": r"C:\evil_once.exe"})
    p = make_plugin(RunServicesOnce, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_once.exe" in f.value for f in findings)


def test_run_services_once_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(RunServicesOnce, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    assert p.run() == []
