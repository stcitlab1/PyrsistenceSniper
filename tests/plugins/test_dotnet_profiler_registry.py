from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1574.dotnet_profiler_registry import (
    DotNetFrameworkProfiler,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_cor_profiler_happy(tmp_path: Path) -> None:
    node = make_node(values={"COR_PROFILER": "{evil-guid}"})
    p = make_plugin(DotNetFrameworkProfiler, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    findings = p.run()
    assert len(findings) >= 1
    assert any("{evil-guid}" in f.value for f in findings)


def test_cor_profiler_path_happy(tmp_path: Path) -> None:
    node = make_node(values={"COR_PROFILER_PATH": r"C:\evil_profiler.dll"})
    p = make_plugin(DotNetFrameworkProfiler, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_profiler.dll" in f.value for f in findings)


def test_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(DotNetFrameworkProfiler, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    assert p.run() == []
