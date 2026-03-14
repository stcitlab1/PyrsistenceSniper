from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.recycle_bin_com import (
    RecycleBinComExtension,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    node = make_node(values={"(Default)": r"C:\evil.exe"})
    p = make_plugin(RecycleBinComExtension, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil.exe" in f.value for f in findings)


def test_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(RecycleBinComExtension, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    assert p.run() == []
