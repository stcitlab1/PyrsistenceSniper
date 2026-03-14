from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1547.font_drivers import FontDrivers

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    node = make_node(values={"EvilFont": r"C:\evil_font.dll"})
    p = make_plugin(FontDrivers, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    findings = p.run()
    assert len(findings) >= 1
    assert any("evil_font.dll" in f.value for f in findings)


def test_empty(tmp_path: Path) -> None:
    node = make_node()
    p = make_plugin(FontDrivers, tmp_path)
    setup_hklm(p, node, hive_path="/fake/SOFTWARE")
    assert p.run() == []
