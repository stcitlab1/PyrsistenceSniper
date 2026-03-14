from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1574.content_index_dll import ContentIndexDll

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_happy_path(tmp_path: Path) -> None:
    lang_node = make_node(
        name="English",
        values={"DLLOverridePath": r"C:\evil_nl6.dll"},
    )
    tree = make_node(children={"English": lang_node})
    p = make_plugin(ContentIndexDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    findings = p.run()
    assert len(findings) == 1
    assert "evil_nl6.dll" in findings[0].value


def test_missing_override_skipped(tmp_path: Path) -> None:
    lang_node = make_node(name="English", values={"Other": "data"})
    tree = make_node(children={"English": lang_node})
    p = make_plugin(ContentIndexDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert p.run() == []


def test_multiple_languages(tmp_path: Path) -> None:
    en = make_node(name="English", values={"DLLOverridePath": "a.dll"})
    fr = make_node(name="French", values={"DLLOverridePath": "b.dll"})
    tree = make_node(children={"English": en, "French": fr})
    p = make_plugin(ContentIndexDll, tmp_path)
    setup_hklm(p, tree, hive_path="/fake/SYSTEM")
    assert len(p.run()) == 2


def test_no_subtree(tmp_path: Path) -> None:
    p = make_plugin(ContentIndexDll, tmp_path)
    p.context.hive_path.return_value = None
    assert p.run() == []
