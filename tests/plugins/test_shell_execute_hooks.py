from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.shell_execute_hooks import (
    SharedTaskScheduler,
    ShellExecuteHooks,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


class TestShellExecuteHooks:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"{evil-clsid}": "EvilHook"})
        p = make_plugin(ShellExecuteHooks, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert len(findings) >= 1

    def test_empty(self, tmp_path: Path) -> None:
        node = make_node()
        p = make_plugin(ShellExecuteHooks, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        assert p.run() == []


class TestSharedTaskScheduler:
    def test_happy_path(self, tmp_path: Path) -> None:
        node = make_node(values={"{evil-clsid}": "EvilScheduler"})
        p = make_plugin(SharedTaskScheduler, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        findings = p.run()
        assert len(findings) >= 1

    def test_empty(self, tmp_path: Path) -> None:
        node = make_node()
        p = make_plugin(SharedTaskScheduler, tmp_path)
        setup_hklm(p, node, hive_path="/fake/SOFTWARE")
        assert p.run() == []
