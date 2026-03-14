from __future__ import annotations

from typing import TYPE_CHECKING

from pyrsistencesniper.plugins.T1546.file_association import (
    FileAssociationHijack,
)

from .conftest import make_node, make_plugin, setup_hklm

if TYPE_CHECKING:
    from pathlib import Path


def test_script_interpreter_flagged(tmp_path: Path) -> None:
    node = make_node(values={"(Default)": r'"C:\Windows\System32\cmd.exe" /c evil.bat'})
    p = make_plugin(FileAssociationHijack, tmp_path)
    setup_hklm(p, node)
    findings = p.run()
    assert len(findings) >= 1
    assert any("cmd.exe" in f.value for f in findings)


def test_powershell_flagged(tmp_path: Path) -> None:
    node = make_node(values={"(Default)": r"powershell.exe -enc base64stuff"})
    p = make_plugin(FileAssociationHijack, tmp_path)
    setup_hklm(p, node)
    findings = p.run()
    assert len(findings) >= 1
    assert any("powershell.exe" in f.value for f in findings)


def test_normal_handler_not_flagged(tmp_path: Path) -> None:
    node = make_node(
        values={"(Default)": r'"C:\Program Files\Notepad++\notepad++.exe"'}
    )
    p = make_plugin(FileAssociationHijack, tmp_path)
    setup_hklm(p, node)
    findings = p.run()
    assert findings == []


def test_no_hive_returns_empty(tmp_path: Path) -> None:
    p = make_plugin(FileAssociationHijack, tmp_path)
    p.context.hive_path.return_value = None
    p.registry.open_hive.return_value = None
    assert p.run() == []
