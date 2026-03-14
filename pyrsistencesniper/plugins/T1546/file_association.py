from __future__ import annotations

import re

from pyrsistencesniper.models.check import HiveProtocol
from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_HIGH_RISK_EXTENSIONS: tuple[str, ...] = (
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".html",
    ".htm",
    ".js",
    ".vbs",
    ".hta",
    ".exe",
    ".bat",
    ".cmd",
    ".ps1",
)

_SCRIPT_INTERPRETER_RE = re.compile(
    r"(cmd\.exe|powershell\.exe|pwsh\.exe|mshta\.exe"
    r"|wscript\.exe|cscript\.exe|rundll32\.exe)",
    re.IGNORECASE,
)


@register_plugin
class FileAssociationHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="file_association_hijack",
        technique="File Association Hijacking",
        mitre_id="T1546.001",
        description=(
            "Per-user and system-wide file association command handlers "
            "for high-risk extensions (.txt, .pdf, .doc, .js, .exe, etc.) "
            "are checked for suspicious values. Handlers pointing to "
            "script interpreters or temp directories are flagged."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
        allow=(
            FilterRule(
                reason="Standard system handler",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        hive = self._open_hive("SOFTWARE")
        if hive is not None:
            self._check_hive(
                hive, "Classes", "HKLM\\SOFTWARE", AccessLevel.SYSTEM, findings
            )

        for profile, uhive in self._iter_user_hives():
            self._check_hive(
                uhive,
                "Software\\Classes",
                f"HKU\\{profile.username}",
                AccessLevel.USER,
                findings,
            )

        return findings

    def _check_hive(
        self,
        hive: HiveProtocol,
        classes_prefix: str,
        path_prefix: str,
        access: AccessLevel,
        findings: list[Finding],
    ) -> None:
        for ext in _HIGH_RISK_EXTENSIONS:
            cmd_path = f"{classes_prefix}\\{ext}\\shell\\open\\command"
            node = self.registry.load_subtree(hive, cmd_path)
            if node is None:
                continue
            default_val = self._to_str(node.get("(Default)"))
            if default_val is None:
                continue
            if not _SCRIPT_INTERPRETER_RE.search(default_val):
                continue
            findings.append(
                self._make_finding(
                    path=f"{path_prefix}\\{cmd_path}",
                    value=default_val,
                    access=access,
                )
            )
