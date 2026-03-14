from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_MONITORS_PATH_TEMPLATE = r"{controlset}\Control\Print\Monitors"
_PROCESSORS_X64_TEMPLATE = (
    r"{controlset}\Control\Print\Environments"
    r"\Windows x64\Print Processors"
)
_PROCESSORS_X86_TEMPLATE = (
    r"{controlset}\Control\Print\Environments"
    r"\Windows NT x86\Print Processors"
)


@register_plugin
class PrintMonitors(PersistencePlugin):
    definition = CheckDefinition(
        id="print_monitors",
        technique="Print Monitors",
        mitre_id="T1547.010",
        description=(
            "Print monitor DLLs are loaded by the Print Spooler service "
            "(spoolsv.exe) at startup with SYSTEM privileges. Default "
            "monitors include Local Port, Standard TCP/IP Port, USB "
            "Monitor, WSD Port. Any additional monitor is suspicious."
        ),
        references=("https://attack.mitre.org/techniques/T1547/010/",),
        allow=(
            FilterRule(
                reason="Default Windows print monitor",
                value_matches=(
                    r"^(localspl|tcpmon|usbmon|WSDMon|APMon|FXSMON"
                    r"|msonppmon)\.dll$"
                ),
                signer="microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        monitors_path = _MONITORS_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self._load_subtree("SYSTEM", monitors_path)
        if tree is None:
            return findings

        for monitor_name, node in tree.children():
            value_str = self._to_str(node.get("Driver"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=(f"HKLM\\SYSTEM\\{monitors_path}\\{monitor_name}\\Driver"),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings


@register_plugin
class PrintProcessors(PersistencePlugin):
    definition = CheckDefinition(
        id="print_processors",
        technique="Print Processors",
        mitre_id="T1547.012",
        description=(
            "Print processor DLLs are loaded by the Print Spooler "
            "service at startup with SYSTEM privileges. The only default "
            "print processor is winprint (winprint.dll). Both x64 and "
            "x86 architecture paths are checked."
        ),
        references=("https://attack.mitre.org/techniques/T1547/012/",),
        allow=(
            FilterRule(
                reason="Default Windows print processor",
                value_matches=r"^winprint\.dll$",
                signer="microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        cs = self.context.active_controlset

        for template in (_PROCESSORS_X64_TEMPLATE, _PROCESSORS_X86_TEMPLATE):
            proc_path = template.replace("{controlset}", cs)
            tree = self._load_subtree("SYSTEM", proc_path)
            if tree is None:
                continue

            for proc_name, node in tree.children():
                value_str = self._to_str(node.get("Driver"))
                if value_str is None:
                    continue
                findings.append(
                    self._make_finding(
                        path=(f"HKLM\\SYSTEM\\{proc_path}\\{proc_name}\\Driver"),
                        value=value_str,
                        access=AccessLevel.SYSTEM,
                    )
                )

        return findings
