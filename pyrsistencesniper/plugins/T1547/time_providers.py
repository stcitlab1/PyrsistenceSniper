from __future__ import annotations

from pyrsistencesniper.models.finding import AccessLevel, FilterRule, Finding
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import CheckDefinition, PersistencePlugin

_TIME_PROVIDERS_PATH_TEMPLATE = r"{controlset}\Services\W32Time\TimeProviders"


@register_plugin
class TimeProviders(PersistencePlugin):
    definition = CheckDefinition(
        id="time_providers",
        technique="Time Providers",
        mitre_id="T1547.003",
        description=(
            "Time provider DLLs are loaded by the W32Time service at "
            "startup. Default providers are NtpClient, NtpServer, and "
            "VMICTimeProvider (Hyper-V). Any non-default time provider "
            "DLL is a strong indicator of persistence."
        ),
        references=("https://attack.mitre.org/techniques/T1547/003/",),
        allow=(
            FilterRule(
                reason="Default Windows time provider",
                value_matches=r"w32time\.dll$",
                signer="microsoft",
            ),
            FilterRule(
                reason="Hyper-V time provider",
                value_matches=r"vmictimeprovider\.dll$",
                signer="microsoft",
            ),
        ),
    )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []

        tp_path = _TIME_PROVIDERS_PATH_TEMPLATE.replace(
            "{controlset}", self.context.active_controlset
        )
        tree = self._load_subtree("SYSTEM", tp_path)
        if tree is None:
            return findings

        for provider_name, node in tree.children():
            value_str = self._to_str(node.get("DllName"))
            if value_str is None:
                continue
            findings.append(
                self._make_finding(
                    path=(f"HKLM\\SYSTEM\\{tp_path}\\{provider_name}\\DllName"),
                    value=value_str,
                    access=AccessLevel.SYSTEM,
                )
            )

        return findings
