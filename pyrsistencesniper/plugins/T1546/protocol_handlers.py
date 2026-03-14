from __future__ import annotations

from pyrsistencesniper.models.finding import FilterRule
from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class ProtocolHandlerHijack(PersistencePlugin):
    definition = CheckDefinition(
        id="protocol_handler_hijack",
        technique="Protocol Handler Hijacking",
        mitre_id="T1546.001",
        description=(
            "Protocol handler commands specify the executable invoked "
            "when a protocol URI is opened. Non-default handlers for "
            "high-risk protocols (http, https, mailto, ms-msdt, "
            "ms-officecmd) are flagged."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\http\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\http\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Classes\https\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\https\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Classes\mailto\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\mailto\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Classes\ms-msdt\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\ms-msdt\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Classes\ms-officecmd\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\ms-officecmd\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
        ),
        allow=(
            FilterRule(
                reason="Default ms-msdt handler",
                value_matches=r"msdt\.exe",
                signer="microsoft",
            ),
            FilterRule(
                reason="Default Windows protocol handler",
                signer="microsoft",
                not_lolbin=True,
            ),
        ),
    )


@register_plugin
class SearchProtocolHandler(PersistencePlugin):
    definition = CheckDefinition(
        id="search_protocol_handler",
        technique="Search Protocol Handler Hijack",
        mitre_id="T1546.001",
        description=(
            "The search-ms protocol handler is normally handled by "
            "explorer.exe. Any modification to this handler is a strong "
            "indicator of search-ms protocol abuse, as documented in "
            "Follina-era attacks."
        ),
        references=("https://attack.mitre.org/techniques/T1546/001/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\search-ms\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"Software\Classes\search-ms\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKU,
            ),
        ),
        allow=(
            FilterRule(
                reason="Default Windows search handler",
                value_matches=r"Explorer\.exe",
                signer="microsoft",
            ),
        ),
    )
