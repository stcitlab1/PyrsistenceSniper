from __future__ import annotations

from pyrsistencesniper.plugins import register_plugin
from pyrsistencesniper.plugins.base import (
    CheckDefinition,
    HiveScope,
    PersistencePlugin,
    RegistryTarget,
)


@register_plugin
class RecycleBinComExtension(PersistencePlugin):
    definition = CheckDefinition(
        id="recycle_bin_com_extension",
        technique="Recycle Bin COM Extension Handler",
        mitre_id="T1546.015",
        description=(
            "Shell verb commands on the Recycle Bin CLSID "
            "({645FF040-5081-101B-9F08-00AA002F954E}) are checked for "
            "non-standard values. Default commands point to explorer.exe."
        ),
        references=("https://attack.mitre.org/techniques/T1546/015/",),
        targets=(
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\empty\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
            RegistryTarget(
                path=r"SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\explore\command",
                values="(Default)",
                scope=HiveScope.HKLM,
            ),
        ),
    )
