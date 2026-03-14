from __future__ import annotations

import csv
from typing import IO, Any

from pyrsistencesniper.models.finding import AnnotatedResult
from pyrsistencesniper.output.base import OutputBase

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _sanitize_cell(value: object) -> str:
    """Escape formula-trigger prefixes to prevent injection."""
    s = str(value)
    stripped = s.lstrip()
    if stripped and stripped[0] in _FORMULA_PREFIXES:
        return f"'{s}"
    return s


class CsvOutput(OutputBase):
    """Writes findings as CSV with formula-injection-safe cell values."""

    def _open_kwargs(self) -> dict[str, Any]:
        return {"newline": ""}

    def _write(self, results: list[AnnotatedResult], out: IO[str]) -> None:
        if not results:
            return

        rows, fieldnames = self._flatten_results(results)
        sanitized = [{k: _sanitize_cell(v) for k, v in row.items()} for row in rows]
        writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in sanitized:
            writer.writerow(row)
