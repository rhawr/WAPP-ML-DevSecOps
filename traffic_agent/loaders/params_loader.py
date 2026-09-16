"""Loader for HttpParamsDataset CSV files."""

from __future__ import annotations

import csv
from pathlib import Path


def load_http_params_payloads(params_dir: str | Path, max_payloads: int | None = None) -> list[str]:
    """Return unique rows marked malicious (label=1) from CSV files."""
    base = Path(params_dir)
    if not base.exists():
        return []
    payloads: list[str] = []
    seen: set[str] = set()
    for path in sorted(base.rglob("*.csv")):
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
                for row in csv.DictReader(handle):
                    payload = (row.get("payload") or "").strip()
                    label = str(row.get("label", "")).strip().lower()
                    if label in {"1", "true", "malicious", "attack"} and payload and payload not in seen:
                        seen.add(payload)
                        payloads.append(payload)
                        if max_payloads and len(payloads) >= max_payloads:
                            return payloads
        except (OSError, csv.Error):
            continue
    return payloads
