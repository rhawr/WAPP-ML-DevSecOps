#!/usr/bin/env python3
"""Fase 5 verification: baseline green -> injected vulnerability -> red -> revert -> green.

Automates the workshop exercise. Two injection modes are supported:

* ``sast`` (default): adds ``app/insecure_extra.py`` with a concatenated SQL
  query, which the Semgrep gate must catch.
* ``sca``: appends an outdated dependency (``PyYAML==5.3.1``, with public CVEs)
  to ``app/requirements.txt``, which the pip-audit gate must catch.

Results are written to ``logs/pipeline_verification.json``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INJECTED_SAST = ROOT / "app" / "insecure_extra.py"
REQUIREMENTS = ROOT / "app" / "requirements.txt"
OUTDATED_DEP = "PyYAML==5.3.1"
INJECTED_SAST_CODE = '''"""Injected vulnerability for the Fase 5 pipeline exercise.

Added by pipeline/verify_pipeline.py and removed on revert; it must never be
committed.
"""


def injected_login_query(email: str) -> str:
    return f"SELECT * FROM users WHERE email = '{email}' AND active = 1"
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["sast", "sca"], default="sast")
    parser.add_argument("--report", default="logs/pipeline_verification.json")
    return parser.parse_args()


def run_pipeline(label: str) -> dict[str, object]:
    print(f"\n>>> [{label}] ejecutando pipeline...")
    process = subprocess.run(
        [sys.executable, "pipeline/run_pipeline.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    print(process.stdout)
    report_path = ROOT / "logs" / "pipeline_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.is_file() else {}
    return {
        "label": label,
        "exit_code": process.returncode,
        "gate_passed": bool(report.get("gate_passed")),
        "failed_stages": report.get("failed_stages", []),
        "stage_status": {r["name"]: r["status"] for r in report.get("results", [])},
    }


def inject(mode: str) -> None:
    if mode == "sast":
        INJECTED_SAST.write_text(INJECTED_SAST_CODE, encoding="utf-8")
        print(f"[inject] {INJECTED_SAST.relative_to(ROOT)}: consulta SQL concatenada sin parametrizar")
    else:
        original = REQUIREMENTS.read_text(encoding="utf-8")
        REQUIREMENTS.write_text(original.rstrip("\n") + f"\n{OUTDATED_DEP}\n", encoding="utf-8")
        print(f"[inject] app/requirements.txt: dependencia desactualizada {OUTDATED_DEP}")


def revert(mode: str) -> None:
    if mode == "sast":
        INJECTED_SAST.unlink(missing_ok=True)
    else:
        content = REQUIREMENTS.read_text(encoding="utf-8")
        cleaned = "\n".join(
            line for line in content.splitlines() if line.strip() != OUTDATED_DEP
        )
        REQUIREMENTS.write_text(cleaned.rstrip("\n") + "\n", encoding="utf-8")
    print("[revert] cambio revertido")


def main() -> int:
    args = parse_args()
    expected_stage = "sast-semgrep" if args.mode == "sast" else "sca-pip-audit"
    outcomes: list[dict[str, object]] = []

    baseline = run_pipeline("baseline")
    outcomes.append(baseline)

    injected: dict[str, object] = {}
    reverified: dict[str, object] = {}
    try:
        inject(args.mode)
        injected = run_pipeline(f"con-vulnerabilidad-{args.mode}")
        outcomes.append(injected)
    finally:
        revert(args.mode)

    reverified = run_pipeline("revertido")
    outcomes.append(reverified)

    checks = {
        "baseline_green": baseline["gate_passed"] is True,
        "injected_red": injected.get("gate_passed") is False,
        "failed_at_expected_stage": expected_stage in injected.get("failed_stages", []),
        "revert_green": reverified.get("gate_passed") is True,
    }
    success = all(checks.values())

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": args.mode,
        "expected_failing_stage": expected_stage,
        "checks": checks,
        "success": success,
        "runs": outcomes,
    }
    report_path = ROOT / args.report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n" + "=" * 72)
    print("VERIFICACIÓN DEL PIPELINE")
    for name, value in checks.items():
        print(f"  {'[OK]' if value else '[NO]':<5} {name}")
    print(f"RESULTADO: {'EXITOSO' if success else 'FALLIDO'}")
    print(f"Reporte: {report_path}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
