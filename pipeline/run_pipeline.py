#!/usr/bin/env python3
"""Local DevSecOps pipeline runner for the WAAP lab (Fase 5).

Runs the security gates in order (SAST, SCA, container build, image scan, IaC
scan, DAST) and only deploys the versioned WAAP rules when every gate passes.
Stages whose tool is not installed are reported as ``skipped`` (use ``--strict``
to turn skips into failures). A machine-readable report is written to
``logs/pipeline_report.json`` and a summary event to ``logs/waap_events.jsonl``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from observability.logger import log_event  # noqa: E402


@dataclass(frozen=True)
class Stage:
    name: str
    control: str
    binary: str
    command: list[str]
    purpose: str


STAGES: list[Stage] = [
    Stage(
        "sast-semgrep",
        "SAST",
        "semgrep",
        ["semgrep", "--config", "pipeline/semgrep-rules.yaml", "--error", "--quiet", "--metrics=off", "app/"],
        "Patrones inseguros en el código de la aplicación",
    ),
    Stage(
        "sca-pip-audit",
        "SCA",
        "pip-audit",
        ["pip-audit", "-r", "app/requirements.txt", "--progress-spinner", "off"],
        "Dependencias con CVE conocidos",
    ),
    Stage(
        "build-image",
        "BUILD",
        "podman",
        ["podman", "build", "-f", "app/Dockerfile", "-t", "taller-waap/app:local", "."],
        "Construcción de la imagen de la aplicación",
    ),
    Stage(
        "container-trivy",
        "CONTAINER",
        "trivy",
        ["trivy", "image", "--severity", "HIGH,CRITICAL", "--exit-code", "1", "--no-progress", "taller-waap/app:local"],
        "Vulnerabilidades en la imagen de contenedor",
    ),
    Stage(
        "iac-checkov",
        "IaC",
        "checkov",
        ["checkov", "--file", "app/Dockerfile", "--file", "docker-compose.yml", "--quiet", "--compact"],
        "Configuraciones inseguras en Dockerfile/Compose",
    ),
    Stage(
        "dast-zap",
        "DAST",
        "podman",
        [
            "podman",
            "run",
            "--rm",
            "--add-host=host.containers.internal:host-gateway",
            "ghcr.io/zaproxy/zaproxy:stable",
            "zap-baseline.py",
            "-t",
            "http://host.containers.internal:4000",
        ],
        "Pruebas dinámicas contra la app protegida por el WAAP",
    ),
]

DEPLOY_STAGE = Stage(
    "deploy-waap-rules",
    "DEPLOY",
    "bash",
    ["bash", "scripts/deploy_waap_rules.sh"],
    "Despliegue de reglas/umbrales versionados (policy as code)",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="Treat skipped stages as failures")
    parser.add_argument("--no-deploy", action="store_true", help="Do not run the deploy stage")
    parser.add_argument("--only", default="", help="Comma-separated stage names to run")
    parser.add_argument("--report", default="logs/pipeline_report.json", help="Report output path")
    return parser.parse_args()


def resolve_tool(binary: str) -> str | None:
    """Find a tool on PATH, falling back to the running interpreter's bin dir."""
    found = shutil.which(binary)
    if found:
        return found
    candidate = Path(sys.executable).parent / binary
    return str(candidate) if candidate.exists() else None


def run_stage(stage: Stage, strict: bool) -> dict[str, object]:
    started = time.perf_counter()
    tool = resolve_tool(stage.binary)
    if tool is None:
        status = "failed" if strict else "skipped"
        return {
            "name": stage.name,
            "control": stage.control,
            "purpose": stage.purpose,
            "status": status,
            "detail": f"herramienta '{stage.binary}' no instalada",
            "command": " ".join(stage.command),
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "output_tail": "",
        }

    command = [tool] + stage.command[1:] if stage.command[0] == stage.binary else stage.command
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    output = (process.stdout or "") + (process.stderr or "")
    tail = "\n".join(output.strip().splitlines()[-12:])
    return {
        "name": stage.name,
        "control": stage.control,
        "purpose": stage.purpose,
        "status": "passed" if process.returncode == 0 else "failed",
        "detail": f"exit code {process.returncode}",
        "command": " ".join(stage.command),
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "output_tail": tail,
    }


def main() -> int:
    args = parse_args()
    selected = {name.strip() for name in args.only.split(",") if name.strip()}
    stages = [stage for stage in STAGES if not selected or stage.name in selected]

    print("=" * 72)
    print("PIPELINE DEVSECOPS — puertas de seguridad")
    print("=" * 72)

    results: list[dict[str, object]] = []
    for stage in stages:
        result = run_stage(stage, args.strict)
        results.append(result)
        icon = {"passed": "[OK]", "failed": "[FAIL]", "skipped": "[SKIP]"}[str(result["status"])]
        print(f"{icon:<7} {result['control']:<9} {result['name']:<18} ({result['duration_ms']} ms)")
        if result["status"] == "failed" and result["output_tail"]:
            for line in str(result["output_tail"]).splitlines():
                print(f"          | {line}")

    failed = [result for result in results if result["status"] == "failed"]
    gate_passed = not failed

    deploy_result = None
    if gate_passed and not args.no_deploy:
        deploy_result = run_stage(DEPLOY_STAGE, args.strict)
        results.append(deploy_result)
        icon = {"passed": "[OK]", "failed": "[FAIL]", "skipped": "[SKIP]"}[str(deploy_result["status"])]
        print(f"{icon:<7} {deploy_result['control']:<9} {deploy_result['name']:<18} ({deploy_result['duration_ms']} ms)")
        gate_passed = deploy_result["status"] == "passed"

    print("-" * 72)
    print(f"RESULTADO: {'VERDE: despliegue habilitado' if gate_passed else 'ROJO: despliegue bloqueado'}")
    if failed:
        print("Etapas que bloquearon: " + ", ".join(str(result["name"]) for result in failed))

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "strict": args.strict,
        "gate_passed": gate_passed,
        "failed_stages": [result["name"] for result in failed],
        "results": results,
    }
    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = ROOT / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    log_event(
        "pipeline",
        "allow" if gate_passed else "block",
        "security_gate",
        gate_passed=gate_passed,
        failed_stages=[result["name"] for result in failed],
        report=str(report_path),
    )
    print(f"Reporte: {report_path}")
    return 0 if gate_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
