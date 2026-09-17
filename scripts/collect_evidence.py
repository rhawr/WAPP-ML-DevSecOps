#!/usr/bin/env python3
"""Consolidate the phase evidence into an ordered ``logs/entrega/`` folder.

Copies every artifact from Fases 3-7 into a per-phase subtree, splits the unified
event stream by layer, writes an ``INDEX.md`` summary and, unless ``--no-zip`` is
given, packages the result as ``logs/entrega.zip``. Missing artifacts are listed
as "no generado" instead of aborting, so the command is always safe to run.
"""

from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# phase -> list of (source, destination-name)
FILE_MAP: dict[str, list[tuple[Path, str]]] = {
    "fase-3-ia-ml": [
        (ROOT / "traffic_agent" / "model.pkl", "model.pkl"),
        (ROOT / "traffic_agent" / "logs" / "traffic_dataset.csv", "traffic_dataset.csv"),
        (ROOT / "traffic_agent" / "logs" / "features_normal_traffic.csv", "features_normal_traffic.csv"),
        (ROOT / "traffic_agent" / "logs" / "evaluation_predictions.csv", "evaluation_predictions.csv"),
        (ROOT / "traffic_agent" / "logs" / "evaluation_metrics.json", "evaluation_metrics.json"),
    ],
    "fase-4-rasp": [
        (ROOT / "logs" / "rasp_test_results.json", "rasp_test_results.json"),
        (ROOT / "logs" / "rasp_latency.csv", "rasp_latency.csv"),
    ],
    "fase-5-pipeline": [
        (ROOT / "logs" / "pipeline_report.json", "pipeline_report.json"),
        (ROOT / "logs" / "pipeline_verification.json", "pipeline_verification.json"),
        (ROOT / "logs" / "waap_rules_deployed.json", "waap_rules_deployed.json"),
        (ROOT / "logs" / "zap_report.html", "zap_report.html"),
    ],
    "fase-6-evasion": [
        (ROOT / "logs" / "evasion_matrix.csv", "evasion_matrix.csv"),
        (ROOT / "logs" / "evasion_matrix.json", "evasion_matrix.json"),
    ],
    "fase-7-metricas": [
        (ROOT / "logs" / "metrics_dashboard.json", "metrics_dashboard.json"),
        (ROOT / "logs" / "metrics_report.md", "metrics_report.md"),
    ],
}

DIR_MAP: dict[str, list[tuple[Path, str]]] = {
    "fase-5-pipeline": [(ROOT / "logs" / "sqlmap", "sqlmap")],
}

PHASE_LABELS = {
    "fase-3-ia-ml": "Fase 3 — Módulo IA/ML",
    "fase-4-rasp": "Fase 4 — Agente RASP",
    "fase-5-pipeline": "Fase 5 — Pipeline DevSecOps",
    "fase-6-evasion": "Fase 6 — Evasión y efectividad",
    "fase-7-metricas": "Fase 7 — Observabilidad y métricas",
}

EVENT_LAYERS = ("waf", "ml", "rasp", "orchestrator", "pipeline", "observability")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(ROOT / "logs" / "entrega"), help="Output directory")
    parser.add_argument("--zip", dest="zip_path", default=str(ROOT / "logs" / "entrega.zip"))
    parser.add_argument("--no-zip", action="store_true", help="Do not create the ZIP package")
    return parser.parse_args()


def copy_file(source: Path, destination: Path) -> bool:
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True


def copy_dir(source: Path, destination: Path) -> bool:
    if not source.is_dir():
        return False
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination)
    return True


def split_events(events_file: Path, out_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not events_file.is_file():
        return counts
    lines: dict[str, list[str]] = {layer: [] for layer in EVENT_LAYERS}
    lines["otros"] = []
    for raw in events_file.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        layer = record.get("layer", "otros")
        lines.setdefault(layer, []).append(raw)
    out_dir.mkdir(parents=True, exist_ok=True)
    for layer, content in lines.items():
        if not content:
            continue
        (out_dir / f"waap_events_{layer}.jsonl").write_text("\n".join(content) + "\n", encoding="utf-8")
        counts[layer] = len(content)
    shutil.copy2(events_file, out_dir / "waap_events.jsonl")
    return counts


def metrics_summary() -> dict | None:
    path = ROOT / "logs" / "metrics_dashboard.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def build_index(out_dir: Path, copied: dict[str, list[str]], missing: dict[str, list[str]], layers: dict[str, int], dashboard: dict | None) -> str:
    lines = ["# Entrega — evidencias del taller WAAP", ""]
    lines.append(f"Generado: `{datetime.now(timezone.utc).isoformat()}`")
    lines.append("")
    lines.append("Comandos usados: `make setup` → `make lab-up` → `make phase3..7` → `make collect`")
    lines.append("")

    lines.append("## Archivos por fase")
    lines.append("")
    for phase in FILE_MAP:
        lines.append(f"### {PHASE_LABELS[phase]}")
        lines.append("")
        if copied.get(phase):
            for name in copied[phase]:
                lines.append(f"- `{phase}/{name}`")
        if missing.get(phase):
            for name in missing[phase]:
                lines.append(f"- `{phase}/{name}` — _no generado_")
        if not copied.get(phase) and not missing.get(phase):
            lines.append("- _sin artefactos definidos_")
        lines.append("")

    lines.append("## Eventos centralizados")
    lines.append("")
    lines.append("`eventos/waap_events.jsonl` (flujo completo) y un archivo por capa:")
    lines.append("")
    for layer, count in sorted(layers.items()):
        lines.append(f"- `eventos/waap_events_{layer}.jsonl` — {count} eventos")
    lines.append("")

    if dashboard:
        lines.append("## Métricas clave (Fase 7)")
        lines.append("")
        lines.append("| Capa | TP | FP | FN | TN | Detección | FPR | MTTD (ms) |")
        lines.append("|---|---|---|---|---|---|---|---|")
        labels = {"rules": "Reglas", "ml": "IA/ML", "rasp": "RASP"}
        for layer in ("rules", "ml", "rasp"):
            data = dashboard.get("layers", {}).get(layer)
            if not data:
                continue
            mttd = dashboard.get("mttd", {}).get(layer, {}).get("mttd_ms")
            det = data.get("detection_rate")
            fpr = data.get("false_positive_rate")
            det_txt = f"{det:.1%}" if isinstance(det, (int, float)) else "N/A"
            fpr_txt = f"{fpr:.1%}" if isinstance(fpr, (int, float)) else "N/A"
            lines.append(
                f"| {labels[layer]} | {data['tp']} | {data['fp']} | {data['fn']} | {data['tn']} | "
                f"{det_txt} | {fpr_txt} | {mttd if mttd is not None else 'N/A'} |"
            )
        combined = dashboard.get("combined", {})
        det = combined.get("detection_rate")
        det_txt = f"{det:.1%}" if isinstance(det, (int, float)) else "N/A"
        lines.append(
            f"| **Combinada** | {combined.get('tp')} | {combined.get('fp')} | {combined.get('fn')} | "
            f"{combined.get('tn')} | {det_txt} | — | — |"
        )
        lines.append("")
        gaps = dashboard.get("coverage_gaps", [])
        if gaps:
            lines.append("**Huecos de cobertura:** " + ", ".join(gaps))
            lines.append("")
        recs = dashboard.get("recommendations", [])
        if recs:
            lines.append("**Recomendaciones de tuning:**")
            lines.append("")
            for tip in recs:
                lines.append(f"- {tip}")
            lines.append("")

    index_path = out_dir / "INDEX.md"
    index_path.write_text("\n".join(lines), encoding="utf-8")
    return str(index_path)


def make_zip(entrega_dir: Path, zip_path: Path) -> None:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    zip_path.unlink(missing_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(entrega_dir.rglob("*")):
            if file.is_file():
                archive.write(file, arcname=str(file.relative_to(entrega_dir.parent)))


def main() -> int:
    args = parse_args()
    out_dir = Path(args.out)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    copied: dict[str, list[str]] = {}
    missing: dict[str, list[str]] = {}
    for phase, files in FILE_MAP.items():
        copied[phase] = []
        missing[phase] = []
        for source, name in files:
            if copy_file(source, out_dir / phase / name):
                copied[phase].append(name)
            else:
                missing[phase].append(name)
        for source, name in DIR_MAP.get(phase, []):
            if copy_dir(source, out_dir / phase / name):
                copied[phase].append(f"{name}/")

    layers = split_events(ROOT / "logs" / "waap_events.jsonl", out_dir / "eventos")
    dashboard = metrics_summary()
    index = build_index(out_dir, copied, missing, layers, dashboard)

    zip_note = ""
    if not args.no_zip:
        zip_path = Path(args.zip_path)
        make_zip(out_dir, zip_path)
        zip_note = f"\n  ZIP: {zip_path}"

    total = sum(len(names) for names in copied.values())
    print("=== Evidencias consolidadas ===")
    for phase, names in copied.items():
        print(f"  {phase:<18} {len(names)} archivo(s)")
    for phase, names in missing.items():
        for name in names:
            print(f"  [faltante] {phase}/{name} (no generado)")
    if layers:
        print("  Eventos por capa: " + ", ".join(f"{layer}={count}" for layer, count in sorted(layers.items())))
    print(f"  Total artefactos: {total}")
    print(f"  Índice: {index}{zip_note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
