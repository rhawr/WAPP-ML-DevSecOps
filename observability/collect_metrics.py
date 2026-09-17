#!/usr/bin/env python3
"""Fase 7 — Observabilidad y métricas.

Centralizes the evidence produced by the previous phases and computes, per layer
(reglas / IA-ML / RASP) and combined:

  * TP, FP, FN, TN y tasa de detección, falsos positivos y falsos negativos.
  * MTTD simulado (latencia desde la petición hasta la alerta registrada).
  * Recomendaciones de ajuste de umbrales.

Inputs (se omiten si no existen):
  * logs/evasion_matrix.json                  (Fase 6)
  * logs/waap_events.jsonl                     (eventos RASP/pipeline/app)
  * traffic_agent/logs/evaluation_metrics.json (métricas del modelo, Fase 3)

Outputs:
  * logs/metrics_dashboard.json
  * logs/metrics_report.md
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
for extra in (ROOT, ROOT / "traffic_agent"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from observability.logger import log_event  # noqa: E402

YES, NO, NA = "Sí", "No", "N/A"
LAYERS = ("rules", "ml", "rasp")
LAYER_LABEL = {"rules": "Reglas (Fase 2)", "ml": "IA/ML (Fase 3)", "rasp": "RASP (Fase 4)"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", default=str(ROOT / "logs" / "evasion_matrix.json"))
    parser.add_argument("--events", default=str(ROOT / "logs" / "waap_events.jsonl"))
    parser.add_argument("--ml-metrics", default=str(ROOT / "traffic_agent" / "logs" / "evaluation_metrics.json"))
    parser.add_argument("--ingest-delay-ms", type=float, default=0.0, help="Retardo simulado de ingesta/SIEM (ms)")
    parser.add_argument("--out-json", default=str(ROOT / "logs" / "metrics_dashboard.json"))
    parser.add_argument("--out-md", default=str(ROOT / "logs" / "metrics_report.md"))
    return parser.parse_args()


def load_json(path: str) -> Any | None:
    file = Path(path)
    if not file.is_file():
        return None
    try:
        return json.loads(file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def status_of(record: dict[str, Any], layer: str) -> bool | None:
    status = record.get("layers", {}).get(layer, {}).get("status", NA)
    if status == YES:
        return True
    if status == NO:
        return False
    return None


def layer_metrics(records: list[dict[str, Any]], layer: str) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for record in records:
        detected = status_of(record, layer)
        if detected is None:
            continue
        if record.get("is_malicious"):
            if detected:
                tp += 1
            else:
                fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1

    def safe(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "detection_rate": safe(tp, tp + fn),
        "false_positive_rate": safe(fp, fp + tn),
        "false_negative_rate": safe(fn, tp + fn),
        "precision": safe(tp, tp + fp),
        "accuracy": safe(tp + tn, tp + fp + fn + tn),
    }


def combined_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = fp = fn = tn = 0
    for record in records:
        available = [status_of(record, layer) for layer in LAYERS]
        available = [value for value in available if value is not None]
        if not available:
            continue
        detected = any(available)
        if record.get("is_malicious"):
            if detected:
                tp += 1
            else:
                fn += 1
        elif detected:
            fp += 1
        else:
            tn += 1

    def safe(num: int, den: int) -> float | None:
        return round(num / den, 4) if den else None

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "detection_rate": safe(tp, tp + fn),
        "false_positive_rate": safe(fp, fp + tn),
    }


def rasp_guard_stats(events_path: str) -> dict[str, Any]:
    path = Path(events_path)
    if not path.is_file():
        return {}
    blocks = allows = 0
    guard_samples: list[float] = []
    by_event: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("layer") != "rasp":
            continue
        if event.get("verdict") == "block":
            blocks += 1
            by_event[event.get("event", "unknown")] = by_event.get(event.get("event", "unknown"), 0) + 1
        elif event.get("verdict") == "allow":
            allows += 1
        if "guard_ms" in event:
            guard_samples.append(float(event["guard_ms"]))
    if not guard_samples and not blocks and not allows:
        return {}
    return {
        "block_events": blocks,
        "allow_events": allows,
        "blocks_by_type": by_event,
        "guard_ms_mean": round(statistics.fmean(guard_samples), 4) if guard_samples else None,
        "guard_ms_p95": round(sorted(guard_samples)[min(len(guard_samples) - 1, int(round(0.95 * (len(guard_samples) - 1))))], 4) if guard_samples else None,
    }


def ml_inference_ms(records: list[dict[str, Any]]) -> tuple[float | None, str | None]:
    """Measure the Isolation Forest inference latency over the matrix requests."""
    try:
        import joblib
        import pandas as pd

        from features import extract_features
    except Exception as error:  # noqa: BLE001
        return None, f"{error.__class__.__name__}: {error}"

    try:
        artifact = joblib.load(ROOT / "traffic_agent" / "model.pkl")
    except Exception as error:  # noqa: BLE001
        return None, f"{error.__class__.__name__}: {error}"

    columns = artifact["feature_columns"]
    model = artifact["model"]
    samples: list[float] = []
    import time

    for record in records:
        request = record.get("request")
        if not request:
            continue
        layers = record.get("layers", {})
        http_code = layers.get("rules", {}).get("http_code") or layers.get("rasp", {}).get("http_code") or 0
        response_ms = layers.get("rules", {}).get("response_time_ms") or layers.get("rasp", {}).get("response_time_ms") or 0.0
        features = extract_features(request["url"], request["body"])
        features["status_code"] = int(http_code or 0)
        features["response_time_ms"] = float(response_ms or 0.0)
        row = {column: features.get(column, 0) for column in columns}
        row["has_suspicious_chars"] = 1 if row["has_suspicious_chars"] else 0
        frame = pd.DataFrame([[row[column] for column in columns]], columns=columns)
        frame = frame.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        started = time.perf_counter()
        model.decision_function(frame)
        samples.append((time.perf_counter() - started) * 1000)
    if not samples:
        return None, "sin peticiones para medir"
    return round(statistics.fmean(samples), 4), None


def mttd_per_layer(records: list[dict[str, Any]], guard_stats: dict[str, Any], ml_ms: float | None, ingest_delay: float) -> dict[str, Any]:
    rule_samples = [
        record["layers"]["rules"].get("response_time_ms")
        for record in records
        if status_of(record, "rules") and record["layers"]["rules"].get("response_time_ms") is not None
    ]
    rasp_samples = [
        record["layers"]["rasp"].get("response_time_ms")
        for record in records
        if status_of(record, "rasp") and record["layers"]["rasp"].get("response_time_ms") is not None
    ]
    result: dict[str, Any] = {}
    if rule_samples:
        result["rules"] = {"mttd_ms": round(statistics.fmean(rule_samples) + ingest_delay, 4), "samples": len(rule_samples), "basis": "latencia de la respuesta 403 del proxy"}
    if ml_ms is not None:
        result["ml"] = {"mttd_ms": round(ml_ms + ingest_delay, 4), "samples": len(records), "basis": "latencia de inferencia del modelo"}
    if guard_stats.get("guard_ms_mean") is not None:
        result["rasp"] = {"mttd_ms": round(guard_stats["guard_ms_mean"] + ingest_delay, 4), "samples": guard_stats.get("block_events", 0) + guard_stats.get("allow_events", 0), "basis": "guard_ms (detección in-process)"}
    return result


def coverage_gaps(records: list[dict[str, Any]]) -> list[str]:
    gaps = []
    for record in records:
        if not record.get("is_malicious"):
            continue
        available = [status_of(record, layer) for layer in LAYERS]
        if not any(value for value in available if value is not None):
            if any(value is not None for value in available):
                gaps.append(record["technique"])
    return gaps


def recommendations(layer_data: dict[str, Any], combined: dict[str, Any], gaps: list[str], ml_eval: dict[str, Any] | None) -> list[str]:
    tips: list[str] = []
    ml = layer_data.get("ml", {})
    if ml.get("false_positive_rate") is not None and ml["false_positive_rate"] > 0.05:
        tips.append(
            f"IA/ML: FPR={ml['false_positive_rate']:.1%} (>5%). Bajar contamination de 0.10 a 0.05 y/o subir el umbral "
            "de decisión (anomaly_threshold) para reducir alertas sobre tráfico legítimo."
        )
    if ml_eval:
        tips.append(
            f"IA/ML (Fase 3): ROC-AUC={ml_eval.get('roc_auc_anomaly_score')}, recall={ml_eval.get('attack_recall_detection_rate')}. "
            "Ampliar el set de entrenamiento normal para estabilizar el umbral."
        )
    rules = layer_data.get("rules", {})
    if rules.get("false_negative_rate"):
        tips.append(
            f"Reglas: FNR={rules['false_negative_rate']:.1%}. Subir Paranoia Level a 2 y habilitar decodificación múltiple "
            "para cubrir doble URL-encoding y fragmentación."
        )
    rasp = layer_data.get("rasp", {})
    if rasp.get("false_negative_rate"):
        tips.append(
            f"RASP: FNR={rasp['false_negative_rate']:.1%}. Normalizar comentarios SQL (/**/, --, #) antes de las firmas "
            "y considerar libinjection a nivel de aplicación para el caso con comentarios."
        )
    if gaps:
        tips.append("Sin cobertura por ninguna capa: " + ", ".join(gaps) + ". Priorizar rate limiting y features de frecuencia.")
    if not tips:
        tips.append("Todas las capas dentro de parámetros aceptables; no se requieren ajustes inmediatos.")
    return tips


def build_markdown(dashboard: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Fase 7 — Panel de observabilidad y métricas")
    lines.append("")
    lines.append(f"Generado: `{dashboard['generated_at']}`")
    lines.append(f"Fuente matriz: `{dashboard['sources']['matrix']}`  ")
    lines.append(f"Eventos: `{dashboard['sources']['events']}`")
    lines.append("")
    lines.append("## Métricas por capa")
    lines.append("")
    lines.append("| Capa | TP | FP | FN | TN | Tasa detección | FPR | FNR | Precisión | MTTD (ms) |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for layer in LAYERS:
        data = dashboard["layers"].get(layer)
        if not data:
            lines.append(f"| {LAYER_LABEL[layer]} | - | - | - | - | N/A | N/A | N/A | N/A | N/A |")
            continue
        mttd = dashboard["mttd"].get(layer, {}).get("mttd_ms")
        def pct(value: Any) -> str:
            return f"{value:.1%}" if isinstance(value, (int, float)) else "N/A"
        lines.append(
            f"| {LAYER_LABEL[layer]} | {data['tp']} | {data['fp']} | {data['fn']} | {data['tn']} | "
            f"{pct(data['detection_rate'])} | {pct(data['false_positive_rate'])} | {pct(data['false_negative_rate'])} | "
            f"{pct(data['precision'])} | {mttd if mttd is not None else 'N/A'} |"
        )
    combined = dashboard["combined"]
    def pct(value: Any) -> str:
        return f"{value:.1%}" if isinstance(value, (int, float)) else "N/A"
    lines.append("")
    lines.append("## Cobertura combinada (reglas ∪ IA/ML ∪ RASP)")
    lines.append("")
    lines.append(f"- TP={combined['tp']}  FP={combined['fp']}  FN={combined['fn']}  TN={combined['tn']}")
    lines.append(f"- Tasa de detección: **{pct(combined['detection_rate'])}** | FPR: {pct(combined['false_positive_rate'])}")
    lines.append("")
    if dashboard.get("rasp_events"):
        events = dashboard["rasp_events"]
        lines.append("## Eventos RASP")
        lines.append("")
        lines.append(f"- Bloqueos: {events.get('block_events')} | Permisos: {events.get('allow_events')}")
        lines.append(f"- Por tipo: {events.get('blocks_by_type')}")
        lines.append(f"- guard_ms medio: {events.get('guard_ms_mean')} | p95: {events.get('guard_ms_p95')}")
        lines.append("")
    if dashboard.get("ml_evaluation"):
        ml = dashboard["ml_evaluation"]
        lines.append("## Métricas del modelo (Fase 3)")
        lines.append("")
        lines.append(f"- Accuracy: {ml.get('accuracy')} | Recall: {ml.get('attack_recall_detection_rate')} | "
                     f"F1: {ml.get('attack_f1')} | ROC-AUC: {ml.get('roc_auc_anomaly_score')}")
        lines.append("")
    if dashboard.get("coverage_gaps"):
        lines.append("## Huecos de cobertura")
        lines.append("")
        for gap in dashboard["coverage_gaps"]:
            lines.append(f"- {gap}")
        lines.append("")
    lines.append("## Recomendaciones de ajuste")
    lines.append("")
    for tip in dashboard["recommendations"]:
        lines.append(f"- {tip}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    matrix = load_json(args.matrix)
    ml_eval = load_json(args.ml_metrics)
    guard_stats = rasp_guard_stats(args.events)

    if not matrix or not matrix.get("cases"):
        print(f"[!] No hay matriz en {args.matrix}; ejecuta la Fase 6 primero.", file=sys.stderr)
        return 1

    records = matrix["cases"]
    layers = {layer: layer_metrics(records, layer) for layer in LAYERS}
    combined = combined_metrics(records)
    ml_ms, ml_error = ml_inference_ms(records)
    mttd = mttd_per_layer(records, guard_stats, ml_ms, args.ingest_delay_ms)
    gaps = coverage_gaps(records)
    recs = recommendations(layers, combined, gaps, ml_eval)

    dashboard = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": {"matrix": args.matrix, "events": args.events, "ml_metrics": args.ml_metrics},
        "ingest_delay_ms": args.ingest_delay_ms,
        "ml_inference_ms": ml_ms,
        "ml_inference_error": ml_error,
        "layers": layers,
        "combined": combined,
        "mttd": mttd,
        "rasp_events": guard_stats,
        "ml_evaluation": ml_eval,
        "coverage_gaps": gaps,
        "recommendations": recs,
    }

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(dashboard, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(build_markdown(dashboard), encoding="utf-8")

    log_event("observability", "alert", "metrics_report", detection_rate=combined["detection_rate"], gaps=gaps)

    print("=== MÉTRICAS FASE 7 ===")
    for layer in LAYERS:
        data = layers[layer]
        print(f"  {LAYER_LABEL[layer]:<16} TP={data['tp']} FP={data['fp']} FN={data['fn']} TN={data['tn']} "
              f"det={data['detection_rate']} fpr={data['false_positive_rate']}")
    print(f"  {'Combinada':<16} det={combined['detection_rate']} fpr={combined['false_positive_rate']}")
    print(f"  MTTD (ms): { {k: v['mttd_ms'] for k, v in mttd.items()} }")
    if ml_ms is None:
        print(f"  IA/ML inferencia no medida: {ml_error}")
    print(f"  Panel: {out_json}")
    print(f"  Reporte: {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
