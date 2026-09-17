#!/usr/bin/env python3
"""Fase 6 — matriz de efectividad y evasión por capa (reglas, IA/ML, RASP).

For every payload/technique in the catalog the script records whether it is
blocked by the rule engine (through the ModSecurity proxy), detected by the
Isolation Forest model and blocked by the in-process RASP agent. Layers whose
target is unreachable or whose dependency is missing are reported as ``N/A``
instead of being silently counted as "No".

Outputs (under ``logs/``):
  * ``evasion_matrix.csv``  — the table required by the workshop.
  * ``evasion_matrix.json`` — structured detail consumed by Fase 7 metrics.

Optional external tools: ``--sqlmap`` runs sqlmap against the proxy when the
binary and the proxy are available; ZAP commands are documented in the phase
notes because the baseline scan is driven by Docker.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin

ROOT = Path(__file__).resolve().parent.parent
for extra in (ROOT, ROOT / "traffic_agent", ROOT / "app"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))


YES, NO, NA = "Sí", "No", "N/A"


@dataclass
class Case:
    id: str
    technique: str
    proxy_method: str
    proxy_path: str
    proxy_params: dict[str, str] | None = None
    proxy_json: dict[str, Any] | None = None
    rasp_method: str = "GET"
    rasp_path: str = "/api/Products/search"
    rasp_params: dict[str, str] | None = None
    rasp_json: dict[str, Any] | None = None
    note: str = ""
    malicious: bool = True


def catalog() -> list[Case]:
    classic = "' OR '1'='1"
    url_encoded = quote(classic, safe="")
    double_encoded = quote(quote(classic, safe=""), safe="")
    xss = "<script>alert(1)</script>"
    xss_double = quote("<script>alert(1)</script>", safe="")
    return [
        Case(
            "sqli_classic", "SQLi clásico ' OR '1'='1",
            "GET", "/rest/products/search", {"q": classic},
            rasp_params={"q": classic},
        ),
        Case(
            "sqli_url_encoded", "SQLi con codificación URL",
            "GET", "/rest/products/search", {"q": url_encoded},
            rasp_params={"q": url_encoded},
        ),
        Case(
            "sqli_double_encoded", "SQLi doble URL-encoding (evasión Fase 2)",
            "GET", "/rest/products/search", {"q": double_encoded},
            rasp_params={"q": double_encoded},
            note="Técnica que evadió CRS en PL1",
        ),
        Case(
            "sqli_fragmented", "SQLi fragmentado en 2 parámetros",
            "GET", "/rest/products/search", {"q": "' OR 1", "extra": "=1--"},
            rasp_params={"q": "' OR 1", "extra": "=1--"},
            note="Cada parámetro es benigno por separado",
        ),
        Case(
            "sqli_comments", "SQLi con comentarios en línea",
            "GET", "/rest/products/search", {"q": "' OR/**/1=1--"},
            rasp_params={"q": "' OR/**/1=1--"},
            note="Intento de romper firmas basadas en cadenas exactas",
        ),
        Case(
            "xss_basic", "XSS reflejado básico",
            "GET", "/rest/products/search", {"q": xss},
            rasp_method="GET", rasp_path="/rest/products/render", rasp_params={"q": xss},
        ),
        Case(
            "xss_attribute", "XSS por manejador de evento (<img onerror>)",
            "GET", "/rest/products/search", {"q": "<img src=x onerror=alert(1)>"},
            rasp_method="GET", rasp_path="/rest/products/render",
            rasp_params={"q": "<img src=x onerror=alert(1)>"},
        ),
        Case(
            "xss_double_encoded", "XSS doble URL-encoding (evasión Fase 2)",
            "GET", "/rest/products/search", {"q": xss_double},
            rasp_method="GET", rasp_path="/rest/products/render", rasp_params={"q": xss_double},
            note="Payload documentado en la Fase 2",
        ),
        Case(
            "path_traversal", "Path traversal ../../etc/passwd",
            "GET", "/rest/products/search", {"q": "../../etc/passwd"},
            rasp_method="GET", rasp_path="/api/files", rasp_params={"name": "../../etc/passwd"},
        ),
        # Benign controls: used by Fase 7 to estimate false positives per layer.
        Case(
            "benign_search", "Búsqueda legítima (control)",
            "GET", "/rest/products/search", {"q": "apple"},
            rasp_params={"q": "apple"}, malicious=False,
        ),
        Case(
            "benign_login", "Login válido (control)",
            "POST", "/rest/user/login", proxy_json={"email": "test@test.com", "password": "test123"},
            rasp_method="POST", rasp_path="/rest/user/login",
            rasp_json={"email": "test@test.com", "password": "test123"}, malicious=False,
        ),
        Case(
            "benign_catalog", "Catálogo de productos (control)",
            "GET", "/api/Products",
            rasp_path="/api/Products/search", rasp_params={"q": "juice"}, malicious=False,
        ),
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-url", default="http://localhost:4000", help="WAAP proxy base URL")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--log-dir", default=str(ROOT / "logs"))
    parser.add_argument("--sqlmap", action="store_true", help="Ejecutar sqlmap contra el proxy si está disponible")
    parser.add_argument("--bot-requests", type=int, default=20, help="Ráfaga para la fila de bot")
    return parser.parse_args()


# --- RASP target ------------------------------------------------------------

def start_rasp_server() -> tuple[Any, threading.Thread, str]:
    from werkzeug.serving import make_server

    from vulnerable_app import create_app

    app = create_app(rasp_enabled=True)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


# --- IA/ML target -----------------------------------------------------------

class MlScorer:
    def __init__(self) -> None:
        self.artifact: dict[str, Any] | None = None
        self.error: str | None = None
        try:
            import joblib

            artifact_path = ROOT / "traffic_agent" / "model.pkl"
            self.artifact = joblib.load(artifact_path)
        except Exception as error:  # noqa: BLE001 - report instead of crashing
            self.error = f"{error.__class__.__name__}: {error}"

    def score(self, url: str, body: str, status_code: int, response_time_ms: float) -> dict[str, Any] | None:
        if self.artifact is None:
            return None
        try:
            import numbers

            import pandas as pd

            from features import extract_features
        except Exception as error:  # noqa: BLE001
            self.error = f"{error.__class__.__name__}: {error}"
            return None

        features = extract_features(url, body)
        features["status_code"] = status_code
        features["response_time_ms"] = response_time_ms
        columns = self.artifact["feature_columns"]
        row = {column: features.get(column, 0) for column in columns}
        row["has_suspicious_chars"] = 1 if row["has_suspicious_chars"] else 0
        frame = pd.DataFrame([[row[column] for column in columns]], columns=columns)
        frame = frame.apply(pd.to_numeric, errors="coerce").fillna(0.0)
        model = self.artifact["model"]
        prediction = int(model.predict(frame)[0])
        score = float(-model.decision_function(frame)[0])
        return {"anomaly_score": round(score, 6), "prediction": prediction, "is_anomaly": prediction == -1}


# --- runners ----------------------------------------------------------------

def send(session: Any, method: str, base: str, path: str, params: dict[str, str] | None, json_body: dict[str, Any] | None, timeout: float) -> dict[str, Any]:
    url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    started = time.perf_counter()
    try:
        response = session.request(method, url, params=params, json=json_body, timeout=timeout, verify=False)
        final_url = response.request.url
        return {
            "ok": True,
            "status_code": response.status_code,
            "response_time_ms": round((time.perf_counter() - started) * 1000, 4),
            "url": final_url,
            "body": response.text[:400],
        }
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "status_code": 0, "response_time_ms": 0.0, "url": url, "body": f"{error.__class__.__name__}: {error}"}


def body_to_text(body: dict[str, Any] | None) -> str:
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")) if body else ""


def run_case(case: Case, session: Any, proxy_url: str, proxy_online: bool, rasp_url: str, ml: MlScorer, timeout: float) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": case.id,
        "technique": case.technique,
        "note": case.note,
        "is_malicious": case.malicious,
        "layers": {},
    }

    # Rule engine (proxy). The response also supplies status/time for the ML.
    if proxy_online:
        proxy = send(session, case.proxy_method, proxy_url, case.proxy_path, case.proxy_params, case.proxy_json, timeout)
        blocked = proxy["status_code"] == 403
        row["layers"]["rules"] = {
            "status": YES if blocked else NO,
            "http_code": proxy["status_code"],
            "response_time_ms": proxy["response_time_ms"],
            "body": proxy["body"],
        }
        scoring_source = proxy
    else:
        row["layers"]["rules"] = {"status": NA, "http_code": None, "body": "proxy no disponible"}
        scoring_source = send(session, case.rasp_method, rasp_url, case.rasp_path, case.rasp_params, case.rasp_json, timeout)

    # RASP (in-process app).
    rasp = send(session, case.rasp_method, rasp_url, case.rasp_path, case.rasp_params, case.rasp_json, timeout)
    row["layers"]["rasp"] = {
        "status": YES if rasp["status_code"] == 403 else NO,
        "http_code": rasp["status_code"],
        "response_time_ms": rasp["response_time_ms"],
        "body": rasp["body"],
    }

    # IA/ML scoring over the request features observed at the perimeter.
    scoring_params = case.proxy_params if proxy_online else case.rasp_params
    scoring_json = case.proxy_json if proxy_online else case.rasp_json
    scoring_body = body_to_text(scoring_json)
    row["request"] = {"url": scoring_source["url"], "body": scoring_body, "params": scoring_params}
    ml_result = ml.score(
        scoring_source["url"],
        scoring_body,
        int(scoring_source["status_code"] or 0),
        float(scoring_source["response_time_ms"] or 0.0),
    )
    if ml_result is None:
        row["layers"]["ml"] = {"status": NA, "detail": ml.error or "modelo no disponible"}
    else:
        row["layers"]["ml"] = {
            "status": YES if ml_result["is_anomaly"] else NO,
            "anomaly_score": ml_result["anomaly_score"],
            "prediction": ml_result["prediction"],
        }
    return row


def run_bot(session: Any, proxy_url: str, proxy_online: bool, burst: int, timeout: float) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "bot_burst",
        "technique": f"Ráfaga de {burst} peticiones (bot)",
        "note": "req_per_minute no es una feature del modelo actual",
        "is_malicious": True,
        "layers": {},
    }
    if proxy_online:
        blocked = 0
        for index in range(burst):
            result = send(session, "POST", proxy_url, "/rest/user/login", None, {"email": "admin@juice-sh.op", "password": f"intento{index}"}, timeout)
            if result["status_code"] == 403:
                blocked += 1
        row["layers"]["rules"] = {"status": YES if blocked else NO, "blocked_requests": blocked, "total": burst}
    else:
        row["layers"]["rules"] = {"status": NA, "detail": "proxy no disponible"}
    row["layers"]["ml"] = {"status": NA, "detail": "el modelo no incorpora frecuencia por IP (req_per_minute)"}
    row["layers"]["rasp"] = {"status": NA, "detail": "el RASP protege operaciones, no volumen de tráfico"}
    return row


def run_sqlmap(proxy_url: str, timeout: float) -> dict[str, Any]:
    if shutil.which("sqlmap") is None:
        return {"status": NA, "detail": "sqlmap no instalado"}
    target = f"{proxy_url.rstrip('/')}/rest/products/search?q=1"
    command = ["sqlmap", "-u", target, "--batch", "--level=1", "--risk=1", "--output-dir=logs/sqlmap"]
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout * 20)
    output = (process.stdout or "") + (process.stderr or "")
    vulnerable = "is vulnerable" in output.lower() or "sqlmap identified the following injection point" in output.lower()
    return {"status": YES if vulnerable else NO, "detail": "sqlmap encontró inyección" if vulnerable else "sqlmap no confirmó inyección"}


def cell(value: str) -> str:
    return value


def main() -> int:
    args = parse_args()
    import urllib3

    import requests

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    output_dir = Path(args.log_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    proxy_online = False
    try:
        requests.get(args.proxy_url, timeout=2.0)
        proxy_online = True
    except requests.RequestException:
        proxy_online = False

    server, thread, rasp_url = start_rasp_server()
    ml = MlScorer()
    try:
        time.sleep(0.2)
        session = requests.Session()
        print(f"[+] Proxy WAAP {'disponible' if proxy_online else 'no disponible (columna reglas = N/A)'}: {args.proxy_url}")
        print(f"[+] App RASP local: {rasp_url}")
        print(f"[+] Modelo IA/ML: {'cargado' if ml.artifact is not None else 'no disponible (' + str(ml.error) + ')'}")

        records = [run_case(case, session, args.proxy_url, proxy_online, rasp_url, ml, args.timeout) for case in catalog()]
        records.append(run_bot(session, args.proxy_url, proxy_online, args.bot_requests, args.timeout))
        sqlmap_result = run_sqlmap(args.proxy_url, args.timeout) if args.sqlmap else None
    finally:
        server.shutdown()
        thread.join(timeout=2)

    # CSV required by the workshop.
    csv_path = output_dir / "evasion_matrix.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Payload / tecnica", "Bloqueado por reglas (Fase 2)", "Detectado por IA/ML (Fase 3)", "Bloqueado por RASP (Fase 4)", "Notas"])
        for row in records:
            writer.writerow([
                row["technique"],
                cell(row["layers"]["rules"]["status"]),
                cell(row["layers"]["ml"]["status"]),
                cell(row["layers"]["rasp"]["status"]),
                row.get("note", ""),
            ])

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proxy_url": args.proxy_url,
        "proxy_online": proxy_online,
        "rasp_url": rasp_url,
        "ml_model_loaded": ml.artifact is not None,
        "ml_error": ml.error,
        "sqlmap": sqlmap_result,
        "cases": records,
    }
    json_path = output_dir / "evasion_matrix.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print("\n=== MATRIZ DE EFECTIVIDAD (Fase 6) ===")
    header = f"{'Payload / técnica':<44} {'Reglas':<7} {'IA/ML':<7} {'RASP':<7}"
    print(header)
    print("-" * len(header))
    for row in records:
        print(f"{row['technique']:<44} {row['layers']['rules']['status']:<7} {row['layers']['ml']['status']:<7} {row['layers']['rasp']['status']:<7}")
    if sqlmap_result is not None:
        print(f"\n[sqlmap] {sqlmap_result['status']} — {sqlmap_result.get('detail', '')}")
    print(f"\n  Matriz CSV: {csv_path}")
    print(f"  Detalle JSON: {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
