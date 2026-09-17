#!/usr/bin/env python3
"""Fase 4 evidence runner: RASP test cases and latency comparison.

Boots the vulnerable Flask app twice in-process (RASP on / RASP off) on an
ephemeral port, exercises the three cases required by the workshop and measures
the per-request latency over a configurable number of rounds. Results are written
to ``logs/rasp_test_results.json`` and ``logs/rasp_latency.csv``; every guard
decision is appended to the unified ``logs/waap_events.jsonl`` stream.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import statistics
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import _path  # noqa: F401  (adds the repository root to sys.path)
from observability.logger import log_dir, log_event
from vulnerable_app import create_app

# Payload that passed through ModSecurity + CRS PL1 in Fase 2 thanks to double
# URL-encoding. Sent as a query value, requests encodes it once more, so the
# transport URL carries %253C... exactly like the documented evasion.
DOUBLE_ENCODED_XSS = quote("<script>alert(1)</script>", safe="")

DESERIALIZE_BLOB = base64.b64encode(
    b'{"cmd": "whoami", "__reduce__": "os.system"}'
).decode("ascii")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=50, help="Benign requests per latency scenario per cycle")
    parser.add_argument("--cycles", type=int, default=3, help="Interleaved RASP on/off cycles (averages out drift)")
    parser.add_argument("--warmup", type=int, default=10, help="Discarded warm-up requests before measuring")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--log-dir", default=str(log_dir()), help="Directory for evidence artifacts")
    args = parser.parse_args()
    if args.rounds < 20:
        parser.error("--rounds must be at least 20 (workshop requires a minimum of 20 per scenario)")
    if args.cycles < 1:
        parser.error("--cycles must be at least 1")
    return args


def start_server(rasp_enabled: bool) -> tuple[Any, threading.Thread, str]:
    from werkzeug.serving import make_server

    app = create_app(rasp_enabled=rasp_enabled)
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    return server, thread, base_url


def wait_for_health(base_url: str, timeout: float) -> None:
    import requests

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{base_url}/api/health", timeout=1.0).status_code == 200:
                return
        except requests.RequestException:
            time.sleep(0.05)
    raise RuntimeError("el servidor no respondió a /api/health")


def timed_request(session: Any, method: str, url: str, **kwargs: Any) -> tuple[int, float, str]:
    started = time.perf_counter()
    try:
        response = session.request(method, url, timeout=5.0, **kwargs)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 4)
        return response.status_code, elapsed_ms, response.text
    except Exception:  # noqa: BLE001 - evidence runner must record failures
        elapsed_ms = round((time.perf_counter() - started) * 1000, 4)
        return 0, elapsed_ms, ""


def run_cases(session: Any, base_url: str, rasp_enabled: bool, results: dict[str, Any]) -> None:
    label = "rasp_on" if rasp_enabled else "rasp_off"
    login_url = f"{base_url}/rest/user/login"
    search_url = f"{base_url}/api/Products/search"
    render_url = f"{base_url}/rest/products/render"
    files_url = f"{base_url}/api/files"
    deserialize_url = f"{base_url}/api/deserialize"

    # Case 1: fragmented SQLi. Each fragment must stay under the radar alone.
    frag_a = timed_request(session, "GET", search_url, params={"q": "' OR 1"})
    frag_b = timed_request(session, "GET", search_url, params={"q": "", "extra": "=1--"})
    combined = timed_request(session, "GET", search_url, params={"q": "' OR 1", "extra": "=1--"})
    results[f"{label}_fragmented"] = {
        "fragment_a_status": frag_a[0],
        "fragment_b_status": frag_b[0],
        "combined_status": combined[0],
        "fragment_a_blocked": frag_a[0] == 403,
        "fragment_b_blocked": frag_b[0] == 403,
        "combined_blocked": combined[0] == 403,
        "combined_body": combined[2][:300],
    }

    # Case 2: the Fase 2 evasion payload against the app.
    xss = timed_request(session, "GET", render_url, params={"q": DOUBLE_ENCODED_XSS})
    results[f"{label}_double_encoded_xss"] = {
        "status": xss[0],
        "blocked": xss[0] == 403,
        "body": xss[2][:300],
    }

    # Extra evidence: path traversal and unsafe deserialization.
    traversal = timed_request(session, "GET", files_url, params={"name": "../outside_secret.txt"})
    results[f"{label}_path_traversal"] = {
        "status": traversal[0],
        "blocked": traversal[0] == 403,
        "body": traversal[2][:200],
    }
    deserial = timed_request(
        session, "POST", deserialize_url, json={"blob": DESERIALIZE_BLOB}
    )
    results[f"{label}_deserialization"] = {
        "status": deserial[0],
        "blocked": deserial[0] == 403,
        "body": deserial[2][:200],
    }

    # Baseline benefit omitted from the CSVs: a valid login must still succeed.
    valid = timed_request(
        session,
        "POST",
        login_url,
        json={"email": "test@test.com", "password": "test123"},
    )
    results[f"{label}_valid_login"] = {"status": valid[0], "blocked": valid[0] == 403}


def measure_latency(session: Any, base_url: str, rounds: int) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    targets = [
        ("GET", f"{base_url}/api/health", None),
        ("POST", f"{base_url}/rest/user/login", {"email": "test@test.com", "password": "test123"}),
        ("GET", f"{base_url}/api/Products/search", {"q": "apple"}),
    ]
    for index in range(rounds):
        method, url, payload = targets[index % len(targets)]
        kwargs = {"json": payload} if method == "POST" else ({"params": payload} if payload else {})
        status, elapsed_ms, _ = timed_request(session, method, url, **kwargs)
        samples.append(
            {"scenario": None, "method": method, "url": url, "status_code": status, "latency_ms": elapsed_ms}
        )
    return samples


def warm_up(session: Any, base_url: str, rounds: int) -> None:
    """Prime the interpreter/framework so warm-up cost is not measured."""
    for _ in range(rounds):
        timed_request(session, "GET", f"{base_url}/api/health")


def guard_time_stats(events_file: Path) -> dict[str, float]:
    """Directly report the in-process inspection time logged by the guards."""
    values: list[float] = []
    if not events_file.is_file():
        return {}
    with events_file.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("layer") == "rasp" and "guard_ms" in record:
                values.append(float(record["guard_ms"]))
    if not values:
        return {}
    values.sort()
    return {
        "samples": len(values),
        "mean_ms": round(statistics.fmean(values), 4),
        "median_ms": round(statistics.median(values), 4),
        "p95_ms": round(values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))], 4),
        "max_ms": round(values[-1], 4),
    }


def summarize(samples: list[dict[str, Any]]) -> dict[str, float]:
    values = sorted(row["latency_ms"] for row in samples)
    count = len(values)
    p95_index = min(count - 1, int(round(0.95 * (count - 1))))
    return {
        "count": count,
        "mean_ms": round(statistics.fmean(values), 4),
        "median_ms": round(statistics.median(values), 4),
        "p95_ms": round(values[p95_index], 4),
        "min_ms": round(values[0], 4),
        "max_ms": round(values[-1], 4),
    }


def main() -> int:
    args = parse_args()
    try:
        import requests  # noqa: F401
    except ImportError:
        print("Falta el paquete 'requests'. Instala: pip install -r app/requirements.txt", file=sys.stderr)
        return 2

    import requests

    output_dir = Path(args.log_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rounds_per_scenario": args.rounds,
        "cycles": args.cycles,
        "warmup_requests": args.warmup,
        "cases": {},
        "latency": {},
        "guard_time_ms": {},
    }
    latency_rows: list[dict[str, Any]] = []
    events_file = output_dir / "waap_events.jsonl"
    events_file.unlink(missing_ok=True)  # keep the event stream scoped to this run

    for cycle in range(args.cycles):
        for rasp_enabled in (True, False):
            label = "rasp_on" if rasp_enabled else "rasp_off"
            server, thread, base_url = start_server(rasp_enabled)
            try:
                wait_for_health(base_url, args.timeout)
                session = requests.Session()
                print(f"[+] Ciclo {cycle + 1}/{args.cycles} · escenario {label} · {base_url}")
                if cycle == 0:
                    run_cases(session, base_url, rasp_enabled, results["cases"])
                warm_up(session, base_url, args.warmup)
                samples = measure_latency(session, base_url, args.rounds)
                for row in samples:
                    row["scenario"] = label
                    row["cycle"] = cycle + 1
                latency_rows.extend(samples)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    for label in ("rasp_on", "rasp_off"):
        results["latency"][label] = summarize([row for row in latency_rows if row["scenario"] == label])

    on_mean = results["latency"]["rasp_on"]["mean_ms"]
    off_mean = results["latency"]["rasp_off"]["mean_ms"]
    results["latency"]["overhead_ms"] = round(on_mean - off_mean, 4)
    results["latency"]["overhead_pct"] = round((on_mean - off_mean) / off_mean * 100, 2) if off_mean else 0.0
    results["guard_time_ms"] = guard_time_stats(events_file)

    latency_path = output_dir / "rasp_latency.csv"
    with latency_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["scenario", "cycle", "method", "url", "status_code", "latency_ms"])
        writer.writeheader()
        writer.writerows(latency_rows)

    results_path = output_dir / "rasp_test_results.json"
    with results_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, ensure_ascii=False)

    log_event(
        "rasp",
        "alert",
        "phase4_summary",
        overhead_ms=results["latency"]["overhead_ms"],
        overhead_pct=results["latency"]["overhead_pct"],
    )

    print("\n=== RESULTADOS FASE 4 ===")
    for name, data in results["cases"].items():
        status = data.get("status", data.get("combined_status"))
        print(f"  {name:<38} status={status} blocked={data.get('blocked', data.get('combined_blocked'))}")
    print(
        f"  Latencia RASP on={on_mean:.3f}ms off={off_mean:.3f}ms "
        f"overhead={results['latency']['overhead_ms']:.3f}ms ({results['latency']['overhead_pct']:.2f}%)"
    )
    if results["guard_time_ms"]:
        g = results["guard_time_ms"]
        print(f"  Tiempo de guarda (in-process): media={g['mean_ms']:.4f}ms p95={g['p95_ms']:.4f}ms máx={g['max_ms']:.4f}ms")
    print(f"\n  Evidencias: {results_path}")
    print(f"              {latency_path}")
    print(f"              {output_dir / 'waap_events.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
