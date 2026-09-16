#!/usr/bin/env python3
"""Generate labelled HTTP traffic for a local Juice Shop + ModSecurity WAAP lab."""

from __future__ import annotations

import argparse
import csv
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from colorama import Fore, Style, init
from requests import Response
from tqdm import tqdm

from features import extract_features
from generators.attack import FALLBACK_PAYLOADS, attack_request
from generators.normal import USER_AGENTS, RequestSpec, normal_request
from loaders.csic_loader import load_csic_payloads
from loaders.params_loader import load_http_params_payloads

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

FIELDNAMES = [
    "timestamp", "method", "url", "status_code", "response_time_ms", "url_length",
    "body_length", "entropy", "n_params", "has_suspicious_chars", "param_max_length",
    "special_char_ratio", "label", "source",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:4000", help="WAAP proxy base URL (default: %(default)s)")
    parser.add_argument("--normal-count", type=int, default=200, help="Normal requests before attacks")
    parser.add_argument("--attack-count", type=int, default=300, help="Dataset-driven attack requests")
    parser.add_argument("--mixed-count", type=int, default=0, help="Optional normal/attack requests after both phases")
    parser.add_argument("--output-dir", default="logs", help="Directory for CSV output")
    parser.add_argument("--datasets-dir", default="datasets", help="Directory containing csic_2010/ and http_params/")
    parser.add_argument("--delay-min", type=float, default=0.5, help="Minimum normal-navigation delay in seconds")
    parser.add_argument("--delay-max", type=float, default=2.0, help="Maximum normal-navigation delay in seconds")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed for reproducibility")
    parser.add_argument("--allow-remote-target", action="store_true", help="Explicitly permit a non-loopback target")
    args = parser.parse_args()
    if min(args.normal_count, args.attack_count, args.mixed_count) < 0:
        parser.error("request counts must be zero or greater")
    if args.delay_min < 0 or args.delay_max < args.delay_min:
        parser.error("require 0 <= --delay-min <= --delay-max")
    host = (urlsplit(args.target).hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "::1"} and not args.allow_remote_target:
        parser.error("non-loopback targets require --allow-remote-target; this agent is intended for an authorized local lab")
    return args


def build_url(target: str, spec: RequestSpec) -> str:
    return urljoin(target.rstrip("/") + "/", spec.path.lstrip("/"))


def execute_request(session: requests.Session, target: str, spec: RequestSpec, label: str, timeout: float, rng: random.Random) -> dict[str, Any]:
    url = build_url(target, spec)
    body = spec.json
    headers = {"User-Agent": rng.choice(USER_AGENTS), "Accept": "application/json, text/plain, */*"}
    started = time.perf_counter()
    status_code = 0
    try:
        response: Response = session.request(spec.method, url, params=spec.params, json=spec.json, headers=headers, timeout=timeout, verify=False)
        status_code = response.status_code
        final_url = response.request.url
    except requests.RequestException as error:
        final_url = requests.Request(spec.method, url, params=spec.params).prepare().url
        print(f"{Fore.RED}[ERROR] {spec.method} {spec.path} -> {error.__class__.__name__}: {error}{Style.RESET_ALL}")
    response_time_ms = round((time.perf_counter() - started) * 1000, 3)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": spec.method,
        "url": final_url,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        **extract_features(final_url, body),
        "label": label,
        "source": spec.source,
    }
    color = Fore.GREEN if label == "normal" else Fore.YELLOW
    print(f"{color}[{label.upper()}] {spec.method} {urlsplit(final_url).path}{('?' + urlsplit(final_url).query) if urlsplit(final_url).query else ''} -> {status_code} ({response_time_ms:.0f}ms){Style.RESET_ALL}")
    return entry


def payload_pool(datasets_dir: str) -> list[tuple[str, str]]:
    base = Path(datasets_dir)
    csic = [(value, "csic") for value in load_csic_payloads(base / "csic_2010")]
    params = [(value, "httpparams") for value in load_http_params_payloads(base / "http_params")]
    fallback = [(value, "generated") for value in FALLBACK_PAYLOADS]
    pool = csic + params
    return pool if pool else fallback


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    rows: list[dict[str, Any]] = []

    print(f"Target WAAP proxy: {args.target.rstrip('/')}")
    print(f"Normal phase: {args.normal_count} requests")
    for _ in tqdm(range(args.normal_count), desc="Normal traffic", unit="request"):
        rows.append(execute_request(session, args.target, normal_request(rng), "normal", args.timeout, rng))
        time.sleep(rng.uniform(args.delay_min, args.delay_max))

    pool = payload_pool(args.datasets_dir)
    source_counts = Counter(source for _, source in pool)
    print(f"Attack payload pool: {len(pool)} ({dict(source_counts)})")
    for index in tqdm(range(args.attack_count), desc="Attack traffic", unit="request"):
        payload, source = rng.choice(pool)
        # Consecutive groups of 12 requests emulate bot bursts in well under two seconds.
        burst = index % 36 < 12
        rows.append(execute_request(session, args.target, attack_request(payload, source, rng, burst), "attack", args.timeout, rng))
        if not burst:
            time.sleep(rng.uniform(0.05, 0.2))

    for _ in tqdm(range(args.mixed_count), desc="Mixed traffic", unit="request"):
        if rng.random() < 0.6:
            rows.append(execute_request(session, args.target, normal_request(rng), "normal", args.timeout, rng))
            time.sleep(rng.uniform(args.delay_min, args.delay_max))
        else:
            payload, source = rng.choice(pool)
            rows.append(execute_request(session, args.target, attack_request(payload, source, rng), "attack", args.timeout, rng))
            time.sleep(rng.uniform(0.05, 0.2))

    all_path = output_dir / "traffic_dataset.csv"
    normal_path = output_dir / "features_normal_traffic.csv"
    write_csv(all_path, rows)
    write_csv(normal_path, [row for row in rows if row["label"] == "normal"])
    labels = Counter(row["label"] for row in rows)
    statuses = Counter(row["status_code"] for row in rows)
    print(f"\n{Fore.CYAN}Summary{Style.RESET_ALL}")
    print(f"  Normal: {labels['normal']} | Attack: {labels['attack']} | Total: {len(rows)}")
    print(f"  Status codes: {dict(sorted(statuses.items()))}")
    print(f"  Dataset: {all_path}")
    print(f"  Normal-only: {normal_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
