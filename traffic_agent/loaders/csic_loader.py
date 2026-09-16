"""Tolerant loader for CSIC 2010 HTTP request files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


REQUEST_LINE_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d(?:\.\d)?$", re.I)


@dataclass(frozen=True)
class CsicRequest:
    method: str
    target: str
    headers: dict[str, str]
    body: str


def _normalise_newlines(text: str) -> str:
    # Some mirrored CSIC files preserve CRLF as literal escape sequences.
    if "\\r\\n" in text and "\n" not in text.replace("\\r\\n", ""):
        text = text.replace("\\r\\n", "\n")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def parse_csic_requests(text: str) -> list[CsicRequest]:
    """Parse request blocks without assuming every file has perfect headers."""
    lines = _normalise_newlines(text).split("\n")
    requests: list[CsicRequest] = []
    index = 0
    while index < len(lines):
        match = REQUEST_LINE_RE.match(lines[index].strip())
        if not match:
            index += 1
            continue
        method, target = match.group(1).upper(), match.group(2)
        index += 1
        headers: dict[str, str] = {}
        while index < len(lines) and lines[index].strip():
            if ":" in lines[index]:
                key, value = lines[index].split(":", 1)
                headers[key.strip()] = value.strip()
            index += 1
        if index < len(lines) and not lines[index].strip():
            index += 1
        body_lines: list[str] = []
        while index < len(lines) and not REQUEST_LINE_RE.match(lines[index].strip()):
            if lines[index].strip():
                body_lines.append(lines[index])
            index += 1
        requests.append(CsicRequest(method, target, headers, "\n".join(body_lines).strip()))
    return requests


def request_payload_candidates(request: CsicRequest) -> list[str]:
    """Extract injectable values from query strings and form/JSON bodies."""
    values = [value for _, value in parse_qsl(urlsplit(request.target).query, keep_blank_values=True)]
    values.extend(value for _, value in parse_qsl(request.body, keep_blank_values=True))
    if request.body and not values:
        values.append(request.body)
    return [value for value in values if value and len(value) <= 4096]


def load_csic_payloads(csic_dir: str | Path, max_payloads: int | None = None) -> list[str]:
    """Load attack candidates from anomalous CSIC files only."""
    base = Path(csic_dir)
    if not base.exists():
        return []
    paths = sorted(path for path in base.rglob("*.txt") if "anomal" in path.name.lower())
    payloads: list[str] = []
    seen: set[str] = set()
    for path in paths:
        try:
            entries = parse_csic_requests(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for entry in entries:
            for payload in request_payload_candidates(entry):
                if payload not in seen:
                    seen.add(payload)
                    payloads.append(payload)
                    if max_payloads and len(payloads) >= max_payloads:
                        return payloads
    return payloads
