"""Feature extraction for the WAAP traffic dataset."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, unquote_plus, urlsplit


SUSPICIOUS_RE = re.compile(
    r"--|;|<\s*script|\.\./|\bunion\b|\bor\s+1\s*=\s*1|'|%27",
    re.IGNORECASE,
)


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def request_body_to_text(body: Any) -> str:
    """Convert a request body to a stable, CSV-friendly string."""
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    if isinstance(body, str):
        return body
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), default=str)


def _body_values(body_text: str) -> list[str]:
    """Get JSON/form values where possible, for param_max_length."""
    if not body_text:
        return []
    try:
        parsed = json.loads(body_text)
        if isinstance(parsed, dict):
            return [str(value) for value in parsed.values()]
    except json.JSONDecodeError:
        pass
    return [value for _, value in parse_qsl(body_text, keep_blank_values=True)]


def extract_features(url: str, body: Any) -> dict[str, Any]:
    """Extract request-only features; response fields are added by the agent."""
    body_text = request_body_to_text(body)
    query_values = [value for _, value in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    values = query_values + _body_values(body_text)
    feature_text = f"{url}{body_text}"
    decoded_text = unquote_plus(feature_text)
    special_count = sum(1 for char in feature_text if not char.isalnum())

    return {
        "url_length": len(url),
        "body_length": len(body_text),
        "entropy": round(shannon_entropy(feature_text), 6),
        "n_params": len(query_values),
        "has_suspicious_chars": bool(
            SUSPICIOUS_RE.search(feature_text) or SUSPICIOUS_RE.search(decoded_text)
        ),
        "param_max_length": max((len(value) for value in values), default=0),
        "special_char_ratio": round(special_count / len(feature_text), 6)
        if feature_text
        else 0.0,
    }
