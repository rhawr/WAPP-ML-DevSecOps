"""Realistic, low-rate Juice Shop navigation request generator."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36",
]
SEARCH_TERMS = ["apple", "juice", "banana", "water", "coffee", "chocolate", "milk", "tea", "lemon", "bread"]


@dataclass(frozen=True)
class RequestSpec:
    method: str
    path: str
    params: dict[str, str] | None = None
    json: dict[str, Any] | None = None
    source: str = "generated"
    is_burst: bool = False


def normal_request(rng: random.Random) -> RequestSpec:
    """Choose one ordinary browser-like Juice Shop action."""
    option = rng.choice(["search", "products", "detail", "login", "basket", "feedback", "home"])
    if option == "search":
        return RequestSpec("GET", "/rest/products/search", {"q": rng.choice(SEARCH_TERMS)})
    if option == "products":
        return RequestSpec("GET", "/api/Products")
    if option == "detail":
        return RequestSpec("GET", f"/api/Products/{rng.randint(1, 35)}")
    if option == "login":
        return RequestSpec("POST", "/rest/user/login", json={"email": "test@test.com", "password": "test123"})
    if option == "basket":
        return RequestSpec("GET", f"/rest/basket/{rng.randint(1, 10)}")
    if option == "feedback":
        return RequestSpec("GET", "/api/Feedbacks")
    return RequestSpec("GET", "/")
