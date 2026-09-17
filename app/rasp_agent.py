"""RASP agent: in-process guards for sensitive runtime operations (Fase 4).

Unlike the perimeter WAF/WAAP, a RASP is embedded in the application process, so
it observes the *final* value that is about to be executed (the concatenated SQL
query, the resolved file path, the decoded serialized payload) after every
decoding/normalization step that happened inside the application.

The agent is deliberately framework-agnostic: guards raise :class:`RaspBlocked`
and the web framework translates that into an HTTP 403 response.
"""

from __future__ import annotations

import base64
import functools
import html
import os
import re
import time
from typing import Callable, Iterable, Pattern
from urllib.parse import unquote_plus

import _path  # noqa: F401  (adds the repository root to sys.path)
from observability.logger import log_event


class RaspBlocked(Exception):
    """Raised when a RASP guard blocks a dangerous runtime operation."""

    def __init__(self, event: str, detail: str, matched_rule: str | None = None) -> None:
        super().__init__(detail)
        self.event = event
        self.detail = detail
        self.matched_rule = matched_rule


PatternRule = tuple[str, Pattern[str]]

SQLI_RULES: list[PatternRule] = [
    ("union_select", re.compile(r"\bunion\b\s+(?:all\s+)?\bselect\b", re.IGNORECASE)),
    ("numeric_tautology", re.compile(r"\b(?:or|and)\b\s+\d+\s*=\s*\d+", re.IGNORECASE)),
    ("string_tautology", re.compile(r"\b(?:or|and)\b\s+'[^']*'\s*=\s*'[^']*'", re.IGNORECASE)),
    ("sql_comment", re.compile(r"['\"]\s*(?:--|#|/\*)")),
    ("stacked_query", re.compile(r";\s*(?:drop|delete|insert|update|alter|exec|shutdown)\b", re.IGNORECASE)),
    ("time_based", re.compile(r"\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", re.IGNORECASE)),
    ("metadata_probe", re.compile(r"\binformation_schema\b", re.IGNORECASE)),
    ("system_table", re.compile(r"\b(?:sqlite_master|sysobjects|pg_catalog)\b", re.IGNORECASE)),
]

XSS_RULES: list[PatternRule] = [
    ("script_tag", re.compile(r"<\s*script\b", re.IGNORECASE)),
    ("event_handler", re.compile(r"\bon(?:error|load|click|mouseover|focus)\s*=", re.IGNORECASE)),
    ("javascript_uri", re.compile(r"javascript\s*:", re.IGNORECASE)),
    ("svg_payload", re.compile(r"<\s*svg\b[^>]*\bon\w+\s*=", re.IGNORECASE)),
    ("img_payload", re.compile(r"<\s*img\b[^>]*\bsrc\s*=\s*[\"']?javascript", re.IGNORECASE)),
]

PATH_RULES: list[PatternRule] = [
    ("path_traversal", re.compile(r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|\\)|\.\.%2f)", re.IGNORECASE)),
    ("absolute_path", re.compile(r"(?:^|[\"'\s])(?:/etc/|/proc/|/root/|[a-z]:\\+windows)", re.IGNORECASE)),
    ("null_byte", re.compile(r"%00|\x00")),
]

DESERIALIZE_RULES: list[PatternRule] = [
    ("python_pickle_opcode", re.compile(r"(?:gASV|gAJ|!!python|__reduce__)", re.IGNORECASE)),
    ("command_execution", re.compile(r"\b(?:os\.system|subprocess|popen|runtime\.exec|eval)\b", re.IGNORECASE)),
    ("java_gadget", re.compile(r"(?:java\.io\.|org\.apache\.commons\.collections|ysoserial)", re.IGNORECASE)),
]


def rasp_enabled() -> bool:
    """Whether guards are active; toggled with the ``RASP_ENABLED`` env var."""
    return os.environ.get("RASP_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def decode_deep(value: str, rounds: int = 3) -> str:
    """Undo stacked URL-encoding and HTML entities.

    A perimeter WAF usually decodes a single layer, which is exactly what lets a
    double-encoded payload slip through. The RASP sees the value already inside
    the application, so it can normalize every layer before matching.
    """
    current = html.unescape(value)
    for _ in range(rounds):
        decoded = html.unescape(unquote_plus(current))
        if decoded == current:
            break
        current = decoded
    return current


def match_rules(text: str, rules: Iterable[PatternRule]) -> tuple[str, str] | None:
    """Return ``(rule_name, matched_text)`` for the first matching rule."""
    for name, pattern in rules:
        match = pattern.search(text)
        if match:
            return name, match.group(0)
    return None


def _block(event: str, target: str, rule: str, matched: str, inspected: str, started: float, **extra: object) -> None:
    elapsed_ms = round((time.perf_counter() - started) * 1000, 4)
    log_event(
        "rasp",
        "block",
        event,
        target=target,
        matched_rule=rule,
        matched_text=matched,
        inspected=inspected,
        guard_ms=elapsed_ms,
        **extra,
    )
    raise RaspBlocked(event, f"{event} bloqueado por RASP (regla {rule})", rule)


def _allow(event: str, target: str, started: float, inspected: str, **extra: object) -> None:
    elapsed_ms = round((time.perf_counter() - started) * 1000, 4)
    log_event(
        "rasp",
        "allow",
        event,
        target=target,
        inspected=inspected,
        guard_ms=elapsed_ms,
        **extra,
    )


def rasp_guard_query(builder: Callable[..., str]) -> Callable[..., str]:
    """Inspect the *final* SQL query returned by ``builder`` before execution."""

    @functools.wraps(builder)
    def wrapper(*args: object, **kwargs: object) -> str:
        query = builder(*args, **kwargs)
        if not rasp_enabled():
            return query
        started = time.perf_counter()
        normalized = decode_deep(str(query))
        hit = match_rules(normalized, SQLI_RULES)
        if hit:
            _block("sql_injection", builder.__name__, hit[0], hit[1], str(query), started)
        _allow("sql_injection_check", builder.__name__, started, str(query))
        return query

    return wrapper


def rasp_guard_output(renderer: Callable[..., str]) -> Callable[..., str]:
    """Inspect a value that is about to be reflected into an HTML response."""

    @functools.wraps(renderer)
    def wrapper(*args: object, **kwargs: object) -> str:
        if not rasp_enabled():
            return renderer(*args, **kwargs)
        started = time.perf_counter()
        inspected = " ".join(decode_deep(str(value)) for value in list(args) + list(kwargs.values()))
        hit = match_rules(inspected, XSS_RULES)
        if hit:
            _block("xss", renderer.__name__, hit[0], hit[1], inspected, started)
        _allow("xss_check", renderer.__name__, started, inspected)
        return renderer(*args, **kwargs)

    return wrapper


def rasp_guard_path(reader: Callable[..., str]) -> Callable[..., str]:
    """Inspect the requested path before the file is actually opened."""

    @functools.wraps(reader)
    def wrapper(path: str, *args: object, **kwargs: object) -> str:
        if not rasp_enabled():
            return reader(path, *args, **kwargs)
        started = time.perf_counter()
        normalized = decode_deep(str(path))
        hit = match_rules(normalized, PATH_RULES)
        if hit:
            _block("path_traversal", reader.__name__, hit[0], hit[1], normalized, started)
        _allow("path_check", reader.__name__, started, normalized)
        return reader(path, *args, **kwargs)

    return wrapper


def rasp_guard_deserialize(loader: Callable[..., object]) -> Callable[..., object]:
    """Decode and inspect a serialized blob before it is deserialized."""

    @functools.wraps(loader)
    def wrapper(blob: str, *args: object, **kwargs: object) -> object:
        if not rasp_enabled():
            return loader(blob, *args, **kwargs)
        started = time.perf_counter()
        decoded = decode_deep(str(blob))
        try:
            decoded = base64.b64decode(decoded, validate=False).decode("utf-8", "replace")
        except (ValueError, UnicodeDecodeError):
            pass
        hit = match_rules(decoded, DESERIALIZE_RULES)
        if hit:
            _block("deserialization", loader.__name__, hit[0], hit[1], decoded, started)
        _allow("deserialization_check", loader.__name__, started, decoded)
        return loader(blob, *args, **kwargs)

    return wrapper
