"""Unified JSON-lines logger shared by the WAF, ML and RASP layers.

Every security event is written as a single JSON object per line so the Fase 7
metrics collector can aggregate detections without parsing free-form text.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
_REQUEST_ID: ContextVar[str | None] = ContextVar("request_id", default=None)

EVENT_FIELDS = ("timestamp", "layer", "verdict", "event")


def log_dir() -> Path:
    """Directory where structured events are stored."""
    default = Path(__file__).resolve().parent.parent / "logs"
    return Path(os.environ.get("WAAP_LOG_DIR", default))


def events_path() -> Path:
    """Full path of the unified JSON-lines event file."""
    return Path(os.environ.get("WAAP_EVENTS_FILE", log_dir() / "waap_events.jsonl"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]


def set_request_id(request_id: str) -> None:
    _REQUEST_ID.set(request_id)


def get_request_id() -> str | None:
    return _REQUEST_ID.get()


def log_event(layer: str, verdict: str, event: str, **fields: Any) -> dict[str, Any]:
    """Append one structured event and return the record that was written.

    ``layer`` is one of ``waf``/``ml``/``rasp``/``orchestrator`` and ``verdict``
    is one of ``allow``/``block``/``alert``. Any additional keyword argument is
    stored as-is; ``None`` values are dropped to keep the JSON small.
    """
    record: dict[str, Any] = {
        "timestamp": now_iso(),
        "layer": layer,
        "verdict": verdict,
        "event": event,
    }
    request_id = get_request_id()
    if request_id:
        record["request_id"] = request_id
    record.update({key: value for key, value in fields.items() if value is not None})

    path = events_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    return record


class Timer:
    """Context manager that measures elapsed milliseconds."""

    def __init__(self) -> None:
        self.elapsed_ms = 0.0
        self._start = 0.0

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.elapsed_ms = round((time.perf_counter() - self._start) * 1000, 4)
