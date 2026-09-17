"""Deliberately vulnerable Flask application instrumented with a RASP agent.

This is the controlled target for Fase 4. It mimics the Juice Shop surfaces that
were exploited in Fase 1 (SQL injection in login, reflected search terms, path
access, deserialization) but runs as a small Python process so the in-process
RASP middleware from :mod:`rasp_agent` can be demonstrated end to end.

Nothing here is exposed outside the local laboratory.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import threading
from urllib.parse import unquote

import _path  # noqa: F401  (adds the repository root to sys.path)
from flask import Flask, Response, jsonify, request

from observability.logger import log_event, new_request_id, set_request_id
from rasp_agent import (
    RaspBlocked,
    rasp_guard_deserialize,
    rasp_guard_output,
    rasp_guard_path,
    rasp_guard_query,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DOCUMENTS_DIR = os.path.join(APP_DIR, "documents")
DB_LOCK = threading.Lock()


def _init_db() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.executescript(
        """
        CREATE TABLE users (
            email TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE products (name TEXT NOT NULL, price REAL NOT NULL);
        INSERT INTO users VALUES ('admin@juice-sh.op', 'admin123', 'admin');
        INSERT INTO users VALUES ('test@test.com', 'test123', 'customer');
        INSERT INTO products VALUES ('apple juice', 2.0);
        INSERT INTO products VALUES ('banana juice', 2.5);
        INSERT INTO products VALUES ('coffee', 3.0);
        """
    )
    connection.commit()
    return connection


DB = _init_db()


# --- Sensitive operations wrapped by the RASP agent -------------------------

@rasp_guard_query
def build_login_query(email: str, password: str) -> str:
    """Vulnerable string-concatenated query; RASP inspects the final result."""
    return f"SELECT email, role FROM users WHERE email = '{email}' AND password = '{password}'"


@rasp_guard_query
def build_search_query(term: str, extra: str) -> str:
    """Two independent query parameters concatenated into a single query."""
    return f"SELECT name FROM products WHERE name LIKE '%{term}{extra}%'"


@rasp_guard_output
def render_search_term(term: str) -> str:
    """Reflects a user-controlled value into HTML without escaping."""
    return f"<h1>Resultados para: {term}</h1>"


@rasp_guard_path
def read_document(name: str) -> str:
    with open(os.path.join(DOCUMENTS_DIR, name), encoding="utf-8") as handle:
        return handle.read()


@rasp_guard_deserialize
def load_object(blob: str) -> object:
    """Academic simulation: decode base64 into a JSON envelope (no real pickle)."""
    import json

    raw = base64.b64decode(blob).decode("utf-8", "replace")
    return json.loads(raw)


def create_app(rasp_enabled: bool = True) -> Flask:
    os.environ["RASP_ENABLED"] = "true" if rasp_enabled else "false"
    os.makedirs(DOCUMENTS_DIR, exist_ok=True)

    app = Flask(__name__)

    @app.before_request
    def _assign_request_id() -> None:
        set_request_id(new_request_id())

    @app.errorhandler(RaspBlocked)
    def _handle_rasp_block(error: RaspBlocked) -> tuple[Response, int]:
        return (
            jsonify(
                error="Operación bloqueada por RASP",
                event=error.event,
                matched_rule=error.matched_rule,
            ),
            403,
        )

    @app.get("/api/health")
    def health() -> Response:
        return jsonify(status="ok", rasp=os.environ.get("RASP_ENABLED"))

    @app.post("/rest/user/login")
    def login() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", ""))
        password = str(data.get("password", ""))
        query = build_login_query(email, password)
        try:
            with DB_LOCK:
                rows = DB.execute(query).fetchall()
        except sqlite3.Error as error:
            return jsonify(error="query error", detail=str(error)), 400
        if not rows:
            return jsonify(error="Invalid credentials"), 401
        log_event("app", "allow", "login_success", user=rows[0][0], method="POST", path="/rest/user/login")
        return jsonify(
            authentication={
                "token": f"lab-token-{rows[0][0]}",
                "umail": rows[0][0],
                "role": rows[0][1],
            }
        ), 200

    @app.get("/api/Products/search")
    def search() -> tuple[Response, int]:
        term = request.args.get("q", "")
        extra = request.args.get("extra", "")
        query = build_search_query(term, extra)
        try:
            with DB_LOCK:
                rows = DB.execute(query).fetchall()
        except sqlite3.Error as error:
            return jsonify(error="query error", detail=str(error)), 400
        return jsonify(query=query, count=len(rows), results=[row[0] for row in rows]), 200

    @app.get("/rest/products/render")
    def render() -> Response:
        # The application decodes its input once more before reflecting it; this
        # is what turns a double-encoded payload that the WAF ignored into XSS.
        html = render_search_term(unquote(request.args.get("q", "")))
        return Response(html, mimetype="text/html")

    @app.get("/api/files")
    def files() -> tuple[Response, int]:
        try:
            content = read_document(request.args.get("name", ""))
        except OSError as error:
            return jsonify(error="file not found", detail=str(error)), 404
        return jsonify(content=content), 200

    @app.post("/api/deserialize")
    def deserialize() -> tuple[Response, int]:
        data = request.get_json(silent=True) or {}
        try:
            obj = load_object(str(data.get("blob", "")))
        except (ValueError, UnicodeDecodeError) as error:
            return jsonify(error="invalid blob", detail=str(error)), 400
        return jsonify(object=obj), 200

    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    create_app(rasp_enabled=True).run(host="127.0.0.1", port=port)
