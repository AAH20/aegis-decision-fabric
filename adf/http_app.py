from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from adf.api import FabricApp, default_app

ROOT = Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "openapi.yaml"


class GateProveHandler(BaseHTTPRequestHandler):
    app: FabricApp

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _json(self, code: int, payload: Any) -> None:
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid_json") from exc
        if not isinstance(data, dict):
            raise ValueError("json_object_required")
        return data

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/health":
            self._json(200, {"ok": True, "service": "aegis-decision-fabric"})
            return
        if path in {"/openapi.yaml", "/v1/openapi.yaml"}:
            body = OPENAPI.read_bytes() if OPENAPI.exists() else b"openapi: 3.0.3\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/yaml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/v1/ledger/"):
            key = path.split("/v1/ledger/", 1)[1]
            found = self.app.get_ledger(key)
            if found is None:
                self._json(404, {"error": "ledger_not_found"})
                return
            self._json(200, found)
            return
        if path == "/":
            self._json(
                200,
                {
                    "service": "aegis-decision-fabric",
                    "docs": "/openapi.yaml",
                    "consultation": "https://a2zsoc.com/consultation",
                },
            )
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        try:
            body = self._body()
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
            return
        if path == "/v1/decide":
            self._json(200, self.app.decide(body))
            return
        if path == "/v1/contain":
            try:
                self._json(200, self.app.contain(body))
            except KeyError:
                self._json(400, {"error": "event_or_alert_id_required"})
            return
        self._json(404, {"error": "not_found"})


def make_server(host: str, port: int, app: FabricApp | None = None) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (GateProveHandler,), {"app": app or default_app()})
    return ThreadingHTTPServer((host, port), handler)


def serve(host: str = "127.0.0.1", port: int = 8080, app: FabricApp | None = None) -> None:
    httpd = make_server(host, port, app=app)
    print(f"adf serve {host}:{port}  Gate/Prove  https://a2zsoc.com/consultation")
    httpd.serve_forever()
