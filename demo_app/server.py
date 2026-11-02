from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).parent
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.test", "role": "member"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.test", "role": "member"},
    99: {"id": 99, "name": "Ada Admin", "email": "admin@example.test", "role": "admin"},
}
TOKENS = {"alice-token": 1, "bob-token": 2, "admin-token": 99}


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "HiddenApiDemo/0.1"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[demo] {self.address_string()} - {format % args}")

    def _identity(self) -> dict | None:
        header = self.headers.get("Authorization", "")
        token = header.removeprefix("Bearer ") if header.startswith("Bearer ") else ""
        user_id = TOKENS.get(token)
        return USERS.get(user_id) if user_id else None

    def _json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _file(self, content_type: str, path: Path) -> None:
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlparse(self.path).path

        if path == "/":
            body = b"""<!doctype html><html><head><title>Account Portal</title></head>
<body><h1>Account Portal</h1><p>An ordinary local demo application.</p>
<script src='/app.js'></script></body></html>"""
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/app.js":
            self._file("application/javascript", ROOT / "static" / "app.js")
            return
        if path == "/openapi.json":
            self._file("application/json", ROOT / "openapi.json")
            return
        if path == "/api/catalog":
            self._json(HTTPStatus.OK, {"items": [{"id": "starter", "name": "Starter plan"}]})
            return

        identity = self._identity()
        if path == "/api/me":
            if not identity:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
            else:
                self._json(HTTPStatus.OK, identity)
            return

        if path.startswith("/api/users/"):
            if not identity:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            try:
                requested_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid user id"})
                return
            user = USERS.get(requested_id)
            if not user:
                self._json(HTTPStatus.NOT_FOUND, {"error": "user not found"})
                return
            # Intentional BOLA: membership is checked, ownership is not.
            self._json(HTTPStatus.OK, user)
            return

        if path == "/api/admin/audit":
            if not identity:
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            # Intentional BFLA: authenticated members are accepted without an admin check.
            self._json(
                HTTPStatus.OK,
                {"events": [{"actor": "system", "action": "demo-started"}], "scope": "admin"},
            )
            return

        if path == "/api/debug/config":
            # Intentional exposure: undocumented debug information is public.
            self._json(
                HTTPStatus.OK,
                {"environment": "training", "features": ["audit-v2"], "secret": "demo-only"},
            )
            return

        self._json(HTTPStatus.NOT_FOUND, {"error": "route not found"})


def create_server(host: str = "127.0.0.1", port: int = 8001) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), DemoHandler)


def main() -> None:
    server = create_server()
    print("Deliberately vulnerable demo listening on http://127.0.0.1:8001")
    print("Use only for authorized local training. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

