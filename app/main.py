import json
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.errors import AppError
from app.programs import catalog
from app.settings import DATA_DIR, LOOPBACK_HOSTS, SINGBOX_BIN, UI_HOST, UI_PORT
from app.supervisor import Supervisor

STATIC_DIR = Path(__file__).resolve().parent / "static"
BODY_LIMIT = 64 * 1024


def main() -> None:
    if UI_HOST not in LOOPBACK_HOSTS:
        raise SystemExit("OUTLINE_UI_HOST must be a loopback address")
    supervisor = Supervisor(DATA_DIR, SINGBOX_BIN)
    supervisor.restore()
    server = ThreadingHTTPServer((UI_HOST, UI_PORT), _handler(supervisor))
    server.daemon_threads = True

    def _stop(signum, _frame) -> None:
        supervisor.shutdown()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"listening on http://{UI_HOST}:{UI_PORT}", flush=True)
    try:
        server.serve_forever()
    finally:
        supervisor.shutdown()
        server.server_close()


def _handler(supervisor: Supervisor):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/api/state":
                self._json(200, supervisor.status())
                return
            if path == "/api/catalog":
                self._json(200, {"applications": catalog()})
                return
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/":
                self._file(STATIC_DIR / "index.html")
                return
            if path.startswith("/static/"):
                relative = path.removeprefix("/static/")
                target = (STATIC_DIR / relative).resolve()
                if target.is_relative_to(STATIC_DIR.resolve()) and target.is_file():
                    self._file(target)
                    return
            self._json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            try:
                payload = self._body()
                if path == "/api/apply":
                    result = supervisor.apply(
                        payload.get("key", ""),
                        payload.get("ips", []),
                        payload.get("apps") if "apps" in payload else None,
                        payload.get("all_traffic") if "all_traffic" in payload else None,
                        domains=payload.get("domains") if "domains" in payload else None,
                    )
                    self._json(200, result)
                    return
                if path == "/api/stop":
                    self._json(200, supervisor.stop())
                    return
                self._json(404, {"error": "Not found"})
            except AppError as exc:
                self._json(400, {"error": str(exc)})
            except Exception:
                self._json(500, {"error": "Internal error"})

        def log_message(self, fmt: str, *args) -> None:
            print(f"[{self.address_string()}] {fmt % args}", flush=True)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0 or length > BODY_LIMIT:
                raise AppError("Request is too large")
            raw = self.rfile.read(length) if length else b""
            if not raw:
                return {}
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise AppError("Request is not valid JSON") from exc
            if not isinstance(data, dict):
                raise AppError("Expected a JSON object")
            return data

        def _json(self, code: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path) -> None:
            data = path.read_bytes()
            kind = {
                ".html": "text/html; charset=utf-8",
                ".css": "text/css; charset=utf-8",
                ".js": "text/javascript; charset=utf-8",
            }.get(path.suffix, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

    return Handler
