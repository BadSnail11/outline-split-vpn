import hmac
import json
import secrets
import socket
import threading
from pathlib import Path

from app.control import _dispatch
from app.errors import AppError
from app.settings import DATA_DIR

SERVICE_FILE = DATA_DIR / "service.json"


def request(payload: dict, timeout: float = 30) -> dict:
    service = _read_service()
    message = dict(payload)
    message["token"] = service["token"]
    data = json.dumps(message).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(("127.0.0.1", service["port"]))
        client.sendall(data)
        chunks: list[bytes] = []
        while True:
            block = client.recv(65536)
            if not block:
                break
            chunks.append(block)
            if b"\n" in block:
                break
    raw = b"".join(chunks).split(b"\n", 1)[0]
    if not raw:
        raise AppError("The tunnel service closed the connection")
    try:
        result = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise AppError("The tunnel service sent an invalid reply") from exc
    if not isinstance(result, dict):
        raise AppError("The tunnel service sent an invalid reply")
    if "error" in result and "headline" not in result:
        raise AppError(str(result["error"]))
    return result


def running(timeout: float = 1) -> bool:
    try:
        request({"cmd": "status"}, timeout=timeout)
    except (OSError, AppError):
        return False
    return True


def serve(supervisor, stop: threading.Event) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(16)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    _write_service(port, token)
    server.listen(8)
    server.settimeout(0.5)
    print(f"tunnel service listening on 127.0.0.1:{port}", flush=True)
    try:
        while not stop.is_set():
            try:
                connection, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if address[0] != "127.0.0.1":
                connection.close()
                continue
            threading.Thread(
                target=_handle,
                args=(supervisor, connection, token, stop),
                daemon=True,
            ).start()
    finally:
        server.close()
        SERVICE_FILE.unlink(missing_ok=True)


def _handle(supervisor, connection: socket.socket, token: str, stop: threading.Event) -> None:
    with connection:
        connection.settimeout(30)
        raw = b""
        while b"\n" not in raw and len(raw) < 65536:
            block = connection.recv(65536)
            if not block:
                break
            raw += block
        line = raw.split(b"\n", 1)[0]
        try:
            payload = json.loads(line.decode("utf-8")) if line else {}
            if not isinstance(payload, dict):
                raise AppError("Expected a JSON object")
            given = payload.get("token", "")
            if not isinstance(given, str) or not hmac.compare_digest(given, token):
                raise AppError("The tunnel service rejected the request")
            if payload.get("cmd") == "quit":
                result = supervisor.stop()
                stop.set()
            else:
                result = _dispatch(supervisor, payload)
        except AppError as exc:
            result = {"error": str(exc)}
        except Exception:
            result = {"error": "Internal error"}
        try:
            connection.sendall(json.dumps(result).encode("utf-8") + b"\n")
        except OSError:
            return


def _read_service() -> dict:
    try:
        loaded = json.loads(SERVICE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AppError("The tunnel service is not running") from exc
    port = loaded.get("port") if isinstance(loaded, dict) else None
    token = loaded.get("token") if isinstance(loaded, dict) else None
    if not isinstance(port, int) or not isinstance(token, str) or not token:
        raise AppError("The tunnel service is not running")
    return {"port": port, "token": token}


def _write_service(port: int, token: str) -> None:
    path = SERVICE_FILE
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"port": port, "token": token}) + "\n", encoding="utf-8")
    tmp.replace(path)
    path.chmod(0o600)


def service_file() -> Path:
    return SERVICE_FILE
