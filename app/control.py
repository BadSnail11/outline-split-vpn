import json
import os
import pwd
import socket
import threading
from pathlib import Path

from app.errors import AppError
from app.programs import catalog


def request(payload: dict, socket_path: Path, timeout: float = 30) -> dict:
    data = json.dumps(payload).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout)
        client.connect(str(socket_path))
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


def serve(supervisor, socket_path: Path, stop: threading.Event) -> None:
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.parent.name == "outline-split":
        os.chmod(socket_path.parent, 0o755)
    if _alive(socket_path):
        raise SystemExit("The tunnel service is already running")
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    uid = int(os.environ.get("PKEXEC_UID") or os.geteuid())
    gid = pwd.getpwuid(uid).pw_gid
    os.chown(socket_path, uid, gid)
    os.chmod(socket_path, 0o600)
    server.listen(8)
    server.settimeout(0.5)
    try:
        while not stop.is_set():
            try:
                connection, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=_handle, args=(supervisor, connection), daemon=True).start()
    finally:
        server.close()
        socket_path.unlink(missing_ok=True)


def _handle(supervisor, connection: socket.socket) -> None:
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
            result = _dispatch(supervisor, payload)
        except AppError as exc:
            result = {"error": str(exc)}
        except Exception:
            result = {"error": "Internal error"}
        connection.sendall(json.dumps(result).encode("utf-8") + b"\n")


def _dispatch(supervisor, payload: dict) -> dict:
    cmd = payload.get("cmd")
    if cmd == "status":
        return supervisor.status()
    if cmd == "catalog":
        return {"applications": catalog()}
    if cmd == "stop":
        return supervisor.stop()
    if cmd == "apply":
        start = payload.get("start", True)
        if not isinstance(start, bool):
            raise AppError("Start must be true or false")
        return supervisor.apply(
            payload.get("key", ""),
            payload.get("ips", []),
            payload.get("apps") if "apps" in payload else None,
            payload.get("all_traffic") if "all_traffic" in payload else None,
            start=start,
            select=payload.get("select") if isinstance(payload.get("select"), str) else None,
            domains=payload.get("domains") if "domains" in payload else None,
        )
    if cmd == "add":
        return supervisor.add_key(payload.get("key", ""))
    if cmd == "vpnbook":
        return supervisor.import_vpnbook()
    if cmd == "select":
        return supervisor.select_key(payload.get("id", ""))
    if cmd == "remove":
        return supervisor.remove_key(payload.get("id", ""))
    raise AppError("Unknown command")


def _alive(socket_path: Path) -> bool:
    if not socket_path.exists():
        return False
    try:
        request({"cmd": "status"}, socket_path, timeout=1)
    except OSError:
        return False
    return True
