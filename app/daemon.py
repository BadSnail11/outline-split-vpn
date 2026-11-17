import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("OUTLINE_DATA", str(ROOT / "data"))
os.environ.setdefault("SINGBOX_BIN", str(ROOT / "bin" / "sing-box"))

from app.control import request, serve
from app.settings import DATA_DIR, SINGBOX_BIN, SOCKET_PATH
from app.supervisor import Supervisor


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("The tunnel service needs administrator rights. Start it from the Outline split window.")
    _replace_stale_service()
    _stop_docker_app()
    supervisor = Supervisor(DATA_DIR, SINGBOX_BIN)
    supervisor.restore()
    stop = threading.Event()

    def _stop(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"tunnel service listening on {SOCKET_PATH}", flush=True)
    try:
        serve(supervisor, SOCKET_PATH, stop)
    finally:
        supervisor.shutdown()


def _replace_stale_service() -> None:
    """Stop a service started before several keys could be saved."""
    if not SOCKET_PATH.exists():
        return
    try:
        current = request({"cmd": "status"}, SOCKET_PATH, timeout=2)
    except OSError:
        SOCKET_PATH.unlink(missing_ok=True)
        return
    if "keys" in current:
        return
    for pid in _service_pids():
        if pid == os.getpid():
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            continue
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and SOCKET_PATH.exists():
        try:
            request({"cmd": "status"}, SOCKET_PATH, timeout=0.5)
        except OSError:
            break
        time.sleep(0.1)
    SOCKET_PATH.unlink(missing_ok=True)


def _service_pids() -> list[int]:
    inode = ""
    try:
        lines = Path("/proc/net/unix").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in lines:
        parts = line.split()
        if parts and parts[-1] == str(SOCKET_PATH):
            inode = parts[-2]
            break
    found: list[int] = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        pid = int(proc.name)
        try:
            command = (proc / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "app/daemon.py" in command:
            found.append(pid)
            continue
        if not inode:
            continue
        fd_dir = proc / "fd"
        try:
            descriptors = list(fd_dir.iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target == f"socket:[{inode}]":
                found.append(pid)
                break
    return found


def _stop_docker_app() -> None:
    """The container uses the same tunnel name. Stop it before this service creates outline0."""
    docker = Path("/usr/bin/docker")
    if not docker.is_file():
        return
    subprocess.run(
        [str(docker), "stop", "outline-split"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=20,
        check=False,
    )


if __name__ == "__main__":
    main()
