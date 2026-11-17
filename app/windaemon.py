import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if len(sys.argv) > 1:
    os.environ["OUTLINE_DATA"] = sys.argv[1]
else:
    _local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    os.environ.setdefault("OUTLINE_DATA", str(Path(_local) / "outline-split"))
_bundled = ROOT / "bin" / "sing-box.exe"
if _bundled.is_file():
    os.environ.setdefault("SINGBOX_BIN", str(_bundled))

from app.settings import DATA_DIR, SINGBOX_BIN
from app.supervisor import Supervisor
from app.wincontrol import running, serve


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("This tunnel service is the Windows version.")
    if not _admin():
        raise SystemExit("Start Outline split from its window so Windows can ask for approval.")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    log_path = DATA_DIR / "service.log"
    log_handle = log_path.open("a", encoding="utf-8")
    os.dup2(log_handle.fileno(), 1)
    os.dup2(log_handle.fileno(), 2)
    if running():
        print("tunnel service already running", flush=True)
        return
    supervisor = Supervisor(DATA_DIR, SINGBOX_BIN)
    supervisor.restore()
    stop = threading.Event()

    def _stop(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, _stop)
    try:
        serve(supervisor, stop)
    finally:
        supervisor.shutdown()
        log_handle.close()


def _admin() -> bool:
    import ctypes

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


if __name__ == "__main__":
    main()
