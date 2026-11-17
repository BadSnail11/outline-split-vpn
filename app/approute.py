import ctypes
import ipaddress
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from app.errors import AppError
from app.programs import matching_pids
from app.settings import APP_MARK, APP_RULE_PRIORITY, APP_TABLE, CGROUP_NAME, TUN_INTERFACE

CGROUP_DIR = Path("/sys/fs/cgroup") / CGROUP_NAME
NFT_TABLE = "outline_split"


class AppRouter:
    """Send every non-local packet from selected programs into the tunnel."""

    def __init__(self) -> None:
        self.attached = 0
        self._programs: list[dict] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, programs: list[dict], server_ips: list[str]) -> None:
        self.close()
        try:
            join_host_cgroup_namespace()
            ensure_cgroup()
            wait_for_interface()
            install_nft(server_ips)
            install_policy_routes()
        except Exception:
            self.close()
            raise
        self._programs = programs
        self._stop.clear()
        self.attached = attach_programs(programs)
        self._thread = threading.Thread(target=self._watch, name="app-route", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3)
        remove_policy_routes()
        remove_nft()
        self.attached = 0

    def _watch(self) -> None:
        while not self._stop.wait(1):
            self.attached = attach_programs(self._programs)


def join_host_cgroup_namespace() -> None:
    """nft cgroup matches are relative to the caller's cgroup namespace."""
    try:
        fd = os.open("/proc/1/ns/cgroup", os.O_RDONLY)
    except OSError as exc:
        raise AppError(
            "Could not reach the host cgroup namespace. Recreate the container with docker-compose."
        ) from exc
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.setns.argtypes = [ctypes.c_int, ctypes.c_int]
        libc.setns.restype = ctypes.c_int
        if libc.setns(fd, 0x02000000) != 0:
            raise AppError(
                f"Could not join the host cgroup namespace: {os.strerror(ctypes.get_errno())}"
            )
    finally:
        os.close(fd)


def ensure_cgroup() -> None:
    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").is_file():
        raise AppError("cgroup v2 is not available, so applications cannot be routed separately.")
    try:
        CGROUP_DIR.mkdir(exist_ok=True)
    except OSError as exc:
        raise AppError(
            "Could not create the application cgroup. Start the app with docker compose so it can manage host cgroups."
        ) from exc


def wait_for_interface(timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    path = Path(f"/sys/class/net/{TUN_INTERFACE}")
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise AppError(f"Tunnel interface {TUN_INTERFACE} did not appear.")


def install_nft(server_ips: list[str]) -> None:
    rules = nft_ruleset(server_ips)
    handle = tempfile.NamedTemporaryFile("w", prefix="outline-split-", suffix=".nft", delete=False)
    try:
        handle.write(rules)
        handle.close()
        os.chmod(handle.name, 0o600)
        remove_nft()
        result = subprocess.run(
            ["nft", "-f", handle.name],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(handle.name).unlink(missing_ok=True)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "nft failed").strip()
        raise AppError(detail[:500])


def remove_nft() -> None:
    subprocess.run(
        ["nft", "delete", "table", "inet", NFT_TABLE],
        capture_output=True,
        text=True,
        check=False,
    )


def install_policy_routes() -> None:
    commands = [
        ["ip", "route", "replace", "default", "dev", TUN_INTERFACE, "table", str(APP_TABLE)],
        ["ip", "rule", "del", "fwmark", str(APP_MARK), "lookup", str(APP_TABLE)],
        ["ip", "rule", "add", "fwmark", str(APP_MARK), "lookup", str(APP_TABLE), "priority", str(APP_RULE_PRIORITY)],
        ["ip", "-6", "route", "replace", "default", "dev", TUN_INTERFACE, "table", str(APP_TABLE)],
        ["ip", "-6", "rule", "del", "fwmark", str(APP_MARK), "lookup", str(APP_TABLE)],
        ["ip", "-6", "rule", "add", "fwmark", str(APP_MARK), "lookup", str(APP_TABLE), "priority", str(APP_RULE_PRIORITY)],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        required = index in {0, 2}
        if required and result.returncode != 0:
            detail = (result.stderr or result.stdout or "ip rule failed").strip()
            raise AppError(detail[:500])


def remove_policy_routes() -> None:
    for command in (
        ["ip", "rule", "del", "fwmark", str(APP_MARK), "lookup", str(APP_TABLE)],
        ["ip", "-6", "rule", "del", "fwmark", str(APP_MARK), "lookup", str(APP_TABLE)],
        ["ip", "route", "flush", "table", str(APP_TABLE)],
        ["ip", "-6", "route", "flush", "table", str(APP_TABLE)],
    ):
        subprocess.run(command, capture_output=True, text=True, check=False)


def attach_programs(programs: list[dict], proc_root: Path = Path("/proc"), cgroup: Path = CGROUP_DIR) -> int:
    procs = cgroup / "cgroup.procs"
    count = 0
    for pid in matching_pids(programs, proc_root):
        try:
            procs.write_text(str(pid), encoding="ascii")
        except OSError:
            continue
        count += 1
    return count


def nft_ruleset(server_ips: list[str]) -> str:
    v4 = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
    ]
    v6 = ["::1/128", "fe80::/10", "fc00::/7", "ff00::/8"]
    for raw in server_ips:
        address = ipaddress.ip_address(raw.split("%", 1)[0])
        if address.version == 4:
            v4.append(f"{address}/32")
        else:
            v6.append(f"{address}/128")
    return (
        f"table inet {NFT_TABLE} {{\n"
        "  set skip4 {\n"
        "    type ipv4_addr\n"
        "    flags interval\n"
        f"    elements = {{ {', '.join(v4)} }}\n"
        "  }\n"
        "  set skip6 {\n"
        "    type ipv6_addr\n"
        "    flags interval\n"
        f"    elements = {{ {', '.join(v6)} }}\n"
        "  }\n"
        "  chain output {\n"
        "    type route hook output priority mangle; policy accept;\n"
        f'    socket cgroupv2 level 1 "{CGROUP_NAME}" ip daddr @skip4 return\n'
        f'    socket cgroupv2 level 1 "{CGROUP_NAME}" ip6 daddr @skip6 return\n'
        f'    socket cgroupv2 level 1 "{CGROUP_NAME}" meta mark set {APP_MARK}\n'
        "  }\n"
        "}\n"
    )
