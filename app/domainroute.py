import json
import subprocess
from pathlib import Path

from app.approute import wait_for_interface
from app.errors import AppError
from app.settings import TUN_DNS

SAVE_PATH = Path("/run/outline-split/dns.json")


class DomainNat:
    """Point system DNS at the tunnel so listed domains can be recognized by name."""

    def peek(self) -> str:
        """Return the DNS server to use for names that stay off the tunnel."""
        self.close()
        servers = _upstream_servers(_read_status())
        return servers[0] if servers else "1.1.1.1"

    def start(self) -> None:
        self.close()
        wait_for_interface()
        links = _default_links(_read_status())
        if not links:
            raise AppError("systemd-resolved has no DNS server, so domains cannot be routed.")
        SAVE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SAVE_PATH.write_text(json.dumps(links), encoding="utf-8")
        SAVE_PATH.chmod(0o600)
        for link in links:
            _run(["resolvectl", "dns", link["name"], TUN_DNS])
        _run(["resolvectl", "flush-caches"])

    def close(self) -> None:
        if not SAVE_PATH.is_file():
            return
        try:
            links = json.loads(SAVE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            links = []
        for link in links:
            servers = [item for item in link.get("servers", []) if item and item != TUN_DNS]
            if servers:
                _run(["resolvectl", "dns", link["name"], *servers])
        _run(["resolvectl", "flush-caches"])
        SAVE_PATH.unlink(missing_ok=True)


def _read_status() -> str:
    result = subprocess.run(["resolvectl", "status"], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "resolvectl failed").strip()
        raise AppError(detail[:300] or "systemd-resolved is not available, so domains cannot be routed.")
    return result.stdout


def _default_links(text: str) -> list[dict]:
    links = _parse_links(text)
    chosen = [link for link in links if link["default"] and link["servers"]]
    if not chosen:
        chosen = [link for link in links if link["servers"]]
    return [{"name": link["name"], "servers": link["servers"]} for link in chosen]


def _upstream_servers(text: str) -> list[str]:
    servers: list[str] = []
    for link in _default_links(text):
        for server in link["servers"]:
            if server not in servers and _usable(server):
                servers.append(server)
    return servers


def _parse_links(text: str) -> list[dict]:
    links: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if raw.startswith("Link ") and "(" in raw and raw.endswith(")"):
            current = {"name": raw.split("(", 1)[1][:-1], "default": False, "servers": []}
            links.append(current)
            continue
        if current is None:
            continue
        if line.startswith("Protocols:") and "+DefaultRoute" in line:
            current["default"] = True
        elif line.startswith("DNS Servers:"):
            current["servers"] = [item for item in line.split()[2:] if item != "--"]
    return links


def _usable(value: str) -> bool:
    if not _ipv4(value) or value == TUN_DNS or value.startswith("127.") or value.startswith("169.254."):
        return False
    return True


def _ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _run(command: list[str]) -> None:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "resolvectl failed").strip()
        raise AppError(detail[:300])
