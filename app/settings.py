import os
from pathlib import Path

UI_HOST = os.environ.get("OUTLINE_UI_HOST", "127.0.0.1")
UI_PORT = int(os.environ.get("OUTLINE_UI_PORT", "8787"))
DATA_DIR = Path(os.environ.get("OUTLINE_DATA", "/data"))
_BUNDLED_SINGBOX = Path(__file__).resolve().parents[1] / "bin" / "sing-box"
SINGBOX_BIN = os.environ.get("SINGBOX_BIN") or (
    str(_BUNDLED_SINGBOX) if _BUNDLED_SINGBOX.is_file() else "sing-box"
)
SOCKET_PATH = Path(os.environ.get("OUTLINE_SOCKET", "/run/outline-split/control.sock"))
RELAY_HOST = "127.0.0.1"
RELAY_PORT = int(os.environ.get("OUTLINE_RELAY_PORT", "18389"))
TUN_INTERFACE = "outline0"
TUN_DNS = "10.255.255.2"
TUN_TABLE = 20819
FAKE_CIDR = "198.18.0.0/15"
APP_TABLE = 20820
APP_MARK = "0x20819"
APP_RULE_PRIORITY = 20820
CGROUP_NAME = "outline-split"
MAX_DESTINATIONS = 200
MAX_DOMAINS = 200
MAX_APPS = 50
MAX_KEYS = 20
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
APP_DIRS = [
    Path(item)
    for item in os.environ.get(
        "OUTLINE_APP_DIRS",
        ":".join(
            [
                "/host/apps/system",
                "/host/apps/local",
                "/host/apps/user",
                "/host/apps/snap",
                "/host/apps/flatpak",
                "/usr/share/applications",
                "/usr/local/share/applications",
                str(Path.home() / ".local/share/applications"),
            ]
        ),
    ).split(":")
    if item
]
