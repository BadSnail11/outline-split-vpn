import os
import shlex
from pathlib import Path

from app.errors import AppError
from app.settings import APP_DIRS, MAX_APPS

GENERIC_BASENAMES = {
    "bash",
    "bwrap",
    "dash",
    "env",
    "flatpak",
    "node",
    "nodejs",
    "perl",
    "python",
    "python3",
    "ruby",
    "sh",
    "snap",
}


def normalize_programs(values: object) -> list[dict]:
    if not isinstance(values, list):
        raise AppError("Application list must be a list")
    chosen: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        program = _one_program(item)
        key = (program["match"], program["exec"])
        if key in seen:
            continue
        seen.add(key)
        chosen.append(program)
        if len(chosen) > MAX_APPS:
            raise AppError(f"Keep the application list to {MAX_APPS} or fewer")
    return chosen


def catalog(dirs: list[Path] | None = None) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for directory in dirs if dirs is not None else APP_DIRS:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.desktop")):
            try:
                program = _from_desktop(path)
            except (OSError, ValueError):
                continue
            if program is None:
                continue
            key = (program["match"], program["exec"])
            if key in seen:
                continue
            seen.add(key)
            found.append(program)
    found.sort(key=lambda item: item["name"].casefold())
    return found


def program_matches(exe: str, cmdline: str, program: dict) -> bool:
    target = program["exec"]
    if program["match"] == "cmdline":
        return target in cmdline.split()
    exe_base = os.path.basename(exe.rstrip("/"))
    target_base = os.path.basename(target.rstrip("/"))
    if "/" in target and os.path.normpath(exe) == os.path.normpath(target):
        return True
    if target_base in GENERIC_BASENAMES:
        return False
    return exe_base == target_base and exe_base != ""


def matching_pids(programs: list[dict], proc_root: Path = Path("/proc")) -> list[int]:
    if not programs or not proc_root.is_dir():
        return []
    parents: dict[int, int] = {}
    matched: set[int] = set()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid <= 1:
            continue
        parents[pid] = _ppid(entry)
        identity, cmdline = _identity(entry)
        if identity and any(program_matches(identity, cmdline, program) for program in programs):
            matched.add(pid)
    chosen = set(matched)
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if pid not in chosen and parent in chosen:
                chosen.add(pid)
                changed = True
    return sorted(chosen)


def _ppid(entry: Path) -> int:
    try:
        text = (entry / "status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    for line in text.splitlines():
        if line.startswith("PPid:"):
            value = line.split(":", 1)[1].strip()
            return int(value) if value.isdigit() else 0
    return 0


def _identity(entry: Path) -> tuple[str, str]:
    try:
        exe = os.readlink(entry / "exe").removesuffix(" (deleted)")
    except OSError:
        exe = ""
    try:
        raw = (entry / "cmdline").read_bytes()[:4096]
    except OSError:
        raw = b""
    argv0 = raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace") if raw else ""
    cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
    # Docker hides other processes' /proc/PID/exe. The command path is still readable.
    if not exe and argv0.startswith("/"):
        exe = argv0
    return exe, cmdline


def _one_program(item: object) -> dict:
    if isinstance(item, str):
        item = {"name": "", "exec": item, "match": "exe"}
    if not isinstance(item, dict):
        raise AppError("Each application needs a name and an executable")
    exec_path = str(item.get("exec", "")).strip()
    match = str(item.get("match", "exe")).strip()
    name = _clean_name(str(item.get("name", "")))
    if match == "exe" and ("\\" in exec_path or exec_path.lower().endswith(".exe")):
        match = "process"
    if match == "process":
        if not exec_path or "\n" in exec_path or "\x00" in exec_path or len(exec_path) > 4096:
            raise AppError("Application executable is empty")
        leaf = exec_path.replace("/", "\\").rsplit("\\", 1)[-1].strip()
        if not leaf or leaf in {".", ".."} or any(ch in leaf for ch in '<>:"|?*'):
            raise AppError("Application executable is empty")
        if not name:
            name = leaf
        return {"name": name, "exec": exec_path, "match": "process"}
    if match not in {"exe", "cmdline"}:
        raise AppError("Application match must be exe or cmdline")
    if not exec_path or "\n" in exec_path or "\x00" in exec_path:
        raise AppError("Application executable is empty")
    if len(exec_path) > 4096:
        raise AppError("Application executable is too long")
    if match == "cmdline":
        if not all(ch.isalnum() or ch in "._-" for ch in exec_path):
            raise AppError(f"'{exec_path}' is not an application id")
    elif "/" in exec_path:
        if not exec_path.startswith("/"):
            raise AppError("Use an absolute path such as /usr/bin/firefox")
    elif not all(ch.isalnum() or ch in "._+-" for ch in exec_path):
        raise AppError("Use an absolute path such as /usr/bin/firefox")
    if match == "exe" and os.path.basename(exec_path.rstrip("/")) in GENERIC_BASENAMES and "/" not in exec_path:
        raise AppError("Use an absolute path such as /usr/bin/firefox")
    if not name:
        name = os.path.basename(exec_path.rstrip("/")) or exec_path
    return {"name": name, "exec": exec_path, "match": match}


def _clean_name(value: str) -> str:
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    return cleaned[:80]


def _from_desktop(path: Path) -> dict | None:
    name = ""
    exec_line = ""
    hidden = False
    entry_type = "Application"
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("["):
            if line == "[Desktop Entry]":
                continue
            if line.startswith("["):
                break
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if key == "Name" and not name:
            name = _clean_name(value)
        elif key == "Exec" and not exec_line:
            exec_line = value
        elif key == "Hidden" and value.lower() == "true":
            hidden = True
        elif key == "NoDisplay" and value.lower() == "true":
            hidden = True
        elif key == "Type":
            entry_type = value
    if hidden or entry_type != "Application" or not exec_line:
        return None
    parts = _command_parts(exec_line)
    if not parts:
        return None
    if os.path.basename(parts[0]) == "flatpak" and "run" in parts:
        index = parts.index("run")
        app_id = next((part for part in parts[index + 1 :] if not part.startswith("-")), "")
        if not app_id:
            return None
        return {"name": name or app_id, "exec": app_id, "match": "cmdline"}
    token = parts[0]
    return {"name": name or os.path.basename(token), "exec": token, "match": "exe"}


def _command_parts(exec_line: str) -> list[str]:
    try:
        parts = shlex.split(exec_line, posix=True)
    except ValueError:
        return []
    cleaned: list[str] = []
    for part in parts:
        if not cleaned and part == "env":
            continue
        if not cleaned and "=" in part and not part.startswith("/"):
            continue
        if len(part) == 2 and part.startswith("%"):
            continue
        cleaned.append(part)
    return cleaned
