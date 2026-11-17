import ipaddress
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from app.accesskey import parse_access_key, summary_of
from app.approute import AppRouter
from app.configgen import build_config
from app.domainroute import DomainNat
from app.domains import normalize_domains
from app.errors import AppError
from app.iplist import all_traffic_routes, normalize_all, split_routes
from app.programs import normalize_programs
from app.redact import redact
from app.relay import PrefixRelay
from app.resolve import resolve_host
from app.vpnbook import fetch_vpnbook_keys
from app.settings import (
    FAKE_CIDR,
    MAX_DESTINATIONS,
    MAX_DOMAINS,
    MAX_KEYS,
    RELAY_HOST,
    RELAY_PORT,
    SINGBOX_BIN,
    TUN_INTERFACE,
)


class Supervisor:
    def __init__(self, data_dir: Path, singbox: str = SINGBOX_BIN):
        self.data_dir = data_dir
        self.singbox = singbox
        self.state_path = data_dir / "state.json"
        self.config_path = data_dir / "sing-box.json"
        self.log_path = data_dir / "sing-box.log"
        self.lock = threading.Lock()
        self.key = ""
        self.keys: list[dict] = []
        self.selected = ""
        self.password = ""
        self.ips: list[str] = []
        self.domains: list[str] = []
        self.apps: list[dict] = []
        self.all_traffic = False
        self.enabled = False
        self.running = False
        self.error = ""
        self.warnings: list[str] = []
        self.summary: dict | None = None
        self.proc: subprocess.Popen | None = None
        self.log_handle = None
        self.relay: PrefixRelay | None = None
        self.router: AppRouter | None = None
        self.domain_nat: DomainNat | None = None
        self._watch_stop = threading.Event()
        self._watch_thread: threading.Thread | None = None
        self._persist = True

    def restore(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        with self.lock:
            self._load()
            if self.enabled and self.key:
                try:
                    self._launch()
                except AppError as exc:
                    self.running = False
                    self.error = str(exc)
        self._watch_thread = threading.Thread(target=self._watch_loop, name="tunnel-watch", daemon=True)
        self._watch_thread.start()

    def shutdown(self) -> None:
        self._watch_stop.set()
        with self.lock:
            self._stop_processes()

    def status(self) -> dict:
        with self.lock:
            return self._status()

    def apply(
        self,
        key: str,
        ips: object,
        apps: object = None,
        all_traffic: object = None,
        start: bool = True,
        select: str | None = None,
        domains: object = None,
    ) -> dict:
        if not isinstance(key, str):
            raise AppError("Key must be a string")
        if not isinstance(ips, list) or not all(isinstance(item, str) for item in ips):
            raise AppError("IP list must be a list of strings")
        with self.lock:
            if key.strip():
                self._store_key(key.strip())
            elif select:
                self._activate(select)
            if not self.key:
                raise AppError("Add a Shadowsocks key")
            parsed = parse_access_key(self.key)
            destinations = normalize_all(ips)
            if len(destinations) > MAX_DESTINATIONS:
                raise AppError(f"Keep the list to {MAX_DESTINATIONS} networks or fewer")
            chosen_apps = self.apps if apps is None else normalize_programs(apps)
            if domains is None:
                chosen_domains = self.domains
            elif isinstance(domains, list) and all(isinstance(item, str) for item in domains):
                chosen_domains = normalize_domains(domains)
                if len(chosen_domains) > MAX_DOMAINS:
                    raise AppError(f"Keep the domain list to {MAX_DOMAINS} or fewer")
            else:
                raise AppError("Domain list must be a list of strings")
            if all_traffic is None:
                chosen_all = self.all_traffic
            elif isinstance(all_traffic, bool):
                chosen_all = all_traffic
            else:
                raise AppError("All-traffic setting must be true or false")
            if not isinstance(start, bool):
                raise AppError("Start must be true or false")
            plan = self._plan(parsed, destinations, chosen_apps, chosen_all, chosen_domains)
            if plan.config is not None:
                self._check(plan.config, parsed.password, self.key)
            self.password = parsed.password
            self.ips = destinations
            self.domains = chosen_domains
            self.apps = chosen_apps
            self.all_traffic = chosen_all
            self.enabled = start
            self.summary = summary_of(parsed)
            self.warnings = plan.warnings
            self.error = ""
            self._persist = True
            self._save()
            if start:
                try:
                    self._launch()
                except AppError as exc:
                    self.error = str(exc)
                    self.running = self.proc is not None and self.proc.poll() is None
            else:
                self._stop_processes()
                self.running = False
            return self._status()

    def import_vpnbook(self) -> dict:
        raws = fetch_vpnbook_keys()
        aliases: dict[str, list[str]] = {}
        for secret in raws:
            parsed = parse_access_key(secret)
            if parsed.server in aliases:
                continue
            try:
                aliases[parsed.server] = resolve_host(parsed.server)
            except AppError:
                aliases[parsed.server] = []
        return self.import_secrets(raws, aliases)

    def import_secrets(self, raws: list[str], aliases: dict[str, list[str]] | None = None) -> dict:
        aliases = aliases or {}
        with self.lock:
            added = updated = 0
            had_selection = bool(self.selected)
            selected_secret = self.key
            for secret in raws:
                parsed = parse_access_key(secret)
                outcome = self._upsert_server(secret, set(aliases.get(parsed.server, [])))
                if outcome == "added":
                    added += 1
                elif outcome == "updated":
                    updated += 1
            if not had_selection and self.keys and not self.selected:
                self._activate(self.keys[0]["id"])
            self.error = ""
            self._persist = True
            self._save()
            if self.enabled and self.key != selected_secret:
                self._relaunch()
            status = self._status()
            status["notice"] = _vpnbook_notice(added, updated)
            return status

    def add_key(self, raw: str) -> dict:
        if not isinstance(raw, str):
            raise AppError("Key must be a string")
        with self.lock:
            self._store_key(raw)
            self.error = ""
            self._persist = True
            self._save()
            if self.enabled:
                self._relaunch()
            return self._status()

    def select_key(self, key_id: str) -> dict:
        if not isinstance(key_id, str) or not key_id:
            raise AppError("Choose a key")
        with self.lock:
            self._activate(key_id)
            self.error = ""
            self._persist = True
            self._save()
            if self.enabled:
                self._relaunch()
            return self._status()

    def remove_key(self, key_id: str) -> dict:
        if not isinstance(key_id, str) or not key_id:
            raise AppError("Choose a key")
        with self.lock:
            if key_id not in {item["id"] for item in self.keys}:
                raise AppError("That key is not saved")
            self.keys = [item for item in self.keys if item["id"] != key_id]
            if self.selected == key_id:
                if self.keys:
                    self._activate(self.keys[0]["id"])
                else:
                    self.selected = ""
                    self.key = ""
                    self.password = ""
                    self.summary = None
            self.error = ""
            self._persist = True
            self._save()
            if self.enabled:
                if self.key:
                    self._relaunch()
                else:
                    self._stop_processes()
                    self.enabled = False
                    self.running = False
                    self._save()
            return self._status()

    def stop(self) -> dict:
        with self.lock:
            self._stop_processes()
            self.enabled = False
            self.running = False
            self.error = ""
            self.warnings = []
            self._save()
            return self._status()

    def _upsert_server(self, raw: str, aliases: set[str] | None = None) -> str:
        parsed = parse_access_key(raw)
        secret = raw.strip()
        identities = {parsed.server.lower(), *(item.lower() for item in aliases or set())}
        matches: list[tuple[dict, object]] = []
        for item in self.keys:
            saved = parse_access_key(item["secret"])
            if saved.port == parsed.port and saved.server.lower() in identities:
                matches.append((item, saved))
        if not matches:
            if len(self.keys) >= MAX_KEYS:
                raise AppError(f"Keep the key list to {MAX_KEYS} or fewer")
            item = {"id": secrets.token_hex(4), "secret": secret}
            self.keys.append(item)
            if not self.selected:
                self._activate(item["id"])
            return "added"
        primary, _saved = next(
            ((item, saved) for item, saved in matches if item["id"] == self.selected),
            matches[0],
        )
        changed = any(
            saved.password != parsed.password or saved.method != parsed.method for _item, saved in matches
        )
        primary["secret"] = secret
        drop = {item["id"] for item, _saved in matches if item is not primary}
        if drop:
            self.keys = [item for item in self.keys if item["id"] not in drop]
        if changed or self.selected in drop:
            self._activate(primary["id"])
        return "updated" if changed or drop else "unchanged"

    def _store_key(self, raw: str) -> None:
        parsed = parse_access_key(raw)
        secret = raw.strip()
        for item in self.keys:
            saved = parse_access_key(item["secret"])
            if _same_key(saved, parsed):
                item["secret"] = secret
                self._activate(item["id"])
                return
        if len(self.keys) >= MAX_KEYS:
            raise AppError(f"Keep the key list to {MAX_KEYS} or fewer")
        item = {"id": secrets.token_hex(4), "secret": secret}
        self.keys.append(item)
        self._activate(item["id"])

    def _activate(self, key_id: str) -> None:
        found = next((item for item in self.keys if item["id"] == key_id), None)
        if found is None:
            raise AppError("That key is not saved")
        parsed = parse_access_key(found["secret"])
        self.selected = found["id"]
        self.key = found["secret"]
        self.password = parsed.password
        self.summary = summary_of(parsed)

    def _relaunch(self) -> None:
        try:
            self._launch()
        except AppError as exc:
            self.error = str(exc)
            self.running = self.proc is not None and self.proc.poll() is None

    def _public_keys(self) -> list[dict]:
        shown: list[dict] = []
        for item in self.keys:
            try:
                parsed = parse_access_key(item["secret"])
            except AppError:
                continue
            shown.append(
                {
                    "id": item["id"],
                    "name": parsed.name,
                    "server": f"{parsed.server}:{parsed.port}",
                    "method": parsed.method,
                }
            )
        return shown

    def _plan(
        self,
        parsed,
        destinations: list[str],
        apps: list[dict],
        all_traffic: bool,
        domains: list[str],
    ):
        names = [] if all_traffic else domains
        addresses = resolve_host(parsed.server) if destinations or apps or all_traffic or names else []
        if all_traffic:
            routes, excludes = all_traffic_routes(addresses)
            apps = []
            warnings = [
                "All traffic except this machine's local network goes through the tunnel.",
                "The tunnel server address stays on the normal route so the connection can stay up.",
            ]
        else:
            routes, excludes = split_routes(destinations, addresses) if destinations else ([], [])
            if names and FAKE_CIDR not in routes:
                routes = [*routes, FAKE_CIDR]
            if apps or names:
                excludes = _with_server(excludes, addresses)
            warnings = _warnings(routes, excludes)
            if names:
                warnings.append(
                    "Listed domains and their subdomains go through the tunnel. Other names keep the normal route."
                )
            if sys.platform == "win32" and apps:
                warnings.append("Quit and reopen a selected program after you connect.")
        config = None
        if routes or apps:
            if not addresses:
                raise AppError(f"Could not resolve {parsed.server}")
            processes = _windows_processes(apps) if sys.platform == "win32" else []
            if sys.platform == "win32" and apps and not processes:
                raise AppError("Use a Windows program such as firefox.exe")
            direct_dns = "1.1.1.1"
            if names and sys.platform != "win32":
                direct_dns = DomainNat().peek()
            config = build_config(
                method=parsed.method,
                password=parsed.password,
                server_ip=addresses[0],
                server_port=parsed.port,
                use_relay=bool(parsed.prefix),
                route_address=routes,
                route_exclude=excludes,
                for_apps=bool(apps),
                domains=names,
                direct_dns=direct_dns,
                platform="windows" if sys.platform == "win32" else "linux",
                process_names=processes,
            )
        return _Plan(addresses, routes, excludes, warnings, config)

    def _launch(self) -> None:
        parsed = parse_access_key(self.key)
        self.password = parsed.password
        self.summary = summary_of(parsed)
        plan = self._plan(parsed, self.ips, self.apps, self.all_traffic, self.domains)
        self.warnings = plan.warnings
        if plan.config is None:
            self._stop_processes()
            self.running = False
            if self.ips and not plan.routes:
                self.warnings.append("The server address stays on the normal route, so there is nothing to tunnel.")
            return
        self._check(plan.config, parsed.password, self.key)
        self._stop_processes()
        self._dump(self.config_path, plan.config)
        try:
            if parsed.prefix:
                relay = PrefixRelay(
                    (RELAY_HOST, RELAY_PORT),
                    (plan.addresses[0], parsed.port),
                    parsed.prefix,
                )
                relay.start()
                self.relay = relay
            self._spawn()
            time.sleep(0.5)
            if self.proc is None or self.proc.poll() is not None:
                code = self.proc.returncode if self.proc is not None else 1
                detail = self._tail() or f"sing-box exited with status {code}"
                raise AppError(_hint(detail))
            if sys.platform != "win32" and self.domains and not self.all_traffic:
                self.domain_nat = DomainNat()
                self.domain_nat.start()
            if sys.platform != "win32" and self.apps:
                self.router = AppRouter()
                self.router.start(self.apps, plan.addresses)
        except AppError:
            self._stop_processes()
            raise
        except OSError as exc:
            self._stop_processes()
            raise AppError(str(exc)) from exc
        self.running = True
        self.error = ""
        attached = self.router.attached if self.router is not None else 0
        print(
            f"tunnel up destinations={len(plan.routes)} domains={len(self.domains)} applications={len(self.apps)} "
            f"attached={attached} server={parsed.server}:{parsed.port} "
            f"prefix={'yes' if parsed.prefix else 'no'}",
            flush=True,
        )

    def _check(self, config: dict, password: str, key: str) -> None:
        binary = self._binary()
        tmp = self.config_path.with_suffix(".check.json")
        self._dump(tmp, config)
        try:
            try:
                result = subprocess.run(
                    [binary, "check", "-c", str(tmp)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    stdin=subprocess.DEVNULL,
                )
            except subprocess.TimeoutExpired as exc:
                raise AppError("sing-box check timed out") from exc
        finally:
            tmp.unlink(missing_ok=True)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "sing-box rejected the config").strip()
            raise AppError(redact(detail, password, key)[:2000])

    def _spawn(self) -> None:
        self.log_path.write_bytes(b"")
        os.chmod(self.log_path, 0o600)
        self.log_handle = open(self.log_path, "ab", buffering=0)
        self.proc = subprocess.Popen(
            [self._binary(), "run", "-c", str(self.config_path)],
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )

    def _binary(self) -> str:
        path = Path(self.singbox)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        found = shutil.which(self.singbox)
        if found:
            return found
        raise AppError("sing-box was not found")

    def _stop_processes(self) -> None:
        domain_nat = self.domain_nat
        self.domain_nat = None
        if domain_nat is not None:
            domain_nat.close()
        router = self.router
        self.router = None
        if router is not None:
            router.close()
        proc = self.proc
        self.proc = None
        relay = self.relay
        self.relay = None
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)
        if self.log_handle is not None:
            self.log_handle.close()
            self.log_handle = None
        if relay is not None:
            relay.stop()
        self.running = False

    def _watch_loop(self) -> None:
        while not self._watch_stop.wait(2):
            with self.lock:
                proc = self.proc
                if proc is None or proc.poll() is None:
                    continue
                detail = self._tail() or f"sing-box exited with status {proc.returncode}"
                self.error = _hint(redact(detail, self.password, self.key))
                self._stop_processes()

    def _tail(self) -> str:
        try:
            lines = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        text = "\n".join(lines[-30:]).strip()
        return redact(text, self.password, self.key)

    def _load(self) -> None:
        if not self.state_path.is_file():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._persist = False
            self.error = "Saved settings could not be read. They were left on disk."
            return
        key = data.get("key", "")
        ips = data.get("ips", [])
        raw_keys = data.get("keys")
        if not isinstance(ips, list) or not isinstance(key, str):
            self._persist = False
            self.error = "Saved settings could not be read."
            return
        if not raw_keys:
            raw_keys = [{"id": "", "secret": key}] if key else []
        if not isinstance(raw_keys, list):
            self._persist = False
            self.error = "Saved settings could not be read."
            return
        try:
            chosen = _load_keys(raw_keys)
            clean = normalize_all([item for item in ips if isinstance(item, str)])
            chosen_apps = normalize_programs(data.get("apps", []))
            raw_domains = data.get("domains", [])
            if not isinstance(raw_domains, list):
                raise AppError("Saved domain list is invalid")
            chosen_domains = normalize_domains([item for item in raw_domains if isinstance(item, str)])
            chosen_all = data.get("all_traffic", False)
            if not isinstance(chosen_all, bool):
                raise AppError("Saved all-traffic setting is invalid")
            selected = data.get("selected", "")
            if not isinstance(selected, str):
                raise AppError("Saved key choice is invalid")
        except AppError as exc:
            self._persist = False
            self.error = f"Saved settings were not loaded: {exc}"
            return
        self.keys = chosen
        if selected not in {item["id"] for item in chosen} and chosen:
            selected = chosen[0]["id"]
        self.selected = selected if any(item["id"] == selected for item in chosen) else ""
        current = next((item["secret"] for item in chosen if item["id"] == self.selected), "")
        parsed = parse_access_key(current) if current else None
        self.key = current
        self.password = parsed.password if parsed else ""
        self.summary = summary_of(parsed) if parsed else None
        self.ips = clean
        self.domains = chosen_domains
        self.apps = chosen_apps
        self.all_traffic = chosen_all
        self.enabled = bool(data.get("enabled", False))

    def _save(self) -> None:
        if not self._persist:
            return
        payload = {
            "key": self.key,
            "keys": [{"id": item["id"], "secret": item["secret"]} for item in self.keys],
            "selected": self.selected,
            "ips": self.ips,
            "domains": self.domains,
            "apps": self.apps,
            "all_traffic": self.all_traffic,
            "enabled": self.enabled,
        }
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.state_path)

    def _dump(self, path: Path, config: dict) -> None:
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        os.chmod(path, 0o600)

    def _status(self) -> dict:
        attached = self.router.attached if self.router is not None else 0
        if self.running:
            state = "up"
            if self.all_traffic:
                headline = "Routing all traffic"
            elif (
                sys.platform != "win32"
                and self.apps
                and attached == 0
                and not self.ips
                and not self.domains
            ):
                headline = "Tunnel is up"
            else:
                headline = "Routing selected traffic"
        elif self.error:
            state = "down"
            headline = "Tunnel failed"
        else:
            state = "idle"
            headline = "Not routing"
        return {
            "key_saved": bool(self.key),
            "keys": self._public_keys(),
            "selected": self.selected,
            "summary": self.summary,
            "ips": list(self.ips),
            "domains": list(self.domains),
            "apps": list(self.apps),
            "all_traffic": self.all_traffic,
            "attached": attached,
            "enabled": self.enabled,
            "running": self.running,
            "state": state,
            "headline": headline,
            "detail": self.error or self._detail(),
            "warnings": _with_outline_warning(self.warnings),
            "interface": TUN_INTERFACE,
        }

    def _detail(self) -> str:
        if self.running and self.all_traffic:
            return f"All traffic except the local network uses {TUN_INTERFACE}."
        if self.running:
            attached = self.router.attached if self.router is not None else 0
            parts: list[str] = []
            if self.ips:
                count = len(self.ips)
                parts.append(f"{count} destination" if count == 1 else f"{count} destinations")
            if self.domains:
                count = len(self.domains)
                parts.append(f"{count} domain" if count == 1 else f"{count} domains")
            if self.apps:
                count = len(self.apps)
                label = f"{count} application" if count == 1 else f"{count} applications"
                if sys.platform == "win32":
                    parts.append(label)
                elif attached == 0 and not parts:
                    return (
                        f"{label} selected, and no matching process is open. "
                        "Close the application and open it again."
                    )
                else:
                    process = "process" if attached == 1 else "processes"
                    parts.append(f"{label} ({attached} {process})")
            text = f"{', '.join(parts)} use {TUN_INTERFACE}. Other traffic keeps the normal route."
            if self.apps:
                text += " Connections already open stay on the normal route until the application is opened again."
            return text
        if not self.key:
            return "Add a Shadowsocks key, then add a destination, a domain, or an application."
        if not self.enabled:
            return "Tunnel is stopped. The saved key and list stay on disk."
        if not self.ips and not self.domains and not self.apps and not self.all_traffic:
            return "Key saved. Add a destination, a domain, an application, or tunnel all traffic."
        if self.warnings:
            return self.warnings[-1]
        return "Tunnel is not running."


class _Plan:
    def __init__(self, addresses, routes, excludes, warnings, config):
        self.addresses = addresses
        self.routes = routes
        self.excludes = excludes
        self.warnings = warnings
        self.config = config


def _load_keys(values: list) -> list[dict]:
    chosen: list[dict] = []
    seen: set[str] = set()
    for item in values:
        if isinstance(item, str):
            item = {"id": "", "secret": item}
        if not isinstance(item, dict):
            raise AppError("Saved key list is invalid")
        secret = item.get("secret", "")
        if not isinstance(secret, str) or not secret.strip():
            continue
        parse_access_key(secret)
        key_id = item.get("id", "")
        if not isinstance(key_id, str) or not key_id or key_id in seen:
            key_id = secrets.token_hex(4)
        seen.add(key_id)
        chosen.append({"id": key_id, "secret": secret.strip()})
        if len(chosen) > MAX_KEYS:
            raise AppError(f"Keep the key list to {MAX_KEYS} or fewer")
    return chosen


def _same_key(left, right) -> bool:
    return (left.method, left.password, left.server, left.port) == (
        right.method,
        right.password,
        right.server,
        right.port,
    )


def _with_server(excludes: list[str], server_ips: list[str]) -> list[str]:
    chosen = list(excludes)
    for raw in server_ips:
        address = ipaddress.ip_address(raw.split("%", 1)[0])
        network = f"{address}/{address.max_prefixlen}"
        if network not in chosen:
            chosen.append(network)
    return chosen


def _windows_processes(apps: list[dict]) -> list[str]:
    names: list[str] = []
    for item in apps:
        raw = str(item.get("exec", "")).replace("/", "\\")
        leaf = raw.rsplit("\\", 1)[-1].strip()
        if not leaf:
            continue
        if not leaf.lower().endswith(".exe"):
            leaf = f"{leaf}.exe"
        if leaf not in names:
            names.append(leaf)
    return names


def outline_desktop_device() -> str:
    root = Path("/sys/class/net")
    if not root.is_dir():
        return ""
    for item in sorted(root.iterdir()):
        if item.name.startswith("outline-tun"):
            return item.name
    return ""


def _with_outline_warning(notes: list[str]) -> list[str]:
    warnings = list(notes)
    device = outline_desktop_device()
    if not device:
        return warnings
    warnings.append(
        f"The Outline desktop app is connected on {device}. Disconnect it. "
        "While it stays connected, traffic keeps that tunnel, so the address you see does not change."
    )
    return warnings


def _warnings(routes: list[str], excludes: list[str]) -> list[str]:
    notes: list[str] = []
    for raw in routes:
        network = ipaddress.ip_network(raw)
        if network.prefixlen == 0:
            notes.append(f"{network} sends all IPv{network.version} traffic through the tunnel.")
    if excludes:
        notes.append("The tunnel server address stays on the normal route so the connection can stay up.")
    return notes


def _vpnbook_notice(added: int, updated: int) -> str:
    if added and updated:
        added_text = "1 VPNBook key" if added == 1 else f"{added} VPNBook keys"
        updated_text = "1" if updated == 1 else str(updated)
        return f"Added {added_text} and refreshed {updated_text}."
    if added:
        return "Added 1 VPNBook key." if added == 1 else f"Added {added} VPNBook keys."
    if updated:
        return "Refreshed 1 VPNBook key." if updated == 1 else f"Refreshed {updated} VPNBook keys."
    return "VPNBook keys are already current."


def _hint(detail: str) -> str:
    lowered = detail.lower()
    if "not permitted" in lowered or "permission denied" in lowered:
        return detail + "\nStart the app with docker compose so it can create the outline0 interface."
    return detail
