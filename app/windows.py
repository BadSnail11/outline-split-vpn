import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if sys.platform == "win32":
    _local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    os.environ.setdefault("OUTLINE_DATA", str(Path(_local) / "outline-split"))
    _bundled = ROOT / "bin" / "sing-box.exe"
    if _bundled.is_file():
        os.environ.setdefault("SINGBOX_BIN", str(_bundled))

from app.domains import normalize_domain
from app.errors import AppError
from app.programs import normalize_programs
from app.wincontrol import request, running


def main() -> None:
    if sys.platform != "win32":
        raise SystemExit("This window is the Windows version. On Ubuntu, run app/desktop.py.")
    import tkinter as tk
    from tkinter import filedialog, ttk

    Window(tk, ttk, filedialog).run()


class Window:
    def __init__(self, tk, ttk, filedialog) -> None:
        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.ips: list[str] = []
        self.domains: list[str] = []
        self.apps: list[dict] = []
        self.keys: list[dict] = []
        self.selected_id = ""
        self._key_signature: tuple = ()
        self._updating = False
        self._busy = False
        self.root = tk.Tk()
        self.root.title("Outline split")
        self.root.geometry("480x760")
        self.root.minsize(420, 640)
        self.connected = tk.BooleanVar()
        self.all_traffic = tk.BooleanVar()
        self.status = tk.StringVar(value="Not routing")
        self.detail = tk.StringVar(value="Add a Shadowsocks key, then add a destination, a domain, or an application.")
        self.error = tk.StringVar()
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._quit)
        self.root.after(200, self._refresh)
        self.root.after(3000, self._tick)

    def run(self) -> None:
        self.root.mainloop()

    def _build(self) -> None:
        tk = self.tk
        ttk = self.ttk
        pad = {"padx": 12, "pady": 4}
        frame = ttk.Frame(self.root, padding=8)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, textvariable=self.status, font=("", 12, "bold")).pack(anchor="w", **pad)
        ttk.Label(frame, textvariable=self.detail, wraplength=440).pack(anchor="w", **pad)
        ttk.Label(frame, textvariable=self.error, wraplength=440, foreground="#a30").pack(anchor="w", **pad)
        switches = ttk.Frame(frame)
        switches.pack(fill="x", **pad)
        ttk.Checkbutton(switches, text="Connected", variable=self.connected, command=self._on_switch).pack(side="left")
        ttk.Checkbutton(
            switches, text="Tunnel all traffic", variable=self.all_traffic, command=self._on_all
        ).pack(side="left", padx=16)

        ttk.Label(frame, text="Key").pack(anchor="w", **pad)
        self.key_box = ttk.Combobox(frame, state="readonly")
        self.key_box.pack(fill="x", **pad)
        self.key_box.bind("<<ComboboxSelected>>", self._on_key)
        self.key_entry = ttk.Entry(frame)
        self.key_entry.pack(fill="x", **pad)
        key_buttons = ttk.Frame(frame)
        key_buttons.pack(fill="x", **pad)
        ttk.Button(key_buttons, text="Add key", command=self._add_key).pack(side="left")
        ttk.Button(key_buttons, text="Remove", command=self._remove_key).pack(side="left", padx=8)
        ttk.Button(key_buttons, text="Add VPNBook keys", command=self._vpnbook).pack(side="left")
        ttk.Label(
            frame,
            text="VPNBook keys change every week. Press the button again to replace the saved ones.",
            wraplength=440,
        ).pack(anchor="w", **pad)

        self.ip_entry, self.ip_list = self._section(frame, "Destination addresses", self._add_ip, self._remove_ip)
        self.domain_entry, self.domain_list = self._section(frame, "Domains", self._add_domain, self._remove_domain)
        self.app_entry, self.app_list = self._section(
            frame, "Applications", self._add_app, self._remove_app, browse=self._browse_app
        )
        ttk.Label(
            frame,
            text="example.com sends that name and its subdomains through the tunnel. An application is a program name such as firefox.exe.",
            wraplength=440,
        ).pack(anchor="w", **pad)

    def _section(self, parent, title, add, remove, browse=None):
        ttk = self.ttk
        tk = self.tk
        ttk.Label(parent, text=title).pack(anchor="w", padx=12, pady=(10, 0))
        entry = ttk.Entry(parent)
        entry.pack(fill="x", padx=12, pady=4)
        buttons = ttk.Frame(parent)
        buttons.pack(fill="x", padx=12, pady=4)
        ttk.Button(buttons, text="Add", command=add).pack(side="left")
        if browse is not None:
            ttk.Button(buttons, text="Browse", command=browse).pack(side="left", padx=8)
            ttk.Button(buttons, text="Remove", command=remove).pack(side="left")
        else:
            ttk.Button(buttons, text="Remove", command=remove).pack(side="left", padx=8)
        listing = tk.Listbox(parent, height=4, exportselection=False)
        listing.pack(fill="x", padx=12, pady=4)
        return entry, listing

    def _on_switch(self) -> None:
        if self._updating or self._busy:
            return
        self._set_connected(self.connected.get())

    def _on_all(self) -> None:
        if self._updating or self._busy:
            return
        if self.connected.get():
            self._set_connected(True)

    def _on_key(self, _event=None) -> None:
        if self._updating or self._busy:
            return
        index = self.key_box.current()
        if index < 0 or index >= len(self.keys):
            return
        self.selected_id = self.keys[index]["id"]
        self._run({"cmd": "select", "id": self.selected_id})

    def _add_key(self) -> None:
        value = self.key_entry.get().strip()
        if not value:
            return
        self.key_entry.delete(0, "end")
        self._run({"cmd": "add", "key": value})

    def _remove_key(self) -> None:
        if not self.selected_id:
            return
        self._run({"cmd": "remove", "id": self.selected_id})

    def _vpnbook(self) -> None:
        self._run({"cmd": "vpnbook"})

    def _add_ip(self) -> None:
        value = self.ip_entry.get().strip()
        self.ip_entry.delete(0, "end")
        if not value or value in self.ips:
            return
        self.ips.append(value)
        self._render_lists()
        self._reapply()

    def _remove_ip(self) -> None:
        self._drop(self.ip_list, self.ips)

    def _add_domain(self) -> None:
        try:
            value = normalize_domain(self.domain_entry.get())
        except AppError as exc:
            self.error.set(str(exc))
            return
        self.error.set("")
        self.domain_entry.delete(0, "end")
        if value not in self.domains:
            self.domains.append(value)
        self._render_lists()
        self._reapply()

    def _remove_domain(self) -> None:
        self._drop(self.domain_list, self.domains)

    def _browse_app(self) -> None:
        path = self.filedialog.askopenfilename(
            title="Application",
            filetypes=[("Programs", "*.exe"), ("All files", "*.*")],
        )
        if path:
            self.app_entry.delete(0, "end")
            self.app_entry.insert(0, path)

    def _add_app(self) -> None:
        raw = self.app_entry.get().strip()
        if not raw:
            return
        try:
            chosen = normalize_programs([{"name": "", "exec": raw, "match": "process"}])
        except AppError as exc:
            self.error.set(str(exc))
            return
        self.error.set("")
        program = chosen[0]
        if any(item["exec"] == program["exec"] and item["match"] == program["match"] for item in self.apps):
            self.app_entry.delete(0, "end")
            return
        self.apps.append(program)
        self.app_entry.delete(0, "end")
        self._render_lists()
        self._reapply()

    def _remove_app(self) -> None:
        self._drop(self.app_list, self.apps)

    def _drop(self, listing, values) -> None:
        index = listing.curselection()
        if not index:
            return
        del values[index[0]]
        self._render_lists()
        self._reapply()

    def _reapply(self) -> None:
        if self.connected.get() and not self._busy:
            self._set_connected(True)

    def _set_connected(self, enabled: bool) -> None:
        if enabled and not self._ensure_service():
            self._updating = True
            self.connected.set(False)
            self._updating = False
            return
        form = {
            "cmd": "apply",
            "key": "",
            "ips": list(self.ips),
            "domains": list(self.domains),
            "apps": list(self.apps),
            "all_traffic": self.all_traffic.get(),
            "start": enabled,
        }
        if self.selected_id:
            form["select"] = self.selected_id
        self._run(form)

    def _ensure_service(self) -> bool:
        if running():
            return True
        self.status.set("Waiting for approval")
        self.detail.set("Windows is asking for administrator approval to start the tunnel service.")
        if not _elevate():
            self.error.set("Windows did not start the tunnel service.")
            return False
        import time

        for _ in range(40):
            if running():
                return True
            self.root.update()
            time.sleep(0.5)
        self.error.set("The tunnel service did not start. Approve the administrator prompt, then turn Connected on again.")
        return False

    def _run(self, payload: dict) -> None:
        self._busy = True

        def work() -> None:
            try:
                result = request(payload)
                error = ""
            except AppError as exc:
                result = None
                error = str(exc)
            except OSError:
                result = None
                error = "The tunnel service is not running."
            self.root.after(0, lambda: self._applied(result, error))

        threading.Thread(target=work, daemon=True).start()

    def _applied(self, result, error: str) -> None:
        self._busy = False
        if error:
            self.error.set(error)
            self._refresh()
            return
        self.error.set("")
        notice = result.get("notice") if isinstance(result, dict) else ""
        if notice:
            self.error.set(str(notice))
        self._show(result if isinstance(result, dict) else {})

    def _tick(self) -> None:
        self._refresh()
        self.root.after(3000, self._tick)

    def _refresh(self) -> None:
        if self._busy or not running():
            return

        def work() -> None:
            try:
                result = request({"cmd": "status"})
            except (AppError, OSError):
                return
            self.root.after(0, lambda: self._show(result))

        threading.Thread(target=work, daemon=True).start()

    def _show(self, data: dict) -> None:
        if self._busy:
            return
        self._updating = True
        self.connected.set(bool(data.get("enabled")))
        self.all_traffic.set(bool(data.get("all_traffic")))
        self.status.set(str(data.get("headline") or "Not routing"))
        self.detail.set(str(data.get("detail") or ""))
        warnings = data.get("warnings") or []
        if warnings and not self.error.get():
            self.detail.set(self.detail.get() + " " + " ".join(str(item) for item in warnings))
        self.keys = list(data.get("keys") or [])
        self.selected_id = str(data.get("selected") or "")
        labels = [_short(item) for item in self.keys]
        signature = tuple((item.get("id"), label) for item, label in zip(self.keys, labels))
        if signature != self._key_signature:
            self._key_signature = signature
            self.key_box["values"] = labels
        selected = next((index for index, item in enumerate(self.keys) if item["id"] == self.selected_id), -1)
        if selected >= 0 and self.key_box.current() != selected:
            self.key_box.current(selected)
        elif selected < 0 and labels and self.key_box.current() < 0:
            self.key_box.current(0)
            self.selected_id = self.keys[0]["id"]
        self.ips = list(data.get("ips") or [])
        self.domains = list(data.get("domains") or [])
        self.apps = list(data.get("apps") or [])
        self._render_lists()
        self._updating = False

    def _render_lists(self) -> None:
        _fill(self.ip_list, self.ips)
        _fill(self.domain_list, self.domains)
        _fill(self.app_list, [_app_label(item) for item in self.apps])

    def _quit(self) -> None:
        if running():
            try:
                request({"cmd": "quit"}, timeout=10)
            except (AppError, OSError):
                pass
        self.root.destroy()


def _short(item: dict) -> str:
    name = str(item.get("name") or "").strip()
    if name:
        return name
    server = str(item.get("server") or "")
    return server.split(":", 1)[0] or "Key"


def _app_label(item: dict) -> str:
    name = str(item.get("name") or "").strip()
    return name or str(item.get("exec") or "Application")


def _fill(listing, values: list[str]) -> None:
    current = [listing.get(index) for index in range(listing.size())]
    if current == values:
        return
    listing.delete(0, "end")
    for value in values:
        listing.insert("end", value)


def _elevate() -> bool:
    import ctypes

    daemon = str(ROOT / "app" / "windaemon.py")
    data = os.environ.get("OUTLINE_DATA", "")
    params = f'"{daemon}" "{data}"' if data else f'"{daemon}"'
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(ROOT), 0)
    return int(result) > 32


if __name__ == "__main__":
    main()
