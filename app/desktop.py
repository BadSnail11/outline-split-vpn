import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3, GLib, Gtk

from app.control import request
from app.domains import normalize_domain
from app.errors import AppError
from app.programs import catalog
from app.settings import SOCKET_PATH

DAEMON = Path(__file__).resolve().parent / "daemon.py"
APP_ID = "by.bsuir.outline-split"


class OutlineSplit(Gtk.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID)
        self.window: Gtk.ApplicationWindow | None = None
        self.ips: list[str] = []
        self.domains: list[str] = []
        self.apps: list[dict] = []
        self.saved_keys: list[dict] = []
        self.selected_id = ""
        self.catalog: list[dict] = []
        self._updating = False
        self._busy = False
        self._synced = False
        self._daemon: subprocess.Popen | None = None
        self._key_menu_signature: tuple = ()

    def do_startup(self) -> None:
        Gtk.Application.do_startup(self)
        self.hold()
        self._build_indicator()
        GLib.timeout_add_seconds(3, self._refresh_silent)

    def do_activate(self) -> None:
        if self.window is None:
            self._build_window()
        self.window.present()
        self._refresh_silent()

    def _build_indicator(self) -> None:
        self.indicator = AyatanaAppIndicator3.Indicator.new(
            "outline-split",
            "network-offline",
            AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS,
        )
        self.indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title("Outline split")
        menu = Gtk.Menu()
        self.menu_status = Gtk.MenuItem.new_with_label("Not connected")
        self.menu_status.set_sensitive(False)
        self.menu_toggle = Gtk.MenuItem.new_with_label("Turn on")
        self.menu_toggle.connect("activate", lambda _item: self._toggle_from_menu())
        self.menu_all = Gtk.CheckMenuItem.new_with_label("Tunnel all traffic")
        self.menu_all.connect("toggled", self._on_menu_all)
        self.key_item = Gtk.MenuItem.new_with_label("Key")
        self.key_menu = Gtk.Menu()
        self.key_item.set_submenu(self.key_menu)
        open_item = Gtk.MenuItem.new_with_label("Open")
        open_item.connect("activate", lambda _item: self.activate())
        quit_item = Gtk.MenuItem.new_with_label("Quit")
        quit_item.connect("activate", lambda _item: self._quit())
        for item in (self.menu_status, self.menu_toggle, self.menu_all, self.key_item, open_item, quit_item):
            menu.append(item)
        menu.show_all()
        self.indicator.set_menu(menu)

    def _build_window(self) -> None:
        self.window = Gtk.ApplicationWindow(application=self, title="Outline split")
        self.window.set_default_size(460, 720)
        self.window.set_position(Gtk.WindowPosition.CENTER)
        header = Gtk.HeaderBar(title="Outline split", show_close_button=True)
        header.set_subtitle("Not connected")
        self.header = header
        self.window.set_titlebar(header)
        self.window.connect("delete-event", self._hide)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        root.set_border_width(16)
        self.status_label = Gtk.Label(xalign=0)
        self.status_label.set_line_wrap(True)
        self.status_label.get_style_context().add_class("dim-label")
        root.pack_start(self.status_label, False, False, 0)

        switch_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        switch_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title = Gtk.Label(label="Connected", xalign=0)
        hint = Gtk.Label(label="Turns the tunnel on and off", xalign=0)
        hint.get_style_context().add_class("dim-label")
        switch_text.pack_start(title, False, False, 0)
        switch_text.pack_start(hint, False, False, 0)
        self.switch = Gtk.Switch()
        self.switch.set_valign(Gtk.Align.CENTER)
        self.switch.connect("notify::active", self._on_switch)
        switch_row.pack_start(switch_text, True, True, 0)
        switch_row.pack_end(self.switch, False, False, 0)
        root.pack_start(switch_row, False, False, 0)

        root.pack_start(Gtk.Separator(), False, False, 0)
        root.pack_start(Gtk.Label(label="Access key", xalign=0), False, False, 0)
        key_row = Gtk.Box(spacing=8)
        self.key_combo = Gtk.ComboBoxText()
        self.key_combo.connect("changed", self._on_combo)
        self.remove_key_button = Gtk.Button(label="Remove")
        self.remove_key_button.connect("clicked", lambda _button: self._remove_key())
        key_row.pack_start(self.key_combo, True, True, 0)
        key_row.pack_start(self.remove_key_button, False, False, 0)
        root.pack_start(key_row, False, False, 0)
        add_row = Gtk.Box(spacing=8)
        self.key_entry = Gtk.Entry(placeholder_text="ss://…", visibility=False)
        self.key_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.key_entry.connect("activate", lambda _entry: self._add_key())
        add_key = Gtk.Button(label="Add")
        add_key.connect("clicked", lambda _button: self._add_key())
        add_row.pack_start(self.key_entry, True, True, 0)
        add_row.pack_start(add_key, False, False, 0)
        root.pack_start(add_row, False, False, 0)
        vpnbook_row = Gtk.Box(spacing=8)
        vpnbook = Gtk.Button(label="Add VPNBook keys")
        vpnbook.connect("clicked", lambda _button: self._load_vpnbook())
        vpnbook_hint = Gtk.Label(label="Loads the current VPNBook keys and replaces saved ones.", xalign=0)
        vpnbook_hint.set_line_wrap(True)
        vpnbook_hint.get_style_context().add_class("dim-label")
        vpnbook_row.pack_start(vpnbook, False, False, 0)
        vpnbook_row.pack_start(vpnbook_hint, True, True, 0)
        root.pack_start(vpnbook_row, False, False, 0)
        self.show_key = Gtk.CheckButton(label="Show key")
        self.show_key.connect("toggled", lambda button: self.key_entry.set_visibility(button.get_active()))
        root.pack_start(self.show_key, False, False, 0)
        key_hint = Gtk.Label(
            label="Add each access key, then choose the one this tunnel uses. The password stays in the saved settings.",
            xalign=0,
        )
        key_hint.set_line_wrap(True)
        key_hint.get_style_context().add_class("dim-label")
        root.pack_start(key_hint, False, False, 0)

        self.all_check = Gtk.CheckButton(label="Tunnel all traffic")
        self.all_check.connect("toggled", self._on_all)
        root.pack_start(self.all_check, False, False, 0)
        all_hint = Gtk.Label(
            label="Local network addresses stay on the normal route. Turn this off to choose destinations, domains, and applications.",
            xalign=0,
        )
        all_hint.set_line_wrap(True)
        all_hint.get_style_context().add_class("dim-label")
        root.pack_start(all_hint, False, False, 0)

        self.split_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.split_box.pack_start(Gtk.Label(label="Destination addresses", xalign=0), False, False, 0)
        ip_row = Gtk.Box(spacing=8)
        self.ip_entry = Gtk.Entry(placeholder_text="203.0.113.10 or 203.0.113.0/24")
        self.ip_entry.connect("activate", lambda _entry: self._add_ip())
        add_ip = Gtk.Button(label="Add")
        add_ip.connect("clicked", lambda _button: self._add_ip())
        ip_row.pack_start(self.ip_entry, True, True, 0)
        ip_row.pack_start(add_ip, False, False, 0)
        self.split_box.pack_start(ip_row, False, False, 0)
        self.ip_box = Gtk.ListBox()
        self.ip_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.split_box.pack_start(self.ip_box, False, False, 0)

        self.split_box.pack_start(Gtk.Label(label="Domains", xalign=0), False, False, 0)
        domain_row = Gtk.Box(spacing=8)
        self.domain_entry = Gtk.Entry(placeholder_text="example.com")
        self.domain_entry.connect("activate", lambda _entry: self._add_domain())
        add_domain = Gtk.Button(label="Add")
        add_domain.connect("clicked", lambda _button: self._add_domain())
        domain_row.pack_start(self.domain_entry, True, True, 0)
        domain_row.pack_start(add_domain, False, False, 0)
        self.split_box.pack_start(domain_row, False, False, 0)
        domain_hint = Gtk.Label(
            label="example.com sends that name and its subdomains through the tunnel.",
            xalign=0,
        )
        domain_hint.set_line_wrap(True)
        domain_hint.get_style_context().add_class("dim-label")
        self.split_box.pack_start(domain_hint, False, False, 0)
        self.domain_box = Gtk.ListBox()
        self.domain_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.split_box.pack_start(self.domain_box, False, False, 0)

        self.split_box.pack_start(Gtk.Label(label="Applications", xalign=0), False, False, 0)
        app_row = Gtk.Box(spacing=8)
        self.app_entry = Gtk.Entry(placeholder_text="Firefox, or /usr/bin/firefox")
        self.app_entry.connect("changed", lambda _entry: self._render_results())
        self.app_entry.connect("activate", lambda _entry: self._add_app_from_search())
        add_app = Gtk.Button(label="Add")
        add_app.connect("clicked", lambda _button: self._add_app_from_search())
        app_row.pack_start(self.app_entry, True, True, 0)
        app_row.pack_start(add_app, False, False, 0)
        self.split_box.pack_start(app_row, False, False, 0)
        self.result_box = Gtk.ListBox()
        self.result_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.split_box.pack_start(self.result_box, False, False, 0)
        app_hint = Gtk.Label(
            label="Close a selected application and open it again after you connect.",
            xalign=0,
        )
        app_hint.set_line_wrap(True)
        app_hint.get_style_context().add_class("dim-label")
        self.split_box.pack_start(app_hint, False, False, 0)
        self.app_box = Gtk.ListBox()
        self.app_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self.split_box.pack_start(self.app_box, False, False, 0)
        root.pack_start(self.split_box, False, False, 0)

        self.error_label = Gtk.Label(xalign=0)
        self.error_label.set_line_wrap(True)
        self.error_label.set_no_show_all(True)
        root.pack_start(self.error_label, False, False, 0)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scrolled.add(root)
        self.window.add(scrolled)
        self.window.show_all()
        self.result_box.set_visible(False)
        self._render_lists()
        self._load_catalog()

    def _hide(self, _window, _event) -> bool:
        self.window.hide()
        return True

    def _on_switch(self, switch, _param) -> None:
        if self._updating or self._busy:
            return
        self._set_connected(switch.get_active())

    def _on_all(self, button) -> None:
        self.split_box.set_visible(not button.get_active())
        if self._updating or self._busy:
            return
        self.menu_all.set_active(button.get_active())
        if self.switch.get_active():
            self._set_connected(True)

    def _on_menu_all(self, item) -> None:
        if self._updating or self.window is None:
            return
        self.all_check.set_active(item.get_active())

    def _toggle_from_menu(self) -> None:
        if self.window is None:
            self._build_window()
        self._set_connected(not self.switch.get_active())

    def _add_ip(self) -> None:
        value = self.ip_entry.get_text().strip()
        if not value or value in self.ips:
            self.ip_entry.set_text("")
            return
        self.ips.append(value)
        self.ip_entry.set_text("")
        self._render_lists()
        if self.switch.get_active():
            self._set_connected(True)

    def _add_domain(self) -> None:
        try:
            value = normalize_domain(self.domain_entry.get_text())
        except AppError as exc:
            self._show_error(str(exc))
            return
        self._show_error("")
        if value not in self.domains:
            self.domains.append(value)
        self.domain_entry.set_text("")
        self._render_lists()
        if self.switch.get_active():
            self._set_connected(True)

    def _add_program(self, program: dict) -> None:
        if any(item["exec"] == program["exec"] and item["match"] == program["match"] for item in self.apps):
            return
        self.apps.append(program)
        self.app_entry.set_text("")
        self._render_lists()
        self._render_results()
        if self.switch.get_active():
            self._set_connected(True)

    def _add_app_from_search(self) -> None:
        query = self.app_entry.get_text().strip()
        if not query:
            return
        if query.startswith("/"):
            self._add_program({"name": Path(query).name, "exec": query, "match": "exe"})
            return
        matches = self._filter_catalog(query)
        exact = [item for item in matches if item["name"].lower() == query.lower()]
        if len(matches) == 1 or exact:
            self._add_program(exact[0] if exact else matches[0])
            return
        self._show_error("Choose an application from the list, or type an absolute path.")

    def _filter_catalog(self, query: str) -> list[dict]:
        needle = query.strip().lower()
        if not needle:
            return []
        return [
            item
            for item in self.catalog
            if needle in item["name"].lower() or needle in item["exec"].lower()
        ][:8]

    def _render_results(self) -> None:
        self._clear(self.result_box)
        for program in self._filter_catalog(self.app_entry.get_text()):
            button = Gtk.Button(relief=Gtk.ReliefStyle.NONE)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            box.pack_start(Gtk.Label(label=program["name"], xalign=0), False, False, 0)
            path = Gtk.Label(label=program["exec"], xalign=0)
            path.get_style_context().add_class("dim-label")
            box.pack_start(path, False, False, 0)
            button.add(box)
            button.connect("clicked", lambda _button, chosen=program: self._add_program(chosen))
            self.result_box.add(button)
        self.result_box.show_all()
        self.result_box.set_visible(bool(self.app_entry.get_text().strip()))

    def _render_lists(self) -> None:
        self._clear(self.ip_box)
        if not self.ips:
            self.ip_box.add(Gtk.Label(label="No destinations yet.", xalign=0))
        for value in self.ips:
            self.ip_box.add(self._row(value, lambda item=value: self._remove_ip(item)))
        self.ip_box.show_all()
        self._clear(self.domain_box)
        if not self.domains:
            self.domain_box.add(Gtk.Label(label="No domains yet.", xalign=0))
        for value in self.domains:
            self.domain_box.add(self._row(value, lambda item=value: self._remove_domain(item)))
        self.domain_box.show_all()
        self._clear(self.app_box)
        if not self.apps:
            self.app_box.add(Gtk.Label(label="No applications yet.", xalign=0))
        for program in self.apps:
            label = f"{program['name']}\n{program['exec']}"
            self.app_box.add(self._row(label, lambda item=program: self._remove_app(item)))
        self.app_box.show_all()

    def _row(self, text: str, remove) -> Gtk.Box:
        row = Gtk.Box(spacing=8)
        label = Gtk.Label(label=text, xalign=0)
        label.set_line_wrap(True)
        button = Gtk.Button(label="Remove")
        button.connect("clicked", lambda _button: remove())
        row.pack_start(label, True, True, 0)
        row.pack_end(button, False, False, 0)
        return row

    def _remove_ip(self, value: str) -> None:
        self.ips = [item for item in self.ips if item != value]
        self._render_lists()
        if self.switch.get_active():
            self._set_connected(True)

    def _remove_domain(self, value: str) -> None:
        self.domains = [item for item in self.domains if item != value]
        self._render_lists()
        if self.switch.get_active():
            self._set_connected(True)

    def _remove_app(self, program: dict) -> None:
        self.apps = [
            item
            for item in self.apps
            if not (item["exec"] == program["exec"] and item["match"] == program["match"])
        ]
        self._render_lists()
        if self.switch.get_active():
            self._set_connected(True)

    def _clear(self, box: Gtk.ListBox) -> None:
        for child in box.get_children():
            box.remove(child)

    def _set_connected(self, active: bool) -> None:
        self._busy = True
        self.switch.set_sensitive(False)
        self._show_error("")
        self.status_label.set_text("Connecting…" if active else "Disconnecting…")
        form = {
            "cmd": "apply",
            "key": self.key_entry.get_text(),
            "ips": list(self.ips),
            "domains": list(self.domains),
            "apps": list(self.apps),
            "all_traffic": self.all_check.get_active(),
            "start": True,
        }
        if self.selected_id:
            form["select"] = self.selected_id

        def work():
            try:
                if active:
                    self._ensure_daemon()
                    result = request(form, SOCKET_PATH, timeout=60)
                else:
                    if not _socket_up():
                        result = None
                    else:
                        result = request({"cmd": "stop"}, SOCKET_PATH, timeout=20)
                GLib.idle_add(self._applied, result, None)
            except Exception as exc:
                GLib.idle_add(self._applied, None, exc)

        threading.Thread(target=work, daemon=True).start()

    def _applied(self, result, error) -> bool:
        self._busy = False
        self.switch.set_sensitive(True)
        if error is not None:
            self._show_error(str(error))
            self._refresh_silent()
            return False
        if result is not None:
            self.key_entry.set_text("")
            self._show_status(result)
        else:
            self._show_status(
                {
                    "running": False,
                    "headline": "Not connected",
                    "detail": "Tunnel is stopped. The saved key and list stay on disk.",
                    "warnings": [],
                    "ips": self.ips,
                    "domains": self.domains,
                    "apps": self.apps,
                    "all_traffic": self.all_check.get_active(),
                }
            )
        return False

    def _ensure_daemon(self) -> None:
        if _service_current():
            return
        if self._daemon is None or self._daemon.poll() is not None:
            self._daemon = subprocess.Popen(
                ["/usr/bin/pkexec", "/usr/bin/python3", str(DAEMON)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        for _ in range(150):
            if _service_current():
                return
            if self._daemon.poll() is not None:
                err = (self._daemon.stderr.read() if self._daemon.stderr else b"").decode("utf-8", "replace").strip()
                raise AppError(err or "Authorization was dismissed, so the tunnel did not start.")
            time.sleep(0.4)
        raise AppError("The tunnel service did not start.")

    def _load_vpnbook(self) -> None:
        if self._busy:
            return
        self._run_key({"cmd": "vpnbook"})

    def _add_key(self) -> None:
        text = self.key_entry.get_text().strip()
        if not text or self._busy:
            return
        self._run_key({"cmd": "add", "key": text}, clear_entry=True)

    def _remove_key(self) -> None:
        if not self.selected_id or self._busy:
            return
        self._run_key({"cmd": "remove", "id": self.selected_id})

    def _on_combo(self, combo) -> None:
        if self._updating or self._busy:
            return
        key_id = combo.get_active_id()
        if not key_id or key_id == self.selected_id:
            return
        self._run_key({"cmd": "select", "id": key_id})

    def _on_menu_key(self, item) -> None:
        if self._updating or self._busy:
            return
        key_id = item.outline_key_id
        if key_id == self.selected_id:
            if not item.get_active():
                item.set_active(True)
            return
        self._updating = True
        for child in self.key_menu.get_children():
            child.set_active(child is item)
        self._updating = False
        self.selected_id = key_id
        self._run_key({"cmd": "select", "id": key_id})

    def _run_key(self, payload: dict, clear_entry: bool = False) -> None:
        self._busy = True
        self.switch.set_sensitive(False)
        self._show_error("")

        def work():
            try:
                self._ensure_daemon()
                result = request(payload, SOCKET_PATH, timeout=60)
                GLib.idle_add(self._key_done, result, None, clear_entry)
            except Exception as exc:
                GLib.idle_add(self._key_done, None, exc, False)

        threading.Thread(target=work, daemon=True).start()

    def _key_done(self, result, error, clear_entry: bool) -> bool:
        self._busy = False
        self.switch.set_sensitive(True)
        if error is not None:
            self._show_error(str(error))
            self._refresh_silent()
            return False
        if clear_entry:
            self.key_entry.set_text("")
        if result is not None:
            self._show_status(result)
        return False

    def _show_keys(self, keys: list, selected: str) -> None:
        self.saved_keys = list(keys)
        self.selected_id = selected if any(item.get("id") == selected for item in keys) else ""
        self.key_combo.remove_all()
        for item in keys:
            self.key_combo.append(item["id"], _key_label(item))
        if self.selected_id:
            self.key_combo.set_active_id(self.selected_id)
        self.remove_key_button.set_sensitive(bool(self.selected_id))
        signature = tuple((item.get("id") or "", _key_short_label(item)) for item in keys)
        if signature != self._key_menu_signature:
            for child in list(self.key_menu.get_children()):
                self.key_menu.remove(child)
            for key_id, label in signature:
                entry = Gtk.CheckMenuItem.new_with_label(label)
                entry.set_draw_as_radio(True)
                entry.outline_key_id = key_id
                entry.connect("activate", self._on_menu_key)
                self.key_menu.append(entry)
                entry.show()
            self._key_menu_signature = signature
        for entry in self.key_menu.get_children():
            active = entry.outline_key_id == self.selected_id
            if entry.get_active() != active:
                entry.set_active(active)
        self.key_item.set_sensitive(bool(keys))

    def _refresh_silent(self) -> bool:
        if self._busy:
            return True

        def work():
            try:
                if not _socket_up():
                    GLib.idle_add(self._show_offline)
                    return
                result = request({"cmd": "status"}, SOCKET_PATH, timeout=2)
                GLib.idle_add(self._show_status, result)
            except Exception:
                return

        threading.Thread(target=work, daemon=True).start()
        return True

    def _show_offline(self) -> bool:
        if self._busy or self.window is None:
            return False
        self._updating = True
        self.switch.set_active(False)
        self.header.set_subtitle("Not connected")
        self.menu_status.set_label("Not connected")
        self.menu_toggle.set_label("Turn on")
        self.indicator.set_icon_full("network-offline", "Not connected")
        self.indicator.set_label("", "")
        self.status_label.set_text("Turn the switch on to connect. Ubuntu will ask for your password the first time.")
        self._updating = False
        return False

    def _show_status(self, data: dict) -> bool:
        if self.window is None or self._busy:
            return False
        self._updating = True
        running = bool(data.get("running"))
        self.switch.set_active(running)
        if running or not self._synced:
            self.ips = list(data.get("ips") or [])
            self.domains = list(data.get("domains") or [])
            self.apps = list(data.get("apps") or [])
            self._render_lists()
            self._synced = True
        if "keys" in data:
            self._show_keys(data.get("keys") or [], data.get("selected") or "")
        all_traffic = bool(data.get("all_traffic"))
        self.all_check.set_active(all_traffic)
        self.menu_all.set_active(all_traffic)
        self.split_box.set_visible(not all_traffic)
        headline = data.get("headline") or "Not connected"
        detail = data.get("detail") or ""
        warnings = data.get("warnings") or []
        text = headline if not detail else f"{headline}\n{detail}"
        if warnings:
            text += "\n" + "\n".join(warnings)
        notice = data.get("notice") or ""
        if notice:
            text += "\n" + notice
        if "keys" not in data and data.get("key_saved"):
            text += "\nTurn the switch on once to update the service. Your saved key stays, and then you can add more."
        self.status_label.set_text(text)
        self.header.set_subtitle("Connected" if running else "Not connected")
        self.menu_status.set_label(headline)
        self.menu_toggle.set_label("Turn off" if running else "Turn on")
        if running and all_traffic:
            self.indicator.set_icon_full("network-vpn", "Routing all traffic")
            self.indicator.set_label("All", "All")
        elif running:
            self.indicator.set_icon_full("network-vpn", "Connected")
            self.indicator.set_label("VPN", "VPN")
        else:
            self.indicator.set_icon_full("network-offline", "Not connected")
            self.indicator.set_label("", "")
        self._updating = False
        return False

    def _show_error(self, message: str) -> None:
        self.error_label.set_text(message)
        self.error_label.set_visible(bool(message))

    def _load_catalog(self) -> None:
        try:
            self.catalog = catalog()
        except Exception:
            self.catalog = []

    def _quit(self) -> None:
        def work():
            try:
                if _socket_up():
                    request({"cmd": "stop"}, SOCKET_PATH, timeout=20)
            except Exception:
                pass
            GLib.idle_add(self.quit)

        threading.Thread(target=work, daemon=True).start()


def _key_label(item: dict) -> str:
    name = item.get("name") or ""
    server = item.get("server") or ""
    if name and server:
        return f"{name} — {server}"
    return name or server or "Key"


def _key_short_label(item: dict) -> str:
    name = (item.get("name") or "").strip()
    if name:
        return name
    server = (item.get("server") or "").split(":", 1)[0]
    return server or "Key"


def _service_current() -> bool:
    try:
        status = request({"cmd": "status"}, SOCKET_PATH, timeout=1)
    except OSError:
        return False
    return "keys" in status


def _socket_up() -> bool:
    try:
        request({"cmd": "status"}, SOCKET_PATH, timeout=1)
    except OSError:
        return False
    return True


def main() -> None:
    app = OutlineSplit()
    app.run(sys.argv)


if __name__ == "__main__":
    main()
