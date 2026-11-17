import os
import unittest
from pathlib import Path

from app.approute import nft_ruleset
from app.errors import AppError
from app.programs import catalog, matching_pids, normalize_programs, program_matches


class ProgramTests(unittest.TestCase):
    def test_desktop_catalog_reads_name_and_exec(self) -> None:
        root = Path(self.id().replace(".", "_"))
        # Keep the fixture next to the test process, under /tmp.
        directory = Path("/tmp") / root
        directory.mkdir(parents=True, exist_ok=True)
        desktop = directory / "firefox.desktop"
        desktop.write_text(
            "\n".join(
                [
                    "[Desktop Entry]",
                    "Type=Application",
                    "Name=Firefox Web Browser",
                    "Exec=firefox %u",
                    "",
                    "[Desktop Action New]",
                    "Name=New Window",
                    "Exec=firefox --new-window",
                ]
            ),
            encoding="utf-8",
        )
        (directory / "hidden.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=Hidden\nExec=/bin/hidden\nNoDisplay=true\n",
            encoding="utf-8",
        )
        (directory / "flatpak.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=Flat Firefox\nExec=flatpak run --branch=stable org.mozilla.firefox\n",
            encoding="utf-8",
        )
        found = catalog([directory])
        by_name = {item["name"]: item for item in found}
        self.assertEqual(by_name["Firefox Web Browser"]["exec"], "firefox")
        self.assertEqual(by_name["Firefox Web Browser"]["match"], "exe")
        self.assertEqual(by_name["Flat Firefox"]["exec"], "org.mozilla.firefox")
        self.assertEqual(by_name["Flat Firefox"]["match"], "cmdline")
        self.assertNotIn("Hidden", by_name)

    def test_normalize_and_match(self) -> None:
        programs = normalize_programs(
            [
                {"name": "Firefox", "exec": "/usr/bin/firefox", "match": "exe"},
                "/usr/bin/telegram-desktop",
                {"name": "Flat", "exec": "org.mozilla.firefox", "match": "cmdline"},
            ]
        )
        self.assertEqual(programs[1]["exec"], "/usr/bin/telegram-desktop")
        self.assertTrue(program_matches("/snap/firefox/1/usr/lib/firefox/firefox", "", programs[0]))
        self.assertFalse(
            program_matches(
                "/usr/bin/python3",
                "python3 -m app",
                {"name": "Python", "exec": "/usr/local/bin/python3", "match": "exe"},
            )
        )
        self.assertTrue(
            program_matches(
                "/usr/bin/bwrap",
                "bwrap flatpak run org.mozilla.firefox",
                programs[2],
            )
        )
        with self.assertRaises(AppError):
            normalize_programs([{"name": "Shell", "exec": "bash", "match": "exe"}])

    def test_matching_pids_reads_proc(self) -> None:
        root = Path("/tmp/outline-split-proc")
        if root.exists():
            for child in root.iterdir():
                if child.is_symlink() or child.is_file():
                    child.unlink()
                elif child.is_dir():
                    for item in child.iterdir():
                        item.unlink()
                    child.rmdir()
        root.mkdir(exist_ok=True)
        proc = root / "42"
        proc.mkdir()
        target = root / "firefox-bin"
        target.write_text("", encoding="utf-8")
        (proc / "exe").symlink_to(target)
        (proc / "cmdline").write_bytes(b"/usr/bin/firefox\x00")
        found = matching_pids([{"name": "Firefox", "exec": str(target), "match": "exe"}], root)
        self.assertEqual(found, [42])
        os.unlink(proc / "exe")

    def test_matching_uses_command_path_and_child_processes(self) -> None:
        root = Path("/tmp/outline-split-proc-cmd")
        if root.exists():
            for child in root.iterdir():
                if child.is_dir():
                    for item in child.iterdir():
                        item.unlink()
                    child.rmdir()
        root.mkdir(exist_ok=True)
        parent = root / "42"
        parent.mkdir()
        (parent / "cmdline").write_bytes(b"/usr/bin/firefox\x00--type=utility\x00")
        (parent / "status").write_text("PPid:\t1\n", encoding="utf-8")
        child = root / "43"
        child.mkdir()
        (child / "cmdline").write_bytes(b"bunx\x00")
        (child / "status").write_text("PPid:\t42\n", encoding="utf-8")
        found = matching_pids([{"name": "Firefox", "exec": "/usr/bin/firefox", "match": "exe"}], root)
        self.assertEqual(found, [42, 43])

    def test_nft_rules_skip_local_and_server_addresses(self) -> None:
        rules = nft_ruleset(["203.0.113.8", "2001:db8::1"])
        self.assertIn("203.0.113.8/32", rules)
        self.assertIn("2001:db8::1/128", rules)
        self.assertIn("192.168.0.0/16", rules)
        self.assertIn('socket cgroupv2 level 1 "outline-split"', rules)
        self.assertIn("meta mark set 0x20819", rules)


if __name__ == "__main__":
    unittest.main()
