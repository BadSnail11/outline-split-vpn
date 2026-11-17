import base64
import json
import tempfile
import unittest
from pathlib import Path

from app.errors import AppError
from app.supervisor import Supervisor
from app.vpnbook import parse_vpnbook_page


def _secret(server: str, password: str = "s3cret") -> str:
    token = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{password}".encode()).decode().rstrip("=")
    return f"ss://{token}@{server}:443/?outline=1"


def _page(pairs: list[tuple[str, str, str]]) -> str:
    chunks = []
    for name, server, password in pairs:
        chunks.append(
            'name\\":\\"'
            + name
            + '\\",\\"hostname\\":\\"'
            + server
            + '\\",\\"connectionString\\":\\"'
            + _secret(server, password)
            + '\\"'
        )
    return "<script>" + "".join(chunks) + "</script>"


class VpnBookTests(unittest.TestCase):
    def test_page_pairs_each_server_with_its_name(self) -> None:
        keys = parse_vpnbook_page(_page([("Poland Server 1", "pl.example.com", "s3cret")]))
        self.assertEqual(len(keys), 1)
        self.assertIn("pl.example.com:443", keys[0])
        self.assertTrue(keys[0].endswith("#Poland%20Server%201"))

    def test_page_without_keys_is_rejected(self) -> None:
        with self.assertRaises(AppError):
            parse_vpnbook_page("<html>no keys here</html>")

    def test_import_keeps_the_chosen_server_and_updates_a_changed_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(Path(tmp))
            first = supervisor.import_secrets(
                parse_vpnbook_page(
                    _page(
                        [
                            ("Poland Server 1", "pl.example.com", "s3cret"),
                            ("Canada Server 3", "ca.example.com", "s3cret"),
                        ]
                    )
                )
            )
            self.assertEqual(len(first["keys"]), 2)
            self.assertEqual(first["summary"]["name"], "Poland Server 1")
            self.assertEqual(first["notice"], "Added 2 VPNBook keys.")
            chosen = first["selected"]
            again = supervisor.import_secrets(
                parse_vpnbook_page(
                    _page(
                        [
                            ("Poland Server 1", "pl.example.com", "rotated"),
                            ("Canada Server 3", "ca.example.com", "s3cret"),
                        ]
                    )
                )
            )
            self.assertEqual(len(again["keys"]), 2)
            self.assertEqual(again["selected"], chosen)
            self.assertEqual(again["notice"], "Refreshed 1 VPNBook key.")
            self.assertNotIn("rotated", json.dumps(again))
            self.assertNotIn("s3cret", json.dumps(again))

    def test_refresh_replaces_a_key_saved_by_address(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(Path(tmp))
            saved = supervisor.add_key(_secret("203.0.113.10", "old-secret") + "#Old")
            chosen = saved["selected"]
            refreshed = supervisor.import_secrets(
                parse_vpnbook_page(_page([("Poland Server 1", "pl.example.com", "rotated")])),
                {"pl.example.com": ["203.0.113.10"]},
            )
            self.assertEqual(len(refreshed["keys"]), 1)
            self.assertEqual(refreshed["selected"], chosen)
            self.assertEqual(refreshed["summary"]["name"], "Poland Server 1")
            self.assertEqual(refreshed["summary"]["server"], "pl.example.com:443")
            self.assertEqual(refreshed["notice"], "Refreshed 1 VPNBook key.")
            self.assertNotIn("old-secret", json.dumps(refreshed))
            self.assertNotIn("rotated", json.dumps(refreshed))


if __name__ == "__main__":
    unittest.main()
