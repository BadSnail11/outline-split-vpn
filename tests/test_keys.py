import base64
import json
import tempfile
import unittest
from pathlib import Path

from app.supervisor import Supervisor


def _key(name: str, server: str, password: str = "s3cret") -> str:
    token = base64.urlsafe_b64encode(f"chacha20-ietf-poly1305:{password}".encode()).decode().rstrip("=")
    return f"ss://{token}@{server}:443/?outline=1#{name}"


class KeyListTests(unittest.TestCase):
    def test_add_choose_and_hide_the_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(Path(tmp))
            first = supervisor.add_key(_key("Office", "vpn.example.com"))
            second = supervisor.add_key(_key("Home", "home.example.com", "other-secret"))
            self.assertEqual(len(second["keys"]), 2)
            self.assertEqual(second["selected"], second["keys"][1]["id"])
            self.assertNotIn("s3cret", json.dumps(second))
            self.assertNotIn("other-secret", json.dumps(second))
            chosen = supervisor.select_key(first["keys"][0]["id"])
            self.assertEqual(chosen["selected"], first["keys"][0]["id"])
            self.assertEqual(chosen["summary"]["name"], "Office")
            again = supervisor.add_key(_key("Office renamed", "vpn.example.com"))
            self.assertEqual(len(again["keys"]), 2)
            self.assertEqual(again["summary"]["name"], "Office renamed")

    def test_old_state_file_becomes_one_saved_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = _key("Legacy", "legacy.example.com")
            (root / "state.json").write_text(
                json.dumps({"key": secret, "ips": [], "apps": [], "enabled": False}) + "\n",
                encoding="utf-8",
            )
            supervisor = Supervisor(root)
            supervisor._load()
            status = supervisor.status()
            self.assertEqual(len(status["keys"]), 1)
            self.assertEqual(status["keys"][0]["name"], "Legacy")
            self.assertEqual(status["selected"], status["keys"][0]["id"])
            self.assertNotIn("s3cret", json.dumps(status))

    def test_remove_the_chosen_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            supervisor = Supervisor(Path(tmp))
            supervisor.add_key(_key("Office", "vpn.example.com"))
            second = supervisor.add_key(_key("Home", "home.example.com"))
            left = supervisor.remove_key(second["selected"])
            self.assertEqual(len(left["keys"]), 1)
            self.assertEqual(left["summary"]["name"], "Office")


if __name__ == "__main__":
    unittest.main()
