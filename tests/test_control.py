import tempfile
import threading
import time
import unittest
from pathlib import Path

from app.control import request, serve
from app.errors import AppError
from app.supervisor import Supervisor


class ControlTests(unittest.TestCase):
    def test_status_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supervisor = Supervisor(root)
            socket_path = root / "control.sock"
            stop = threading.Event()
            thread = threading.Thread(target=serve, args=(supervisor, socket_path, stop), daemon=True)
            thread.start()
            deadline = time.monotonic() + 2
            status = None
            while time.monotonic() < deadline:
                try:
                    status = request({"cmd": "status"}, socket_path)
                    break
                except OSError:
                    time.sleep(0.02)
            self.assertIsNotNone(status)
            self.assertEqual(status["headline"], "Not routing")
            self.assertFalse(status["all_traffic"])
            with self.assertRaises(AppError):
                request({"cmd": "nope"}, socket_path)
            stop.set()
            thread.join(2)


if __name__ == "__main__":
    unittest.main()
