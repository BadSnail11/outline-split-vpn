import socket
import threading
import unittest

from app.relay import PrefixRelay


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RelayTests(unittest.TestCase):
    def test_tcp_prefix_is_written_before_the_stream(self) -> None:
        upstream = _free_port()
        listen = _free_port()
        ready = threading.Event()
        received: dict[str, bytes] = {}

        def serve() -> None:
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", upstream))
                sock.listen(1)
                ready.set()
                conn, _addr = sock.accept()
                with conn:
                    conn.settimeout(2)
                    data = b""
                    while len(data) < len(b"POST cipher"):
                        chunk = conn.recv(64)
                        if not chunk:
                            break
                        data += chunk
                    received["data"] = data

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.assertTrue(ready.wait(2))
        relay = PrefixRelay(("127.0.0.1", listen), ("127.0.0.1", upstream), b"POST ")
        relay.start()
        try:
            with socket.create_connection(("127.0.0.1", listen), timeout=2) as client:
                client.sendall(b"cipher")
                client.shutdown(socket.SHUT_WR)
            thread.join(3)
        finally:
            relay.stop()
        self.assertEqual(received.get("data"), b"POST cipher")


if __name__ == "__main__":
    unittest.main()
