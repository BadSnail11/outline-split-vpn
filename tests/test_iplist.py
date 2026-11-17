import unittest

from app.errors import AppError
from app.iplist import all_traffic_routes, normalize, normalize_all, split_routes


class IpListTests(unittest.TestCase):
    def test_normalize_host_and_network(self) -> None:
        self.assertEqual(normalize("1.2.3.4"), "1.2.3.4/32")
        self.assertEqual(normalize("1.2.3.5/24"), "1.2.3.0/24")
        self.assertEqual(normalize("::1"), "::1/128")
        self.assertEqual(normalize_all(["1.2.3.4", "1.2.3.4/32", "8.8.8.8"]), ["1.2.3.4/32", "8.8.8.8/32"])

    def test_reject_names(self) -> None:
        with self.assertRaises(AppError):
            normalize("example.com")
        with self.assertRaises(AppError):
            normalize("")

    def test_split_routes_keeps_a_hole_for_the_server(self) -> None:
        self.assertEqual(split_routes(["0.0.0.0/0"], ["1.2.3.4"]), (["0.0.0.0/0"], ["1.2.3.4/32"]))
        self.assertEqual(split_routes(["1.2.3.4/32"], ["1.2.3.4"]), ([], []))
        self.assertEqual(split_routes(["8.8.8.8/32"], ["1.2.3.4"]), (["8.8.8.8/32"], []))
        self.assertEqual(split_routes(["2001:db8::/32"], ["1.2.3.4"]), (["2001:db8::/32"], []))

    def test_all_traffic_keeps_local_networks_and_the_server_direct(self) -> None:
        routes, excludes = all_traffic_routes(["203.0.113.8", "2001:db8::1"])
        self.assertEqual(routes, ["0.0.0.0/0", "::/0"])
        self.assertIn("192.168.0.0/16", excludes)
        self.assertIn("fc00::/7", excludes)
        self.assertIn("203.0.113.8/32", excludes)
        self.assertIn("2001:db8::1/128", excludes)


if __name__ == "__main__":
    unittest.main()
