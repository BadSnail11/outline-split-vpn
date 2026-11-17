import json
import unittest

from app.configgen import build_config
from app.iplist import all_traffic_routes
from app.settings import FAKE_CIDR, RELAY_HOST, RELAY_PORT


class ConfigTests(unittest.TestCase):
    def test_prefix_uses_local_relay_and_listed_routes_only(self) -> None:
        config = build_config(
            method="chacha20-ietf-poly1305",
            password="s3cret",
            server_ip="203.0.113.8",
            server_port=443,
            use_relay=True,
            route_address=["198.51.100.0/24"],
            route_exclude=["203.0.113.8/32"],
        )
        encoded = json.dumps(config)
        self.assertNotIn("POST ", encoded)
        tun = config["inbounds"][0]
        proxy = config["outbounds"][0]
        self.assertEqual(tun["route_address"], ["198.51.100.0/24"])
        self.assertEqual(tun["route_exclude_address"], ["203.0.113.8/32"])
        self.assertNotIn("0.0.0.0/0", tun["route_address"])
        self.assertEqual(proxy["server"], RELAY_HOST)
        self.assertEqual(proxy["server_port"], RELAY_PORT)
        self.assertEqual(proxy["password"], "s3cret")
        self.assertEqual(config["route"]["final"], "direct")
        routed = [rule for rule in config["route"]["rules"] if rule.get("action") == "route"]
        self.assertEqual(routed[0]["outbound"], "direct")
        self.assertEqual(routed[1]["outbound"], "proxy")
        self.assertEqual(config["dns"]["final"], "dns-proxy")
        self.assertEqual(config["dns"]["servers"][0]["type"], "tcp")
        self.assertEqual(config["dns"]["servers"][0]["detour"], "proxy")

    def test_plain_key_dials_the_server_directly(self) -> None:
        config = build_config(
            method="aes-256-gcm",
            password="s3cret",
            server_ip="203.0.113.8",
            server_port=8388,
            use_relay=False,
            route_address=["2001:db8::/32"],
            route_exclude=[],
        )
        proxy = config["outbounds"][0]
        self.assertEqual(proxy["server"], "203.0.113.8")
        self.assertEqual(proxy["server_port"], 8388)
        self.assertIn("fd00:ffff:255::1/126", config["inbounds"][0]["address"])
        self.assertNotIn("route_exclude_address", config["inbounds"][0])

    def test_applications_capture_traffic_without_a_default_route(self) -> None:
        config = build_config(
            method="chacha20-ietf-poly1305",
            password="s3cret",
            server_ip="203.0.113.8",
            server_port=443,
            use_relay=False,
            route_address=[],
            route_exclude=["203.0.113.8/32"],
            for_apps=True,
        )
        tun = config["inbounds"][0]
        self.assertFalse(tun["auto_route"])
        self.assertNotIn("route_address", tun)
        self.assertEqual(config["route"]["final"], "proxy")
        routed = [rule for rule in config["route"]["rules"] if rule.get("action") == "route"]
        self.assertEqual(routed[0]["outbound"], "direct")
        self.assertEqual(config["route"]["rules"][0]["action"], "sniff")
        self.assertEqual(config["route"]["rules"][1]["action"], "hijack-dns")
        self.assertIn("fd00:ffff:255::1/126", tun["address"])

    def test_all_traffic_installs_default_routes_with_local_exclusions(self) -> None:
        routes, excludes = all_traffic_routes(["203.0.113.8"])
        config = build_config(
            method="chacha20-ietf-poly1305",
            password="s3cret",
            server_ip="203.0.113.8",
            server_port=443,
            use_relay=False,
            route_address=routes,
            route_exclude=excludes,
        )
        tun = config["inbounds"][0]
        self.assertTrue(tun["auto_route"])
        self.assertEqual(tun["route_address"], ["0.0.0.0/0", "::/0"])
        self.assertIn("192.168.0.0/16", tun["route_exclude_address"])
        self.assertIn("203.0.113.8/32", tun["route_exclude_address"])
        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(config["route"]["rules"][-1]["outbound"], "proxy")
        self.assertIn("fd00:ffff:255::1/126", tun["address"])

    def test_domains_use_a_tunnel_address_and_leave_other_names_direct(self) -> None:
        config = build_config(
            method="chacha20-ietf-poly1305",
            password="s3cret",
            server_ip="203.0.113.8",
            server_port=443,
            use_relay=False,
            route_address=[],
            route_exclude=["203.0.113.8/32"],
            domains=["example.com"],
        )
        tun = config["inbounds"][0]
        self.assertIn(FAKE_CIDR, tun["route_address"])
        self.assertEqual(config["dns"]["final"], "dns-direct")
        self.assertEqual(config["dns"]["rules"][1]["server"], "fakeip")
        self.assertEqual(config["dns"]["rules"][1]["domain_suffix"], ["example.com"])
        self.assertEqual(config["route"]["default_domain_resolver"], "dns-proxy")
        self.assertEqual(config["dns"]["servers"][1]["server"], "1.1.1.1")
        names = [rule for rule in config["route"]["rules"] if rule.get("domain_suffix")]
        self.assertEqual(names[0]["outbound"], "proxy")

    def test_empty_route_list_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            build_config(
                method="aes-256-gcm",
                password="s3cret",
                server_ip="203.0.113.8",
                server_port=8388,
                use_relay=False,
                route_address=[],
                route_exclude=[],
            )


if __name__ == "__main__":
    unittest.main()
