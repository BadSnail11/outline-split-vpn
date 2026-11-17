import json
import unittest

from app.configgen import build_config
from app.iplist import all_traffic_routes
from app.programs import normalize_programs
from app.settings import FAKE_CIDR


def _config(**overrides):
    values = {
        "method": "chacha20-ietf-poly1305",
        "password": "s3cret",
        "server_ip": "203.0.113.8",
        "server_port": 443,
        "use_relay": False,
        "route_address": ["198.51.100.10/32"],
        "route_exclude": ["203.0.113.8/32"],
        "platform": "windows",
    }
    values.update(overrides)
    return build_config(**values)


class WindowsConfigTests(unittest.TestCase):
    def test_listed_address_stays_a_limited_route(self) -> None:
        config = _config()
        tun = config["inbounds"][0]
        self.assertEqual(tun["route_address"], ["198.51.100.10/32"])
        self.assertNotIn("iproute2_table_index", tun)
        self.assertEqual(config["route"]["final"], "direct")
        self.assertEqual(config["dns"]["final"], "dns-direct")
        self.assertNotIn("process_name", json.dumps(config["route"]))

    def test_program_captures_the_adapter_and_matches_the_exe(self) -> None:
        config = _config(route_address=[], for_apps=True, process_names=["firefox.exe"])
        tun = config["inbounds"][0]
        self.assertTrue(tun["auto_route"])
        self.assertNotIn("route_address", tun)
        self.assertNotIn("iproute2_table_index", tun)
        self.assertEqual(config["route"]["final"], "direct")
        matched = [rule for rule in config["route"]["rules"] if "process_name" in rule]
        self.assertEqual(matched, [{"process_name": ["firefox.exe"], "action": "route", "outbound": "proxy"}])

    def test_domain_uses_fakeip_without_a_limited_route(self) -> None:
        config = _config(route_address=[FAKE_CIDR], domains=["example.com"])
        tun = config["inbounds"][0]
        self.assertNotIn("route_address", tun)
        self.assertTrue(tun["auto_route"])
        encoded = json.dumps(config)
        self.assertIn(FAKE_CIDR, encoded)
        self.assertEqual(config["dns"]["final"], "dns-direct")
        self.assertEqual(config["route"]["default_domain_resolver"], "dns-proxy")
        self.assertEqual(config["route"]["final"], "direct")

    def test_all_traffic_keeps_the_default_routes(self) -> None:
        routes, excludes = all_traffic_routes(["203.0.113.8"])
        config = _config(route_address=routes, route_exclude=excludes)
        tun = config["inbounds"][0]
        self.assertIn("0.0.0.0/0", tun["route_address"])
        self.assertNotIn("iproute2_table_index", tun)
        self.assertEqual(config["dns"]["final"], "dns-proxy")
        self.assertEqual(config["route"]["final"], "direct")


class WindowsProgramTests(unittest.TestCase):
    def test_exe_path_is_a_process_name(self) -> None:
        chosen = normalize_programs(
            [{"name": "", "exec": r"C:\Program Files\Mozilla Firefox\firefox.exe", "match": "exe"}]
        )
        self.assertEqual(chosen[0]["match"], "process")
        self.assertEqual(chosen[0]["name"], "firefox.exe")
        self.assertTrue(chosen[0]["exec"].endswith("firefox.exe"))

    def test_bare_exe_name_is_accepted(self) -> None:
        chosen = normalize_programs([{"name": "Firefox", "exec": "firefox.exe", "match": "process"}])
        self.assertEqual(chosen[0]["name"], "Firefox")
        self.assertEqual(chosen[0]["exec"], "firefox.exe")
