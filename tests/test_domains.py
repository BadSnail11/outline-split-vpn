import unittest

from app.domainroute import _default_links, _parse_links, _upstream_servers
from app.domains import normalize_domain, normalize_domains
from app.errors import AppError


STATUS = """
Global
         Protocols: -LLMNR

Link 2 (wlp0s20f3)
    Current Scopes: none
         Protocols: -DefaultRoute -LLMNR

Link 93 (outline-tun1)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR
Current DNS Server: 169.254.113.53
       DNS Servers: 169.254.113.53
        DNS Domain: ~.
"""


class DomainTests(unittest.TestCase):
    def test_normalize_suffix_and_case(self) -> None:
        self.assertEqual(normalize_domain("*.Example.COM."), "example.com")
        self.assertEqual(normalize_domains(["Example.com", "example.com", "www.example.com"]), [
            "example.com",
            "www.example.com",
        ])

    def test_reject_addresses_and_urls(self) -> None:
        with self.assertRaises(AppError):
            normalize_domain("203.0.113.10")
        with self.assertRaises(AppError):
            normalize_domain("https://example.com/path")
        with self.assertRaises(AppError):
            normalize_domain("com")

    def test_default_dns_link_is_the_one_resolved_uses(self) -> None:
        links = _default_links(STATUS)
        self.assertEqual(links, [{"name": "outline-tun1", "servers": ["169.254.113.53"]}])
        self.assertEqual(_upstream_servers(STATUS), [])
        wifi = STATUS.replace("169.254.113.53", "192.168.100.1")
        self.assertEqual(_upstream_servers(wifi), ["192.168.100.1"])
        self.assertTrue(any(link["default"] for link in _parse_links(STATUS)))


if __name__ == "__main__":
    unittest.main()
