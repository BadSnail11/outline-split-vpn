import unittest

from app.accesskey import parse_access_key
from app.errors import AppError


def _token(text: str) -> str:
    import base64

    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


class AccessKeyTests(unittest.TestCase):
    def test_sip002_with_outline_prefix(self) -> None:
        user = _token("chacha20-ietf-poly1305:s3cret")
        key = parse_access_key(
            f"ss://{user}@vpn.example.com:443/?outline=1&prefix=POST%20#Office%20link"
        )
        self.assertEqual(key.method, "chacha20-ietf-poly1305")
        self.assertEqual(key.password, "s3cret")
        self.assertEqual(key.server, "vpn.example.com")
        self.assertEqual(key.port, 443)
        self.assertEqual(key.prefix, b"POST ")
        self.assertEqual(key.name, "Office link")
        self.assertNotIn("s3cret", repr(key))

    def test_binary_prefix_is_not_decoded_as_text(self) -> None:
        user = _token("aes-256-gcm:s3cret")
        prefix = bytes([0x05, 0xDC, 0x5F, 0x00])
        encoded = "".join(f"%{byte:02X}" for byte in prefix)
        key = parse_access_key(f"ss://{user}@10.1.2.3:8388/?prefix={encoded}")
        self.assertEqual(key.prefix, prefix)
        self.assertEqual(key.server, "10.1.2.3")

    def test_legacy_base64_and_plain_userinfo(self) -> None:
        legacy = _token("chacha20-ietf-poly1305:s3cret@10.1.2.3:8388")
        parsed = parse_access_key(f"ss://{legacy}#legacy")
        self.assertEqual(parsed.server, "10.1.2.3")
        self.assertEqual(parsed.port, 8388)
        self.assertEqual(parsed.prefix, b"")
        plain = parse_access_key("ss://chacha20-ietf-poly1305:pass:word@[2001:db8::1]:9443")
        self.assertEqual(plain.password, "pass:word")
        self.assertEqual(plain.server, "2001:db8::1")
        self.assertEqual(plain.port, 9443)

    def test_rejects_bad_keys(self) -> None:
        with self.assertRaises(AppError):
            parse_access_key("https://example")
        with self.assertRaises(AppError):
            parse_access_key("ss://not-a-key")
        with self.assertRaises(AppError):
            parse_access_key(f"ss://{_token('made-up:s3cret')}@10.0.0.1:1")


if __name__ == "__main__":
    unittest.main()
