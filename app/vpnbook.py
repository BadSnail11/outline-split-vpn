import json
import re
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.accesskey import parse_access_key
from app.errors import AppError

VPNBOOK_URL = "https://www.vpnbook.com/ru/freevpn/outline-vpn"
_PAGE_LIMIT = 2_000_000
_PAIR = re.compile(
    r'name\\":\\"(?P<name>[^\\"]*)\\"'
    r'.{0,800}?'
    r'connectionString\\":\\"(?P<key>ss://[^\\"]*)\\"',
    re.S,
)


def fetch_vpnbook_keys(url: str = VPNBOOK_URL) -> list[str]:
    request = Request(url, headers={"User-Agent": "outline-split"})
    try:
        with urlopen(request, timeout=20) as response:
            raw = response.read(_PAGE_LIMIT + 1)
    except (OSError, TimeoutError) as exc:
        raise AppError("Could not download the VPNBook page.") from exc
    if len(raw) > _PAGE_LIMIT:
        raise AppError("The VPNBook page is too large.")
    return parse_vpnbook_page(raw.decode("utf-8", "replace"))


def parse_vpnbook_page(html: str) -> list[str]:
    found: list[str] = []
    seen: set[tuple[str, int]] = set()
    for match in _PAIR.finditer(html):
        secret = _with_name(_js_unescape(match.group("key")), _js_unescape(match.group("name")))
        try:
            parsed = parse_access_key(secret)
        except AppError:
            continue
        identity = (parsed.server, parsed.port)
        if identity in seen:
            continue
        seen.add(identity)
        found.append(secret)
    if not found:
        raise AppError("No Outline keys were found on the VPNBook page.")
    return found


def _with_name(secret: str, name: str) -> str:
    secret = secret.strip()
    name = "".join(ch for ch in name if ch.isprintable()).strip()[:80]
    if not name or "#" in secret:
        return secret
    return secret + "#" + quote(name, safe="")


def _js_unescape(value: str) -> str:
    try:
        return json.loads(f'"{value}"')
    except json.JSONDecodeError:
        return value
