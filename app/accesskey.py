import base64
from dataclasses import dataclass
from urllib.parse import unquote, unquote_to_bytes

from app.errors import AppError

# Ciphers sing-box accepts on a Shadowsocks outbound.
CIPHERS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "chacha20",
}


@dataclass(frozen=True)
class ShadowsocksKey:
    method: str
    password: str
    server: str
    port: int
    prefix: bytes
    name: str

    def __repr__(self) -> str:
        return (
            "ShadowsocksKey("
            f"server={self.server!r}, port={self.port}, method={self.method!r}, "
            f"prefix={bool(self.prefix)}, name={self.name!r})"
        )


def summary_of(key: ShadowsocksKey) -> dict:
    return {
        "server": f"{key.server}:{key.port}",
        "method": key.method,
        "prefix": bool(key.prefix),
        "name": key.name,
    }


def parse_access_key(raw: str) -> ShadowsocksKey:
    text = raw.strip().strip('"').strip("'").lstrip("\ufeff")
    found = text.lower().find("ss://")
    if found < 0:
        raise AppError("Key must start with ss://")
    text = text[found + 5 :]
    body, name = _split_fragment(text)
    body, query = _split_query(body)
    prefix = _prefix(query)
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        method, password = _method_password(userinfo)
        server, port = _split_host_port(hostport.rstrip("/"))
    else:
        try:
            decoded = _b64(body).decode("utf-8")
        except UnicodeError as exc:
            raise AppError("Key encoding is not valid") from exc
        if "@" not in decoded:
            raise AppError("Key is missing a server address")
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = _method_password(userinfo)
        server, port = _split_host_port(hostport.rstrip("/"))
    if not password:
        raise AppError("Key is missing a password")
    return ShadowsocksKey(method, password, server, port, prefix, name)


def _split_fragment(text: str) -> tuple[str, str]:
    left, sep, right = text.partition("#")
    if not sep:
        return text, ""
    name = unquote(right)
    name = "".join(ch for ch in name if ch.isprintable()).strip()[:80]
    return left, name


def _split_query(body: str) -> tuple[str, str]:
    left, sep, right = body.partition("?")
    if not sep:
        return body, ""
    return left, right


def _prefix(query: str) -> bytes:
    for part in query.split("&"):
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep or unquote(key) != "prefix":
            continue
        raw = unquote_to_bytes(value)
        if len(raw) > 256:
            raise AppError("Prefix is too long")
        return raw
    return b""


def _method_password(userinfo: str) -> tuple[str, str]:
    decoded = unquote(userinfo)
    if ":" in decoded:
        method, password = decoded.split(":", 1)
        canonical = _canonical(method)
        if canonical and password:
            return canonical, password
    try:
        raw = _b64(decoded).decode("utf-8")
    except (UnicodeError, AppError):
        raw = ""
    if ":" in raw:
        method, password = raw.split(":", 1)
        canonical = _canonical(method)
        if canonical and password:
            return canonical, password
        if method.strip() and not canonical:
            shown = method.strip()[:40]
            raise AppError(f"Unsupported cipher: {shown}")
    raise AppError("Key is missing a supported cipher and password")


def _canonical(method: str) -> str | None:
    key = method.strip().lower()
    if key in CIPHERS:
        return key
    return None


def _b64(data: str) -> bytes:
    cleaned = data.strip().replace("-", "+").replace("_", "/")
    cleaned += "=" * ((-len(cleaned)) % 4)
    try:
        return base64.b64decode(cleaned, validate=False)
    except Exception as exc:
        raise AppError("Key encoding is not valid base64") from exc


def _split_host_port(hostport: str) -> tuple[str, int]:
    hostport = unquote(hostport.strip())
    if hostport.startswith("["):
        end = hostport.find("]")
        if end < 0:
            raise AppError("Key has an invalid server address")
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if not rest.startswith(":"):
            raise AppError("Key is missing a port")
        port_text = rest[1:]
    else:
        if ":" not in hostport:
            raise AppError("Key is missing a port")
        host, port_text = hostport.rsplit(":", 1)
    host = host.strip()
    if not host:
        raise AppError("Key is missing a server address")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise AppError("Key has an invalid port") from exc
    if not 1 <= port <= 65535:
        raise AppError("Key has an invalid port")
    return host, port
