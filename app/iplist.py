import ipaddress

from app.errors import AppError


def normalize_all(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        network = normalize(value)
        if network not in seen:
            seen.append(network)
    return seen


def normalize(value: str) -> str:
    text = value.strip()
    if not text:
        raise AppError("Destination is empty")
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
        else:
            address = ipaddress.ip_address(text)
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
    except ValueError as exc:
        shown = text if len(text) <= 80 else f"{text[:80]}…"
        raise AppError(
            f"'{shown}' is not an IP address or network. Use 203.0.113.10 or 203.0.113.0/24."
        ) from exc
    return str(network)


LOCAL_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
)
LOCAL_V6 = ("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")


def all_traffic_routes(server_ips: list[str]) -> tuple[list[str], list[str]]:
    """Send every non-local address through the tunnel, and keep the server direct."""
    excludes = list(LOCAL_V4 + LOCAL_V6)
    for raw in server_ips:
        address = ipaddress.ip_address(raw.split("%", 1)[0])
        network = f"{address}/{address.max_prefixlen}"
        if network not in excludes:
            excludes.append(network)
    return ["0.0.0.0/0", "::/0"], excludes


def split_routes(destinations: list[str], server_ips: list[str]) -> tuple[list[str], list[str]]:
    """Return tun destinations and server addresses that must stay direct.

    A destination that is only the tunnel server is dropped. A wider destination
    that contains the server stays, and the server address is excluded so the
    tunnel can still reach its own endpoint.
    """
    servers = [_host_network(ip) for ip in server_ips]
    kept: list[str] = []
    excluded: list[str] = []
    for raw in destinations:
        dest = ipaddress.ip_network(raw)
        if any(_covers(server, dest) for server in servers):
            continue
        kept.append(str(dest))
        for server in servers:
            if server.version == dest.version and server.subnet_of(dest) and str(server) not in excluded:
                excluded.append(str(server))
    return kept, excluded


def _host_network(ip: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    address = ipaddress.ip_address(ip.split("%", 1)[0])
    return ipaddress.ip_network(f"{address}/{address.max_prefixlen}")


def _covers(outer: ipaddress.IPv4Network | ipaddress.IPv6Network, inner: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if outer.version != inner.version:
        return False
    return inner.subnet_of(outer)
