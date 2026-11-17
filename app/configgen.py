import ipaddress

from app.settings import FAKE_CIDR, RELAY_HOST, RELAY_PORT, TUN_INTERFACE, TUN_TABLE


def build_config(
    *,
    method: str,
    password: str,
    server_ip: str,
    server_port: int,
    use_relay: bool,
    route_address: list[str],
    route_exclude: list[str],
    for_apps: bool = False,
    domains: list[str] | None = None,
    direct_dns: str = "1.1.1.1",
) -> dict:
    names = list(domains or [])
    route_address = list(route_address)
    if names and FAKE_CIDR not in route_address:
        route_address.append(FAKE_CIDR)
    if not route_address and not for_apps:
        raise ValueError("route_address is empty")
    server = RELAY_HOST if use_relay else server_ip
    port = RELAY_PORT if use_relay else server_port
    addresses = ["10.255.255.1/30"]
    if for_apps or any(ipaddress.ip_network(item).version == 6 for item in route_address):
        addresses.append("fd00:ffff:255::1/126")
    tun: dict = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": TUN_INTERFACE,
        "address": addresses,
        "mtu": 1400,
        "auto_route": bool(route_address),
        "strict_route": False,
        "stack": "gvisor",
    }
    rules: list[dict] = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    if route_address:
        tun["iproute2_table_index"] = TUN_TABLE
        tun["iproute2_rule_index"] = TUN_TABLE
        tun["route_address"] = route_address
        if route_exclude:
            tun["route_exclude_address"] = route_exclude
    if route_exclude:
        rules.append(
            {
                "ip_cidr": route_exclude,
                "action": "route",
                "outbound": "direct",
            }
        )
    if names:
        rules.append(
            {
                "domain_suffix": names,
                "action": "route",
                "outbound": "proxy",
            }
        )
    if route_address:
        rules.append(
            {
                "ip_cidr": route_address,
                "action": "route",
                "outbound": "proxy",
            }
        )
    outbounds = [
        {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": server,
            "server_port": port,
            "method": method,
            "password": password,
        },
        {"type": "direct", "tag": "direct"},
    ]
    route: dict = {
        "auto_detect_interface": True,
        "rules": rules,
        "final": "proxy" if for_apps else "direct",
    }
    if names:
        route["default_domain_resolver"] = "dns-proxy"
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": _dns(names, direct_dns),
        "inbounds": [tun],
        "outbounds": outbounds,
        "route": route,
    }


def _dns(domains: list[str], direct_dns: str) -> dict:
    proxy = {
        "type": "tcp",
        "tag": "dns-proxy",
        "server": "1.1.1.1",
        "server_port": 53,
        "detour": "proxy",
    }
    if not domains:
        return {"servers": [proxy], "strategy": "prefer_ipv4", "final": "dns-proxy"}
    return {
        "servers": [
            proxy,
            {
                "type": "udp",
                "tag": "dns-direct",
                "server": direct_dns,
                "server_port": 53,
            },
            {"type": "fakeip", "tag": "fakeip", "inet4_range": FAKE_CIDR},
        ],
        "rules": [
            {
                "domain_suffix": domains,
                "query_type": ["AAAA", "HTTPS"],
                "action": "reject",
            },
            {"domain_suffix": domains, "query_type": ["A"], "server": "fakeip"},
        ],
        "strategy": "prefer_ipv4",
        "final": "dns-direct",
    }
