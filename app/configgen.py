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
    platform: str = "linux",
    process_names: list[str] | None = None,
) -> dict:
    names = list(domains or [])
    processes = [item for item in (process_names or []) if item]
    route_address = list(route_address)
    if names and FAKE_CIDR not in route_address:
        route_address.append(FAKE_CIDR)
    windows = platform == "windows"
    # Windows has no cgroup mark. Selected programs and domain names need every
    # packet in the adapter; sing-box then sends the rest out the normal route.
    capture_all = windows and bool(processes or names)
    if capture_all:
        route_address = [item for item in route_address if item != FAKE_CIDR]
    tun_routes = [] if capture_all else route_address
    if not tun_routes and not for_apps and not capture_all:
        raise ValueError("route_address is empty")
    server = RELAY_HOST if use_relay else server_ip
    port = RELAY_PORT if use_relay else server_port
    addresses = ["10.255.255.1/30"]
    if for_apps or capture_all or any(ipaddress.ip_network(item).version == 6 for item in tun_routes):
        addresses.append("fd00:ffff:255::1/126")
    tun: dict = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": TUN_INTERFACE,
        "address": addresses,
        "mtu": 1400,
        "auto_route": bool(tun_routes) or capture_all,
        "strict_route": False,
        "stack": "gvisor",
    }
    rules: list[dict] = [
        {"action": "sniff"},
        {"protocol": "dns", "action": "hijack-dns"},
    ]
    if tun_routes and not windows:
        tun["iproute2_table_index"] = TUN_TABLE
        tun["iproute2_rule_index"] = TUN_TABLE
        tun["route_address"] = tun_routes
        if route_exclude:
            tun["route_exclude_address"] = route_exclude
    elif tun_routes:
        tun["route_address"] = tun_routes
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
    if processes:
        rules.append(
            {
                "process_name": processes,
                "action": "route",
                "outbound": "proxy",
            }
        )
    proxy_cidrs = list(route_address)
    if capture_all and names and FAKE_CIDR not in proxy_cidrs:
        proxy_cidrs.append(FAKE_CIDR)
    if proxy_cidrs:
        rules.append(
            {
                "ip_cidr": proxy_cidrs,
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
        "final": "proxy" if for_apps and not capture_all else "direct",
    }
    if names:
        route["default_domain_resolver"] = "dns-proxy"
    full = any(ipaddress.ip_network(item).prefixlen == 0 for item in proxy_cidrs)
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": _dns(names, direct_dns, direct_final=windows and not names and not full),
        "inbounds": [tun],
        "outbounds": outbounds,
        "route": route,
    }


def _dns(domains: list[str], direct_dns: str, direct_final: bool = False) -> dict:
    proxy = {
        "type": "tcp",
        "tag": "dns-proxy",
        "server": "1.1.1.1",
        "server_port": 53,
        "detour": "proxy",
    }
    if not domains and not direct_final:
        return {"servers": [proxy], "strategy": "prefer_ipv4", "final": "dns-proxy"}
    if not domains:
        return {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": direct_dns,
                    "server_port": 53,
                }
            ],
            "strategy": "prefer_ipv4",
            "final": "dns-direct",
        }
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
