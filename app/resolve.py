import ipaddress
import socket

from app.errors import AppError


def resolve_host(host: str) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        query = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AppError("Server name is not valid") from exc
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5)
    try:
        try:
            infos = socket.getaddrinfo(query, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AppError(f"Could not resolve {host}") from exc
    finally:
        socket.setdefaulttimeout(previous)
    found: list[str] = []
    for info in infos:
        address = info[4][0].split("%", 1)[0]
        if address not in found:
            found.append(address)
    if not found:
        raise AppError(f"Could not resolve {host}")
    found.sort(key=lambda item: ipaddress.ip_address(item).version)
    return found
