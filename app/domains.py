import ipaddress
import re

from app.errors import AppError

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domains(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        name = normalize_domain(value)
        if name not in seen:
            seen.append(name)
    return seen


def normalize_domain(value: str) -> str:
    text = value.strip().lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if not text:
        raise AppError("Domain is empty")
    if "://" in text or "/" in text or ":" in text or " " in text:
        raise AppError("Use a domain such as example.com, without a path or port.")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise AppError("That is an address. Add it under destination addresses.")
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AppError("Domain has an invalid name") from exc
    labels = text.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels) or len(text) > 253:
        shown = text if len(text) <= 80 else f"{text[:80]}…"
        raise AppError(f"'{shown}' is not a domain. Use a name such as example.com.")
    return text
