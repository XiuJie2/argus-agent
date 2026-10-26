"""公開 HTTP(S)／WebSocket 目標位址政策（由 Argus apps/scans/services.py 抽出）。

這是 SSRF 防線：agent 在導航、送請求、開 WebSocket 前都會過這裡，拒絕 localhost、
私網、保留與非公開位址、非標準埠。**原樣沿用，不得放寬。** 只移除了 Argus 專屬、
agent 不會用到的 user_owns_domain / get_client_ip。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings

PUBLIC_WEB_PORTS = {80, 443}


class PublicScanTargetError(ValueError):
    """掃描目標不符合公開 HTTP(S) 位址政策。"""


def _parse_url(raw_url: str):
    parsed = urlparse(raw_url.strip())
    if not parsed.scheme:
        parsed = urlparse(f"https://{raw_url.strip()}")
    try:
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise PublicScanTargetError("請輸入有效的 HTTP 或 HTTPS 網址。") from exc
    return parsed, hostname, port


def _host_for_url(hostname: str) -> str:
    return f"[{hostname}]" if ":" in hostname else hostname


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not ip.is_global


def _resolve_host_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise PublicScanTargetError("無法解析此網域，請確認網址是否正確。") from exc

    ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for record in records:
        try:
            ips.add(ipaddress.ip_address(record[4][0]))
        except ValueError:
            continue
    if not ips:
        raise PublicScanTargetError("無法解析此網域，請確認網址是否正確。")
    return sorted(ips, key=lambda item: (item.version, int(item)))


def allow_private_targets() -> bool:
    """是否開啟本機／隔離測試的私網目標旁路（ARGUS_ALLOW_PRIVATE_TARGETS 且 DEBUG）。

    正式部署請維持 DEBUG=False，誤設環境變數也不生效。開啟時放行私網、localhost、
    單標籤 hostname 與非標準 port，供受控測試目標（如 Docker 內的靶機）使用。
    """
    return bool(getattr(settings, "ARGUS_ALLOW_PRIVATE_TARGETS", False)) and settings.DEBUG


def resolve_public_host_ips(hostname: str) -> list[str]:
    allow_private = allow_private_targets()
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        ips = _resolve_host_ips(hostname)
    else:
        ips = [literal_ip]
    if not allow_private and any(_is_blocked_ip(ip) for ip in ips):
        raise PublicScanTargetError("掃描目標不允許內網、保留或非公開位址。")
    return [str(ip) for ip in ips]


def normalize_url(raw_url: str) -> str:
    parsed, hostname, port_value = _parse_url(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("請輸入有效的 HTTP 或 HTTPS 網址。")
    port = f":{port_value}" if port_value else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{_host_for_url(hostname)}{port}{path}{query}"


def assert_public_http_url(raw_url: str) -> str:
    """正規化 URL，並確認每一筆 DNS 結果都是公開位址。"""
    allow_private = allow_private_targets()
    raw_parsed, _, _ = _parse_url(raw_url)
    if raw_parsed.username is not None or raw_parsed.password is not None:
        raise PublicScanTargetError("掃描網址不可包含帳號或密碼。")
    normalized = normalize_url(raw_url)
    parsed, hostname, port = _parse_url(normalized)
    if not hostname or (hostname in {"localhost", "ip6-localhost"} and not allow_private):
        raise PublicScanTargetError("掃描目標不允許 localhost 或內網位址。")
    if port is not None and port not in PUBLIC_WEB_PORTS and not allow_private:
        raise PublicScanTargetError("掃描目標只允許標準 HTTP／HTTPS 連接埠。")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        if "." not in hostname and ":" not in hostname and not allow_private:
            raise PublicScanTargetError("請輸入完整且可解析的公開網域。") from None
        try:
            hostname.encode("idna")
        except UnicodeError as exc:
            raise PublicScanTargetError("請輸入有效的公開網域。") from exc
        resolve_public_host_ips(hostname)
    else:
        resolve_public_host_ips(str(literal_ip))
    return normalized


def assert_public_websocket_url(raw_url: str) -> str:
    """將 WebSocket URL 套用與 HTTP(S) 相同的公開位址政策。"""
    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in {"ws", "wss"}:
        raise PublicScanTargetError("只允許公開的 WebSocket 連線。")
    http_scheme = "https" if parsed.scheme == "wss" else "http"
    assert_public_http_url(parsed._replace(scheme=http_scheme).geturl())
    return raw_url


def get_hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def get_origin(url: str) -> str:
    parsed, hostname, port_value = _parse_url(url)
    port = f":{port_value}" if port_value else ""
    return f"{parsed.scheme}://{_host_for_url(hostname)}{port}"
