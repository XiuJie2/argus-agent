"""相容 Argus 匯入路徑：agent/tools.py 需要 redact_url_query_values。

Argus 版本委派到共用 redaction 模組；獨立服務只需要這一個 URL 遮罩函式，
故自含實作（不牽動個資／卡號遮罩鏈）。遮罩 query value、保留明顯無害的路由／語系值、
移除 fragment，避免機密隨工具輸出落到 AgentStep。
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SAFE_QUERY_KEYS = frozenset({
    "lang", "language", "locale", "hl", "lng", "l",
    "page", "p", "pg", "tab", "view", "sort", "order", "orderby", "dir",
    "type", "category", "cat", "plugin", "action", "module", "controller", "mode", "ad",
})
_SAFE_QUERY_VALUE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_-]{0,23}$|^[0-9]{1,6}$|^[a-z]{2}(-[A-Za-z]{2,4})?$"
)


def _safe_query_value(key: str, value: str) -> bool:
    return key.lower() in _SAFE_QUERY_KEYS and bool(_SAFE_QUERY_VALUE.match(value or ""))


def redact_url_query_values(url: str) -> str:
    """保留 URL query key、遮罩 value（明顯無害的路由／語系值除外），並移除 fragment。"""
    parsed = urlsplit(url or "")
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode([
        (key, value if _safe_query_value(key, value) else "[REDACTED]")
        for key, value in pairs
    ])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
