"""讓 Chromium 走受控 egress proxy（由 Argus config/egress.py 抽出）。"""
from django.conf import settings


def playwright_launch_kwargs() -> dict:
    url = getattr(settings, "ARGUS_EGRESS_PROXY_URL", "")
    if not url:
        return {}
    return {"proxy": {"server": url}}
