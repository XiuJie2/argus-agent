"""獨立 AI Agent 服務的 Django 設定。

這個服務用 Django ORM＋SQLite 當單次掃描的暫存狀態（原封不動沿用 Argus 已驗證的 agent
程式）；對外以 FastAPI 提供 API。所有可調參數都讀環境變數，沒有任何硬編碼金鑰。
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-insecure-not-for-production")
DEBUG = _env_bool("DEBUG", False)
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = ["scans", "agent"]
MIDDLEWARE = []
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.getenv("ARGUS_DB_PATH", str(BASE_DIR / "db.sqlite3")),
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"

MEDIA_ROOT = os.getenv("ARGUS_MEDIA_ROOT", str(BASE_DIR / "media"))

# ---- AI Agent 參數（與 Argus 同名，語意相同）----
ARGUS_AGENT_ENABLED = _env_bool("ARGUS_AGENT_ENABLED", True)
ARGUS_AGENT_MAX_STEPS = _env_int("ARGUS_AGENT_MAX_STEPS", 20)
ARGUS_AGENT_SPECIALIST_MAX_STEPS = _env_int("ARGUS_AGENT_SPECIALIST_MAX_STEPS", 30)
ARGUS_AGENT_MAX_SPECIALIST_DISPATCH = _env_int("ARGUS_AGENT_MAX_SPECIALIST_DISPATCH", 6)
ARGUS_AGENT_MAX_TOKENS = _env_int("ARGUS_AGENT_MAX_TOKENS", 60000)
ARGUS_AGENT_UX_MAX_TOKENS = _env_int("ARGUS_AGENT_UX_MAX_TOKENS", 120000)
ARGUS_AGENT_STEP_TIMEOUT = _env_int("ARGUS_AGENT_STEP_TIMEOUT", 30)

# ---- 掃描器身分與網路 ----
ARGUS_SCANNER_USER_AGENT = os.getenv(
    "ARGUS_SCANNER_USER_AGENT",
    "ArgusAgent/1.0 (+https://github.com/)",
)
ARGUS_NUCLEI_TEMPLATES_DIR = os.getenv("ARGUS_NUCLEI_TEMPLATES_DIR", "")
ARGUS_EGRESS_PROXY_URL = os.getenv("ARGUS_EGRESS_PROXY_URL", "")
ARGUS_SCANNER_EGRESS_IPS = [
    ip.strip() for ip in os.getenv("ARGUS_SCANNER_EGRESS_IPS", "").split(",") if ip.strip()
]
# 僅限 DEBUG：放行私網／localhost 目標（受控靶機測試用），正式環境維持 False
ARGUS_ALLOW_PRIVATE_TARGETS = _env_bool("ARGUS_ALLOW_PRIVATE_TARGETS", False)

# LLM provider 金鑰一律讀環境變數（providers.py）：MINIMAX_API_KEY / GLM_API_KEY /
# GOOGLE_API_KEY，絕不寫進程式或設定檔。
