"""在使用 Django ORM 前完成 setup 並建好資料表（單檔 SQLite 暫存）。"""
from __future__ import annotations

import os

_READY = False


def setup() -> None:
    global _READY
    if _READY:
        return
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "svc.settings")
    import django

    django.setup()
    from django.core.management import call_command

    # --run-syncdb 讓沒有 migration 檔時也能依 model 直接建表（服務是暫存用途）
    call_command("migrate", run_syncdb=True, verbosity=0)
    _READY = True
