"""Kali／sqlmap 攻擊鏈 facade——獨立服務預設停用的 stub。

Argus 的 Kali 整合需要一整套 Kubernetes runner／Redis 預算／admission 控制平面，
不適合放進單機獨立服務，且預設本就關閉。這裡保留 agent/tools.py 期望的呼叫契約
（run_sqlmap 回傳含 blocked_reason／confirmed／error／evidence_summary 的 dict），
一律回報停用；ToolExecutor 會優雅處理 blocked_reason、不影響其餘測試。

要接自己的主動 SQLi 驗證後端，替換 run_sqlmap 的實作即可（回傳同樣的 dict 契約）。
"""
from __future__ import annotations


def run_sqlmap(target_url: str, scan_job_id: int) -> dict:
    return {
        "ok": False,
        "tool": "sqlmap",
        "blocked_reason": "kali_disabled",
        "confirmed": False,
        "error": "",
        "evidence_summary": {},
    }
