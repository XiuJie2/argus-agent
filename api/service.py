"""把 Argus 的 run_agent_for_scan 包成一次 HTTP 掃描。

流程（同步，在 worker thread 執行，內部自建事件迴圈——與 Argus Celery 端的 _run_async
同一模式，避免 Django ORM 的 async 陷阱）：
  1. SSRF 閘：assert_public_http_url 正規化並拒絕內網／非公開目標。
  2. 建立暫存 ScanJob＋起點 Page。
  3. asyncio.run(run_agent_for_scan(...))：agent 自己開瀏覽器往外測、過程寫 Finding。
  4. 讀回 Finding 組成 JSON。
  5. 預設刪除整列（連帶 Page／Session／Step／Finding），不累積 SQLite。
"""
from __future__ import annotations

import asyncio


class ScanError(Exception):
    """對應 HTTP 400：請求不合法或目標不符合公開位址政策。"""


def run_scan_sync(payload: dict) -> dict:
    from django.conf import settings

    from agent.runner import run_agent_for_scan
    from scans.models import Finding, Page, ScanJob
    from scans.services import PublicScanTargetError, assert_public_http_url, get_origin

    mode = payload.get("mode", "both")
    deep = mode in {"deep", "both"}
    run_ux = mode in {"ux", "both"}
    if deep and not payload.get("authorized"):
        raise ScanError("深度資安／主動測試需要 authorized=true（你必須擁有或已獲授權掃描此目標）。")
    if not settings.ARGUS_AGENT_ENABLED:
        raise ScanError("ARGUS_AGENT_ENABLED 為 false，服務未啟用 agent。")

    try:
        normalized = assert_public_http_url(payload["url"])
    except (PublicScanTargetError, KeyError, ValueError) as exc:
        raise ScanError(str(exc) or "請提供有效的公開 HTTP/HTTPS 網址。") from exc
    origin = get_origin(normalized)

    scan = ScanJob.objects.create(
        original_url=normalized,
        normalized_url=normalized,
        origin=origin,
        scan_mode=ScanJob.ScanMode.ACTIVE if deep else ScanJob.ScanMode.PASSIVE,
        active_testing_authorized=bool(deep),
        deep_agent_requested=bool(deep),
        test_auth_email_encrypted=payload.get("test_auth_email") or "",
        test_auth_password_encrypted=payload.get("test_auth_password") or "",
        status=ScanJob.Status.AGENT_TESTING,
    )
    Page.objects.create(scan_job=scan, url=normalized, final_url=normalized, depth=0)

    try:
        result = asyncio.run(
            run_agent_for_scan(
                scan,
                recon_intel=payload.get("recon_intel"),
                may_submit_forms=bool(payload.get("submit_forms")),
                known_findings=payload.get("known_findings"),
                run_ux=run_ux,
            )
        )
        findings = [_finding_out(f) for f in scan.findings.all().order_by("-priority_score")]
        return {
            "status": (result.status if result else "no_result"),
            "steps": (result.steps if result else 0),
            "total_tokens": (result.total_tokens if result else 0),
            "summary": (result.final_summary if result else ""),
            "error": (result.error if result else ""),
            "ux_issue_count": sum(1 for f in findings if f["category"] == "ux"),
            "security_finding_count": sum(1 for f in findings if f["category"] == "security"),
            "findings": findings,
        }
    finally:
        # 暫存資料用完即刪，連帶 Page／Finding／AgentSession／AgentStep（cascade）
        scan.delete()


def _finding_out(f) -> dict:
    return {
        "category": f.category,
        "severity": f.severity,
        "rule_id": f.rule_id,
        "title": f.title,
        "description": f.description,
        "remediation": f.remediation,
        "evidence": f.evidence,
        "evidence_json": f.evidence_json or {},
        "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id,
        "impact_area": f.impact_area,
        "confidence": f.confidence,
        "priority_score": f.priority_score,
        "ai_handoff_prompt": f.ai_handoff_prompt,
        "url": (f.page.final_url or f.page.url) if f.page_id else None,
    }
