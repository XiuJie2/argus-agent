"""把 Argus 的 run_agent_for_scan 包成一次掃描，對外講 agent-service 契約。

同步 /scan 與非同步 /v1/scans 都走 execute_scan：
  1. SSRF 閘：assert_public_http_url 正規化並拒絕內網／非公開目標。
  2. 建暫存 ScanJob＋起點 Page。
  3. asyncio.run(run_agent_for_scan(...))：自家多代理（recon→指揮官→專家＋UX）往外測、寫 Finding。
     progress_cb 把「第 N 回合：角色」轉成 trace 事件，並在取消時中止。
  4. 讀回 Finding → 遮罩敏感值 → 組契約回應。
  5. 刪整列（連帶 Page／Finding…），不累積 SQLite。

AGENT_BACKEND=strix 時改走 strix_backend（只做資安、無 trace／cancel）。
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Callable


class ScanError(Exception):
    """對應 HTTP 400：請求不合法或目標不符合公開位址政策。"""


class CancelledScan(Exception):
    """掃描在執行中被取消（progress_cb 偵測到 cancel_event）。"""


# ---- 敏感值遮罩（服務端第一道；Argus 端還會再遮一次）----
_AUTH_HEADER_RE = re.compile(r"(?im)^(authorization|cookie|set-cookie|x-api-key)\s*:\s*.+$")
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b")
_MAX_EVIDENCE = 4000


def redact(text: str, *, extra_secrets: list[str] | None = None, max_len: int | None = None) -> str:
    """抹掉注入的測試帳密／email／長 token。正文（title/desc/remediation）傳 max_len=None 不截斷。"""
    if not text:
        return ""
    out = str(text)
    for secret in extra_secrets or []:
        if secret:
            out = out.replace(secret, "[REDACTED]")
    out = _AUTH_HEADER_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", out)
    out = _EMAIL_RE.sub("[REDACTED_EMAIL]", out)
    out = _LONG_TOKEN_RE.sub("[REDACTED_TOKEN]", out)
    if max_len and len(out) > max_len:
        out = out[:max_len] + "…[truncated]"
    return out


def run_scan_sync(payload: dict) -> dict:
    """同步 /scan 入口（相容舊名）。"""
    return execute_scan(payload)


def execute_scan(
    payload: dict,
    *,
    cancel_event: Any = None,
    on_event: Callable[[str, str, str], None] | None = None,
) -> dict:
    """跑一次掃描並回契約 dict。

    cancel_event：threading.Event；progress_cb 偵測到即中止（拋 CancelledScan）。
    on_event(kind, message, agent)：把即時進度轉成 trace 事件（非同步模式用）。
    """
    from django.conf import settings

    backend = getattr(settings, "AGENT_BACKEND", "argus-agent")
    if backend == "strix":
        from strix_backend.runner import run_strix_scan

        return run_strix_scan(payload)
    return _run_argus_agent(payload, cancel_event=cancel_event, on_event=on_event)


def _run_argus_agent(payload: dict, *, cancel_event=None, on_event=None) -> dict:
    from django.conf import settings

    from agent.runner import run_agent_for_scan
    from scans.models import Page, ScanJob
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

    secrets = [s for s in (payload.get("test_auth_email"), payload.get("test_auth_password")) if s]

    def _progress(role_label: str, rnd: int) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise CancelledScan()
        if on_event is not None:
            on_event("agent", f"第 {rnd} 回合：{role_label}", role_label)

    cancelled = False
    try:
        result = asyncio.run(
            run_agent_for_scan(
                scan,
                recon_intel=payload.get("recon_intel"),
                may_submit_forms=bool(payload.get("submit_forms")),
                known_findings=payload.get("known_findings"),
                prior_findings=payload.get("prior_findings"),
                instruction=(payload.get("instruction") or "").strip(),
                run_ux=run_ux,
                progress_cb=_progress,
            )
        )
        findings = [
            _finding_out(f, secrets)
            for f in scan.findings.all().order_by("-priority_score")
        ]
        status = _map_status(result)
        return {
            "status": status,
            "steps": (result.steps if result else 0),
            "total_tokens": (result.total_tokens if result else 0),
            "summary": redact((result.final_summary if result else "") or "",
                              extra_secrets=secrets, max_len=None),
            "error": (result.error if result else "no_result") if status == "error" else "",
            "ux_issue_count": sum(1 for f in findings if f["category"] == "ux"),
            "security_finding_count": sum(1 for f in findings if f["category"] == "security"),
            "findings": findings,
            "cost_usd": 0.0,
            "engine": "argus-agent",
        }
    except CancelledScan:
        cancelled = True
        return {
            "status": "error", "steps": 0, "total_tokens": 0, "summary": "",
            "error": "cancelled", "ux_issue_count": 0, "security_finding_count": 0,
            "findings": [], "cost_usd": 0.0, "engine": "argus-agent",
        }
    finally:
        scan.delete()  # 暫存用完即刪（cascade Page／Finding…）


def _map_status(result) -> str:
    """AgentRunResult → 契約 status。沒跑起來＝error；完成＝completed；其餘（含步數/預算
    用盡提早收尾）＝partial，讓上游不把它當成完整驗證。"""
    if result is None:
        return "error"
    if getattr(result, "status", "") == "completed":
        return "completed"
    if getattr(result, "error", "") and not getattr(result, "security_findings", None) \
            and not getattr(result, "issues", None):
        return "error"
    return "partial"


def _finding_out(f, secrets: list[str]) -> dict:
    return {
        "category": f.category,
        "severity": f.severity,
        "rule_id": f.rule_id,
        "title": redact(f.title, extra_secrets=secrets, max_len=255)[:255],
        "description": redact(f.description, extra_secrets=secrets, max_len=None),
        "remediation": redact(f.remediation, extra_secrets=secrets, max_len=None),
        "evidence": redact(f.evidence, extra_secrets=secrets, max_len=_MAX_EVIDENCE),
        "evidence_json": f.evidence_json or {},
        "owasp_category": f.owasp_category,
        "cwe_id": f.cwe_id,
        "impact_area": f.impact_area,
        "confidence": f.confidence,
        "priority_score": f.priority_score,
        "ai_handoff_prompt": f.ai_handoff_prompt,
        "url": (f.page.final_url or f.page.url) if f.page_id else None,
        "evidence_source": "argus-agent",
    }
