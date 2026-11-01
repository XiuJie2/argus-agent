"""API 請求／回應結構 —— 對 Argus 實作 agent-service HTTP 契約 v1.0（同步）＋ v2.0（非同步）。

權威來源：Argus repo `backend/apps/scans/agent_client.py`（`CONTRACT_VERSION = "1.0"`）與
其非同步協定（POST /v1/scans → 輪詢 status/trace → GET result）。argus-agent 對外講同一條
契約，所以 Argus 只要把 `ARGUS_AGENT_SERVICE_URL` 指向本服務即可無痛替換 strix wrapper。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

CONTRACT_VERSION = "1.0"
CONTRACT_VERSION_ASYNC = "2.0"


class ScanRequest(BaseModel):
    """POST /scan 與 POST /v1/scans 的請求 body（見 Argus 契約）。"""

    contract_version: str = CONTRACT_VERSION
    url: str = Field(..., description="要測試的目標網址（必須是公開 HTTP/HTTPS）")
    mode: Literal["ux", "deep", "both"] = Field(
        "both", description="ux＝只跑 UX；deep＝只跑資安滲透；both＝兩者都跑"
    )
    authorized: bool = Field(
        False, description="深度資安／主動測試需明確授權。mode 含 deep 時必須為 true"
    )
    submit_forms: bool = Field(False, description="UX 是否允許實際送出表單")
    recon_intel: list[str] | None = Field(None, description="選填：已知同站 API 端點")
    known_findings: list[dict[str, Any]] | None = Field(
        None, description="選填：已由其他工具找到的資安發現（叫 agent 別重報）"
    )
    test_auth_email: str | None = Field(None, description="選填：authenticated scan 測試帳號")
    test_auth_password: str | None = Field(None, description="選填：authenticated scan 測試密碼")
    # per-scan 操作者聚焦（選填，預設空）：由 Argus 的 scan.agent_focus 帶入。
    instruction: str = Field("", description="本次掃描的操作者聚焦指示（選填）")
    # 同站歷次掃描的資安發現聯集：叫 agent 先驗證還在不在（verify-first），再往深挖。
    prior_findings: list[dict[str, Any]] | None = Field(
        None, description="選填：同站歷次掃描的資安發現，供 PHASE 1 回歸重測"
    )


class FindingOut(BaseModel):
    """單筆發現。欄位對齊 Argus 契約；Argus 端會再正規化。"""

    category: str = "security"
    severity: str = "low"
    rule_id: str = ""
    title: str = ""
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    evidence_json: dict[str, Any] = Field(default_factory=dict)
    owasp_category: str = ""
    cwe_id: str = ""
    impact_area: str = ""
    confidence: float = 1.0
    priority_score: float | None = None
    ai_handoff_prompt: str = ""
    url: str | None = None
    evidence_source: str = "argus-agent"


class ScanResponse(BaseModel):
    """POST /scan 的回應 body。"""

    status: Literal["completed", "partial", "error"] = "completed"
    steps: int = 0
    total_tokens: int = 0
    summary: str = ""
    error: str = ""
    ux_issue_count: int = 0
    security_finding_count: int = 0
    findings: list[FindingOut] = Field(default_factory=list)
    cost_usd: float = 0.0
    engine: str = "argus-agent"


# ---- 非同步契約 v2（start → poll/trace → result → cancel/message）----


class ScanStartResponse(BaseModel):
    scan_id: str
    status: str = "queued"


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str  # queued|running|succeeded|partial|failed|cancelled
    phase: str = ""
    steps: int = 0
    cost_usd: float = 0.0
    total_tokens: int = 0
    error: str = ""
    engine: str = "argus-agent"


class TraceEventModel(BaseModel):
    seq: int
    ts: float
    kind: str
    message: str
    agent: str = ""


class TraceResponse(BaseModel):
    scan_id: str
    status: str
    events: list[TraceEventModel] = Field(default_factory=list)
    next: int = 0


class ScanResultResponse(ScanResponse):
    scan_id: str = ""


class MessageRequest(BaseModel):
    message: str
