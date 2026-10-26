"""API 請求／回應結構。"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., description="要測試的目標網址（必須是公開 HTTP/HTTPS）")
    mode: Literal["ux", "deep", "both"] = Field(
        "both",
        description="ux＝只跑擬真使用者 UX 測試；deep＝只跑深度資安滲透；both＝兩者都跑",
    )
    authorized: bool = Field(
        False,
        description="深度資安／主動測試需明確授權（你擁有或已獲授權掃描此目標）。mode 含 deep 時必須為 true",
    )
    submit_forms: bool = Field(
        False, description="UX 測試是否允許實際送出表單（未授權目標預設 false，只填欄位不送出）"
    )
    recon_intel: list[str] | None = Field(
        None, description="選填：已知的同站 API 端點清單，餵給指揮官省去重複偵察"
    )
    known_findings: list[dict] | None = Field(
        None, description="選填：已由其他工具找到的資安發現摘要，叫 agent 別重報"
    )
    test_auth_email: str | None = Field(None, description="選填：authenticated scan 的測試帳號")
    test_auth_password: str | None = Field(None, description="選填：authenticated scan 的測試密碼")


class FindingOut(BaseModel):
    category: str
    severity: str
    rule_id: str
    title: str
    description: str
    remediation: str
    evidence: str
    evidence_json: dict
    owasp_category: str
    cwe_id: str
    impact_area: str
    confidence: float
    priority_score: float | None
    ai_handoff_prompt: str
    url: str | None


class ScanResponse(BaseModel):
    status: str
    steps: int
    total_tokens: int
    summary: str
    error: str
    ux_issue_count: int
    security_finding_count: int
    findings: list[FindingOut]
