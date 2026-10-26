"""make_finding 與其輔助函式（由 Argus apps/scans/scanners.py 原樣抽出）。

獨立服務只需要「把一筆發現組成標準 dict」這段，不含 Argus 的四維掃描器本體。
agent/findings.py 與 agent/tools.py 透過 make_finding 產生 Finding dict。
"""
from __future__ import annotations

import hashlib
import re


def build_ai_handoff_prompt(
    *,
    category: str,
    severity: str,
    description: str,
    remediation: str,
    evidence: str,
) -> str:
    return (
        "我網站有以下問題，請協助我分析並提供修復方向：\n"
        f"- 問題類型：{category}\n"
        f"- 嚴重度：{severity}\n"
        f"- 問題描述：{description}\n"
        "- 相關證據：\n"
        f"{evidence}\n"
        f"- 修補建議方向：{remediation}\n\n"
        "請依此資訊提供具體修改方向、檢查步驟與注意事項；不要輸出完整修復程式碼。"
    )


def _normalize_rule_token(value: str) -> str:
    token = re.sub(r"[^0-9A-Za-z]+", "_", value or "").strip("_").upper()
    return token[:80] or "GENERAL"


_SEVERITY_DEFAULT_PRIORITY = {
    "critical": 90.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
    "info": 10.0,
}


def _default_rule_id(category: str, title: str) -> str:
    digest = hashlib.sha1(title.encode("utf-8")).hexdigest()[:10].upper()
    return f"{_normalize_rule_token(str(category))}_{_normalize_rule_token(title)}_{digest}"


def _default_evidence_json(
    *,
    evidence: str,
    evidence_type: str,
    evidence_source: str,
    selector: str,
    bounding_box: dict | None,
) -> dict:
    payload = {
        "type": evidence_type or "text",
        "source": evidence_source,
        "excerpt": (evidence or "")[:1000],
    }
    if selector:
        payload["selector"] = selector
    if bounding_box:
        payload["bounding_box"] = bounding_box
    return payload


def make_finding(
    *,
    category: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    evidence: str = "",
    selector: str = "",
    bounding_box: dict | None = None,
    priority_score: float | None = None,
    impact_area: str = "",
    confidence: float = 1.0,
    rule_id: str = "",
    evidence_type: str = "",
    evidence_json: dict | None = None,
    evidence_source: str = "",
) -> dict:
    resolved_rule_id = rule_id or _default_rule_id(str(category), title)
    resolved_priority_score = (
        priority_score
        if priority_score is not None
        else _SEVERITY_DEFAULT_PRIORITY.get(str(severity), 10.0)
    )
    resolved_evidence_type = evidence_type or "text"
    resolved_evidence_source = evidence_source or "rule_engine"
    resolved_evidence_json = evidence_json or _default_evidence_json(
        evidence=evidence,
        evidence_type=resolved_evidence_type,
        evidence_source=resolved_evidence_source,
        selector=selector,
        bounding_box=bounding_box,
    )
    return {
        "category": category,
        "severity": severity,
        "rule_id": resolved_rule_id,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence": evidence[:4000],
        "evidence_type": resolved_evidence_type,
        "evidence_json": resolved_evidence_json,
        "evidence_source": resolved_evidence_source,
        "ai_explanation": "",
        "ai_remediation": "",
        "llm_model": "",
        "llm_generated_at": None,
        "selector": selector,
        "bounding_box": bounding_box,
        "priority_score": resolved_priority_score,
        "impact_area": impact_area,
        "confidence": confidence,
        "ai_handoff_prompt": build_ai_handoff_prompt(
            category=category,
            severity=severity,
            description=description,
            remediation=remediation,
            evidence=evidence[:2000],
        ),
    }
