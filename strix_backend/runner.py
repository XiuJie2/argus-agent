"""用 usestrix/strix CLI 跑一次掃描，解析其輸出成同一條 /scan 契約的回應。

Strix（https://github.com/usestrix/strix）是開源的自動化 AI 滲透測試器，只有 CLI＋Docker、
沒有 REST API。本模組把它包成跟自家 agent 相同的介面：

  run_strix_scan(payload) -> dict（與 api.service.run_scan_sync 回傳同結構）

流程：
  1. 前置檢查：strix 只做資安滲透（沒有 UX 測試概念）。mode 不含 deep → 回空結果（附說明）；
     deep 必須 authorized=true。
  2. SSRF 閘：assert_public_http_url 正規化並拒絕內網／非公開目標（與 agent 路徑同一道防線）。
  3. 在隔離的暫存工作目錄執行 `strix -n --target <url> [--instruction ...]`
     （`-n`＝headless／非互動，給 CI／伺服器用）。strix 會把結果寫到 `<cwd>/strix_runs/<run>/`。
  4. 解析最新一次 run 的 `vulnerabilities.json`（strix 的結構化發現），映射成 Finding dict。
  5. 清掉暫存工作目錄。

strix 本體讀自己的環境變數（STRIX_LLM／LLM_API_KEY／LLM_API_BASE，或 `strix auth login`），
需要 Docker；這些是部署需求，不是本契約的一部分。
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)

# strix 的嚴重度與 Argus 五級一致；仍過濾一次，未知退回 info
_VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}
# strix 的 confidence 是 high/medium/low 字串 → Argus 的 0–1 信心值
_CONFIDENCE = {"high": 1.0, "medium": 0.6, "low": 0.3}


def _empty_result(summary: str) -> dict:
    return {
        "status": "completed",
        "steps": 0,
        "total_tokens": 0,
        "summary": summary,
        "error": "",
        "ux_issue_count": 0,
        "security_finding_count": 0,
        "findings": [],
    }


def run_strix_scan(payload: dict) -> dict:
    # 延後 import，避免在非 strix backend 時也相依 api.service
    from api.service import ScanError
    from scans.services import PublicScanTargetError, assert_public_http_url

    mode = payload.get("mode", "both")
    deep = mode in {"deep", "both"}
    if not deep:
        # strix 是純資安滲透工具，沒有擬真使用者 UX 測試；mode=ux 對它沒有對應輸出。
        return _empty_result("Strix backend 只做資安滲透，mode=ux 無對應輸出，未執行。")
    if not payload.get("authorized"):
        raise ScanError("Strix 深度／主動測試需要 authorized=true（你必須擁有或已獲授權掃描此目標）。")

    try:
        normalized = assert_public_http_url(payload["url"])
    except (PublicScanTargetError, KeyError, ValueError) as exc:
        raise ScanError(str(exc) or "請提供有效的公開 HTTP/HTTPS 網址。") from exc

    work_dir = Path(tempfile.mkdtemp(prefix="strix-"))
    try:
        cmd = _build_command(normalized, payload)
        completed = _run_strix(cmd, work_dir)
        vulns = _read_vulnerabilities(work_dir)
        findings = [_to_finding(v, normalized) for v in vulns]
        findings = [f for f in findings if f is not None]

        # 有解析到 vulnerabilities.json＝完成（strix 退出碼非 0 代表「發現漏洞」，不是失敗）。
        # 完全沒有輸出檔且退出碼非 0＝真的出錯。
        if completed.returncode != 0 and not vulns and not _has_run_dir(work_dir):
            tail = (completed.stderr or completed.stdout or "")[-500:]
            return {
                **_empty_result(""),
                "status": "error",
                "error": f"strix 執行失敗（exit {completed.returncode}）：{tail}".strip(),
            }

        return {
            "status": "completed",
            "steps": 0,  # strix 無對應「步數」概念
            "total_tokens": 0,  # strix 的用量在 run.json，未納入本契約
            "summary": _summary(work_dir, len(findings)),
            "error": "",
            "ux_issue_count": 0,
            "security_finding_count": len(findings),
            "findings": findings,
        }
    except FileNotFoundError as exc:
        # strix 執行檔不在 PATH（host 未安裝）
        raise ScanError(
            f"找不到 strix 執行檔（STRIX_BIN={settings.STRIX_BIN}）；"
            "AGENT_BACKEND=strix 需在 host 安裝 strix 並讓 Docker 可用。"
        ) from exc
    except subprocess.TimeoutExpired:
        return {
            **_empty_result(""),
            "status": "partial",
            "error": f"strix 逾時（STRIX_TIMEOUT={settings.STRIX_TIMEOUT}s）。",
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _build_command(url: str, payload: dict) -> list[str]:
    cmd = [settings.STRIX_BIN, "-n", "--target", url]
    instruction = _build_instruction(payload)
    if instruction:
        cmd += ["--instruction", instruction]
    cmd += list(settings.STRIX_EXTRA_ARGS)
    return cmd


def _build_instruction(payload: dict) -> str:
    parts: list[str] = []
    email = payload.get("test_auth_email")
    password = payload.get("test_auth_password")
    if email and password:
        # 與 strix 文件示例一致的授權測試指示；帳密不另寫 log／輸出。
        parts.append(
            f"Perform authenticated testing using credentials: {email}:{password}"
        )
    if not payload.get("submit_forms"):
        parts.append("Do not actually submit forms or perform destructive write actions; "
                     "only fill fields to probe behaviour.")
    return " ".join(parts)


def _run_strix(cmd: list[str], work_dir: Path) -> subprocess.CompletedProcess:
    logger.info("執行 strix：%s（cwd=%s）", " ".join(cmd[:4]) + " …", work_dir)
    # 繼承環境（strix 讀 STRIX_LLM／LLM_API_KEY…）；strix_runs 落在隔離的 cwd。
    return subprocess.run(  # noqa: S603 — cmd 由設定與已正規化網址組成，非使用者任意字串
        cmd,
        cwd=str(work_dir),
        capture_output=True,
        text=True,
        timeout=settings.STRIX_TIMEOUT,
        check=False,
    )


def _runs_root(work_dir: Path) -> Path:
    return work_dir / "strix_runs"


def _has_run_dir(work_dir: Path) -> bool:
    root = _runs_root(work_dir)
    return root.is_dir() and any(root.iterdir())


def _latest_run_dir(work_dir: Path) -> Path | None:
    root = _runs_root(work_dir)
    if not root.is_dir():
        return None
    candidates = [d for d in root.iterdir() if (d / "vulnerabilities.json").is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda d: (d / "vulnerabilities.json").stat().st_mtime)


def _read_vulnerabilities(work_dir: Path) -> list[dict]:
    run_dir = _latest_run_dir(work_dir)
    if run_dir is None:
        return []
    try:
        data = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.exception("讀取 strix vulnerabilities.json 失敗")
        return []
    return data if isinstance(data, list) else []


def _summary(work_dir: Path, count: int) -> str:
    run_dir = _latest_run_dir(work_dir)
    if run_dir is not None:
        report = run_dir / "penetration_test_report.md"
        if report.is_file():
            try:
                return report.read_text(encoding="utf-8")[:1000]
            except OSError:
                pass
    return f"Strix 完成，回報 {count} 項資安發現。"


def _to_finding(v: dict, target_url: str) -> dict | None:
    """把 strix 的一筆 vulnerability 映射成契約的 finding dict。

    strix 欄位（strix/report/writer.py vulnerabilities.json）：title、severity、cvss、cwe、
    target、endpoint、method、description、impact、technical_analysis、poc_description、
    evidence、remediation_steps、confidence、id。strix 不提供 OWASP 分類（留空）。
    """
    if not isinstance(v, dict):
        return None
    title = (v.get("title") or "").strip()
    if not title:
        return None

    severity = str(v.get("severity") or "").strip().lower()
    if severity not in _VALID_SEVERITY:
        severity = "info"

    cvss = v.get("cvss")
    priority = None
    if cvss is not None:
        try:
            priority = max(0.0, min(10.0, float(cvss))) * 10.0
        except (TypeError, ValueError):
            priority = None

    cwe = str(v.get("cwe") or "").strip()  # strix 已是 CWE-NNN 格式

    url = (v.get("target") or v.get("endpoint") or target_url or "").strip() or None

    # 描述併入影響與技術分析（契約的 description 是給人看的完整說明）
    description = _join(
        v.get("description"),
        _labelled("影響", v.get("impact")),
        _labelled("技術分析", v.get("technical_analysis")),
    )
    # 證據併入重現步驟（遮罩交給 Argus 端；strix 自身不含我方個資）
    evidence = _join(v.get("evidence"), _labelled("重現", v.get("poc_description")))

    rid = str(v.get("id") or "").strip()
    rule_id = f"strix-{rid}" if rid else ""

    return {
        "category": "security",
        "severity": severity,
        "rule_id": rule_id,
        "title": title[:255],
        "description": description,
        "remediation": v.get("remediation_steps") or "",
        "evidence": evidence,
        "evidence_json": {
            "source": "strix",
            "endpoint": v.get("endpoint") or "",
            "method": v.get("method") or "",
            "cvss": cvss,
            "confidence": v.get("confidence") or "",
        },
        "owasp_category": "",  # strix 不提供 OWASP 分類
        "cwe_id": cwe,
        "impact_area": "",
        "confidence": _CONFIDENCE.get(str(v.get("confidence") or "").lower(), 1.0),
        "priority_score": priority,
        "ai_handoff_prompt": "",  # 留空由 Argus 端 make_finding 產生
        "url": url,
    }


def _labelled(label: str, text) -> str:
    text = (text or "").strip() if isinstance(text, str) else ""
    return f"【{label}】{text}" if text else ""


def _join(*parts) -> str:
    return "\n\n".join(p for p in parts if p and str(p).strip())
