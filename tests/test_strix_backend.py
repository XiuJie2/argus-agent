"""Strix backend 測試：不需真的裝 strix／Docker，mock 掉 subprocess 與 SSRF 閘。

驗證：strix 的 vulnerabilities.json 能正確映射成契約 finding；mode=ux 與未授權的前置檢查；
AGENT_BACKEND 分派。
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, override_settings

from api.service import ScanError, run_scan_sync
from strix_backend import runner

_SAMPLE_VULNS = [
    {
        "id": "vuln-0001",
        "title": "SQL Injection on /api/login",
        "severity": "critical",
        "cvss": 9.8,
        "cwe": "CWE-89",
        "target": "https://example.com/api/login",
        "endpoint": "/api/login",
        "method": "POST",
        "description": "login 參數可注入",
        "impact": "可讀整個資料庫",
        "technical_analysis": "boolean-based blind",
        "poc_description": "送 ' OR 1=1--",
        "evidence": "回應時間差 5s",
        "remediation_steps": "改用參數化查詢",
        "confidence": "high",
    },
    {
        "id": "vuln-0002",
        "title": "Reflected XSS",
        "severity": "WeIrD",  # 未知嚴重度 → info
        "target": "https://example.com/search",
        "description": "q 參數反射",
        "confidence": "medium",
    },
    {"title": ""},  # 無標題 → 丟棄
]


def _fake_run_writing(vulns, *, returncode=1, report="# 報告\n找到 2 項"):
    """回一個 subprocess.run 替身：把 vulns 寫進 cwd/strix_runs/run1/，模擬 strix。"""

    def _runner(cmd, cwd, **kwargs):
        run_dir = Path(cwd) / "strix_runs" / "run1"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps(vulns, ensure_ascii=False), encoding="utf-8"
        )
        (run_dir / "penetration_test_report.md").write_text(report, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr="")

    return _runner


@override_settings(AGENT_BACKEND="strix", STRIX_BIN="strix", STRIX_TIMEOUT=60, STRIX_EXTRA_ARGS=[])
class StrixBackendTests(SimpleTestCase):
    def setUp(self):
        # 避免 DNS／SSRF 實際連線：直接回傳正規化網址
        p = mock.patch(
            "scans.services.assert_public_http_url", side_effect=lambda u: u
        )
        p.start()
        self.addCleanup(p.stop)

    def _payload(self, **over):
        base = {
            "url": "https://example.com/",
            "mode": "deep",
            "authorized": True,
            "submit_forms": False,
        }
        base.update(over)
        return base

    def test_ux_only_returns_empty(self):
        out = runner.run_strix_scan(self._payload(mode="ux", authorized=False))
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["findings"], [])
        self.assertIn("只做資安滲透", out["summary"])

    def test_deep_requires_authorized(self):
        with self.assertRaises(ScanError):
            runner.run_strix_scan(self._payload(authorized=False))

    def test_vulnerabilities_mapped(self):
        with mock.patch.object(
            runner.subprocess, "run", side_effect=_fake_run_writing(_SAMPLE_VULNS)
        ):
            out = runner.run_strix_scan(self._payload())

        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["security_finding_count"], 2)  # 空標題被丟棄
        self.assertEqual(out["summary"], "# 報告\n找到 2 項")

        first = out["findings"][0]
        self.assertEqual(first["category"], "security")
        self.assertEqual(first["severity"], "critical")
        self.assertEqual(first["cwe_id"], "CWE-89")
        self.assertEqual(first["priority_score"], 98.0)  # cvss 9.8 × 10
        self.assertEqual(first["rule_id"], "strix-vuln-0001")
        self.assertEqual(first["url"], "https://example.com/api/login")
        self.assertEqual(first["owasp_category"], "")  # strix 不提供
        self.assertIn("影響", first["description"])
        self.assertIn("重現", first["evidence"])

        second = out["findings"][1]
        self.assertEqual(second["severity"], "info")  # 未知嚴重度退回 info

    def test_instruction_includes_credentials(self):
        captured = {}

        def _capture(cmd, cwd, **kwargs):
            captured["cmd"] = cmd
            return _fake_run_writing([])(cmd, cwd, **kwargs)

        with mock.patch.object(runner.subprocess, "run", side_effect=_capture):
            runner.run_strix_scan(
                self._payload(test_auth_email="u@e.co", test_auth_password="pw")
            )
        joined = " ".join(captured["cmd"])
        self.assertIn("--instruction", captured["cmd"])
        self.assertIn("u@e.co:pw", joined)
        self.assertIn("-n", captured["cmd"])

    def test_strix_not_installed_raises(self):
        with mock.patch.object(runner.subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaises(ScanError):
                runner.run_strix_scan(self._payload())

    def test_dispatch_to_strix(self):
        with mock.patch(
            "strix_backend.runner.run_strix_scan", return_value={"ok": 1}
        ) as m:
            self.assertEqual(run_scan_sync({"mode": "deep", "authorized": True}), {"ok": 1})
        m.assert_called_once()
