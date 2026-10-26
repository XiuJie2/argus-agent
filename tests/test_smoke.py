"""結構健全性煙霧測試（mock LLM 與瀏覽器，不需金鑰或真實目標）。

驗證：抽離後的 agent 程式能對精簡模型跑起來、Finding 持久化與 OWASP 標記路徑可用。
真正的線上掃描需要 provider 金鑰＋真實目標，不在單元測試範圍。
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase, override_settings

from agent.loop import AgentRunResult
from scans.models import Finding, Page, ScanJob
from scans.scanners import make_finding
from scans.security import owasp_mapper


class _FakeAgent:
    """假 HermesAgent：不碰瀏覽器或 LLM，回一個完成的結果。"""

    def __init__(self, **kwargs):
        pass

    async def run(self, task_prompt: str):
        return AgentRunResult(
            session_id=1, status="completed", steps=1, total_tokens=0,
            issues=[], security_findings=[],
        )


class _FakePlaywrightCM:
    async def __aenter__(self):
        pw = MagicMock()
        browser = MagicMock()
        browser.close = AsyncMock()
        pw.chromium.launch = AsyncMock(return_value=browser)
        return pw

    async def __aexit__(self, *exc):
        return False


@override_settings(ARGUS_AGENT_ENABLED=True)
class TransplantSmokeTests(TestCase):
    def setUp(self):
        self.scan = ScanJob.objects.create(
            origin="https://example.com",
            normalized_url="https://example.com/",
            original_url="https://example.com/",
            scan_mode=ScanJob.ScanMode.PASSIVE,  # 非 deep → 走單一 UX session 分支
        )
        Page.objects.create(
            scan_job=self.scan, url="https://example.com/", final_url="https://example.com/", depth=0
        )

    def test_run_agent_for_scan_runs_against_trimmed_models(self):
        from agent import runner

        page = MagicMock(final_url="https://example.com/", url="https://example.com/")
        context = MagicMock()
        context.new_page = AsyncMock(return_value=MagicMock(goto=AsyncMock()))
        with (
            patch.object(runner, "_pick_starting_page", return_value=page),
            patch.object(runner, "build_default_chain", return_value=MagicMock()),
            patch.object(runner, "async_playwright", return_value=_FakePlaywrightCM()),
            patch.object(runner, "_make_agent_context", new=AsyncMock(return_value=context)),
            patch.object(runner, "ToolExecutor", MagicMock()),
            patch.object(runner, "HermesAgent", _FakeAgent),
        ):
            result = asyncio.run(runner.run_agent_for_scan(self.scan, run_ux=True))
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "completed")

    def test_finding_persist_and_owasp_tag_path(self):
        tagged = owasp_mapper.tag(
            make_finding(
                category="security",
                severity="high",
                title="Exposed .env file",
                description="d",
                remediation="r",
                rule_id="exposure-file-env",
            )
        )
        Finding.objects.create(scan_job=self.scan, page=None, **tagged)
        f = self.scan.findings.get()
        self.assertEqual(f.owasp_category, "A02")
        self.assertEqual(f.cwe_id, "CWE-200")
        self.assertTrue(f.ai_handoff_prompt)
