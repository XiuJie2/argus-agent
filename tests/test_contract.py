"""agent-service 契約測試（同步 /scan ＋ 非同步 /v1/scans ＋ Bearer auth）。

mock 掉 execute_scan（不碰瀏覽器／LLM／DB 引擎），只驗 HTTP 契約與非同步狀態機。
"""
from __future__ import annotations

import time
from unittest import mock

from django.test import TestCase, override_settings
from fastapi.testclient import TestClient

import svc.bootstrap as _bootstrap
_bootstrap._READY = True  # 測試已由 test runner 完成 Django setup；lifespan 的 migrate 不可在 async 內跑

from api.app import app

_CANNED = {
    "status": "completed", "steps": 7, "total_tokens": 1234, "summary": "done",
    "error": "", "ux_issue_count": 0, "security_finding_count": 1,
    "findings": [{"category": "security", "severity": "high", "rule_id": "agent-x",
                  "title": "IDOR", "description": "d", "remediation": "r", "evidence": "e",
                  "evidence_json": {}, "owasp_category": "A01", "cwe_id": "CWE-862",
                  "impact_area": "", "confidence": 1.0, "priority_score": 50.0,
                  "ai_handoff_prompt": "", "url": "https://example.com/x",
                  "evidence_source": "argus-agent"}],
    "cost_usd": 0.0, "engine": "argus-agent",
}


def _client() -> TestClient:
    return TestClient(app)


class HealthContractTests(TestCase):
    def test_healthz(self):
        with _client() as c:
            r = c.get("/healthz")
            assert r.status_code == 200
            body = r.json()
            assert body["contract_version"] == "1.0"
            assert body["engine"] == "argus-agent"
            assert "async" in body["protocols"]

    def test_sync_scan_contract(self):
        with mock.patch("api.app.execute_scan", return_value=dict(_CANNED)) as m, _client() as c:
            r = c.post("/scan", json={"url": "https://example.com", "mode": "deep",
                                      "authorized": True})
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "completed" and body["engine"] == "argus-agent"
            assert len(body["findings"]) == 1 and body["findings"][0]["title"] == "IDOR"
            assert m.called

    def test_bad_target_rejected_at_submit(self):
        with _client() as c:
            r = c.post("/v1/scans", json={"url": "http://127.0.0.1/", "mode": "deep",
                                          "authorized": True})
            assert r.status_code == 400, r.text

    def test_deep_requires_authorized(self):
        with _client() as c:
            r = c.post("/scan", json={"url": "https://example.com", "mode": "deep",
                                      "authorized": False})
            assert r.status_code == 400


@override_settings(SERVICE_API_KEY="sekret")
class AuthContractTests(TestCase):
    def test_missing_bearer_401(self):
        with _client() as c:
            r = c.post("/scan", json={"url": "https://example.com", "mode": "ux"})
            assert r.status_code == 401

    def test_correct_bearer_ok(self):
        with mock.patch("api.app.execute_scan", return_value=dict(_CANNED, status="completed")), _client() as c:
            r = c.post("/scan", headers={"Authorization": "Bearer sekret"},
                       json={"url": "https://example.com", "mode": "ux"})
            assert r.status_code == 200, r.text


class AsyncFlowTests(TestCase):
    def test_start_poll_trace_result(self):
        def _fake(payload, *, cancel_event=None, on_event=None):
            if on_event:
                on_event("agent", "第 1 回合：recon", "recon")
                on_event("agent", "第 2 回合：orchestrator", "orchestrator")
            return dict(_CANNED)

        with mock.patch("api.jobs.execute_scan", side_effect=_fake), _client() as c:
            r = c.post("/v1/scans", json={"url": "https://example.com", "mode": "deep",
                                          "authorized": True})
            assert r.status_code == 200, r.text
            scan_id = r.json()["scan_id"]

            # 輪詢到終端
            status = None
            for _ in range(100):
                s = c.get(f"/v1/scans/{scan_id}").json()
                status = s["status"]
                if status in {"succeeded", "partial", "failed", "cancelled"}:
                    break
                time.sleep(0.05)
            assert status == "succeeded", status

            trace = c.get(f"/v1/scans/{scan_id}/trace").json()
            assert any(e["agent"] == "recon" for e in trace["events"])

            res = c.get(f"/v1/scans/{scan_id}/result").json()
            assert res["status"] == "completed"        # succeeded → completed（契約詞彙）
            assert len(res["findings"]) == 1
            assert res["scan_id"] == scan_id

    def test_result_before_finished_409(self):
        import threading
        gate = threading.Event()

        def _slow(payload, *, cancel_event=None, on_event=None):
            gate.wait(timeout=5)
            return dict(_CANNED)

        with mock.patch("api.jobs.execute_scan", side_effect=_slow), _client() as c:
            scan_id = c.post("/v1/scans", json={"url": "https://example.com", "mode": "ux"}).json()["scan_id"]
            r = c.get(f"/v1/scans/{scan_id}/result")
            assert r.status_code == 409
            gate.set()

    def test_unknown_scan_404(self):
        with _client() as c:
            assert c.get("/v1/scans/nope").status_code == 404
            assert c.post("/v1/scans/nope/cancel").status_code == 404
