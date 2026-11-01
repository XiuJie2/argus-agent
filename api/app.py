"""FastAPI 服務：對 Argus 實作 agent-service 契約（同步 /scan ＋ 非同步 /v1/scans）。

啟動時完成 Django setup 並建表。/scan 在 worker thread 跑一次完整掃描（可能數分鐘）不阻塞
事件迴圈；/v1/scans 立即下單、背景跑、呼叫端輪詢 status/trace、最後取 result。
"""
from __future__ import annotations

import asyncio
import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException

from api import jobs
from api.runstore import store
from api.schemas import (
    CONTRACT_VERSION,
    CONTRACT_VERSION_ASYNC,
    MessageRequest,
    ScanRequest,
    ScanResponse,
    ScanResultResponse,
    ScanStartResponse,
    ScanStatusResponse,
    TraceEventModel,
    TraceResponse,
)
from api.service import ScanError, execute_scan

# runstore 狀態（succeeded/partial/failed/cancelled）→ 契約 ScanResponse 狀態。
_RESULT_STATUS = {"succeeded": "completed", "partial": "partial",
                  "failed": "error", "cancelled": "error", "running": "partial",
                  "queued": "partial"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    from svc.bootstrap import setup

    setup()
    yield


app = FastAPI(
    title="Argus AI Agent",
    description="由 Argus 抽離的 AI 滲透／UX 測試代理；對 Argus 講 agent-service 契約。",
    version="1.0.0",
    lifespan=lifespan,
)


def _check_auth(authorization: str | None) -> None:
    """設定了 ARGUS_AGENT_SERVICE_KEY 時，要求相符的 Bearer（常數時間比較）。"""
    from django.conf import settings

    key = getattr(settings, "SERVICE_API_KEY", "")
    if not key:
        return
    if not hmac.compare_digest(authorization or "", f"Bearer {key}"):
        raise HTTPException(status_code=401, detail="unauthorized")


def _validate_target(req: ScanRequest) -> None:
    """公開位址政策＋授權閘門先行檢查（讓壞目標在下單時就 400，而不是非同步才失敗）。"""
    from scans.services import PublicScanTargetError, assert_public_http_url

    if req.mode in {"deep", "both"} and not req.authorized:
        raise HTTPException(status_code=400, detail="深度資安測試需要 authorized=true")
    try:
        assert_public_http_url(req.url)
    except (PublicScanTargetError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc) or "無效或非公開的目標網址") from exc


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "ok": True,
        "contract_version": CONTRACT_VERSION,
        "contract_version_async": CONTRACT_VERSION_ASYNC,
        "protocols": ["sync", "async"],
        "engine": "argus-agent",
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest, authorization: str | None = Header(default=None)) -> ScanResponse:
    _check_auth(authorization)
    _validate_target(req)
    try:
        result = await asyncio.to_thread(execute_scan, req.model_dump())
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanResponse(**result)


@app.post("/v1/scans", response_model=ScanStartResponse)
async def start_scan(req: ScanRequest, authorization: str | None = Header(default=None)) -> ScanStartResponse:
    _check_auth(authorization)
    _validate_target(req)
    run = store.create(req.model_dump())
    jobs.start_run(run)
    return ScanStartResponse(scan_id=run.scan_id, status=run.status)


@app.get("/v1/scans/{scan_id}", response_model=ScanStatusResponse)
async def scan_status(scan_id: str, authorization: str | None = Header(default=None)) -> ScanStatusResponse:
    _check_auth(authorization)
    run = store.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    return ScanStatusResponse(
        scan_id=run.scan_id, status=run.status, phase=run.phase, steps=run.steps,
        cost_usd=run.cost_usd, total_tokens=run.total_tokens, error=run.error,
    )


@app.get("/v1/scans/{scan_id}/trace", response_model=TraceResponse)
async def scan_trace(scan_id: str, after: int = 0,
                     authorization: str | None = Header(default=None)) -> TraceResponse:
    _check_auth(authorization)
    run = store.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    events = run.events_after(after)
    return TraceResponse(
        scan_id=run.scan_id, status=run.status,
        events=[TraceEventModel(seq=e.seq, ts=e.ts, kind=e.kind, message=e.message, agent=e.agent)
                for e in events],
        next=(events[-1].seq if events else after),
    )


@app.get("/v1/scans/{scan_id}/result", response_model=ScanResultResponse)
async def scan_result(scan_id: str, authorization: str | None = Header(default=None)) -> ScanResultResponse:
    _check_auth(authorization)
    run = store.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    if not run.is_terminal:
        raise HTTPException(status_code=409, detail=f"scan not finished (status={run.status})")
    findings = run.findings or []
    return ScanResultResponse(
        scan_id=run.scan_id,
        status=_RESULT_STATUS.get(run.status, "completed"),
        steps=run.steps, total_tokens=run.total_tokens, summary=run.summary, error=run.error,
        ux_issue_count=sum(1 for f in findings if f.get("category") == "ux"),
        security_finding_count=sum(1 for f in findings if f.get("category") == "security"),
        findings=findings, cost_usd=run.cost_usd, engine="argus-agent",
    )


@app.post("/v1/scans/{scan_id}/cancel")
async def scan_cancel(scan_id: str, authorization: str | None = Header(default=None)) -> dict:
    _check_auth(authorization)
    run = store.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    run.cancel_event.set()
    run.add_event("info", "收到取消請求")
    return {"scan_id": scan_id, "cancelling": True}


@app.post("/v1/scans/{scan_id}/message")
async def scan_message(scan_id: str, req: MessageRequest,
                       authorization: str | None = Header(default=None)) -> dict:
    _check_auth(authorization)
    run = store.get(scan_id)
    if run is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    # 自家多代理目前不支援執行中動態插話；先收下留言、記一筆 trace，供日後接線。
    run.messages.append(req.message)
    run.add_event("info", "收到操作者留言（目前不即時注入）")
    return {"scan_id": scan_id, "accepted": True}
