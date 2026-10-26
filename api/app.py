"""FastAPI 服務：把 Argus AI Agent 以 HTTP 提供。

啟動時完成 Django setup 並建表；/scan 在 worker thread 跑一次完整 agent 測試（可能數分鐘），
不佔用事件迴圈。
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from api.schemas import ScanRequest, ScanResponse
from api.service import ScanError, run_scan_sync


@asynccontextmanager
async def lifespan(app: FastAPI):
    from svc.bootstrap import setup

    setup()
    yield


app = FastAPI(
    title="Argus AI Agent",
    description="由 Argus 抽離的 AI 滲透／UX 測試代理，給一個網址即自動開瀏覽器測試並回傳發現。",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    try:
        # agent 會跑數分鐘，丟到 thread（內部自建事件迴圈），不阻塞 FastAPI 事件迴圈
        result = await asyncio.to_thread(run_scan_sync, req.model_dump())
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanResponse(**result)
