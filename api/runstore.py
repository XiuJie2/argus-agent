"""非同步掃描的 run 狀態與 trace 事件存放層（記憶體內，單一 worker）。

非同步模型需要在「下單」與「取結果」之間保存 run 狀態與一串即時事件（trace），讓呼叫端
輪詢 status、拉 trace 看 agent 在做什麼。

⚠ 單 process 記憶體內：多 worker 不共享、重啟即失。本服務請以單 worker 跑；Argus 端輪詢到
run 不存在時，把該 agent 階段視為失敗（不中斷掃描）。
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

Status = Literal["queued", "running", "succeeded", "partial", "failed", "cancelled"]
TERMINAL: frozenset[str] = frozenset({"succeeded", "partial", "failed", "cancelled"})


@dataclass
class TraceEvent:
    seq: int
    ts: float
    kind: str  # phase | agent | tool | info | error
    message: str
    agent: str = ""


@dataclass
class Run:
    scan_id: str
    request: dict[str, Any]
    status: Status = "queued"
    phase: str = "queued"
    steps: int = 0
    cost_usd: float = 0.0
    total_tokens: int = 0
    summary: str = ""
    error: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    ended_at: float | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    messages: list[str] = field(default_factory=list)
    _events: list[TraceEvent] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add_event(self, kind: str, message: str, agent: str = "") -> None:
        with self._lock:
            self._events.append(
                TraceEvent(seq=len(self._events) + 1, ts=time.time(),
                           kind=kind, message=message, agent=agent)
            )

    def events_after(self, after: int) -> list[TraceEvent]:
        with self._lock:
            return [e for e in self._events if e.seq > after]

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL


class RunStore:
    def __init__(self, max_runs: int = 200) -> None:
        self._runs: dict[str, Run] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._max_runs = max_runs

    def create(self, request: dict[str, Any]) -> Run:
        scan_id = uuid.uuid4().hex
        run = Run(scan_id=scan_id, request=request)
        with self._lock:
            self._runs[scan_id] = run
            self._order.append(scan_id)
            # 只淘汰最舊的「已終端」run；進行中的不動（否則 /trace、/result 回 404 被誤判失敗）。
            while len(self._order) > self._max_runs:
                victim = next(
                    (sid for sid in self._order
                     if (self._runs.get(sid) is not None and self._runs[sid].is_terminal)),
                    None,
                )
                if victim is None:
                    break
                self._order.remove(victim)
                self._runs.pop(victim, None)
        return run

    def get(self, scan_id: str) -> Run | None:
        with self._lock:
            return self._runs.get(scan_id)


store = RunStore()
