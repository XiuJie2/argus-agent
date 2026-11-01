"""背景執行：把一個非同步 Run 跑起來，邊跑邊寫 trace 事件、結束寫 findings。

在 daemon thread 內跑 execute_scan（自家多代理，asyncio.run）。progress_cb 把「第 N 回合：角色」
轉成 trace 事件（呼叫端 /trace 的即時來源）；run.cancel_event 設定時在下一個回合邊界中止。
"""
from __future__ import annotations

import threading
import time

from api.service import CancelledScan, ScanError, execute_scan
from api.runstore import Run

# status（契約 completed/partial/error）→ runstore 的終端狀態詞彙。
_STATUS_MAP = {"completed": "succeeded", "partial": "partial", "error": "failed"}


def start_run(run: Run) -> None:
    threading.Thread(target=_execute, args=(run,), daemon=True).start()


def _execute(run: Run) -> None:
    run.status = "running"
    run.phase = "starting"
    run.started_at = time.time()
    try:
        def _on_event(kind: str, message: str, agent: str = "") -> None:
            run.phase = message
            run.steps += 1
            run.add_event(kind, message, agent)

        result = execute_scan(run.request, cancel_event=run.cancel_event, on_event=_on_event)

        run.findings = result.get("findings", [])
        run.summary = result.get("summary", "")
        run.total_tokens = int(result.get("total_tokens", 0) or 0)
        run.cost_usd = float(result.get("cost_usd", 0.0) or 0.0)
        if result.get("steps"):
            run.steps = int(result["steps"])
        if run.cancel_event.is_set():
            run.status = "cancelled"
            run.add_event("info", "已取消")
            return
        run.status = _STATUS_MAP.get(result.get("status", "completed"), "succeeded")
        if run.status == "failed":
            run.error = str(result.get("error") or "")[:200]
        run.add_event("info", f"完成，{len(run.findings)} 筆發現")
    except CancelledScan:
        run.status = "cancelled"
        run.add_event("info", "已取消")
    except ScanError as exc:
        # 請求不合法／目標不符合公開位址政策（400 類）：以 failed 收尾並帶可讀原因。
        run.status = "failed"
        run.error = str(exc)[:200]
        run.add_event("error", str(exc)[:200])
    except Exception as exc:  # noqa: BLE001 — 任何錯誤都落成 run 的 error，不讓執行緒炸掉
        run.status = "failed"
        run.error = type(exc).__name__
        run.add_event("error", f"engine error: {type(exc).__name__}")
    finally:
        if not run.is_terminal:
            run.status = "succeeded"
        run.phase = "done"
        run.ended_at = time.time()
