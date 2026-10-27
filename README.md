# Argus AI Agent

由 [Argus 網站健檢平台](https://github.com/) 抽離出來的 **AI 滲透／UX 測試代理**，獨立成一個可用 HTTP API 呼叫的服務。

給它一個網址，它會**自己開 Chromium 瀏覽器**像人一樣操作、像滲透測試員一樣探測，回傳結構化的發現（JSON）。內部由 LLM 驅動的多代理架構（偵察 → 指揮官 → 多位資安專家 ＋ 擬真使用者 UX 測試）。

> ⚠️ **授權聲明**：深度資安測試會對目標送出主動請求／攻擊 payload。**只能對你自己擁有或已獲明確授權的網站使用。** `mode` 含 `deep` 時必須在請求帶 `authorized: true`，且服務內建 SSRF 防線（拒絕內網／localhost／非公開位址）。未經授權掃描他人網站可能違法。

## 架構

```
HTTP POST /scan ──► FastAPI (api/) ──► run_agent_for_scan (agent/)
                                         ├─ recon        （偵察，自開瀏覽器）
                                         ├─ orchestrator （指揮官，派工）
                                         ├─ specialists  （auth/idor、injection、xss …）
                                         └─ UX session   （擬真使用者體驗測試）
                                        ↓
                              findings（JSON 回傳）
```

- `agent/`：原封不動自 Argus 抽出的代理核心（`runner`/`loop`/`tools`/`providers`/`findings`）。
- `scans/`：精簡支援層——資料模型（單次掃描暫存）、`make_finding`、**SSRF 位址政策**、OWASP 對映、IP 判讀、URL 遮罩。移除了 Argus 的使用者／計費／排程耦合。
- `api/`：FastAPI 包裝，把 `run_agent_for_scan` 變成一個 HTTP 端點。
- 內部用 Django ORM＋SQLite 當單次掃描的暫存狀態（用完即刪），以沿用 Argus 已驗證的代理程式。

## 快速開始

```bash
pip install -r requirements.txt
playwright install chromium        # 下載瀏覽器（Docker 內用 --with-deps）

cp .env.example .env               # 填入至少一個 LLM 金鑰（MINIMAX_API_KEY 等）
export $(grep -v '^#' .env | xargs)

uvicorn api.app:app --host 0.0.0.0 --port 8000
```

或用 Docker：

```bash
docker build -t argus-agent .
docker run -p 8000:8000 --env-file .env argus-agent
```

## API

### `POST /scan`

```jsonc
{
  "url": "https://example.com",
  "mode": "both",          // ux | deep | both
  "authorized": true,       // mode 含 deep 時必填 true
  "submit_forms": false,    // UX 是否實際送出表單
  "recon_intel": null,      // 選填：已知同站 API 端點
  "known_findings": null,   // 選填：已知發現摘要（叫 agent 別重報）
  "test_auth_email": null,  // 選填：authenticated scan 測試帳號
  "test_auth_password": null
}
```

回應：

```jsonc
{
  "status": "completed",
  "steps": 42,
  "total_tokens": 85000,
  "summary": "…",
  "ux_issue_count": 1,
  "security_finding_count": 3,
  "findings": [
    {
      "category": "security",
      "severity": "high",
      "rule_id": "agent-observed-security-…",
      "title": "…",
      "description": "…",
      "remediation": "…",
      "evidence": "…",
      "owasp_category": "A01",
      "cwe_id": "CWE-862",
      "ai_handoff_prompt": "…",
      "url": "https://example.com/…"
    }
  ]
}
```

`GET /health` → `{"ok": true}`。

## 設定（環境變數）

| 變數 | 說明 | 預設 |
|---|---|---|
| `MINIMAX_API_KEY` / `GLM_API_KEY` / `GOOGLE_API_KEY` | LLM provider 金鑰（至少一個，依序 fallback） | — |
| `ARGUS_AGENT_SPECIALIST_MAX_STEPS` | 每位專家／recon／UX session 步數上限（**時間／成本主旋鈕**） | 30 |
| `ARGUS_AGENT_MAX_SPECIALIST_DISPATCH` | 指揮官最多派幾位專家 | 6 |
| `ARGUS_AGENT_MAX_STEPS` | recon／orchestrator 步數上限 | 20 |
| `ARGUS_AGENT_MAX_TOKENS` / `ARGUS_AGENT_UX_MAX_TOKENS` | 資安／UX session 的 token 上限 | 60000 / 120000 |
| `ARGUS_SCANNER_USER_AGENT` | 瀏覽器 User-Agent | ArgusAgent/1.0 |
| `ARGUS_SCANNER_EGRESS_IPS` | 掃描器出口 IP（逗號分隔），避免自身 IP 被誤判成內網外洩 | — |
| `ARGUS_ALLOW_PRIVATE_TARGETS` | 受控靶機測試放行私網（需 `DEBUG=true`） | false |

時間權衡：預設每位專家 30 步，一次深度掃描最壞約 `20×2 + 6×30 = 220` 步。調大 `ARGUS_AGENT_SPECIALIST_MAX_STEPS` 更能組出多步攻擊鏈（登入→枚舉→越權→驗證常要 15–25 步），調小更快但深的鏈狀漏洞可能來不及做完。

## 掃描後端（argus-agent / Strix）

同一條 `POST /scan` 契約可由不同引擎實作，用環境變數 `AGENT_BACKEND` 切換，**呼叫端（Argus）無感**：

| `AGENT_BACKEND` | 引擎 | 說明 |
|---|---|---|
| `argus-agent`（預設） | 自家 LLM 多代理 | recon→指揮官→專家＋UX，資安與 UX 都做 |
| `strix` | [usestrix/strix](https://github.com/usestrix/strix) CLI | 只做資安滲透（無 UX）；`mode=ux` 回空結果 |

### Strix backend

Strix 是開源的自動化 AI 滲透測試器，**只有 CLI＋Docker、沒有 REST API**。本服務的 `strix_backend/`
把它包成同一條契約：叫起 `strix -n --target <url> [--instruction …]`、解析 `strix_runs/<run>/vulnerabilities.json`、
映射成契約的 finding（severity 五級、CVSS→priority_score、CWE、target→url；Strix 不提供 OWASP 分類，留空）。

啟用步驟（在 host 上）：

```bash
# 1. 安裝 strix 並確保 Docker 可用（strix 會在 Docker sandbox 內跑）
pipx install strix-agent          # 依 strix 官方說明
# 2. 設定 strix 自己的 LLM（擇一）
export STRIX_LLM=openrouter/z-ai/glm-5.3
export LLM_API_KEY=...            # 或 `strix auth login`
# 3. 切換本服務後端
export AGENT_BACKEND=strix
uvicorn api.app:app --host 0.0.0.0 --port 8000
```

| 變數 | 說明 | 預設 |
|---|---|---|
| `AGENT_BACKEND` | `argus-agent`（預設）或 `strix` | argus-agent |
| `STRIX_BIN` | strix 執行檔路徑 | strix |
| `STRIX_TIMEOUT` | 單次掃描逾時（秒） | 3600 |
| `STRIX_EXTRA_ARGS` | 額外傳給 strix 的參數（空白分隔） | — |
| `STRIX_LLM` / `LLM_API_KEY` / `LLM_API_BASE` | strix 自身的 LLM 設定（由 strix 讀取） | — |

完整部署範例（Dockerfile＋compose＋Docker sandbox 三種接法＋安全注意）見 [`deploy/strix/`](deploy/strix/README.md)。

> 授權：`strix` 偏主動攻擊，本 backend 強制 `authorized=true` 才跑；`submit_forms=false` 時以 instruction
> 要求 strix 不做破壞性寫入。送攻擊流量前仍請確定你擁有或已獲授權掃描該目標。
> Docker-in-Docker：以容器部署本服務要跑 strix backend 時，需讓容器能存取 Docker（掛 socket 或 DinD）。

## 限制

- **Kali／sqlmap 主動驗證**在獨立服務是停用 stub（Argus 版需整套 Kubernetes 控制平面）；要接自己的後端，替換 `scans/security/kali_tools.py` 的 `run_sqlmap`（回傳同樣 dict 契約）。
- 單次掃描可能數分鐘；SQLite 暫存建議單 worker 跑（或換成每請求獨立 DB）。
- 需要真實 LLM 金鑰與可連線的公開目標才能實際運作；`python manage.py test tests` 的煙霧測試以 mock 驗證結構健全性，不需金鑰。

## 測試

```bash
python manage.py test tests      # 煙霧測試（mock LLM 與瀏覽器）
```

## 授權

MIT。本專案抽離自 Argus；代理核心程式沿用其實作。
