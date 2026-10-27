# Strix 版 argus-agent 部署

把 argus-agent 以 **Strix（usestrix/strix）** 當後端跑起來，對外仍是同一條 `POST /scan` 契約，
Argus 端無感（設定與自家引擎版完全相同，只差 `ARGUS_AGENT_SERVICE_URL` 指向本服務）。

```
Argus worker ──POST /scan──► 本服務 (AGENT_BACKEND=strix) ──subprocess──► strix CLI ──► Docker sandbox ──► 目標
```

> ⚠️ Strix 只有 CLI＋Docker、**沒有自己的 HTTP API**。所以不能把 Argus 指向 strix；要指向「跑著
> `AGENT_BACKEND=strix` 的本服務」，由它叫起 strix。

## 前置需求

- 一台可用 **Docker daemon** 的主機（strix 會在 Docker sandbox 內跑目標）。
- 一組 strix 能用的 **LLM**（`STRIX_LLM` + `LLM_API_KEY`，或在映像內 `strix auth login`）。
- 本服務與 Argus worker 之間網路可達。

## 啟動

```bash
cd deploy/strix
cp .env.strix.example .env.strix      # 填 STRIX_LLM / LLM_API_KEY
docker compose -f docker-compose.strix.yml up -d --build
curl http://localhost:8000/health     # → {"ok":true}
```

## 接上 Argus

在 **Argus** 那端（`.env` 或 K8s ConfigMap/Secret）設：

```
ARGUS_AGENT_ENABLED=true
ARGUS_AGENT_SERVICE_URL=http://<本服務host>:8000
ARGUS_AGENT_SERVICE_TIMEOUT=1800
```

重啟 Argus 的 Django／Celery worker。跑一次「全網站＋主動＋網域已驗證＋勾深度資安」的掃描即會呼叫本服務。

## Docker sandbox：三種接法

strix 需要一個 Docker daemon。擇一：

1. **掛主機 socket（本範例預設，最簡單）**：`-v /var/run/docker.sock:/var/run/docker.sock`，
   strix 的 sandbox 以 sibling 容器在主機上啟動。
   **⚠️ 掛 socket＝把主機 root 權限給此容器**，只在可信主機、私有網路用。
2. **Docker-in-Docker（dind）sidecar**：另跑一個 `docker:dind` 容器，本服務設
   `DOCKER_HOST=tcp://dind:2376`（＋TLS）。隔離較好、設定較繁。
3. **Rootless Docker**：降權，但要主機先設定好 rootless daemon。

## 安全注意

- **本服務的 `/scan` 沒有內建驗證**。`ARGUS_AGENT_SERVICE_KEY` 由 Argus 送出 `Authorization: Bearer`，
  但服務端目前不驗證——請用**私有網路／防火牆／反向代理**保護，切勿公開暴露。要強制驗證可在前面擺一層
  nginx/traefik 檢查該 Bearer。
- strix 偏主動攻擊：本服務的 strix 後端**強制 `authorized=true` 才跑**（對應 Argus 的深度資安閘門：
  全網站＋active＋網域已驗證），`submit_forms=false` 時以 instruction 要求不做破壞性寫入。
- 只對你**擁有或已獲明確授權**的目標掃描。

## 限制

- **只做資安滲透，沒有 UX 測試**：只勾 UX（`mode=ux`）的掃描在本後端回空結果——要 UX 發現請用自家引擎版。
- strix 不提供 OWASP 分類（finding 的 `owasp_category` 會是空）；severity／CVSS／CWE／target 都會映射。
- 單次掃描可能數分鐘，`ARGUS_AGENT_SERVICE_TIMEOUT` 要留足。

## 驗證輸出

接上後，worker log 不再出現「未設定 ARGUS_AGENT_SERVICE_URL」；掃描完成後「問題分析」會出現來自
agent 服務的資安發現（rule_id `strix-<id>` → 落地後走 Argus 的 `agent-observed-security-*` 觀察層，
不進基準分、報告封頂中風險）。
