"""獨立服務用的精簡資料模型（由 Argus 抽離）。

只保留 AI Agent 真正會讀寫的欄位與關聯，移除了 Argus 的 user／SiteProject 外鍵與
計費／排程欄位。這些資料列只是單次掃描的暫存狀態：API 收到請求 → 建立 ScanJob＋Page
→ 跑 agent（過程中寫 AgentSession／AgentStep／Finding）→ 讀回 Finding 組成 JSON 回傳
→ 刪除整列。用 Django ORM＋SQLite 當暫存，是為了原封不動沿用 Argus 已驗證的 agent 程式，
而不是冒險重寫 2500 行。
"""
from __future__ import annotations

from django.db import models


def encrypt_test_auth(value: str) -> str:
    """獨立服務不落地加密測試帳密（請求進來即是明文、用完即刪列），原樣回傳。"""
    return value or ""


def decrypt_test_auth(value: str) -> str:
    """與 encrypt_test_auth 對稱：ScanJob 直接存明文，這裡原樣回傳。"""
    return value or ""


class ScanJob(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "等待中"
        AGENT_TESTING = "agent_testing", "Agent 測試中"
        COMPLETED = "completed", "已完成"
        FAILED = "failed", "失敗"

    class ScanMode(models.TextChoices):
        PASSIVE = "passive", "被動偵測"
        ACTIVE = "active", "主動測試"

    original_url = models.URLField(max_length=2048, blank=True, default="")
    normalized_url = models.URLField(max_length=2048, blank=True, default="")
    origin = models.CharField(max_length=255, db_index=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)
    scan_mode = models.CharField(
        max_length=16, choices=ScanMode.choices, default=ScanMode.PASSIVE
    )
    # 主動測試（送攻擊 payload）必須明確授權；is_deep_security_mode 的三重閘之一
    active_testing_authorized = models.BooleanField(default=False)
    # 勾選 AI Agent 深度資安滲透才為 True；否則只跑擬真使用者 UX 測試
    deep_agent_requested = models.BooleanField(default=False)
    # 選填測試帳密（authenticated scan）；獨立服務直接存明文、用完刪列
    test_auth_email_encrypted = models.TextField(blank=True, default="")
    test_auth_password_encrypted = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"ScanJob<{self.id}>:{self.origin}"


class Page(models.Model):
    """掃描起點頁面。獨立服務由 API 請求建立（agent 從這裡開瀏覽器往外探索）。"""

    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="pages")
    url = models.URLField(max_length=2048)
    final_url = models.URLField(max_length=2048, blank=True, default="")
    depth = models.PositiveSmallIntegerField(default=0)
    blocked_reason = models.CharField(max_length=64, blank=True, default="")

    def __str__(self) -> str:
        return self.final_url or self.url


class Finding(models.Model):
    class Category(models.TextChoices):
        SEO = "seo", "SEO"
        AEO = "aeo", "AEO"
        GEO = "geo", "GEO"
        SECURITY = "security", "資訊安全"
        UX = "ux", "使用者體驗"

    class Severity(models.TextChoices):
        CRITICAL = "critical", "嚴重"
        HIGH = "high", "高"
        MEDIUM = "medium", "中"
        LOW = "low", "低"
        INFO = "info", "資訊"

    scan_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="findings")
    page = models.ForeignKey(
        Page, on_delete=models.SET_NULL, null=True, blank=True, related_name="findings"
    )
    # 以下欄位對應 scanners.make_finding 的輸出 ＋ owasp_mapper.tag 補的兩欄，
    # 讓 findings.persist_* 的 Finding.objects.create(**tagged) 不會因未知欄位報錯。
    category = models.CharField(max_length=16, choices=Category.choices)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    rule_id = models.CharField(max_length=128, blank=True, default="")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    remediation = models.TextField(blank=True, default="")
    evidence = models.TextField(blank=True, default="")
    evidence_type = models.CharField(max_length=32, blank=True, default="text")
    evidence_json = models.JSONField(default=dict, blank=True)
    evidence_source = models.CharField(max_length=32, blank=True, default="")
    ai_explanation = models.TextField(blank=True, default="")
    ai_remediation = models.TextField(blank=True, default="")
    llm_model = models.CharField(max_length=128, blank=True, default="")
    llm_generated_at = models.DateTimeField(null=True, blank=True)
    selector = models.CharField(max_length=512, blank=True, default="")
    bounding_box = models.JSONField(null=True, blank=True)
    priority_score = models.FloatField(null=True, blank=True)
    impact_area = models.CharField(max_length=64, blank=True, default="")
    confidence = models.FloatField(default=1.0)
    ai_handoff_prompt = models.TextField(blank=True, default="")
    owasp_category = models.CharField(max_length=8, blank=True, default="")
    cwe_id = models.CharField(max_length=16, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"[{self.severity}] {self.title}"


class AgentSession(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "等待中"
        RUNNING = "running", "執行中"
        COMPLETED = "completed", "已完成"
        FAILED = "failed", "失敗"

    scan_job = models.ForeignKey(
        ScanJob, on_delete=models.CASCADE, related_name="agent_sessions"
    )
    provider = models.CharField(max_length=64)
    model = models.CharField(max_length=128)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)
    max_steps = models.PositiveSmallIntegerField(default=20)
    total_tokens = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class AgentStep(models.Model):
    session = models.ForeignKey(AgentSession, on_delete=models.CASCADE, related_name="steps")
    step_number = models.PositiveSmallIntegerField()
    observation = models.TextField(blank=True)
    thought_summary = models.TextField(blank=True)
    tool_name = models.CharField(max_length=128, blank=True)
    tool_arguments = models.JSONField(default=dict, blank=True)
    tool_result = models.JSONField(default=dict, blank=True)
    token_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["step_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["session", "step_number"], name="unique_agent_step_per_session"
            ),
        ]
