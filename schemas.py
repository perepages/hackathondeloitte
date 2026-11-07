from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Alert(BaseModel):
    """Normalized subset of an alert; unknown source fields are preserved."""

    model_config = ConfigDict(extra="allow")

    alert_id: str
    created_at: str | None = None
    source_product: str = "unknown"
    rule_id: str | None = None
    rule_name: str = "Unclassified alert"
    severity: str = "medium"
    status: str = "new"
    description: str = ""
    entities: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    related_events: list[str] = Field(default_factory=list)
    runbook: str | None = None


class QueryRecord(BaseModel):
    method: str = "GET"
    path: str
    params: dict[str, Any] = Field(default_factory=dict)
    status: Literal["ok", "not_found", "error"]
    result_count: int | None = None
    note: str | None = None


class ContextRecord(BaseModel):
    kind: str
    key: str
    data: dict[str, Any]


class TriagePreview(BaseModel):
    """Evidence-first preview; not a final analyst ticket or LLM verdict."""

    alert: Alert
    contexts: list[ContextRecord] = Field(default_factory=list)
    related_logs: list[dict[str, Any]] = Field(default_factory=list)
    queries: list[QueryRecord] = Field(default_factory=list)
    verdict: Literal["needs_more_info"] = "needs_more_info"
    severity: str
    severity_rationale: str
    open_questions: list[str] = Field(default_factory=list)
