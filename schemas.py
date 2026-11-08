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


Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]


class RecommendedAction(BaseModel):
    action: str
    target: str
    requires_approval: bool
    justification: str = ""


class InjectionFlag(BaseModel):
    field: str
    excerpt: str
    kind: str = "instruccio"  # instruccio: órdenes al sistema · ocultacio: texto escondido a la persona


class TriagePreview(BaseModel):
    """Evidencias + propuesta de N1 (veredicto, decisión, acciones). La persona decide al final."""

    alert: Alert
    contexts: list[ContextRecord] = Field(default_factory=list)
    related_logs: list[dict[str, Any]] = Field(default_factory=list)
    queries: list[QueryRecord] = Field(default_factory=list)
    verdict: Verdict = "needs_more_info"
    severity: str
    severity_rationale: str
    open_questions: list[str] = Field(default_factory=list)
    # Propuesta (verdict.decide). Vacíos si no se ha decidido.
    confidence: float | None = None
    justification: str = ""
    decision: Literal["close", "escalate"] | None = None
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    injection_flags: list[InjectionFlag] = Field(default_factory=list)
    title: str = ""
    summary: str = ""
    decision_source: Literal["llm", "rules"] | None = None
    decision_notes: list[str] = Field(default_factory=list)  # correcciones de la política sobre la propuesta
    rule_applied: str = ""  # regla que decidió, si fueron las reglas (p. ej. «RB-01 simulacro»)
    second_opinion: dict[str, Any] | None = None  # si decidió la IA: qué opinan las reglas (verdict, rule, justification)
