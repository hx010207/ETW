from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

from etw.models.enums import ClassificationState, DispositionState, ReviewPriority
from etw.models.evidence import AssetCandidate


class AuditEvent(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    from_status: DispositionState
    to_status: DispositionState
    actor: str = "analyst"
    note: str = ""


class Case(BaseModel):
    id: str
    fingerprint: str
    credential_type: str
    asset_scope: str
    classification: ClassificationState
    disposition: DispositionState = DispositionState.NEW
    priority: ReviewPriority = ReviewPriority.P3
    priority_factors: List[str] = Field(default_factory=list)
    classification_reasons: List[str] = Field(default_factory=list)
    observation_ids: List[str] = Field(default_factory=list)
    observations_count: int = 1
    related_cases: List[str] = Field(default_factory=list)
    asset_candidates: List[AssetCandidate] = Field(default_factory=list)
    audit_history: List[AuditEvent] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
