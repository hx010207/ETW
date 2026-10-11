from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

from etw.models.enums import SourceValidity
from etw.models.evidence import LocationEvidence, AssetCandidate


class Observation(BaseModel):
    id: str
    detector: str
    rule_id: str
    source_reported_validity: SourceValidity = SourceValidity.NOT_CHECKED
    location: LocationEvidence
    asset_scope: str
    candidate_fingerprint: str
    redacted_match: str
    raw_secret: Optional[str] = Field(default=None, exclude=True, repr=False)
    extracted_assets: List[AssetCandidate] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
