from typing import Optional
from pydantic import BaseModel, Field
from etw.models.enums import EvidenceLevel


class LocationEvidence(BaseModel):
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_timestamp: Optional[str] = None
    repo_name: Optional[str] = None
    branch: Optional[str] = None


class ContextSnippet(BaseModel):
    pre_context: str = ""
    match_preview: str = ""
    post_context: str = ""


class AssetCandidate(BaseModel):
    identifier: str
    asset_type: str  # e.g., hostname, url, package, cloud_resource, repo
    evidence_level: EvidenceLevel = EvidenceLevel.DERIVED
    source_snippet: Optional[str] = None
