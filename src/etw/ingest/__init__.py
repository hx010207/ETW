"""ETW Scanner Ingestion Adapters"""

from etw.ingest.common import IngestResult, IngestError
from etw.ingest.trufflehog import ingest_trufflehog
from etw.ingest.gitleaks import ingest_gitleaks
from etw.ingest.mcp_config import ingest_mcp_config

__all__ = [
    "IngestResult",
    "IngestError",
    "ingest_trufflehog",
    "ingest_gitleaks",
    "ingest_mcp_config",
]
