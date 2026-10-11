"""
JSON export generator for Exposure Triage Workbench (ETW).

Guarantees:
1. Strict schema compliance with Pydantic model dumps.
2. Raw secrets are NEVER included in any serialized case or observation.
3. Summary distributions by priority, classification, and disposition.
"""

from collections import Counter
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from etw.models.case import Case
from etw.models.enums import ClassificationState, ReviewPriority
from etw.models.observation import Observation


def generate_json_export(
    cases: List[Case],
    observations_by_case: Optional[Dict[str, List[Observation]]] = None,
    run_id: Optional[str] = None,
    tool_version: str = "0.2.0",
) -> Dict[str, Any]:
    """
    Produces a sanitized, machine-readable JSON triage bundle.

    Args:
        cases: List of Case domain models.
        observations_by_case: Optional map of case_id -> list of Observation models.
        run_id: Optional scan run identifier.
        tool_version: Current ETW version.

    Returns:
        Structured dictionary ready for JSON serialization.
    """
    if run_id is None:
        run_id = "run-manual"

    now_iso = datetime.now(timezone.utc).isoformat()
    total_cases = len(cases)
    total_observations = sum(c.observations_count for c in cases)

    priority_counts = Counter(c.priority.value for c in cases)
    classification_counts = Counter(c.classification.value for c in cases)
    disposition_counts = Counter(c.disposition.value for c in cases)

    noise_count = (
        classification_counts.get(ClassificationState.LIKELY_PLACEHOLDER.value, 0)
        + classification_counts.get(ClassificationState.LIKELY_TEST_VALUE.value, 0)
    )

    cases_payload: List[Dict[str, Any]] = []
    for c in cases:
        c_dict = c.model_dump()
        # If observations provided, attach nested sanitized observations
        if observations_by_case and c.id in observations_by_case:
            obs_list = [o.model_dump() for o in observations_by_case[c.id]]
            # Double check raw_secret is excluded
            for o in obs_list:
                o.pop("raw_secret", None)
            c_dict["observations"] = obs_list
        cases_payload.append(c_dict)

    export_bundle: Dict[str, Any] = {
        "metadata": {
            "tool": "Exposure Triage Workbench (ETW)",
            "version": tool_version,
            "generated_at": now_iso,
            "run_id": run_id,
            "total_cases": total_cases,
            "total_observations": total_observations,
            "noise_reduction_count": noise_count,
            "noise_reduction_percentage": round(noise_count / total_cases * 100, 2) if total_cases > 0 else 0.0,
        },
        "summary": {
            "by_priority": dict(priority_counts),
            "by_classification": dict(classification_counts),
            "by_disposition": dict(disposition_counts),
        },
        "cases": cases_payload,
    }

    return export_bundle
