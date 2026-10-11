"""
Observation-to-case correlation service for Exposure Triage Workbench (ETW).

Enforces:
1. Deterministic grouping by (fingerprint, credential_type, asset_scope).
2. Strict cross-asset boundary: observations in different repositories/scopes
   are NEVER merged, even if their HMAC secret fingerprints match.
3. Cross-repository linking: cases sharing the same secret fingerprint across
   different asset scopes are linked via related_cases.
4. Aggregation of observation provenance, asset candidates, and classification rationale.
"""

import hashlib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from etw.analysis.prioritize import calculate_case_priority
from etw.models.case import AuditEvent, Case
from etw.models.enums import ClassificationState, DispositionState, ReviewPriority
from etw.models.evidence import AssetCandidate
from etw.models.observation import Observation
from etw.rules.classifier import ClassificationResult, classify_observation


CLASSIFICATION_SEVERITY_ORDER = {
    ClassificationState.CANDIDATE_SECRET: 1,
    ClassificationState.LIKELY_CANARY: 2,
    ClassificationState.NEEDS_REVIEW: 3,
    ClassificationState.LIKELY_TEST_VALUE: 4,
    ClassificationState.LIKELY_PLACEHOLDER: 5,
    ClassificationState.EXCLUDED_BY_POLICY: 6,
}


def _generate_case_id(fingerprint: str, credential_type: str, asset_scope: str) -> str:
    """Generate deterministic case identifier from correlation key."""
    key = f"{fingerprint}:{credential_type}:{asset_scope}".encode("utf-8")
    digest = hashlib.sha256(key).hexdigest()[:12]
    return f"case-{digest}"


def correlate_observations_into_cases(
    observations: List[Observation],
    classification_map: Optional[Dict[str, ClassificationResult]] = None,
) -> List[Case]:
    """
    Correlates a list of Observations into deduplicated, scoped Cases.

    Args:
        observations: List of validated Observation objects.
        classification_map: Optional precomputed map of observation.id -> ClassificationResult.
            If not provided, each observation is classified using classify_observation().

    Returns:
        List of Case objects with observation-to-case links and cross-asset relationships.
    """
    if not observations:
        return []

    # 1. Group observations by (fingerprint, credential_type, asset_scope)
    # Using tuple key ensures observations from different asset_scope are never merged
    groups: Dict[Tuple[str, str, str], List[Observation]] = {}

    for obs in observations:
        scope = obs.asset_scope.strip() if obs.asset_scope else (obs.location.repo_name or "default_scope")
        group_key = (obs.candidate_fingerprint, obs.rule_id, scope)
        if group_key not in groups:
            groups[group_key] = []
        groups[group_key].append(obs)

    # 2. Build Case object for each group
    now_iso = datetime.now(timezone.utc).isoformat()
    cases: List[Case] = []

    for (fingerprint, cred_type, scope), group_obs in groups.items():
        case_id = _generate_case_id(fingerprint, cred_type, scope)
        obs_ids = [o.id for o in group_obs]

        # Gather classification results for observations in this group
        results: List[ClassificationResult] = []
        for o in group_obs:
            if classification_map and o.id in classification_map:
                res = classification_map[o.id]
            else:
                res = classify_observation(o)
            results.append(res)

        # Aggregate classification: choose highest severity state
        case_classification = min(
            (r.state for r in results),
            key=lambda s: CLASSIFICATION_SEVERITY_ORDER.get(s, 99),
        )

        # Calculate case priority and priority factors
        case_priority, priority_factors = calculate_case_priority(results)

        # Aggregate unique classification reasons
        reasons: List[str] = []
        seen_reasons = set()
        for r in results:
            if r.rationale and r.rationale not in seen_reasons:
                seen_reasons.add(r.rationale)
                reasons.append(r.rationale)

        # Aggregate and deduplicate asset candidates
        asset_candidates: List[AssetCandidate] = []
        seen_assets = set()
        for o in group_obs:
            for ac in o.extracted_assets:
                asset_key = (ac.identifier, ac.asset_type)
                if asset_key not in seen_assets:
                    seen_assets.add(asset_key)
                    asset_candidates.append(ac)

        # Determine initial disposition
        if case_classification == ClassificationState.NEEDS_REVIEW:
            initial_disposition = DispositionState.NEEDS_REVIEW
        else:
            initial_disposition = DispositionState.NEW

        initial_audit = AuditEvent(
            timestamp=now_iso,
            from_status=DispositionState.NEW,
            to_status=initial_disposition,
            actor="system",
            note=f"Correlated {len(group_obs)} observation(s) under scope {scope}",
        )

        case = Case(
            id=case_id,
            fingerprint=fingerprint,
            credential_type=cred_type,
            asset_scope=scope,
            classification=case_classification,
            disposition=initial_disposition,
            priority=case_priority,
            priority_factors=priority_factors,
            classification_reasons=reasons,
            observation_ids=obs_ids,
            observations_count=len(obs_ids),
            related_cases=[],
            asset_candidates=asset_candidates,
            audit_history=[initial_audit],
            created_at=now_iso,
            updated_at=now_iso,
        )
        cases.append(case)

    # 3. Cross-repository linking:
    # Identify cases sharing the same secret fingerprint but living in different asset scopes
    fingerprint_to_cases: Dict[str, List[Case]] = {}
    for c in cases:
        if c.fingerprint not in fingerprint_to_cases:
            fingerprint_to_cases[c.fingerprint] = []
        fingerprint_to_cases[c.fingerprint].append(c)

    for fp, linked_cases in fingerprint_to_cases.items():
        if len(linked_cases) > 1:
            for c in linked_cases:
                c.related_cases = [other.id for other in linked_cases if other.id != c.id]

    return cases
