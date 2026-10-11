"""
Priority calculation for cases in Exposure Triage Workbench (ETW).
"""

from typing import List, Tuple
from etw.models.enums import ReviewPriority
from etw.rules.classifier import ClassificationResult


PRIORITY_ORDER = {
    ReviewPriority.P1: 1,
    ReviewPriority.P2: 2,
    ReviewPriority.P3: 3,
    ReviewPriority.P4: 4,
}


def calculate_case_priority(
    results: List[ClassificationResult],
) -> Tuple[ReviewPriority, List[str]]:
    """
    Computes aggregated review priority for a group of observations forming a Case.

    Takes the highest priority across all observations in the case and aggregates
    the unique priority factors.
    """
    if not results:
        return ReviewPriority.P3, ["default_normal_priority"]

    # Sort results by priority severity (lowest rank number = highest severity)
    highest_prio = min((r.priority for r in results), key=lambda p: PRIORITY_ORDER.get(p, 99))

    all_factors: List[str] = []
    seen = set()
    for r in results:
        for f in r.priority_factors:
            if f not in seen:
                seen.add(f)
                all_factors.append(f)

    return highest_prio, all_factors
