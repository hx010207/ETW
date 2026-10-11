from enum import Enum


class ClassificationState(str, Enum):
    CANDIDATE_SECRET = "candidate_secret"
    LIKELY_PLACEHOLDER = "likely_placeholder"
    LIKELY_TEST_VALUE = "likely_test_value"
    LIKELY_CANARY = "likely_canary"
    NEEDS_REVIEW = "needs_review"
    EXCLUDED_BY_POLICY = "excluded_by_policy"


class DispositionState(str, Enum):
    NEW = "new"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED_ISSUE = "confirmed_issue"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"


class ReviewPriority(str, Enum):
    P1 = "P1_urgent"
    P2 = "P2_high"
    P3 = "P3_normal"
    P4 = "P4_low"


class SourceValidity(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"
    NOT_CHECKED = "not_checked"


class EvidenceLevel(str, Enum):
    OBSERVED = "observed"
    DERIVED = "derived"
    ANALYST_CONFIRMED = "analyst_confirmed"
