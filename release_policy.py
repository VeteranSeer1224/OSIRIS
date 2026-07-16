"""Fail-closed dissemination policy for OSIRIS artifacts.

This module is deliberately dependency-free so every report and export path can
use the same decision.  A report may still be rendered for technical review,
but only a PASS decision permits an external intelligence export.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


FINAL_SCORE_MODES = frozenset({"REAL"})


class ReleaseBlockedError(RuntimeError):
    """Raised when an external dissemination path is attempted without PASS."""


@dataclass(frozen=True)
class ReleaseDecision:
    status: str
    reasons: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "passed": self.passed, "reasons": list(self.reasons)}


def evaluate_release(report: Mapping[str, Any]) -> ReleaseDecision:
    """Return the sole dissemination decision for a completed report.

    Legacy reports lack the authorization and integrity evidence required for a
    PASS and therefore become review-only.  This is intentional: missing data
    cannot silently be interpreted as approval.
    """
    reasons: list[str] = []
    audit = report.get("audit_gate")
    if not isinstance(audit, Mapping) or audit.get("status") != "PASS":
        reasons.append("explanation, fairness, and robustness audit did not pass")

    risk = report.get("risk_assessment")
    score_mode = risk.get("score_mode") if isinstance(risk, Mapping) else None
    if str(score_mode or "UNKNOWN").upper() not in FINAL_SCORE_MODES:
        reasons.append("output mode is not REAL")

    authorization = report.get("case_authorization")
    if not isinstance(authorization, Mapping) or authorization.get("status") != "APPROVED":
        reasons.append("valid case authorization is absent")

    integrity = report.get("evidence_integrity")
    if not isinstance(integrity, Mapping) or integrity.get("status") != "PASS":
        reasons.append("raw-evidence integrity verification did not pass")

    return ReleaseDecision("PASS" if not reasons else "BLOCKED", tuple(reasons))


def require_release(report: Mapping[str, Any], destination: str) -> None:
    decision = evaluate_release(report)
    if not decision.passed:
        detail = "; ".join(decision.reasons)
        raise ReleaseBlockedError(f"{destination} is prohibited: {detail}")
