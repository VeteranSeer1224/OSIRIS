from typing import Any

from schema_validation import (
    validate_raw_scan,
    validate_report,
    validate_explanation_cards,
)
from schemas.models import Dossier


def test_raw_scan_schema():
    scan = {
        "target": "example.com",
        "scan_date": "2026-06-29",
        "entities": [
            {"type": "domain", "value": "example.com"}
        ],
        "events": []
    }

    assert validate_raw_scan(scan)


def test_report_schema():
    report: dict[str, Any] = {
        "report_metadata": {},
        "summary": {},
        "risk_assessment": {},
        "findings": []
    }

    assert validate_report(report)


def test_explanation_cards_schema():
    cards = {
        "schema_version": "1.0",
        "generated_at": "2026-06-30T00:00:00+00:00",
        "card_count": 1,
        "cards": [
            {
                "entity_id": "example.com",
                "entity": "example.com",
                "timestamp": "2026-06-30T00:00:00+00:00",
                "risk_score": 72,
                "top_features": [
                    {
                        "feature": "breach_appearance_count",
                        "contribution": "+0.41",
                        "plain_language": "Appeared in 3 breaches",
                    }
                ],
                "supporting_evidence": ["Appeared in 3 breaches"],
                "contradicting_evidence": [],
                "explanation": "example.com received a risk score of 72.",
                "confidence": 0.85,
                "fairness_check": {"passed": True, "flagged": False, "notes": []},
                "robustness_check": {"passed": True, "notes": []},
            }
        ],
    }

    assert validate_explanation_cards(cards)


def test_dossier_schema():
    from schema_validation import validate_dossier
    dossier = {
        "target": "example.com",
        "scan_date": "2026-06-30T00:00:00Z",
        "profiled_at": "2026-06-30T00:01:00Z",
        "risk_score": 50,
        "risk_level": "MEDIUM",
        "injection_detected": False,
        "injection_details": None,
        "profile": {},
        "risk_features": [],
        "insufficient_data_flags": [],
        "executive_summary": "Summary.",
        "model_metadata": {},
        "schema_version": "1.0"
    }
    assert validate_dossier(dossier)


def test_dossier_pydantic_contract_rejects_incomplete_model_metadata():
    dossier = {
        "target": "example.com", "scan_date": "2026-06-30T00:00:00Z",
        "profiled_at": "2026-06-30T00:01:00Z", "risk_score": 50,
        "profile": {"identity": "x", "geo_temporal": "x", "technical_stack": [], "opsec_posture": "x"},
        "risk_features": [], "executive_summary": "Summary.",
        "model_metadata": {"prompt_version": "v1"},
    }
    try:
        Dossier.model_validate(dossier)
    except ValueError:
        pass
    else:
        raise AssertionError("Pydantic dossier contract accepted incomplete model metadata")
