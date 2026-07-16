"""Jurisdiction-aware legal-review draft generation; never legal advice."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


REQUIRED_NOTICE = (
    "DRAFT FOR REVIEW\nNOT LEGAL ADVICE\nREQUIRES REVIEW AND SIGNATURE BY THE "
    "APPROPRIATE RESPONSIBLE PERSON, FORENSIC EXPERT, AND LEGAL COUNSEL"
)


def _value(data: Mapping[str, Any], key: str, placeholder: str = "[NOT PROVIDED]") -> str:
    value = data.get(key)
    return str(value) if value not in (None, "") else placeholder


def generate_electronic_record_certificate(case: Mapping[str, Any], evidence: Mapping[str, Any], *, jurisdiction: str) -> str:
    """Generate a review-only draft; callers must supply real facts themselves."""
    profile = jurisdiction.upper()
    jurisdiction_note = (
        "India profile: drafted for legal/forensic review against applicable electronic-record requirements."
        if profile == "IN" else
        f"{profile} profile: obtain jurisdiction-specific legal review before use."
    )
    return f"""{REQUIRED_NOTICE}

OSIRIS ELECTRONIC-RECORD CERTIFICATE — DRAFT
Jurisdiction: {profile}
{jurisdiction_note}

Case ID: {_value(case, 'case_id')}
Authorization reference: {_value(case, 'authorization_reference')}
Handling marking: {_value(case, 'handling_marking')}
Evidence ID: {_value(evidence, 'evidence_id')}
Evidence SHA-256: {_value(evidence, 'sha256')}
Evidence byte length: {_value(evidence, 'byte_length')}
Collection time: {_value(evidence, 'collected_at')}
Source identifier: {_value(evidence, 'source_identifier')}
Collector/version: {_value(evidence, 'collector_version')}
System/location details: [NOT PROVIDED]
Transformation history: [REFER TO PROVENANCE AND CHAIN-OF-CUSTODY RECORDS]

Responsible person name/signature: [REQUIRES HUMAN COMPLETION]
Forensic expert name/signature: [REQUIRES HUMAN COMPLETION]
Legal counsel review: [REQUIRES HUMAN COMPLETION]
Generated at: {datetime.now(timezone.utc).isoformat()}
"""
