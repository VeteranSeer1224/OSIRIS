import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from case_authorization import CaseAuthorization, CollectionMode
from evidence_store import LocalEvidenceStore
from release_policy import (
    ReleaseBlockedError,
    ReleaseContext,
    evaluate_release,
    require_release,
    verify_authorization_signature,
)


def _signed_authorization(tmp_path):
    now = datetime.now(timezone.utc)
    authorization = CaseAuthorization.model_validate({
        "case_id": "CASE-RELEASE",
        "title": "Release test",
        "purpose": "Verify the typed release boundary",
        "jurisdiction": "GB",
        "created_at": now.isoformat(),
        "created_by": "reviewer",
        "authorization_reference": "AUTH-1",
        "authorization_document_hash": f"sha256:{'a' * 64}",
        "allowed_collection_modes": ["passive"],
        "authorized_targets": ["example.com"],
        "valid_from": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "data_retention_policy": "retain 30 days",
        "handling_marking": "INTERNAL",
        "approvers": ["reviewer"],
        "status": "APPROVED",
    })
    private_key = Ed25519PrivateKey.generate()
    public_path = tmp_path / "trusted-authorization.pem"
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    payload = json.dumps(
        authorization.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    proof = verify_authorization_signature(
        authorization,
        signature_b64=base64.b64encode(private_key.sign(payload)).decode("ascii"),
        trusted_public_key=public_path,
    )
    return authorization, proof


def test_forged_release_maps_cannot_pass():
    forged = {
        "authorization": {"status": "APPROVED"},
        "integrity": {"status": "PASS"},
        "audit_gate": {"status": "PASS"},
    }
    assert evaluate_release(forged).status == "BLOCKED"  # type: ignore[arg-type]


def test_verified_typed_release_context_can_pass(tmp_path):
    authorization, proof = _signed_authorization(tmp_path)
    store = LocalEvidenceStore(tmp_path / "evidence")
    record = store.preserve(
        b"raw observation",
        case_id=authorization.case_id,
        run_id="RUN-RELEASE",
        source_type="offline_fixture",
        source_identifier="fixture.json",
    )
    identity = {"case_id": "CASE-RELEASE", "run_id": "RUN-RELEASE"}
    report = {
        "report_metadata": dict(identity),
        "summary": {"target": "example.com"},
        "findings": [],
        "release_decision": {"status": "BLOCKED"},
    }
    context = ReleaseContext(
        authorization_proof=proof,
        target="example.com",
        collection_mode=CollectionMode.PASSIVE,
        evidence_store=store,
        evidence_records=(record,),
        raw_scan=dict(identity),
        dossier={
            **identity,
            "score_mode": "REAL",
            "risk_score": 15,
            "scoring_metadata": {"intercept": 15, "contributions": []},
        },
        explanation_cards={
            **identity,
            "cards": [{
                "fairness_check": {"passed": True, "evaluated_variants": 1},
                "robustness_check": {"passed": True, "evaluated_variants": 1},
            }],
        },
        report=report,
        lineage=dict(identity),
        provenance={"@graph": [
            {
                "id": f"osiris:evidence/{record.evidence_id}",
                "osiris:caseId": record.case_id,
                "osiris:runId": record.run_id,
                "osiris:sha256": record.sha256,
            },
            *[
                {"id": f"osiris:artifact/RUN-RELEASE/{name}"}
                for name in (
                    "raw_scan.json",
                    "dossier.json",
                    "explanation_cards.json",
                    "report.json",
                )
            ],
        ]},
    )
    assert evaluate_release(context).status == "PASS"
    require_release(report, "test export", context=context)
    with pytest.raises(ReleaseBlockedError, match="not bound"):
        require_release(
            {**report, "summary": {"target": "attacker.example"}},
            "test export",
            context=context,
        )

    tampered_proof = replace(proof, signature_b64=base64.b64encode(b"x" * 64).decode())
    assert evaluate_release(
        replace(context, authorization_proof=tampered_proof)
    ).status == "BLOCKED"

    wrong_run_record = replace(record, run_id="OTHER-RUN")
    assert evaluate_release(
        replace(context, evidence_records=(wrong_run_record,))
    ).status == "BLOCKED"

    malformed_cards = {
        **identity,
        "cards": [{
            "fairness_check": {"passed": True, "evaluated_variants": "not-a-number"},
            "robustness_check": {"passed": True, "evaluated_variants": 1},
        }],
    }
    malformed = evaluate_release(replace(context, explanation_cards=malformed_cards))
    assert malformed.status == "BLOCKED"
