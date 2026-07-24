"""Typed, fail-closed dissemination policy for OSIRIS artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from case_authorization import CaseAuthorization, CollectionMode, validate_collection
from evidence_store import LocalEvidenceStore, RawEvidenceRecord


FINAL_SCORE_MODES = frozenset({"REAL"})
REQUIRED_PROVENANCE_ARTIFACTS = frozenset({
    "raw_scan.json", "dossier.json", "explanation_cards.json", "report.json",
})
_PROOF_TOKEN = object()


class ReleaseBlockedError(RuntimeError):
    """Raised when dissemination is attempted without a verified PASS."""


@dataclass(frozen=True)
class AuthorizationProof:
    authorization: CaseAuthorization
    signer_fingerprint: str
    signature_b64: str = field(repr=False)
    trusted_public_key_pem: bytes = field(repr=False)
    _token: object = field(repr=False)


def _authorization_payload(authorization: CaseAuthorization) -> bytes:
    return json.dumps(
        authorization.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reverify_authorization_proof(proof: AuthorizationProof) -> None:
    if proof._token is not _PROOF_TOKEN:
        raise ReleaseBlockedError(
            "authorization proof was not produced by signature verification"
        )
    loaded = serialization.load_pem_public_key(proof.trusted_public_key_pem)
    if not isinstance(loaded, Ed25519PublicKey):
        raise ReleaseBlockedError("trusted authorization key is not Ed25519")
    raw = loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fingerprint = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if fingerprint != proof.signer_fingerprint:
        raise ReleaseBlockedError("authorization signer fingerprint changed")
    try:
        loaded.verify(
            base64.b64decode(proof.signature_b64, validate=True),
            _authorization_payload(proof.authorization),
        )
    except Exception as exc:
        raise ReleaseBlockedError("authorization signature revalidation failed") from exc


def verify_authorization_signature(
    authorization: CaseAuthorization,
    *,
    signature_b64: str,
    trusted_public_key: str | Path,
) -> AuthorizationProof:
    """Verify canonical authorization bytes against an external trusted key."""
    loaded = serialization.load_pem_public_key(Path(trusted_public_key).read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise ReleaseBlockedError("trusted authorization key is not Ed25519")
    public_key_pem = Path(trusted_public_key).read_bytes()
    try:
        loaded.verify(
            base64.b64decode(signature_b64, validate=True),
            _authorization_payload(authorization),
        )
    except Exception as exc:
        raise ReleaseBlockedError("authorization signature verification failed") from exc
    raw = loaded.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return AuthorizationProof(
        authorization=authorization,
        signer_fingerprint=f"sha256:{hashlib.sha256(raw).hexdigest()}",
        signature_b64=signature_b64,
        trusted_public_key_pem=public_key_pem,
        _token=_PROOF_TOKEN,
    )


@dataclass(frozen=True)
class ReleaseContext:
    authorization_proof: AuthorizationProof
    target: str
    collection_mode: CollectionMode
    evidence_store: LocalEvidenceStore
    evidence_records: tuple[RawEvidenceRecord, ...]
    raw_scan: Mapping[str, Any]
    dossier: Mapping[str, Any]
    explanation_cards: Mapping[str, Any]
    report: Mapping[str, Any]
    lineage: Mapping[str, Any]
    provenance: Mapping[str, Any]

    def validation_reasons(self) -> list[str]:
        reasons: list[str] = []
        proof = self.authorization_proof
        try:
            _reverify_authorization_proof(proof)
        except Exception as exc:
            reasons.append(f"authorization proof validation failed: {exc}")
        authorization = proof.authorization
        try:
            validate_collection(authorization, self.target, self.collection_mode)
        except Exception as exc:
            reasons.append(f"authorization validation failed: {exc}")

        documents = {
            "raw_scan": self.raw_scan,
            "dossier": self.dossier,
            "explanation_cards": self.explanation_cards,
            "lineage": self.lineage,
        }
        identities: set[tuple[str, str]] = set()
        for name, document in documents.items():
            case_id, run_id = document.get("case_id"), document.get("run_id")
            if not isinstance(case_id, str) or not case_id:
                reasons.append(f"{name} case ID is missing")
            if not isinstance(run_id, str) or not run_id:
                reasons.append(f"{name} run ID is missing")
            if isinstance(case_id, str) and isinstance(run_id, str):
                identities.add((case_id, run_id))
        report_metadata = self.report.get("report_metadata")
        if not isinstance(report_metadata, Mapping):
            reasons.append("report identity metadata is missing")
        else:
            report_case = report_metadata.get("case_id")
            report_run = report_metadata.get("run_id")
            if not isinstance(report_case, str) or not report_case:
                reasons.append("report case ID is missing")
            if not isinstance(report_run, str) or not report_run:
                reasons.append("report run ID is missing")
            if isinstance(report_case, str) and isinstance(report_run, str):
                identities.add((report_case, report_run))

        expected_run_id: str | None = None
        if len(identities) != 1:
            reasons.append("artifact case/run IDs are incomplete or inconsistent")
        else:
            artifact_case_id, expected_run_id = next(iter(identities))
            if artifact_case_id != authorization.case_id:
                reasons.append("artifact case ID does not match authorization")
        if not self.evidence_records:
            reasons.append("no verified raw-evidence observations")
        for record in self.evidence_records:
            try:
                self.evidence_store.verify(record)
            except Exception as exc:
                reasons.append(f"evidence verification failed: {exc}")
            if record.case_id != authorization.case_id:
                reasons.append("evidence case ID does not match authorization")
            if expected_run_id is None or record.run_id != expected_run_id:
                reasons.append("evidence run ID does not match artifacts")

        score_mode = str(self.dossier.get("score_mode", "UNKNOWN")).upper()
        if score_mode not in FINAL_SCORE_MODES:
            reasons.append("output mode is not REAL")
        metadata = self.dossier.get("scoring_metadata")
        try:
            if not isinstance(metadata, Mapping):
                raise TypeError("scoring metadata must be an object")
            contributions = metadata.get("contributions")
            if not isinstance(contributions, list):
                raise TypeError("scoring contributions must be a list")
            if any(not isinstance(item, Mapping) for item in contributions):
                raise TypeError("every scoring contribution must be an object")
            total = float(metadata["intercept"]) + sum(
                float(item["contribution_points"])
                for item in contributions
            )
            reconstructed = max(0, min(100, round(total)))
            if reconstructed != self.dossier.get("risk_score"):
                reasons.append("score reconstruction failed")
        except (KeyError, TypeError, ValueError):
            reasons.append("scoring reconstruction metadata is invalid")

        cards = self.explanation_cards.get("cards")
        if not isinstance(cards, list) or not cards:
            reasons.append("explanation audit is missing")
        else:
            for card in cards:
                for name in ("fairness_check", "robustness_check"):
                    control = card.get(name)
                    try:
                        evaluated = int(control.get("evaluated_variants", 0))
                    except (AttributeError, TypeError, ValueError):
                        evaluated = 0
                    if not isinstance(control, Mapping) or (
                        control.get("passed") is not True or evaluated <= 0
                    ):
                        reasons.append(f"{name} is missing, unevaluated, inconclusive, or failed")

        graph = self.provenance.get("@graph")
        if not isinstance(graph, list) or not graph:
            reasons.append("provenance is missing or incomplete")
        else:
            nodes = [node for node in graph if isinstance(node, Mapping)]
            evidence_nodes = {
                str(node.get("id")): node
                for node in nodes
                if str(node.get("id", "")).startswith("osiris:evidence/")
            }
            for record in self.evidence_records:
                node = evidence_nodes.get(f"osiris:evidence/{record.evidence_id}")
                if (
                    node is None
                    or node.get("osiris:caseId") != record.case_id
                    or node.get("osiris:runId") != record.run_id
                    or node.get("osiris:sha256") != record.sha256
                ):
                    reasons.append(
                        f"provenance does not authenticate evidence {record.evidence_id}"
                    )
            provenance_artifacts = {
                str(node.get("id", "")).rsplit("/", 1)[-1]
                for node in nodes
                if str(node.get("id", "")).startswith("osiris:artifact/")
            }
            if not REQUIRED_PROVENANCE_ARTIFACTS.issubset(provenance_artifacts):
                reasons.append("provenance does not cover all required artifacts")
        return reasons


@dataclass(frozen=True)
class ReleaseDecision:
    status: str
    reasons: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "passed": self.passed, "reasons": list(self.reasons)}


def evaluate_release(context: ReleaseContext | None) -> ReleaseDecision:
    """Only a typed, revalidated context can produce PASS."""
    if not isinstance(context, ReleaseContext):
        return ReleaseDecision(
            "BLOCKED",
            ("verified typed release context is absent",),
        )
    try:
        reasons = context.validation_reasons()
    except Exception as exc:
        reasons = [f"release context validation failed closed: {exc}"]
    return ReleaseDecision("PASS" if not reasons else "BLOCKED", tuple(reasons))


def require_release(
    report: Mapping[str, Any],
    destination: str,
    *,
    context: ReleaseContext | None = None,
) -> None:
    decision = evaluate_release(context)
    if not decision.passed:
        detail = "; ".join(decision.reasons)
        raise ReleaseBlockedError(f"{destination} is prohibited: {detail}")
    if context is None:
        raise ReleaseBlockedError(
            f"{destination} is prohibited: verified release context is absent"
        )
    supplied = dict(report)
    bound = dict(context.report)
    supplied.pop("release_decision", None)
    bound.pop("release_decision", None)
    if supplied != bound:
        raise ReleaseBlockedError(
            f"{destination} is prohibited: report is not bound to the verified release context"
        )
