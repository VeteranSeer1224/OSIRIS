"""Deterministic PROV-O JSON-LD for the local OSIRIS pipeline."""
from __future__ import annotations

from typing import Any, Mapping


PROV_CONTEXT = {
    "prov": "http://www.w3.org/ns/prov#",
    "osiris": "https://osiris.example/ns#",
    "id": "@id",
    "type": "@type",
}


def build_provenance(*, case_id: str, run_id: str, raw_evidence: Mapping[str, Any], artifacts: Mapping[str, str]) -> dict[str, Any]:
    """Build a compact, deterministic graph linking normalized outputs to raw bytes."""
    evidence_id = str(raw_evidence["evidence_id"])
    raw_node = {
        "id": f"osiris:evidence/{evidence_id}", "type": "prov:Entity",
        "osiris:caseId": case_id, "osiris:runId": run_id,
        "osiris:sha256": raw_evidence["sha256"],
        "osiris:path": raw_evidence["relative_path"],
        "prov:generatedAtTime": raw_evidence["collected_at"],
    }
    activity_id = f"osiris:activity/normalize/{run_id}"
    graph: list[dict[str, Any]] = [raw_node, {
        "id": activity_id, "type": "prov:Activity", "osiris:caseId": case_id,
        "osiris:runId": run_id, "prov:used": raw_node["id"],
        "prov:wasAssociatedWith": "osiris:agent/OSIRIS-Sense/1.0",
    }]
    for name, digest in sorted(artifacts.items()):
        graph.append({
            "id": f"osiris:artifact/{run_id}/{name}", "type": "prov:Entity",
            "osiris:caseId": case_id, "osiris:runId": run_id,
            "osiris:sha256": f"sha256:{digest}",
            "prov:wasDerivedFrom": raw_node["id"], "prov:wasGeneratedBy": activity_id,
        })
    return {"@context": PROV_CONTEXT, "@graph": graph}
