"""Release-gated threat-intelligence interchange exports."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from release_policy import require_release


def export_stix21(report: Mapping[str, Any], output_path: str | Path) -> Path:
    """Export observable findings as a STIX 2.1 bundle only after PASS."""
    require_release(report, "STIX export")
    metadata = report.get("report_metadata", {})
    summary = report.get("summary", {})
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    objects: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        for item in finding.get("items", []):
            if not isinstance(item, Mapping):
                continue
            value, kind = str(item.get("value", "")), str(item.get("type", ""))
            pattern = {"ip": "ipv4-addr:value", "domain": "domain-name:value", "subdomain": "domain-name:value", "url": "url:value", "email": "email-addr:value"}.get(kind)
            if not value or not pattern:
                continue
            objects.append({
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}", "created": now, "modified": now,
                "name": f"OSIRIS {kind} observation", "pattern_type": "stix",
                "pattern": f"[{pattern} = '{value.replace("'", "\\'")}']",
                "valid_from": now, "confidence": 50,
                "labels": ["osiris", "release-approved"],
                "external_references": [{"source_name": "OSIRIS", "external_id": str(metadata.get("run_id", "unknown"))}],
            })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects,
              "x_osiris_case_id": metadata.get("case_id"), "x_osiris_run_id": metadata.get("run_id"),
              "x_osiris_target": summary.get("target")}
    destination = Path(output_path)
    destination.write_text(json.dumps(bundle, sort_keys=True, indent=2), encoding="utf-8")
    return destination
