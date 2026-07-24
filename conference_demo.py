"""Repeatable, fully offline three-scenario conference demonstration."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from evidence_capsule import (
    CapsuleVerificationError,
    build_capsule,
    generate_development_key,
    verify_capsule,
    write_public_key,
)
from release_policy import ReleaseBlockedError
from report_build import export_misp
from run_pipeline import pipeline_from_existing_scan


FIXTURE = [
    {"type": "DOMAIN_NAME", "data": "example.com", "module": "offline_fixture"},
    {"type": "IP_ADDRESS", "data": "93.184.216.34", "module": "offline_fixture"},
]


def run_conference_demo(output_root: str | Path) -> dict[str, Any]:
    root = Path(output_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="run.", dir=root))
    valid_artifacts = run_root / "valid-review-only" / "artifacts"
    blocked_artifacts = run_root / "release-blocked" / "artifacts"
    valid_artifacts.mkdir(parents=True)
    blocked_artifacts.mkdir(parents=True)
    fixture = run_root / "offline-spiderfoot-fixture.json"
    fixture.write_text(json.dumps(FIXTURE), encoding="utf-8")

    pipeline_from_existing_scan(
        "example.com", fixture, valid_artifacts,
        do_export_pdf=True, do_export_dashboard=True,
    )

    with tempfile.TemporaryDirectory(prefix="osiris-demo-keys-") as key_dir:
        private_key = generate_development_key(Path(key_dir) / "private.pem")
        public_key = write_public_key(private_key, Path(key_dir) / "trusted-public.pem")
        valid_capsule = build_capsule(
            valid_artifacts,
            run_root / "valid-review-only" / "OSIRIS-Evidence-Capsule",
            key_path=private_key,
        )
        valid_result = verify_capsule(
            valid_capsule, trusted_public_key=public_key
        )

        tampered_capsule = run_root / "tampered" / "OSIRIS-Evidence-Capsule"
        tampered_capsule.parent.mkdir()
        shutil.copytree(valid_capsule, tampered_capsule)
        with (tampered_capsule / "report.json").open("ab") as handle:
            handle.write(b"\nTAMPERED\n")
        try:
            verify_capsule(tampered_capsule, trusted_public_key=public_key)
        except CapsuleVerificationError:
            tamper_rejected = True
        else:
            raise RuntimeError("deliberately tampered capsule verified successfully")

    blocked_results = pipeline_from_existing_scan(
        "example.com", fixture, blocked_artifacts, skip_graph=True,
    )
    blocked_report = json.loads(
        Path(blocked_results["report"]).read_text(encoding="utf-8")
    )
    try:
        export_misp(blocked_report, blocked_artifacts / "misp.json")
    except ReleaseBlockedError:
        export_blocked = True
    else:
        raise RuntimeError("STUB report bypassed the release gate")

    return {
        "status": "PASS",
        "run_root": str(run_root),
        "valid_review_only_capsule": str(valid_capsule),
        "valid_release_status": valid_result["release_status"],
        "tampered_capsule": str(tampered_capsule),
        "tamper_rejected": tamper_rejected,
        "release_blocked_artifacts": str(blocked_artifacts),
        "export_blocked": export_blocked,
    }
