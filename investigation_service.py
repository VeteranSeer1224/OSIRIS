"""Shared terminal investigation services used by both CLI and wizard."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from artifact_io import atomic_write_json
from case_authorization import (
    CaseAuthorization, CollectionMode, canonical_target,
    load_case_authorization, validate_collection,
)


APPROVAL_PHRASE = "I CONFIRM LEGAL AUTHORITY"
RUN_STATUSES = frozenset({"PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"})
MAX_CASE_TARGETS = 100
MAX_ADDITIONAL_SOURCE_BYTES = 100 * 1024 * 1024
PROJECT_ROOT = Path(__file__).resolve().parent


def _load_project_dotenv() -> None:
    """Load simple repository-local values without overriding process state."""
    dotenv = PROJECT_ROOT / ".env"
    if not dotenv.is_file():
        return
    import re
    for raw in dotenv.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


def _bounded_text(value: Any, name: str, maximum: int) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} is required")
    if len(text) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return text


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _now().isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")[:96] or "artifact"


@dataclass(frozen=True)
class RunRequest:
    target: str
    collection: str
    source_input: str | None = None
    llm_mode: str = "dry"
    model: str | None = None
    use_case: str | None = None
    modules: str | None = None
    export_pdf: bool = True
    export_dashboard: bool = True
    generate_graph: bool = True
    spiderfoot_timeout: float = 900
    output_class: str = "review-only"

    def validate(self) -> "RunRequest":
        canonical_target(self.target)
        if self.collection not in {"replay", "live"}:
            raise ValueError("collection must be replay or live")
        if self.collection == "replay" and not self.source_input:
            raise ValueError("replay collection requires source_input")
        if self.llm_mode not in {"dry", "openrouter", "ollama"}:
            raise ValueError("llm_mode must be dry, openrouter, or ollama")
        if not 1 <= float(self.spiderfoot_timeout) <= 86_400:
            raise ValueError("spiderfoot_timeout must be between 1 and 86400")
        if self.output_class not in {"review-only", "release"}:
            raise ValueError("output_class must be review-only or release")
        if self.output_class == "release":
            raise ValueError(
                "release output requires a separately verified typed ReleaseContext; "
                "terminal runs currently generate review-only artifacts"
            )
        if self.modules:
            import re
            selected = [item.strip() for item in self.modules.split(",") if item.strip()]
            if len(selected) > 100 or any(re.fullmatch(r"sfp_[A-Za-z0-9_]+", item) is None for item in selected):
                raise ValueError("modules must be at most 100 comma-separated sfp_ module names")
        return self


class InvestigationService:
    """Case-safe application layer. It never invokes project scripts through a shell."""

    def __init__(self, workspace: Any):
        self.workspace = workspace

    def create_case(self, metadata: dict[str, Any]) -> dict[str, Any]:
        metadata = dict(metadata)
        metadata["case_id"] = _bounded_text(metadata.get("case_id"), "case_id", 128)
        metadata["title"] = _bounded_text(metadata.get("title"), "title", 200)
        metadata["purpose"] = _bounded_text(metadata.get("purpose"), "purpose", 2000)
        metadata["jurisdiction"] = _bounded_text(metadata.get("jurisdiction"), "jurisdiction", 64)
        metadata["data_retention_policy"] = _bounded_text(metadata.get("data_retention_policy"), "retention policy", 2000)
        metadata["handling_marking"] = _bounded_text(metadata.get("handling_marking"), "handling marking", 128)
        investigator = metadata.get("investigator")
        if not isinstance(investigator, dict):
            raise ValueError("investigator must be an object")
        metadata["investigator"] = {
            "name": _bounded_text(investigator.get("name"), "investigator name", 200),
            "id": _bounded_text(investigator.get("id"), "investigator ID", 200),
            "organization": _bounded_text(investigator.get("organization"), "organization", 300),
        }
        targets = metadata.get("targets")
        if not isinstance(targets, list) or not targets or len(targets) > MAX_CASE_TARGETS:
            raise ValueError(f"targets must contain between 1 and {MAX_CASE_TARGETS} entries")
        metadata["targets"] = list(dict.fromkeys(canonical_target(str(item)) for item in targets))
        metadata["additional_sources"] = []
        path = self.workspace.create(metadata)
        (path / "run-records").mkdir(exist_ok=True)
        return {"status": "CREATED", "case_id": metadata["case_id"], "path": str(path)}

    def list_cases(self) -> list[dict[str, Any]]:
        return self.workspace.list_cases()

    def get_case(self, case_id: str) -> dict[str, Any]:
        path, metadata = self.workspace.load(case_id)
        return {**metadata, "path": str(path)}

    def set_case_status(self, case_id: str, status: str) -> dict[str, Any]:
        if status not in {"OPEN", "CLOSED"}:
            raise ValueError("case status must be OPEN or CLOSED")
        path, metadata = self.workspace.load(case_id)
        metadata["status"] = status
        self.workspace.save(path, metadata)
        return {"status": status, "case_id": case_id, "path": str(path)}

    def add_source(self, case_id: str, value: str) -> dict[str, Any]:
        value = _bounded_text(value, "source", 4096)
        case_path, metadata = self.workspace.load(case_id)
        candidate = Path(value).expanduser()
        if candidate.is_file():
            if candidate.stat().st_size > MAX_ADDITIONAL_SOURCE_BYTES:
                raise ValueError("additional source exceeds 100 MiB")
            destination = case_path / "inputs" / "additional" / _safe_name(candidate.name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                destination = destination.with_name(f"{_now():%Y%m%d%H%M%S}-{destination.name}")
            shutil.copy2(candidate.resolve(), destination)
            record = {
                "kind": "file", "value": str(destination.relative_to(case_path)),
                "sha256": _sha256(destination), "added_at": _iso_now(),
            }
        else:
            record = {"kind": "reference", "value": value, "added_at": _iso_now()}
        metadata.setdefault("additional_sources", []).append(record)
        self.workspace.save(case_path, metadata)
        return {"status": "ADDED", "case_id": case_id, "source": record}

    def draft_authorization(
        self, case_id: str, *, active: bool, authorization_reference: str,
        valid_from: str | None = None, expires_at: str | None = None,
        excluded_targets: list[str] | None = None,
    ) -> dict[str, Any]:
        case_path, case = self.workspace.load(case_id)
        draft = {
            "schema_version": "1.0", "case_id": case_id, "title": case["title"],
            "purpose": case["purpose"], "jurisdiction": case["jurisdiction"],
            "created_at": _iso_now(), "created_by": case["investigator"]["name"],
            "authorization_reference": authorization_reference,
            "authorization_document_hash": "sha256:" + "0" * 64,
            "allowed_collection_modes": ["passive", "active"] if active else ["passive"],
            "active_scanning_authorized": active,
            "authorized_targets": case["targets"],
            "excluded_targets": excluded_targets or [],
            "valid_from": valid_from or _iso_now(),
            "expires_at": expires_at or (_now() + timedelta(days=30)).isoformat(),
            "data_retention_policy": case["data_retention_policy"],
            "handling_marking": case["handling_marking"],
            "approvers": [], "status": "DRAFT",
        }
        validated = CaseAuthorization.model_validate(draft).model_dump(mode="json")
        auth_path = case_path / "authorization" / "authorization.json"
        atomic_write_json(auth_path, validated)
        approval = auth_path.with_name("approval-record.json")
        if approval.exists():
            approval.rename(approval.with_name(f"approval-record.superseded-{_now():%Y%m%d%H%M%S}.json"))
        return {"status": "DRAFT", "case_id": case_id, "authorization": str(auth_path)}

    def approve_authorization(
        self, case_id: str, *, source_document: str, approver_name: str,
        approver_role: str, approver_identifier: str, attestation: str,
        scope_review_confirmed: bool,
    ) -> dict[str, Any]:
        if attestation != APPROVAL_PHRASE or not scope_review_confirmed:
            raise ValueError("human authority attestation and scope review are required")
        case_path, _ = self.workspace.load(case_id)
        auth_path = case_path / "authorization" / "authorization.json"
        data = json.loads(auth_path.read_text(encoding="utf-8"))
        source = Path(source_document).expanduser().resolve()
        if not source.is_file():
            raise ValueError("authorization source document does not exist")
        destination = case_path / "authorization" / "source" / _safe_name(source.name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            destination = destination.with_name(f"{_now():%Y%m%d%H%M%S}-{destination.name}")
        shutil.copy2(source, destination)
        source_hash = _sha256(destination)
        data.update({
            "authorization_document_hash": f"sha256:{source_hash}",
            "approvers": [approver_name], "status": "APPROVED",
        })
        validated = CaseAuthorization.model_validate(data)
        atomic_write_json(auth_path, validated.model_dump(mode="json"))
        record = {
            "schema_version": "1.0", "case_id": case_id,
            "authorization_reference": validated.authorization_reference,
            "approver": {"name": approver_name, "role": approver_role, "identifier": approver_identifier},
            "attestation": attestation, "scope_review_confirmed": True,
            "approved_at": _iso_now(),
            "source_document": str(destination.relative_to(case_path)),
            "source_document_sha256": source_hash,
        }
        record["record_sha256"] = hashlib.sha256(json.dumps(
            record, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        approval_path = auth_path.with_name("approval-record.json")
        atomic_write_json(approval_path, record)
        return {"status": "APPROVED", "case_id": case_id, "approval_record": str(approval_path)}

    def verify_authorization(self, case_id: str, *, target: str, active: bool) -> dict[str, Any]:
        case_path, _ = self.workspace.load(case_id)
        auth_path = case_path / "authorization" / "authorization.json"
        authorization = load_case_authorization(auth_path)
        record_path = auth_path.with_name("approval-record.json")
        record = json.loads(record_path.read_text(encoding="utf-8"))
        recorded_hash = str(record.pop("record_sha256", ""))
        actual_hash = hashlib.sha256(json.dumps(
            record, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        if recorded_hash != actual_hash:
            raise ValueError("approval record integrity check failed")
        source = (case_path / str(record["source_document"])).resolve()
        if not source.is_relative_to(case_path.resolve()) or not source.is_file():
            raise ValueError("approved source document is missing or outside the case")
        source_hash = _sha256(source)
        if source_hash != record.get("source_document_sha256"):
            raise ValueError("approved source document hash changed")
        if authorization.authorization_document_hash != f"sha256:{source_hash}":
            raise ValueError("authorization document hash does not match approval record")
        mode = CollectionMode.ACTIVE if active else CollectionMode.PASSIVE
        validate_collection(authorization, target, mode)
        return {
            "status": "PASS", "case_id": case_id,
            "target": canonical_target(target), "collection_mode": mode.value,
            "authorization": str(auth_path),
        }

    def preflight(
        self, *, llm_mode: str = "dry", live_collection: bool = False,
        require_graph: bool = True, require_pdf: bool = True,
    ) -> dict[str, Any]:
        _load_project_dotenv()
        checks: list[dict[str, Any]] = []

        def check(name: str, function: Callable[[], Any], remediation: str) -> None:
            try:
                function()
                checks.append({"name": name, "status": "PASS", "remediation": None})
            except Exception as exc:
                checks.append({"name": name, "status": "FAIL", "detail": str(exc), "remediation": remediation})

        def check_disclaimer() -> None:
            path = PROJECT_ROOT / "DISCLAIMER.md"
            content = path.read_text(encoding="utf-8")
            if "- [x]" not in content and "- [X]" not in content:
                raise ValueError("DISCLAIMER.md is not acknowledged")

        check("python", lambda: sys.version_info[:2] == (3, 12) or (_ for _ in ()).throw(ValueError(sys.version)), "Use the project-required Python 3.12 runtime.")
        check("ethics_acknowledgement", check_disclaimer, "Acknowledge DISCLAIMER.md according to project policy.")
        check("case_workspace", lambda: os.access(self.workspace.root, os.W_OK) or (_ for _ in ()).throw(ValueError("not writable")), "Choose a writable --cases-root.")
        required_modules = ["pydantic", "cryptography"]
        if require_graph:
            required_modules.append("pyvis")
        if require_pdf:
            required_modules.append("weasyprint")
        for module in required_modules:
            check(module, lambda module=module: importlib.util.find_spec(module) or (_ for _ in ()).throw(ImportError(module)), f"Install the pinned {module} dependency.")
        if llm_mode == "openrouter":
            check("openai_sdk", lambda: importlib.util.find_spec("openai") or (_ for _ in ()).throw(ImportError("openai")), "Install the pinned OpenAI SDK.")
            check("openrouter_key", lambda: len(os.getenv("OPENROUTER_API_KEY", "")) >= 20 or (_ for _ in ()).throw(ValueError("OPENROUTER_API_KEY is missing or too short")), "Set OPENROUTER_API_KEY in the process or gitignored .env.")
        elif llm_mode == "ollama":
            def check_ollama() -> None:
                from urllib.parse import urlparse
                import requests
                host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
                parsed = urlparse(host)
                if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                    raise ValueError("OLLAMA_HOST is not a valid HTTP(S) URL")
                response = requests.get(host.rstrip("/") + "/api/tags", timeout=3)
                response.raise_for_status()
            check("ollama_runtime", check_ollama, "Start Ollama and verify OLLAMA_HOST, then retry.")
        if live_collection:
            import spiderfoot_runner
            check("spiderfoot_runtime", spiderfoot_runner.require_spiderfoot_runtime, "Run ./setup.sh and resolve the reported SpiderFoot dependency error.")
        failed = [item for item in checks if item["status"] == "FAIL"]
        return {"status": "PASS" if not failed else "FAIL", "checks": checks, "failed_count": len(failed)}

    def run_case(
        self, case_id: str, request: RunRequest,
        *, progress_callback: Callable[[str, int, str], None] | None = None,
        retry_of: str | None = None,
    ) -> dict[str, Any]:
        request.validate()
        case_path, case = self.workspace.load(case_id)
        if case.get("status") != "OPEN":
            raise ValueError("case is closed; reopen it before running")
        if canonical_target(request.target) not in [canonical_target(item) for item in case.get("targets", [])]:
            raise ValueError("target is not listed in the case")
        preflight = self.preflight(
            llm_mode=request.llm_mode, live_collection=request.collection == "live",
            require_graph=request.generate_graph, require_pdf=request.export_pdf,
        )
        if preflight["status"] != "PASS":
            details = "; ".join(
                f"{item['name']}: {item.get('detail', 'failed')}" for item in preflight["checks"]
                if item["status"] == "FAIL"
            )
            raise ValueError(f"preflight failed: {details}")
        if request.llm_mode == "openrouter" and not request.model:
            raise ValueError("OpenRouter live analysis requires a model")

        auth_path = case_path / "authorization" / "authorization.json"
        selected_auth: Path | None = None
        if request.collection == "live":
            self.verify_authorization(case_id, target=request.target, active=True)
            selected_auth = auth_path
        elif auth_path.exists():
            try:
                self.verify_authorization(case_id, target=request.target, active=False)
                selected_auth = auth_path
            except Exception:
                selected_auth = None

        run_name = f"{_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        run_dir = case_path / "runs" / run_name
        records_dir = case_path / "run-records"
        records_dir.mkdir(exist_ok=True)
        manifest_path = records_dir / f"{run_name}.json"
        manifest = {
            "schema_version": "2.0", "run_name": run_name, "case_id": case_id,
            "started_at": _iso_now(), "status": "RUNNING", "request": asdict(request),
            "retry_of": retry_of, "preflight": preflight,
            "additional_sources": case.get("additional_sources", []),
        }
        atomic_write_json(manifest_path, manifest)
        try:
            from run_pipeline import pipeline_from_existing_scan, pipeline_with_spiderfoot
            backend = "openrouter" if request.llm_mode == "openrouter" else "ollama"
            if request.collection == "live":
                results = pipeline_with_spiderfoot(
                    request.target, run_dir, do_export_pdf=request.export_pdf,
                    mind_dry_run=request.llm_mode == "dry", mind_backend=backend,
                    mind_model=request.model, skip_graph=not request.generate_graph,
                    do_export_dashboard=request.export_dashboard, modules=request.modules,
                    use_case=request.use_case, case_authorization_path=selected_auth,
                    progress_callback=progress_callback,
                    spiderfoot_timeout=request.spiderfoot_timeout,
                )
            else:
                source = Path(str(request.source_input)).expanduser().resolve()
                if not source.is_file():
                    raise ValueError("replay source does not exist")
                copied = case_path / "inputs" / f"{run_name}-{_safe_name(source.name)}"
                shutil.copy2(source, copied)
                manifest["preserved_source_input"] = str(copied.relative_to(case_path))
                atomic_write_json(manifest_path, manifest)
                results = pipeline_from_existing_scan(
                    request.target, copied, run_dir,
                    do_export_pdf=request.export_pdf,
                    mind_dry_run=request.llm_mode == "dry", mind_backend=backend,
                    mind_model=request.model, skip_graph=not request.generate_graph,
                    do_export_dashboard=request.export_dashboard,
                    case_authorization_path=selected_auth,
                    progress_callback=progress_callback,
                    case_id_override=case_id,
                )
            summary = self._summarize_results(run_name, results)
            manifest.update({
                "status": "COMPLETED", "completed_at": _iso_now(),
                "results": results, "summary": summary,
            })
            atomic_write_json(manifest_path, manifest)
            return {**summary, "case_id": case_id, "run_name": run_name,
                    "run_dir": str(run_dir), "manifest": str(manifest_path), "results": results}
        except KeyboardInterrupt:
            manifest.update({"status": "CANCELLED", "completed_at": _iso_now(), "error": "cancelled by investigator"})
            atomic_write_json(manifest_path, manifest)
            raise
        except Exception as exc:
            manifest.update({"status": "FAILED", "completed_at": _iso_now(), "error": str(exc)})
            atomic_write_json(manifest_path, manifest)
            raise

    def _summarize_results(self, run_name: str, results: dict[str, str]) -> dict[str, Any]:
        report = json.loads(Path(results["report"]).read_text(encoding="utf-8"))
        audit = report.get("audit_gate", {})
        release = report.get("release_decision", {})
        return {
            "status": "COMPLETED", "technical_status": "PASS",
            "audit_status": str(audit.get("status", "UNKNOWN")),
            "release_status": str(release.get("status", "BLOCKED")),
            "output_class": "RELEASE" if release.get("status") == "PASS" else "REVIEW_ONLY",
            "run_name": run_name,
        }

    def list_runs(self, case_id: str) -> list[dict[str, Any]]:
        case_path, _ = self.workspace.load(case_id)
        manifests = []
        records = case_path / "run-records"
        for path in sorted(records.glob("*.json"), reverse=True) if records.exists() else []:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                value["manifest"] = str(path)
                manifests.append(value)
            except (OSError, json.JSONDecodeError):
                manifests.append({"status": "INVALID", "manifest": str(path)})
        # Backward-compatible visibility for v1 run manifests.
        for path in sorted((case_path / "runs").glob("*/run.json"), reverse=True):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                value["manifest"] = str(path)
                manifests.append(value)
            except (OSError, json.JSONDecodeError):
                manifests.append({"status": "INVALID", "manifest": str(path)})
        return manifests

    def resume_run(
        self, case_id: str, run_name: str,
        *, progress_callback: Callable[[str, int, str], None] | None = None,
    ) -> dict[str, Any]:
        case_path, _ = self.workspace.load(case_id)
        manifest_path = case_path / "run-records" / f"{run_name}.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") not in {"FAILED", "CANCELLED"}:
            raise ValueError("only failed or cancelled runs can be retried")
        request_data = dict(manifest["request"])
        if manifest.get("preserved_source_input"):
            request_data["source_input"] = str(case_path / manifest["preserved_source_input"])
        return self.run_case(
            case_id, RunRequest(**request_data),
            progress_callback=progress_callback, retry_of=run_name,
        )

    def evaluate_run_release(
        self, case_id: str, run_name: str, *, signature_file: str,
        trusted_public_key: str, export_stix: bool = False,
        export_misp: bool = False,
    ) -> dict[str, Any]:
        """Build and evaluate the repository's typed release context."""
        import base64
        from evidence_store import LocalEvidenceStore, RawEvidenceRecord
        from exports import export_stix21
        from release_policy import (
            ReleaseContext, evaluate_release, verify_authorization_signature,
        )
        from report_build import export_misp as write_misp

        case_path, _ = self.workspace.load(case_id)
        run_dir = case_path / "runs" / run_name
        if not run_dir.is_dir():
            raise ValueError("completed run directory does not exist")

        def load(name: str) -> dict[str, Any]:
            value = json.loads((run_dir / name).read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError(f"{name} must contain a JSON object")
            return value

        authorization = load_case_authorization(case_path / "authorization" / "authorization.json")
        signature_text = Path(signature_file).read_text(encoding="utf-8").strip()
        # Accept a raw base64 signature or a small {"signature": "..."} record.
        if signature_text.startswith("{"):
            signature_text = str(json.loads(signature_text).get("signature", ""))
        base64.b64decode(signature_text, validate=True)
        proof = verify_authorization_signature(
            authorization, signature_b64=signature_text,
            trusted_public_key=trusted_public_key,
        )
        raw_scan, dossier = load("raw_scan.json"), load("dossier.json")
        cards, report = load("explanation_cards.json"), load("report.json")
        lineage, provenance = load("lineage.json"), load("provenance.jsonld")
        record = RawEvidenceRecord(**lineage["raw_evidence"])
        collection_status = load("collection-status.json")
        collection_mode = (
            CollectionMode.ACTIVE if collection_status.get("status") == "FINISHED"
            else CollectionMode.PASSIVE
        )
        context = ReleaseContext(
            authorization_proof=proof, target=str(raw_scan["target"]),
            collection_mode=collection_mode,
            evidence_store=LocalEvidenceStore(run_dir), evidence_records=(record,),
            raw_scan=raw_scan, dossier=dossier, explanation_cards=cards,
            report=report, lineage=lineage, provenance=provenance,
        )
        decision = evaluate_release(context)
        release_dir = case_path / "releases" / run_name
        release_dir.mkdir(parents=True, exist_ok=True)
        decision_path = release_dir / "release-decision.json"
        atomic_write_json(decision_path, {
            "schema_version": "1.0", "case_id": case_id, "run_id": raw_scan["run_id"],
            "evaluated_at": _iso_now(), "signer_fingerprint": proof.signer_fingerprint,
            **decision.as_dict(),
        })
        exports: dict[str, str] = {}
        if export_stix:
            exports["stix"] = str(export_stix21(
                report, release_dir / "stix_export.json", release_context=context,
            ))
        if export_misp:
            exports["misp"] = str(write_misp(
                report, release_dir / "misp_export.json", release_context=context,
            ))
        return {
            "status": decision.status, "case_id": case_id, "run_name": run_name,
            "release_decision": str(decision_path), "reasons": list(decision.reasons),
            "exports": exports,
        }
