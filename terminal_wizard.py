#!/usr/bin/env python3
"""Interactive, terminal-only investigator workflow for OSIRIS.

The wizard is intentionally dependency-free. It orchestrates the existing
fail-closed authorization and pipeline contracts; it does not weaken them.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import shutil
import sys
import textwrap
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from case_authorization import (
    CaseAuthorization,
    CollectionMode,
    canonical_target,
    load_case_authorization,
    validate_collection,
)


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CASES_ROOT = PROJECT_ROOT / "data" / "live_case" / "cases"
CASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
APPROVAL_PHRASE = "I CONFIRM LEGAL AUTHORITY"
USE_CASES = (
    "osiris_fast", "osiris_full", "threat_intel", "infrastructure",
    "identity", "vulnerabilities", "passive", "investigate", "all",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def _json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _json_read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
    return cleaned[:96] or "artifact"


class WizardCancelled(Exception):
    """Raised when an investigator cancels an interactive operation."""


@dataclass
class TerminalIO:
    input_fn: Callable[[str], str] = input
    secret_fn: Callable[[str], str] = getpass.getpass
    output: Any = sys.stdout

    @property
    def interactive(self) -> bool:
        return bool(getattr(self.output, "isatty", lambda: False)())

    def clear(self) -> None:
        if self.interactive:
            print("\033[2J\033[H", end="", file=self.output)

    def write(self, message: str = "") -> None:
        print(message, file=self.output)

    def heading(self, title: str) -> None:
        self.write()
        self.write(title)
        self.write("─" * min(72, max(20, len(title))))

    def ask(self, prompt: str, *, default: str | None = None, required: bool = True) -> str:
        suffix = f" [{default}]" if default is not None else ""
        while True:
            value = self.input_fn(f"{prompt}{suffix}: ").strip()
            if value:
                return value
            if default is not None:
                return default
            if not required:
                return ""
            self.write("A value is required.")

    def secret(self, prompt: str) -> str:
        while True:
            value = self.secret_fn(f"{prompt}: ").strip()
            if value:
                return value
            self.write("A value is required.")

    def confirm(self, prompt: str, *, default: bool = False) -> bool:
        marker = "Y/n" if default else "y/N"
        while True:
            value = self.input_fn(f"{prompt} [{marker}]: ").strip().lower()
            if not value:
                return default
            if value in {"y", "yes"}:
                return True
            if value in {"n", "no"}:
                return False
            self.write("Enter yes or no.")

    def choose(self, prompt: str, options: list[tuple[str, str]]) -> str:
        self.write(prompt)
        for index, (_, label) in enumerate(options, 1):
            self.write(f"  {index}) {label}")
        while True:
            value = self.input_fn("Select an option: ").strip()
            if value.isdigit() and 1 <= int(value) <= len(options):
                return options[int(value) - 1][0]
            self.write("Choose one of the numbered options.")

    def pause(self) -> None:
        self.input_fn("\nPress Enter to continue...")


class CaseWorkspace:
    """Persistent, path-safe case repository used by the interactive wizard."""

    def __init__(self, root: str | Path = DEFAULT_CASES_ROOT):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def case_path(self, case_id: str) -> Path:
        if CASE_ID_RE.fullmatch(case_id) is None:
            raise ValueError("case ID must contain only letters, digits, dot, underscore, or hyphen")
        candidate = (self.root / case_id).resolve()
        if candidate.parent != self.root:
            raise ValueError("unsafe case path")
        return candidate

    def create(self, metadata: dict[str, Any]) -> Path:
        case_id = str(metadata.get("case_id", ""))
        path = self.case_path(case_id)
        if path.exists():
            raise FileExistsError(f"case already exists: {case_id}")
        for child in ("authorization", "inputs", "notes", "runs"):
            (path / child).mkdir(parents=True, exist_ok=True)
        metadata = dict(metadata)
        metadata.setdefault("schema_version", "1.0")
        metadata.setdefault("created_at", iso_now())
        metadata.setdefault("status", "OPEN")
        metadata.setdefault("additional_sources", [])
        _json_write(path / "case.json", metadata)
        return path

    def list_cases(self) -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = []
        for manifest in sorted(self.root.glob("*/case.json")):
            try:
                data = _json_read(manifest)
                data["_path"] = str(manifest.parent)
                cases.append(data)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
        return sorted(cases, key=lambda item: str(item.get("created_at", "")), reverse=True)

    def load(self, case_id: str) -> tuple[Path, dict[str, Any]]:
        path = self.case_path(case_id)
        return path, _json_read(path / "case.json")

    def save(self, case_path: Path, metadata: dict[str, Any]) -> None:
        metadata = dict(metadata)
        metadata["updated_at"] = iso_now()
        _json_write(case_path / "case.json", metadata)


class ProgressDisplay:
    def __init__(self, io: TerminalIO):
        self.io = io

    def __call__(self, stage: str, percent: int, detail: str) -> None:
        width = 30
        completed = max(0, min(width, round(width * percent / 100)))
        bar = "█" * completed + "░" * (width - completed)
        self.io.write(f"[{bar}] {percent:3d}%  {stage:<15} {detail}")


class OsirisWizard:
    def __init__(self, *, workspace: CaseWorkspace | None = None, io: TerminalIO | None = None):
        self.workspace = workspace or CaseWorkspace()
        self.io = io or TerminalIO()

    def run(self) -> int:
        while True:
            self._welcome()
            action = self.io.choose("Main menu", [
                ("new", "Create a new case"),
                ("open", "Open an existing case"),
                ("list", "View case register"),
                ("preflight", "System preflight"),
                ("docs", "Documentation and workflow guide"),
                ("help", "Help and safety information"),
                ("exit", "Exit OSIRIS"),
            ])
            try:
                if action == "new":
                    self.create_case()
                elif action == "open":
                    self.open_case()
                elif action == "list":
                    self.show_cases()
                elif action == "preflight":
                    self.system_preflight()
                elif action == "docs":
                    self.show_docs()
                elif action == "help":
                    self.show_help()
                else:
                    self.io.write("Investigation workspace closed safely.")
                    return 0
            except (WizardCancelled, KeyboardInterrupt):
                self.io.write("\nOperation cancelled; no scan was started.")
                self.io.pause()
            except Exception as exc:
                self.io.write(f"\nUnable to complete operation: {exc}")
                self.io.pause()

    def _welcome(self) -> None:
        self.io.clear()
        self.io.write("╔══════════════════════════════════════════════════════════════╗")
        self.io.write("║                       WELCOME TO OSIRIS                     ║")
        self.io.write("║       Evidence-first, authorized OSINT investigation       ║")
        self.io.write("╚══════════════════════════════════════════════════════════════╝")
        self.io.write(f"Case workspace: {self.workspace.root}")

    def create_case(self) -> None:
        self.io.clear()
        self.io.heading("Create a new investigation case")
        proposed = f"CASE-{utc_now():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"
        case_id = self.io.ask("Case ID", default=proposed)
        title = self.io.ask("Case title")
        purpose = self.io.ask("Lawful investigative purpose")
        jurisdiction = self.io.ask("Jurisdiction", default="IN")
        investigator_name = self.io.ask("Investigator full name")
        investigator_id = self.io.ask("Investigator employee/licence ID")
        organization = self.io.ask("Organization")
        targets = [
            canonical_target(item)
            for item in self._ask_list("Authorized target domain/IP (blank when finished)", minimum=1)
        ]
        retention = self.io.ask("Data retention policy", default="Retain per case authority; review at closure")
        marking = self.io.ask("Handling marking", default="TLP:CLEAR")
        sources = self._ask_list("Additional source file or source description (optional)", minimum=0)
        path = self.workspace.create({
            "case_id": case_id,
            "title": title,
            "purpose": purpose,
            "jurisdiction": jurisdiction,
            "investigator": {
                "name": investigator_name,
                "id": investigator_id,
                "organization": organization,
            },
            "targets": targets,
            "data_retention_policy": retention,
            "handling_marking": marking,
            "additional_sources": [],
        })
        if sources:
            metadata = _json_read(path / "case.json")
            metadata["additional_sources"] = [self._record_source(path, item) for item in sources]
            self.workspace.save(path, metadata)
        self.io.write(f"\nCase created: {path}")
        if self.io.confirm("Create its authorization draft now?", default=True):
            self.create_authorization(path)
        self.case_menu(path)

    def _ask_list(self, prompt: str, *, minimum: int) -> list[str]:
        values: list[str] = []
        while True:
            value = self.io.ask(prompt, required=False)
            if not value:
                if len(values) >= minimum:
                    return values
                self.io.write(f"At least {minimum} value(s) required.")
                continue
            if value not in values:
                values.append(value)

    def show_cases(self) -> None:
        self.io.clear()
        self.io.heading("Case register")
        cases = self.workspace.list_cases()
        if not cases:
            self.io.write("No cases have been created.")
        for case in cases:
            targets = ", ".join(str(item) for item in case.get("targets", []))
            self.io.write(
                f"{case.get('case_id')}  [{case.get('status', 'UNKNOWN')}]  "
                f"{case.get('title', '')}  targets={targets}"
            )
        self.io.pause()

    def open_case(self) -> None:
        cases = self.workspace.list_cases()
        if not cases:
            self.io.write("No cases exist. Create one first.")
            self.io.pause()
            return
        selected = self.io.choose("Select a case", [
            (str(case["case_id"]), f"{case['case_id']} — {case.get('title', '')}")
            for case in cases
        ] + [("back", "Back")])
        if selected != "back":
            path, _ = self.workspace.load(selected)
            self.case_menu(path)

    def case_menu(self, case_path: Path) -> None:
        while True:
            case = _json_read(case_path / "case.json")
            self.io.clear()
            self.io.heading(f"{case['case_id']} — {case['title']}")
            self.io.write(f"Status: {case.get('status')}  Targets: {', '.join(case.get('targets', []))}")
            self.io.write(f"Folder: {case_path}")
            action = self.io.choose("Case menu", [
                ("run", "Run investigation pipeline"),
                ("authorization", "Authorization and human verification"),
                ("sources", "Manage additional sources"),
                ("runs", "View previous runs"),
                ("summary", "View case details"),
                ("close", "Close or reopen case"),
                ("back", "Back to main menu"),
            ])
            if action == "run":
                self.run_investigation(case_path)
            elif action == "authorization":
                self.authorization_menu(case_path)
            elif action == "sources":
                self.manage_sources(case_path)
            elif action == "runs":
                self.show_runs(case_path)
            elif action == "summary":
                self.io.write(json.dumps(case, indent=2))
                self.io.pause()
            elif action == "close":
                case["status"] = "CLOSED" if case.get("status") != "CLOSED" else "OPEN"
                self.workspace.save(case_path, case)
            else:
                return

    def authorization_menu(self, case_path: Path) -> None:
        while True:
            auth_path = case_path / "authorization" / "authorization.json"
            status = "NOT CREATED"
            if auth_path.exists():
                try:
                    status = str(_json_read(auth_path).get("status", "UNKNOWN"))
                except Exception:
                    status = "INVALID"
            self.io.clear()
            self.io.heading(f"Authorization — {status}")
            action = self.io.choose("Authorization menu", [
                ("draft", "Create or replace authorization draft"),
                ("review", "Review authorization artifact"),
                ("approve", "Record human approval and source document"),
                ("verify", "Verify authorization and approval artifacts"),
                ("back", "Back"),
            ])
            if action == "draft":
                self.create_authorization(case_path)
            elif action == "review":
                if auth_path.exists():
                    self.io.write(json.dumps(_json_read(auth_path), indent=2))
                else:
                    self.io.write("No authorization draft exists.")
                self.io.pause()
            elif action == "approve":
                self.approve_authorization(case_path)
            elif action == "verify":
                self.verify_authorization_artifacts(case_path, active=True)
                self.io.pause()
            else:
                return

    def create_authorization(self, case_path: Path) -> Path:
        case = _json_read(case_path / "case.json")
        self.io.heading("Authorization draft")
        mode = self.io.choose("Permitted collection", [
            ("passive", "Passive/replay only"),
            ("active", "Passive and active network collection"),
        ])
        reference = self.io.ask("Authorization reference", default=f"AUTH-{case['case_id']}")
        valid_from = self.io.ask("Valid from (ISO 8601 with timezone)", default=iso_now())
        expires_default = (utc_now() + timedelta(days=30)).isoformat()
        expires_at = self.io.ask("Expires at (ISO 8601 with timezone)", default=expires_default)
        excluded = self._ask_list("Explicitly excluded target (optional)", minimum=0)
        draft = {
            "schema_version": "1.0",
            "case_id": case["case_id"],
            "title": case["title"],
            "purpose": case["purpose"],
            "jurisdiction": case["jurisdiction"],
            "created_at": iso_now(),
            "created_by": case["investigator"]["name"],
            "authorization_reference": reference,
            "authorization_document_hash": "sha256:" + "0" * 64,
            "allowed_collection_modes": ["passive", "active"] if mode == "active" else ["passive"],
            "active_scanning_authorized": mode == "active",
            "authorized_targets": case["targets"],
            "excluded_targets": excluded,
            "valid_from": valid_from,
            "expires_at": expires_at,
            "data_retention_policy": case["data_retention_policy"],
            "handling_marking": case["handling_marking"],
            "approvers": [],
            "status": "DRAFT",
        }
        # Validate every field except the intentionally pending approval/hash semantics.
        CaseAuthorization.model_validate(draft)
        path = case_path / "authorization" / "authorization.json"
        _json_write(path, draft)
        approval = case_path / "authorization" / "approval-record.json"
        if approval.exists():
            approval.rename(approval.with_name(f"approval-record.superseded-{utc_now():%Y%m%d%H%M%S}.json"))
        self.io.write(f"Draft saved: {path}")
        return path

    def approve_authorization(self, case_path: Path) -> Path:
        auth_path = case_path / "authorization" / "authorization.json"
        if not auth_path.exists():
            raise ValueError("create an authorization draft first")
        auth = _json_read(auth_path)
        self.io.heading("Human authorization checkpoint")
        self.io.write("This records an approver's attestation; it is not legal advice or identity proof.")
        source = Path(self.io.ask("Path to the signed/approved authorization document")).expanduser().resolve()
        if not source.is_file():
            raise ValueError("authorization source document does not exist")
        approver_name = self.io.ask("Approver full name")
        approver_role = self.io.ask("Approver role/title")
        approver_identifier = self.io.ask("Approver employee/licence/email identifier")
        assertion = self.io.ask(
            f"Type '{APPROVAL_PHRASE}' to attest authority for the listed scope",
            required=True,
        )
        if assertion != APPROVAL_PHRASE:
            raise WizardCancelled("approval phrase did not match")
        if not self.io.confirm("Has the approver reviewed target, mode, expiry, and retention?", default=False):
            raise WizardCancelled("approval review not confirmed")
        source_dir = case_path / "authorization" / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        copied = source_dir / _safe_name(source.name)
        if copied.exists():
            copied = source_dir / f"{utc_now():%Y%m%d%H%M%S}-{_safe_name(source.name)}"
        shutil.copy2(source, copied)
        digest = _sha256(copied)
        auth["authorization_document_hash"] = f"sha256:{digest}"
        auth["approvers"] = [approver_name]
        auth["status"] = "APPROVED"
        validated = CaseAuthorization.model_validate(auth)
        _json_write(auth_path, validated.model_dump(mode="json"))
        record = {
            "schema_version": "1.0",
            "case_id": auth["case_id"],
            "approved_at": iso_now(),
            "approver": {
                "name": approver_name,
                "role": approver_role,
                "identifier": approver_identifier,
            },
            "attestation": APPROVAL_PHRASE,
            "authorization_reference": auth["authorization_reference"],
            "source_document": str(copied.relative_to(case_path)),
            "source_document_sha256": digest,
            "authorized_targets": auth["authorized_targets"],
            "allowed_collection_modes": auth["allowed_collection_modes"],
            "expires_at": auth["expires_at"],
        }
        record["record_sha256"] = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        record_path = case_path / "authorization" / "approval-record.json"
        _json_write(record_path, record)
        self.io.write(f"Approval artifacts saved under {case_path / 'authorization'}")
        return auth_path

    def verify_authorization_artifacts(
        self, case_path: Path, *, active: bool, target: str | None = None
    ) -> CaseAuthorization:
        auth_path = case_path / "authorization" / "authorization.json"
        record_path = case_path / "authorization" / "approval-record.json"
        auth = load_case_authorization(auth_path)
        record = _json_read(record_path)
        record_copy = dict(record)
        recorded_record_hash = str(record_copy.pop("record_sha256", ""))
        actual_record_hash = hashlib.sha256(
            json.dumps(record_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if recorded_record_hash != actual_record_hash:
            raise ValueError("approval record integrity check failed")
        source = (case_path / str(record["source_document"])).resolve()
        if not source.is_relative_to(case_path.resolve()) or not source.is_file():
            raise ValueError("approved source document is missing or outside the case")
        actual_source_hash = _sha256(source)
        if actual_source_hash != record.get("source_document_sha256"):
            raise ValueError("approved source document hash changed")
        if auth.authorization_document_hash != f"sha256:{actual_source_hash}":
            raise ValueError("authorization document hash does not match approval record")
        selected_target = target or auth.authorized_targets[0]
        validate_collection(
            auth, selected_target,
            CollectionMode.ACTIVE if active else CollectionMode.PASSIVE,
        )
        self.io.write(f"PASS: authorization {auth.case_id} is valid for {selected_target}")
        return auth

    def manage_sources(self, case_path: Path) -> None:
        case = _json_read(case_path / "case.json")
        self.io.heading("Additional case sources")
        for source in case.get("additional_sources", []):
            if isinstance(source, dict):
                self.io.write(f"- {source.get('kind')}: {source.get('value')}")
            else:
                self.io.write(f"- reference: {source}")
        additions = self._ask_list("Add file path, URL reference, or source description", minimum=0)
        case.setdefault("additional_sources", []).extend(
            self._record_source(case_path, item) for item in additions
        )
        self.workspace.save(case_path, case)

    def _record_source(self, case_path: Path, value: str) -> dict[str, Any]:
        candidate = Path(value).expanduser()
        if candidate.is_file():
            source_dir = case_path / "inputs" / "additional"
            source_dir.mkdir(parents=True, exist_ok=True)
            destination = source_dir / _safe_name(candidate.name)
            if destination.exists():
                destination = source_dir / f"{utc_now():%Y%m%d%H%M%S}-{_safe_name(candidate.name)}"
            shutil.copy2(candidate.resolve(), destination)
            return {
                "kind": "file",
                "value": str(destination.relative_to(case_path)),
                "sha256": _sha256(destination),
                "added_at": iso_now(),
            }
        return {"kind": "reference", "value": value, "added_at": iso_now()}

    def _select_target(self, case: dict[str, Any]) -> str:
        targets = [str(item) for item in case.get("targets", [])]
        if len(targets) == 1:
            return targets[0]
        return self.io.choose("Select target", [(item, item) for item in targets])

    def run_investigation(self, case_path: Path) -> None:
        # Delay heavy graph/XAI imports until a run is actually requested so
        # the menu, help and case register start immediately.
        from run_pipeline import PipelineError, pipeline_from_existing_scan, pipeline_with_spiderfoot

        case = _json_read(case_path / "case.json")
        if case.get("status") != "OPEN":
            raise ValueError("case is closed; reopen it before running a pipeline")
        self.io.clear()
        self.io.heading("Configure investigation run")
        target = self._select_target(case)
        collection = self.io.choose("Evidence collection source", [
            ("live", "Authorized live SpiderFoot collection"),
            ("replay", "Existing SpiderFoot JSON/CSV export"),
        ])
        source_path: Path | None = None
        use_case: str | None = None
        modules: str | None = None
        if collection == "replay":
            source_path = Path(self.io.ask("SpiderFoot JSON/CSV file path")).expanduser().resolve()
            if not source_path.is_file():
                raise ValueError("source export does not exist")
        else:
            use_case = self.io.choose("SpiderFoot profile", [(name, name) for name in USE_CASES])
            modules = self.io.ask("Optional comma-separated module override", required=False) or None

        llm_mode = self.io.choose("Analysis mode", [
            ("openrouter", "OpenRouter live LLM (openai/gpt-oss-120b)"),
            ("ollama", "Local Ollama live LLM"),
            ("dry", "Offline dry-run dossier"),
        ])
        model: str | None = None
        if llm_mode == "openrouter":
            model = self.io.ask("OpenRouter model", default="openai/gpt-oss-120b")
            self._ensure_secret("OPENROUTER_API_KEY", "OpenRouter API key")
        elif llm_mode == "ollama":
            model = self.io.ask("Ollama model", default="llama3.2")

        export_pdf = self.io.confirm("Generate PDF report?", default=True)
        export_dashboard = self.io.confirm("Generate analyst dashboard?", default=True)
        skip_graph = not self.io.confirm("Generate relationship graph?", default=True)
        self.io.heading("Preflight")
        authorization_candidate = case_path / "authorization" / "authorization.json"
        auth_path: Path | None = authorization_candidate
        if collection == "live":
            self.verify_authorization_artifacts(case_path, active=True, target=target)
            self._check_spiderfoot()
        elif authorization_candidate.exists():
            # Replay may use an approved passive authorization but does not
            # fabricate approval when none exists.
            try:
                self.verify_authorization_artifacts(case_path, active=False, target=target)
            except Exception as exc:
                self.io.write(f"NOTICE: replay remains review-only: {exc}")
                auth_path = None
        else:
            auth_path = None

        if not self.io.confirm("Start this investigation run now?", default=False):
            raise WizardCancelled("run not confirmed")
        run_name = f"{utc_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
        run_dir = case_path / "runs" / run_name
        run_dir.mkdir(parents=True, exist_ok=False)
        run_manifest = {
            "schema_version": "1.0",
            "run_name": run_name,
            "case_id": case["case_id"],
            "started_at": iso_now(),
            "target": target,
            "collection": collection,
            "llm_mode": llm_mode,
            "model": model,
            "use_case": use_case,
            "modules": modules,
            "additional_sources": case.get("additional_sources", []),
            "status": "RUNNING",
        }
        _json_write(run_dir / "run.json", run_manifest)
        progress = ProgressDisplay(self.io)
        try:
            if collection == "live":
                results = pipeline_with_spiderfoot(
                    target, run_dir, do_export_pdf=export_pdf,
                    mind_dry_run=llm_mode == "dry",
                    mind_backend="openrouter" if llm_mode == "openrouter" else "ollama",
                    mind_model=model, skip_graph=skip_graph,
                    do_export_dashboard=export_dashboard, modules=modules,
                    use_case=use_case, case_authorization_path=auth_path,
                    progress_callback=progress,
                )
            else:
                assert source_path is not None
                copied_input = case_path / "inputs" / f"{run_name}-{_safe_name(source_path.name)}"
                shutil.copy2(source_path, copied_input)
                run_manifest["source_input"] = str(copied_input.relative_to(case_path))
                results = pipeline_from_existing_scan(
                    target, copied_input, run_dir, do_export_pdf=export_pdf,
                    mind_dry_run=llm_mode == "dry",
                    mind_backend="openrouter" if llm_mode == "openrouter" else "ollama",
                    mind_model=model, skip_graph=skip_graph,
                    do_export_dashboard=export_dashboard,
                    case_authorization_path=auth_path,
                    progress_callback=progress,
                )
            run_manifest.update({"status": "COMPLETED", "completed_at": iso_now(), "results": results})
            _json_write(run_dir / "run.json", run_manifest)
            self.io.write(f"\nRun completed. All artifacts: {run_dir}")
        except Exception as exc:
            run_manifest.update({"status": "FAILED", "completed_at": iso_now(), "error": str(exc)})
            _json_write(run_dir / "run.json", run_manifest)
            raise PipelineError(f"run failed; diagnostic saved in {run_dir / 'run.json'}: {exc}") from exc
        self.io.pause()

    def _ensure_secret(self, variable: str, label: str) -> None:
        if os.getenv(variable):
            self.io.write(f"PASS: {label} is available for this session.")
            return
        value = self.io.secret(label)
        os.environ[variable] = value
        if self.io.confirm("Save this key to the gitignored .env file?", default=False):
            env_path = PROJECT_ROOT / ".env"
            existing = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
            filtered = [line for line in existing if not line.startswith(f"{variable}=")]
            filtered.append(f"{variable}={value}")
            env_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")
            env_path.chmod(0o600)
            self.io.write(f"Secret saved with owner-only permissions: {env_path}")

    def _check_spiderfoot(self) -> None:
        import spiderfoot_runner

        spiderfoot_runner.require_spiderfoot_runtime()
        self.io.write("PASS: SpiderFoot runtime imports successfully.")

    def system_preflight(self) -> None:
        self.io.clear()
        self.io.heading("System preflight")
        checks: list[tuple[str, Callable[[], Any]]] = [
            ("Python 3.12", lambda: sys.version_info[:2] == (3, 12) or (_ for _ in ()).throw(ValueError(sys.version))),
            ("Ethics acknowledgement", lambda: self._check_disclaimer()),
            ("Case workspace writable", lambda: os.access(self.workspace.root, os.W_OK) or (_ for _ in ()).throw(ValueError("not writable"))),
            ("SpiderFoot runtime", self._check_spiderfoot),
        ]
        for name, check in checks:
            try:
                check()
                self.io.write(f"PASS  {name}")
            except Exception as exc:
                self.io.write(f"FAIL  {name}: {exc}")
        self.io.write("INFO  OpenRouter key: configured" if os.getenv("OPENROUTER_API_KEY") else "INFO  OpenRouter key: requested only when needed")
        self.io.pause()

    def _check_disclaimer(self) -> None:
        from run_pipeline import check_ethics_gate

        check_ethics_gate()

    def show_runs(self, case_path: Path) -> None:
        self.io.clear()
        self.io.heading("Previous runs")
        manifests = sorted((case_path / "runs").glob("*/run.json"), reverse=True)
        if not manifests:
            self.io.write("No runs recorded for this case.")
        for manifest in manifests:
            try:
                run = _json_read(manifest)
                self.io.write(
                    f"{run.get('run_name')}  [{run.get('status')}]  "
                    f"{run.get('target')}  {run.get('collection')}  {manifest.parent}"
                )
            except Exception as exc:
                self.io.write(f"INVALID {manifest}: {exc}")
        self.io.pause()

    def show_docs(self) -> None:
        self.io.clear()
        self.io.heading("Documentation")
        documents = [
            PROJECT_ROOT / "README.md",
            PROJECT_ROOT / "docs" / "security" / "threat_model.md",
            PROJECT_ROOT / "docs" / "audits" / "technical_review_remediation_report.md",
            PROJECT_ROOT / "docs" / "plans" / "production_legal_readiness_plan.md",
        ]
        for path in documents:
            self.io.write(str(path))
        self.io.write("\nOpen these files in a separate terminal or editor; the wizard never launches a browser.")
        self.io.pause()

    def show_help(self) -> None:
        self.io.clear()
        self.io.heading("OSIRIS help")
        self.io.write(textwrap.dedent("""
            Create/open a case, prepare a scoped authorization, record human approval,
            then run either a live SpiderFoot collection or replay an existing export.
            The wizard saves source copies, run settings, failures, and generated artifacts
            inside the case folder. Active collection fails closed without a valid,
            unexpired approval artifact and an operational SpiderFoot runtime.

            OSIRIS outputs are investigative research artifacts. They do not establish
            source truth, legal admissibility, or a complete model-validation claim.
            Never collect outside authority, scope, time, or organizational policy.
        """).strip())
        self.io.pause()


def run_wizard(*, cases_root: str | Path | None = None) -> int:
    workspace = CaseWorkspace(cases_root or DEFAULT_CASES_ROOT)
    return OsirisWizard(workspace=workspace).run()
