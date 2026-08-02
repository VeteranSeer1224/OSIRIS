#!/usr/bin/env python3
"""OSIRIS command-line entry point and terminal investigator wizard."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evidence_capsule import (
    CapsuleVerificationError,
    build_capsule,
    generate_development_key,
    verify_capsule,
    write_public_key,
)
from terminal_wizard import run_wizard
from terminal_wizard import CaseWorkspace, DEFAULT_CASES_ROOT
from investigation_service import APPROVAL_PHRASE, InvestigationService, RunRequest


def _print_result(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"{result['status']}: case={result.get('case_id', 'unknown')} run={result.get('run_id', 'unknown')}")


def main(argv: list[str] | None = None) -> int:
    argv = list(argv) if argv is not None else sys.argv[1:]
    # Global JSON mode is accepted anywhere for automation friendliness.
    json_anywhere = "--json" in argv
    argv = [item for item in argv if item != "--json"]
    parser = argparse.ArgumentParser(prog="osiris", description="OSIRIS investigation workspace")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit structured JSON")
    parser.add_argument("--cases-root", default=str(DEFAULT_CASES_ROOT), help="case workspace directory")
    subparsers = parser.add_subparsers(dest="command")
    wizard = subparsers.add_parser("wizard", help="open the terminal investigator wizard")
    wizard.add_argument("--cases-root", dest="wizard_cases_root", help="override the case workspace directory")
    preflight = subparsers.add_parser("preflight", help="validate local runtime readiness")
    preflight.add_argument("--llm-mode", choices=("dry", "openrouter", "ollama"), default="dry")
    preflight.add_argument("--live", action="store_true", help="include live SpiderFoot checks")

    case = subparsers.add_parser("case", help="create and manage cases")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    case_create = case_sub.add_parser("create", help="create a case")
    case_create.add_argument("--case-id", required=True)
    case_create.add_argument("--title", required=True)
    case_create.add_argument("--purpose", required=True)
    case_create.add_argument("--jurisdiction", default="IN")
    case_create.add_argument("--investigator-name", required=True)
    case_create.add_argument("--investigator-id", required=True)
    case_create.add_argument("--organization", required=True)
    case_create.add_argument("--target", action="append", required=True)
    case_create.add_argument("--retention", default="Retain per case authority; review at closure")
    case_create.add_argument("--marking", default="TLP:CLEAR")
    case_sub.add_parser("list", help="list cases")
    case_show = case_sub.add_parser("show", help="show one case")
    case_show.add_argument("case_id")
    case_status = case_sub.add_parser("status", help="open or close a case")
    case_status.add_argument("case_id")
    case_status.add_argument("status", choices=("OPEN", "CLOSED"))
    source = case_sub.add_parser("add-source", help="add a case source")
    source.add_argument("case_id")
    source.add_argument("value")

    authorization = subparsers.add_parser("authorization", help="authorization workflow")
    auth_sub = authorization.add_subparsers(dest="authorization_command", required=True)
    auth_draft = auth_sub.add_parser("draft", help="create an authorization draft")
    auth_draft.add_argument("case_id")
    auth_draft.add_argument("--reference", required=True)
    auth_draft.add_argument("--active", action="store_true")
    auth_draft.add_argument("--valid-from")
    auth_draft.add_argument("--expires-at")
    auth_draft.add_argument("--exclude", action="append", default=[])
    auth_approve = auth_sub.add_parser("approve", help="record human approval")
    auth_approve.add_argument("case_id")
    auth_approve.add_argument("--document", required=True)
    auth_approve.add_argument("--approver-name", required=True)
    auth_approve.add_argument("--approver-role", required=True)
    auth_approve.add_argument("--approver-id", required=True)
    auth_approve.add_argument("--attestation", required=True, help=f"must equal: {APPROVAL_PHRASE}")
    auth_approve.add_argument("--scope-reviewed", action="store_true", required=True)
    auth_verify = auth_sub.add_parser("verify", help="verify approval and scope")
    auth_verify.add_argument("case_id")
    auth_verify.add_argument("--target", required=True)
    auth_verify.add_argument("--active", action="store_true")

    run = subparsers.add_parser("run", help="execute or retry a case pipeline")
    run_sub = run.add_subparsers(dest="run_command", required=True)
    run_start = run_sub.add_parser("start", help="start a pipeline run")
    run_start.add_argument("case_id")
    run_start.add_argument("--target", required=True)
    source_group = run_start.add_mutually_exclusive_group(required=True)
    source_group.add_argument("--source", help="existing SpiderFoot JSON/CSV export")
    source_group.add_argument("--live", action="store_true")
    run_start.add_argument("--llm-mode", choices=("dry", "openrouter", "ollama"), default="dry")
    run_start.add_argument("--model")
    run_start.add_argument("--use-case", default="osiris_fast")
    run_start.add_argument("--modules")
    run_start.add_argument("--timeout", type=float, default=900)
    run_start.add_argument("--no-pdf", action="store_true")
    run_start.add_argument("--no-dashboard", action="store_true")
    run_start.add_argument("--no-graph", action="store_true")
    run_start.add_argument("--output-class", choices=("review-only", "release"), default="review-only")
    run_list = run_sub.add_parser("list", help="list case runs")
    run_list.add_argument("case_id")
    run_resume = run_sub.add_parser("resume", help="retry a failed/cancelled run")
    run_resume.add_argument("case_id")
    run_resume.add_argument("run_name")
    release = subparsers.add_parser("release", help="evaluate typed release context and gated exports")
    release.add_argument("case_id")
    release.add_argument("run_name")
    release.add_argument("--authorization-signature", required=True, help="file containing canonical authorization signature")
    release.add_argument("--trusted-key", required=True, help="trusted Ed25519 public key")
    release.add_argument("--stix", action="store_true", help="write STIX 2.1 only if release passes")
    release.add_argument("--misp", action="store_true", help="write MISP only if release passes")
    verify = subparsers.add_parser("verify", help="verify a signed Evidence Capsule")
    verify.add_argument("path")
    verify.add_argument("--trusted-key", required=True)
    capsule = subparsers.add_parser("capsule", help="build or sign local Evidence Capsules")
    capsule_sub = capsule.add_subparsers(dest="capsule_command", required=True)
    keygen = capsule_sub.add_parser("keygen", help="generate an Ed25519 local-development key")
    keygen.add_argument("path")
    keygen.add_argument("--public-key")
    build = capsule_sub.add_parser("build", help="build and sign an Evidence Capsule")
    build.add_argument("--source", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--key", required=True)
    demo = subparsers.add_parser("demo", help="run offline OSIRIS demonstrations")
    demo_sub = demo.add_subparsers(dest="demo_command", required=True)
    conference = demo_sub.add_parser("conference", help="run the offline conference demo")
    conference.add_argument("--output", default="demo-output")
    args = parser.parse_args(argv)
    args.as_json = bool(args.as_json or json_anywhere)
    service = InvestigationService(CaseWorkspace(args.cases_root))
    try:
        if args.command in {None, "wizard"}:
            return run_wizard(cases_root=getattr(args, "wizard_cases_root", None) or args.cases_root)
        if args.command == "preflight":
            result = service.preflight(llm_mode=args.llm_mode, live_collection=args.live)
            _print_result(result, args.as_json)
            return 0 if result["status"] == "PASS" else 3
        if args.command == "case":
            if args.case_command == "create":
                result = service.create_case({
                    "case_id": args.case_id, "title": args.title, "purpose": args.purpose,
                    "jurisdiction": args.jurisdiction,
                    "investigator": {"name": args.investigator_name, "id": args.investigator_id, "organization": args.organization},
                    "targets": args.target, "data_retention_policy": args.retention,
                    "handling_marking": args.marking, "additional_sources": [],
                })
            elif args.case_command == "list":
                result = {"status": "PASS", "cases": service.list_cases()}
            elif args.case_command == "show":
                result = {"status": "PASS", "case": service.get_case(args.case_id)}
            elif args.case_command == "status":
                result = service.set_case_status(args.case_id, args.status)
            else:
                result = service.add_source(args.case_id, args.value)
            _print_result(result, args.as_json)
            return 0
        if args.command == "authorization":
            if args.authorization_command == "draft":
                result = service.draft_authorization(
                    args.case_id, active=args.active, authorization_reference=args.reference,
                    valid_from=args.valid_from, expires_at=args.expires_at,
                    excluded_targets=args.exclude,
                )
            elif args.authorization_command == "approve":
                result = service.approve_authorization(
                    args.case_id, source_document=args.document,
                    approver_name=args.approver_name, approver_role=args.approver_role,
                    approver_identifier=args.approver_id, attestation=args.attestation,
                    scope_review_confirmed=args.scope_reviewed,
                )
            else:
                result = service.verify_authorization(
                    args.case_id, target=args.target, active=args.active,
                )
            _print_result(result, args.as_json)
            return 0
        if args.command == "run":
            if args.run_command == "list":
                result = {"status": "PASS", "runs": service.list_runs(args.case_id)}
            elif args.run_command == "resume":
                result = service.resume_run(args.case_id, args.run_name)
            else:
                result = service.run_case(args.case_id, RunRequest(
                    target=args.target, collection="live" if args.live else "replay",
                    source_input=args.source, llm_mode=args.llm_mode, model=args.model,
                    use_case=args.use_case if args.live else None, modules=args.modules,
                    export_pdf=not args.no_pdf, export_dashboard=not args.no_dashboard,
                    generate_graph=not args.no_graph, spiderfoot_timeout=args.timeout,
                    output_class=args.output_class,
                ))
            _print_result(result, args.as_json)
            return 0
        if args.command == "release":
            result = service.evaluate_run_release(
                args.case_id, args.run_name,
                signature_file=args.authorization_signature,
                trusted_public_key=args.trusted_key,
                export_stix=args.stix, export_misp=args.misp,
            )
            _print_result(result, args.as_json)
            return 0 if result["status"] == "PASS" else 4
        if args.command == "demo":
            from conference_demo import run_conference_demo

            _print_result(run_conference_demo(args.output), args.as_json)
        elif args.command == "verify":
            _print_result(
                verify_capsule(args.path, trusted_public_key=args.trusted_key),
                args.as_json,
            )
        elif args.command == "capsule" and args.capsule_command == "keygen":
            path = generate_development_key(args.path)
            if args.public_key:
                write_public_key(path, args.public_key)
            _print_result({"status": "PASS", "key_path": str(path)}, args.as_json)
        else:
            output = build_capsule(
                args.source, args.output, key_path=args.key
            )
            manifest = json.loads(
                (Path(output) / "artifact-manifest.json").read_text(encoding="utf-8")
            )
            result = {
                "status": "PASS", "capsule": str(output),
                "case_id": manifest["case_id"], "run_id": manifest["run_id"],
            }
            _print_result(result, args.as_json)
        return 0
    except KeyboardInterrupt:
        result = {"status": "CANCELLED", "error": "cancelled by investigator"}
        print(json.dumps(result, sort_keys=True) if args.as_json else "CANCELLED: investigator interrupt", file=sys.stderr)
        return 130
    except (CapsuleVerificationError, OSError, ValueError, RuntimeError) as exc:
        result = {"status": "FAIL", "error": str(exc)}
        if args.as_json:
            print(json.dumps(result, sort_keys=True), file=sys.stderr)
        else:
            print(f"FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
