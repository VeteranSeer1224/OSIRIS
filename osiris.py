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


def _print_result(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"{result['status']}: case={result.get('case_id', 'unknown')} run={result.get('run_id', 'unknown')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osiris", description="OSIRIS investigation workspace")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit structured JSON")
    subparsers = parser.add_subparsers(dest="command")
    wizard = subparsers.add_parser("wizard", help="open the terminal investigator wizard")
    wizard.add_argument("--cases-root", help="override the case workspace directory")
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
    try:
        if args.command in {None, "wizard"}:
            return run_wizard(cases_root=getattr(args, "cases_root", None))
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
    except (CapsuleVerificationError, OSError, ValueError) as exc:
        result = {"status": "FAIL", "error": str(exc)}
        if args.as_json:
            print(json.dumps(result, sort_keys=True), file=sys.stderr)
        else:
            print(f"FAIL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
