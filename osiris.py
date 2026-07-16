#!/usr/bin/env python3
"""OSIRIS command-line entry point (currently capsule and verification paths)."""
from __future__ import annotations

import argparse
import json
import sys

from evidence_capsule import (
    CapsuleVerificationError,
    build_capsule,
    generate_development_key,
    verify_capsule,
)


def _print_result(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"{result['status']}: case={result.get('case_id', 'unknown')} run={result.get('run_id', 'unknown')}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="osiris", description="OSIRIS evidence integrity commands")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit structured JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify a signed Evidence Capsule")
    verify.add_argument("path")
    capsule = subparsers.add_parser("capsule", help="build or sign local Evidence Capsules")
    capsule_sub = capsule.add_subparsers(dest="capsule_command", required=True)
    keygen = capsule_sub.add_parser("keygen", help="generate an Ed25519 local-development key")
    keygen.add_argument("path")
    build = capsule_sub.add_parser("build", help="build and sign an Evidence Capsule")
    build.add_argument("--source", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--case", required=True, dest="case_id")
    build.add_argument("--run", required=True, dest="run_id")
    build.add_argument("--key", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            _print_result(verify_capsule(args.path), args.as_json)
        elif args.capsule_command == "keygen":
            path = generate_development_key(args.path)
            _print_result({"status": "PASS", "key_path": str(path)}, args.as_json)
        else:
            output = build_capsule(args.source, args.output, case_id=args.case_id, run_id=args.run_id, key_path=args.key)
            _print_result({"status": "PASS", "capsule": str(output), "case_id": args.case_id, "run_id": args.run_id}, args.as_json)
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
