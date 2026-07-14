#!/usr/bin/env python3
"""
OSIRIS Stage 4 — explanation_card_build.py

Consumes:
    - dossier.json (single dossier or a list of dossiers)

Calls:
    - explabox_wrapper.py

Produces:
    - outputs/explanation_cards.json
    - outputs/fairness_report.md
    - outputs/robustness_report.md

Design goals
------------
- Keep the report-generation responsibility here.
- Keep Explabox/backend interaction inside explabox_wrapper.py.
- Be tolerant of the current repository's sample dossier shape.
- Support a single dossier or a batch of dossiers.
- Emit deterministic, human-readable artifacts.

This script intentionally does not perform any network calls.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple, Union

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from explabox_wrapper import ExplaboxWrapper  # noqa: E402
from schema_validation import validate_explanation_cards  # noqa: E402
from schemas.models import ExplanationCards  # noqa: E402


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OSIRIS-Conscience] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_INPUT = HERE / "schemas" / "samples" / "sample_dossier.json"
DEFAULT_OUTPUT_DIR = HERE / "outputs"
DEFAULT_RISK_THRESHOLD = 70
DEFAULT_MAX_TOP_FEATURES = 5
DEFAULT_CARD_MIN_SCORE = 0


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

JSONDict = Dict[str, Any]
DossierDict = Dict[str, Any]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BuildConfig:
    input_path: Path
    output_dir: Path = DEFAULT_OUTPUT_DIR
    risk_threshold: int = DEFAULT_RISK_THRESHOLD
    max_top_features: int = DEFAULT_MAX_TOP_FEATURES


@dataclass
class BuildArtifacts:
    explanation_cards: JSONDict
    fairness_report_md: str
    fairness_report_json: JSONDict
    robustness_report_md: str
    robustness_report_json: JSONDict
    analysis_batches: List[JSONDict]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()



def _load_json_file(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Input dossier not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))



def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path



def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)



def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(round(float(value)))
    except Exception:
        return default



def _is_mapping(value: Any) -> bool:
    return isinstance(value, Mapping)



def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]



def _normalize_dossier(raw: Any) -> DossierDict:
    """Coerce a dossier-like object into the minimum shape the wrapper expects.

    The current repo has a sample dossier that is lighter than the full Pydantic
    contract. This function keeps the build tolerant while still validating the
    fields that matter to Stage 4.
    """
    if not _is_mapping(raw):
        raise TypeError("Each dossier must be a JSON object / mapping")

    dossier: DossierDict = dict(raw)

    # Minimum contract required by explabox_wrapper.py.
    dossier.setdefault("target", "unknown")
    dossier.setdefault("profile", {})
    dossier.setdefault("risk_score", 0)
    dossier.setdefault("risk_features", [])
    dossier.setdefault("risk_level", "UNKNOWN")

    if not _is_mapping(dossier.get("profile")):
        dossier["profile"] = {}

    dossier["risk_features"] = [f for f in _as_list(dossier.get("risk_features")) if _is_mapping(f)]

    # Optional fields used by the wrapper or for report context.
    dossier.setdefault("insufficient_data_flags", [])
    dossier["insufficient_data_flags"] = [f for f in _as_list(dossier.get("insufficient_data_flags")) if _is_mapping(f)]

    if "executive_summary" not in dossier:
        dossier["executive_summary"] = _build_summary_stub(dossier)

    return dossier



def _load_dossiers(input_path: Path) -> List[DossierDict]:
    raw = _load_json_file(input_path)

    if isinstance(raw, list):
        dossiers = raw
    elif _is_mapping(raw):
        # Support either a single dossier or a wrapped object like
        # {"dossiers": [...]} or {"cards": [...]} from earlier stages.
        if isinstance(raw.get("dossiers"), list):
            dossiers = raw["dossiers"]
        else:
            dossiers = [raw]
    else:
        raise TypeError("Input file must contain a JSON object or a JSON list")

    normalized: List[DossierDict] = []
    for idx, item in enumerate(dossiers):
        try:
            normalized.append(_normalize_dossier(item))
        except Exception as exc:
            raise ValueError(f"Invalid dossier at index {idx}: {exc}") from exc

    if not normalized:
        raise ValueError("No dossiers found in the input")

    return normalized



def _entity_id(target: str) -> str:
    """Stable identifier for an explanation card entity."""
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", target.strip().lower())
    return slug or "unknown_entity"


def _format_contribution(weight: Any) -> str:
    try:
        value = float(weight)
    except Exception:
        return "+0.00"
    sign = "+" if value >= 0 else ""
    return f"{sign}{value:.2f}"



def _feature_plain_language(feature: Mapping[str, Any]) -> str:
    """Create a plain-language sentence from a risk feature."""
    from explabox_wrapper import _feature_plain_language as _ew_feature_plain_language
    return _ew_feature_plain_language(feature)




def _build_summary_stub(dossier: Mapping[str, Any]) -> str:
    """Fallback executive summary when the upstream dossier does not provide one."""
    target = _safe_str(dossier.get("target"), "unknown target")
    score = _safe_int(dossier.get("risk_score"), 0)
    level = _safe_str(dossier.get("risk_level"), "UNKNOWN")
    features = dossier.get("risk_features", []) or []

    if not features:
        return (
            f"{target} has a {level.lower()} risk profile with a score of {score}. "
            f"No structured risk features were available to explain the result."
        )

    top = []
    for feat in features[:2]:
        if not _is_mapping(feat):
            continue
        top.append(_safe_str(feat.get("feature"), "feature"))

    if top:
        feature_text = ", ".join(top)
        return (
            f"{target} has a {level.lower()} risk profile with a score of {score}. "
            f"The main structured drivers are {feature_text}."
        )

    return f"{target} has a {level.lower()} risk profile with a score of {score}."



def _summarize_notes(notes: Any, limit: int = 6) -> List[str]:
    items = [str(n) for n in _as_list(notes) if str(n).strip()]
    if len(items) > limit:
        return items[:limit] + [f"... and {len(items) - limit} more"]
    return items


# ---------------------------------------------------------------------------
# Core build logic
# ---------------------------------------------------------------------------


def _build_card_from_analysis(dossier: Mapping[str, Any], analysis: Mapping[str, Any], *, max_top_features: int) -> JSONDict:
    explain = analysis.get("explain", {}) if _is_mapping(analysis.get("explain")) else {}
    expose = analysis.get("expose", {}) if _is_mapping(analysis.get("expose")) else {}

    top_features: List[JSONDict] = []
    for feat in _as_list(explain.get("top_features")):
        if not _is_mapping(feat):
            continue
        top_features.append(
            {
                "feature": _safe_str(feat.get("feature"), "unknown_feature"),
                "contribution": _format_contribution(feat.get("weight", feat.get("contribution", 0))),
                "plain_language": _feature_plain_language(feat),
            }
        )
        if len(top_features) >= max_top_features:
            break

    if not top_features:
        # Fall back to dossier risk features if the backend returned nothing.
        for feat in _as_list(dossier.get("risk_features")):
            if not _is_mapping(feat):
                continue
            top_features.append(
                {
                    "feature": _safe_str(feat.get("feature"), "unknown_feature"),
                    "contribution": _format_contribution(feat.get("weight", 0)),
                    "plain_language": _feature_plain_language(feat),
                }
            )
            if len(top_features) >= max_top_features:
                break

    fairness = expose.get("fairness", {}) if _is_mapping(expose.get("fairness")) else {}
    robustness = expose.get("robustness", {}) if _is_mapping(expose.get("robustness")) else {}

    entity = _safe_str(explain.get("target") or dossier.get("target"), "unknown")

    return {
        "entity_id": _entity_id(entity),
        "entity": entity,
        "timestamp": _utc_now(),
        # Use the dossier's canonical score as the card score.
        "risk_score": _safe_int(dossier.get("risk_score", explain.get("risk_score", explain.get("prediction", 0))), 0),
        "top_features": top_features,
        "supporting_evidence": list(_as_list(explain.get("positive_evidence", []))),
        "contradicting_evidence": list(_as_list(explain.get("negative_evidence", []))),
        "explanation": _safe_str(explain.get("explanation", "")),
        "confidence": float(explain.get("confidence", 1.0)),
        "fairness_check": {
            "passed": bool(fairness.get("passed", True)),
            "flagged": bool(fairness.get("flagged", False)),
            "notes": _summarize_notes(fairness.get("notes", [])),
            "max_score_delta": fairness.get("max_score_delta", 0),
            "avg_score_delta": fairness.get("avg_score_delta", 0),
            "threshold": fairness.get("threshold", 10),
            "evaluated_variants": fairness.get("evaluated_variants", 0),
        },
        "robustness_check": {
            "passed": bool(robustness.get("passed", True)),
            "notes": _summarize_notes(robustness.get("notes", [])),
            "max_score_delta": robustness.get("max_score_delta", 0),
            "avg_score_delta": robustness.get("avg_score_delta", 0),
            "threshold": robustness.get("threshold", 10),
            "decision_flipped": bool(robustness.get("decision_flipped", False)),
            "feature_stability": robustness.get("feature_stability", 1.0),
            "evaluated_variants": robustness.get("evaluated_variants", 0),
        },
    }



def _build_fairness_report(cards: Sequence[Mapping[str, Any]], analyses: Sequence[Mapping[str, Any]], target_label: str) -> str:
    lines: List[str] = []
    lines.append(f"# OSIRIS Fairness Report")
    lines.append("")
    lines.append(f"Generated: {_utc_now()}")
    lines.append(f"Target: {target_label}")
    lines.append("")

    if not cards:
        lines.append("No cards were generated.")
        return "\n".join(lines)

    for idx, (card, analysis) in enumerate(zip(cards, analyses), start=1):
        expose = analysis.get("expose", {}) if _is_mapping(analysis.get("expose")) else {}
        fairness = expose.get("fairness", {}) if _is_mapping(expose.get("fairness")) else {}
        lines.append(f"## Card {idx}: {_safe_str(card.get('entity'), 'unknown')}")
        lines.append("")
        lines.append(f"- Risk score: `{card.get('risk_score', 0)}`")
        lines.append(f"- Passed: `{bool(fairness.get('passed', True))}`")
        lines.append(f"- Flagged: `{bool(fairness.get('flagged', False))}`")
        lines.append(f"- Max score delta: `{fairness.get('max_score_delta', 0)}`")
        lines.append(f"- Avg score delta: `{fairness.get('avg_score_delta', 0)}`")
        lines.append(f"- Threshold: `{fairness.get('threshold', 10)}`")
        lines.append(f"- Evaluated variants: `{fairness.get('evaluated_variants', 0)}`")
        notes = _summarize_notes(fairness.get('notes', []))
        if notes:
            lines.append("- Notes:")
            for note in notes:
                lines.append(f"  - {note}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"



def _build_robustness_report(cards: Sequence[Mapping[str, Any]], analyses: Sequence[Mapping[str, Any]], target_label: str) -> str:
    lines: List[str] = []
    lines.append(f"# OSIRIS Robustness Report")
    lines.append("")
    lines.append(f"Generated: {_utc_now()}")
    lines.append(f"Target: {target_label}")
    lines.append("")

    if not cards:
        lines.append("No cards were generated.")
        return "\n".join(lines)

    for idx, (card, analysis) in enumerate(zip(cards, analyses), start=1):
        expose = analysis.get("expose", {}) if _is_mapping(analysis.get("expose")) else {}
        robustness = expose.get("robustness", {}) if _is_mapping(expose.get("robustness")) else {}
        lines.append(f"## Card {idx}: {_safe_str(card.get('entity'), 'unknown')}")
        lines.append("")
        lines.append(f"- Risk score: `{card.get('risk_score', 0)}`")
        lines.append(f"- Passed: `{bool(robustness.get('passed', True))}`")
        lines.append(f"- Decision flipped: `{bool(robustness.get('decision_flipped', False))}`")
        lines.append(f"- Max score delta: `{robustness.get('max_score_delta', 0)}`")
        lines.append(f"- Avg score delta: `{robustness.get('avg_score_delta', 0)}`")
        lines.append(f"- Threshold: `{robustness.get('threshold', 10)}`")
        lines.append(f"- Feature stability: `{robustness.get('feature_stability', 1.0)}`")
        lines.append(f"- Evaluated variants: `{robustness.get('evaluated_variants', 0)}`")
        notes = _summarize_notes(robustness.get('notes', []))
        if notes:
            lines.append("- Notes:")
            for note in notes:
                lines.append(f"  - {note}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"



def _build_fairness_report_json(cards: Sequence[Mapping[str, Any]], analyses: Sequence[Mapping[str, Any]], target_label: str) -> JSONDict:
    """Structured JSON fairness report."""
    per_card: List[JSONDict] = []
    all_passed = True
    for card, analysis in zip(cards, analyses):
        expose = analysis.get("expose", {}) if _is_mapping(analysis.get("expose")) else {}
        fairness = expose.get("fairness", {}) if _is_mapping(expose.get("fairness")) else {}
        passed = bool(fairness.get("passed", True))
        if not passed:
            all_passed = False
        per_card.append({
            "entity": _safe_str(card.get("entity"), "unknown"),
            "risk_score": card.get("risk_score", 0),
            "passed": passed,
            "flagged": bool(fairness.get("flagged", False)),
            "max_score_delta": fairness.get("max_score_delta", 0),
            "avg_score_delta": fairness.get("avg_score_delta", 0),
            "threshold": fairness.get("threshold", 10),
            "evaluated_variants": fairness.get("evaluated_variants", 0),
            "notes": _summarize_notes(fairness.get("notes", [])),
        })
    return {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "target": target_label,
        "overall_passed": all_passed,
        "card_count": len(per_card),
        "cards": per_card,
    }


def _build_robustness_report_json(cards: Sequence[Mapping[str, Any]], analyses: Sequence[Mapping[str, Any]], target_label: str) -> JSONDict:
    """Structured JSON robustness report."""
    per_card: List[JSONDict] = []
    all_passed = True
    for card, analysis in zip(cards, analyses):
        expose = analysis.get("expose", {}) if _is_mapping(analysis.get("expose")) else {}
        robustness = expose.get("robustness", {}) if _is_mapping(expose.get("robustness")) else {}
        passed = bool(robustness.get("passed", True))
        if not passed:
            all_passed = False
        per_card.append({
            "entity": _safe_str(card.get("entity"), "unknown"),
            "risk_score": card.get("risk_score", 0),
            "passed": passed,
            "decision_flipped": bool(robustness.get("decision_flipped", False)),
            "max_score_delta": robustness.get("max_score_delta", 0),
            "avg_score_delta": robustness.get("avg_score_delta", 0),
            "threshold": robustness.get("threshold", 10),
            "feature_stability": robustness.get("feature_stability", 1.0),
            "evaluated_variants": robustness.get("evaluated_variants", 0),
            "notes": _summarize_notes(robustness.get("notes", [])),
        })
    return {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "target": target_label,
        "overall_passed": all_passed,
        "card_count": len(per_card),
        "cards": per_card,
    }


def build_artifacts(config: BuildConfig) -> BuildArtifacts:
    dossiers = _load_dossiers(config.input_path)
    target_label = _safe_str(dossiers[0].get("target"), "unknown")

    # Cohort analysis improves the fairness/robustness outputs when multiple
    # dossiers are available. When only one dossier exists, the wrapper still
    # returns meaningful single-item results.
    wrapper = ExplaboxWrapper(risk_threshold=config.risk_threshold)

    analyses: List[JSONDict] = []
    cards: List[JSONDict] = []

    for dossier in dossiers:
        analysis = wrapper.analyze(dossier, cohort=dossiers)
        analyses.append(analysis)
        cards.append(_build_card_from_analysis(dossier, analysis, max_top_features=config.max_top_features))

    explanation_cards = {
        "schema_version": "1.0",
        "generated_at": _utc_now(),
        "target": target_label if len(dossiers) == 1 else target_label,
        "targets": [str(d.get("target", "unknown")) for d in dossiers],
        "card_count": len(cards),
        "cards": cards,
    }

    fairness_report_md = _build_fairness_report(cards, analyses, target_label)
    fairness_report_json = _build_fairness_report_json(cards, analyses, target_label)
    robustness_report_md = _build_robustness_report(cards, analyses, target_label)
    robustness_report_json = _build_robustness_report_json(cards, analyses, target_label)

    validate_explanation_cards(explanation_cards)
    ExplanationCards.model_validate(explanation_cards)

    return BuildArtifacts(
        explanation_cards=explanation_cards,
        fairness_report_md=fairness_report_md,
        fairness_report_json=fairness_report_json,
        robustness_report_md=robustness_report_md,
        robustness_report_json=robustness_report_json,
        analysis_batches=analyses,
    )


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def write_outputs(artifacts: BuildArtifacts, output_dir: Path) -> Dict[str, Path]:
    _ensure_dir(output_dir)

    explanation_cards_path = output_dir / "explanation_cards.json"
    fairness_report_path = output_dir / "fairness_report.md"
    fairness_report_json_path = output_dir / "fairness_report.json"
    robustness_report_path = output_dir / "robustness_report.md"
    robustness_report_json_path = output_dir / "robustness_report.json"

    explanation_cards_path.write_text(
        json.dumps(artifacts.explanation_cards, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    fairness_report_path.write_text(artifacts.fairness_report_md, encoding="utf-8")
    fairness_report_json_path.write_text(
        json.dumps(artifacts.fairness_report_json, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    robustness_report_path.write_text(artifacts.robustness_report_md, encoding="utf-8")
    robustness_report_json_path.write_text(
        json.dumps(artifacts.robustness_report_json, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return {
        "explanation_cards": explanation_cards_path,
        "fairness_report": fairness_report_path,
        "fairness_report_json": fairness_report_json_path,
        "robustness_report": robustness_report_path,
        "robustness_report_json": robustness_report_json_path,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OSIRIS Stage 4 explanation card builder")
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="Path to dossier.json (or a JSON file containing a dossier list).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where explanation_cards.json and reports will be written.",
    )
    parser.add_argument(
        "--risk-threshold",
        type=int,
        default=DEFAULT_RISK_THRESHOLD,
        help="Risk threshold passed to ExplaboxWrapper.",
    )
    parser.add_argument(
        "--max-top-features",
        type=int,
        default=DEFAULT_MAX_TOP_FEATURES,
        help="Maximum number of top features to include in each explanation card.",
    )
    return parser



def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config = BuildConfig(
        input_path=args.input,
        output_dir=args.output_dir,
        risk_threshold=args.risk_threshold,
        max_top_features=args.max_top_features,
    )

    log.info("Loading dossier(s) from %s", config.input_path)
    artifacts = build_artifacts(config)
    validate_explanation_cards(artifacts.explanation_cards)
    ExplanationCards.model_validate(artifacts.explanation_cards)
    paths = write_outputs(artifacts, config.output_dir)

    log.info("Wrote %s", paths["explanation_cards"])
    log.info("Wrote %s", paths["fairness_report"])
    log.info("Wrote %s", paths["fairness_report_json"])
    log.info("Wrote %s", paths["robustness_report"])
    log.info("Wrote %s", paths["robustness_report_json"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
