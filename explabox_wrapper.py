#!/usr/bin/env python3
"""
OSIRIS Stage 4 — explabox_wrapper.py

This module is the adapter layer between OSIRIS and the explainability stack.
It is intentionally split into two concerns:

1. A stable, project-facing interface for Stage 4.
2. A backend implementation that can later be swapped from the deterministic
   fallback to the real Explabox integration without changing the public API.

Important design notes
----------------------
- This file does NOT generate reports.
- This file does NOT write project output JSON files.
- This file returns structured Python dictionaries only.
- The real Explabox API is not assumed here because it is not pinned in the
  repository. A deterministic fallback backend is provided so the wrapper is
  usable now and can be replaced later.

Expected upstream inputs
-------------------------
- Person B's `dossier.json` contract output.
- Optionally a batch of dossier-like dictionaries for dataset-level analysis.

Public API
----------
- ExplaboxWrapper.initialize()
- ExplaboxWrapper.explore(...)
- ExplaboxWrapper.examine(...)
- ExplaboxWrapper.explain(...)
- ExplaboxWrapper.expose(...)
- ExplaboxWrapper.analyze(...)

The wrapper also accepts a custom predictor adapter. By default it will derive
scores from the dossier structure itself, which keeps Stage 4 runnable in the
absence of the real model/backend.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import math
import os
import re
import statistics
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Union, cast

try:
    from mind.mind_profile import (
        extract_feature_vector,
        score_from_features,
        DeterministicScorer,
        _default_scorer,
        normalise_value,
        DEFAULT_WEIGHTS,
    )  # noqa: E402
    _MIND_SCORING_AVAILABLE = True
except ImportError:
    _MIND_SCORING_AVAILABLE = False

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
# Explabox availability detection
# ---------------------------------------------------------------------------

try:
    import explabox as _explabox_pkg  # type: ignore[import-untyped]
    _EXPLABOX_AVAILABLE = True
except ImportError:
    _EXPLABOX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

JSONDict = Dict[str, Any]
DossierLike = Mapping[str, Any]
DossierInput = Union[DossierLike, str, Path]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_RISK_THRESHOLD = 70
DEFAULT_FAIRNESS_THRESHOLD = 10
DEFAULT_ROBUSTNESS_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _load_json(source: DossierInput) -> JSONDict:
    """Load a JSON dict from a mapping, file path, or JSON string."""
    if isinstance(source, Mapping):
        return dict(source)

    if isinstance(source, Path):
        return cast(JSONDict, json.loads(source.read_text(encoding="utf-8")))

    if isinstance(source, str):
        candidate = Path(source)
        if candidate.exists():
            return cast(JSONDict, json.loads(candidate.read_text(encoding="utf-8")))
        return cast(JSONDict, json.loads(source))

    raise TypeError(f"Unsupported input type: {type(source)!r}")


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _clip_score(score: float) -> int:
    return int(max(0, min(100, round(score))))


def _mean_or_zero(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _risk_level(score: int) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def _compute_confidence(dossier: Mapping[str, Any]) -> float:
    """Derive confidence from insufficient-data flags and feature coverage.

    Each flag reduces confidence by 0.15. Fewer than 2 features also
    reduce confidence. Result is clamped to [0.0, 1.0].
    """
    flags = dossier.get("insufficient_data_flags", []) or []
    flag_count = len([f for f in flags if isinstance(f, Mapping)])
    features = dossier.get("risk_features", []) or []
    feature_count = len([f for f in features if isinstance(f, Mapping)])

    confidence = 1.0 - 0.15 * flag_count
    if feature_count < 2:
        confidence -= 0.20
    return float(max(0.0, min(1.0, confidence)))


def _build_explanation(dossier: Mapping[str, Any], top_features: List[Mapping[str, Any]]) -> str:
    """Generate a comprehensive, natural-language explanation grounded in dossier fields.

    Synthesizes multiple risk drivers and mitigating factors into a cohesive analytical summary.
    """
    target = _safe_str(dossier.get("target"), "unknown target")
    score = _clip_score(float(dossier.get("risk_score", 0) or 0))
    level = _safe_str(dossier.get("risk_level")) or _risk_level(score)
    exec_summary = _safe_str(dossier.get("executive_summary"), "").strip()

    positive = []
    negative = []
    for feat in top_features:
        if not isinstance(feat, Mapping):
            continue
        plain = _safe_str(feat.get("plain_language"), "").strip()
        if not plain or plain.endswith("increased the score.") or plain.endswith("decreased the score."):
            plain = _feature_plain_language(feat)
        weight = feat.get("weight", 0)
        if isinstance(weight, (int, float)) and weight >= 0:
            positive.append(plain.rstrip("."))
        else:
            negative.append(plain.rstrip("."))

    parts: List[str] = []
    parts.append(f"{target} received a risk score of {score} ({level}).")

    if positive:
        if len(positive) == 1:
            parts.append(f"Primary risk driver: {positive[0]}.")
        else:
            parts.append(f"Primary risk drivers: {'; '.join(positive)}.")
    if negative:
        if len(negative) == 1:
            parts.append(f"Mitigating factor: {negative[0]}.")
        else:
            parts.append(f"Mitigating factors: {'; '.join(negative)}.")

    if exec_summary and exec_summary.lower() not in ("none", "null", ""):
        parts.append(exec_summary)

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Model / predictor adapter
# ---------------------------------------------------------------------------


class PredictorProtocol(Protocol):
    """Minimal protocol expected by the wrapper."""

    def predict(self, text: str) -> float:
        ...


@dataclass
class PredictorAdapter:
    """Normalize a variety of callable predictor styles to one interface.

    Person B may expose one of several likely shapes:
    - predict(text: str) -> score
    - score(text: str) -> score
    - __call__(text: str) -> score
    - predict(payload: dict) -> score

    The adapter tries these in a safe order. The goal is not to guess the
    final Explabox contract; the goal is to keep the wrapper stable while the
    model backend changes.
    """

    predictor: Any

    def predict(self, text: str, payload: Optional[Mapping[str, Any]] = None) -> float:
        predictor = self.predictor

        # Common case: callable predictor with text-only interface.
        if hasattr(predictor, "predict"):
            try:
                result = predictor.predict(text)
                return float(result)
            except TypeError:
                if payload is not None:
                    try:
                        result = predictor.predict(payload)
                        return float(result)
                    except Exception as exc:  # pragma: no cover - defensive fallback
                        raise RuntimeError(f"predictor.predict failed: {exc}") from exc

        # Alternative common names.
        if hasattr(predictor, "score"):
            try:
                return float(predictor.score(text))
            except TypeError:
                if payload is not None:
                    return float(predictor.score(payload))

        # Callable object.
        if callable(predictor):
            try:
                return float(predictor(text))
            except TypeError:
                if payload is not None:
                    return float(predictor(payload))

        raise TypeError(
            "Unsupported predictor interface. Expected predict(text), score(text), or a callable."
        )


# ---------------------------------------------------------------------------
# Dossier conversion helpers
# ---------------------------------------------------------------------------


def dossier_to_text(dossier: Mapping[str, Any]) -> str:
    """Convert a dossier into a compact text block for explainability backends.

    Many explainability frameworks operate on a text input or a feature string.
    This function is intentionally deterministic so that the same dossier
    always converts to the same explanation text.
    """
    profile = dossier.get("profile", {}) if isinstance(dossier.get("profile"), Mapping) else {}
    risk_features = dossier.get("risk_features", []) or []
    flags = dossier.get("insufficient_data_flags", []) or []

    parts: List[str] = []
    parts.append(f"target: {_safe_str(dossier.get('target'), 'unknown')}")
    parts.append(f"risk_score: {_safe_str(dossier.get('risk_score'), '0')}")
    parts.append(f"risk_level: {_safe_str(dossier.get('risk_level'), 'unknown')}")
    parts.append(f"identity: {_safe_str(profile.get('identity'), '')}")
    parts.append(f"geo_temporal: {_safe_str(profile.get('geo_temporal'), '')}")
    parts.append(f"technical_stack: {', '.join(_ensure_list(profile.get('technical_stack')))}")
    parts.append(f"ideology: {_safe_str(profile.get('ideology'), 'none')}")
    parts.append(f"opsec_posture: {_safe_str(profile.get('opsec_posture'), '')}")

    if isinstance(profile.get("ocean_psychology"), Mapping):
        ocean = profile["ocean_psychology"]
        for key in ("openness", "conscientiousness", "extraversion", "agreeableness", "neuroticism"):
            if key in ocean:
                parts.append(f"ocean_{key}: {_safe_str(ocean.get(key), '')}")

    for feature in risk_features:
        if isinstance(feature, Mapping):
            parts.append(
                "feature: "
                f"{_safe_str(feature.get('feature'))}="
                f"{_safe_str(feature.get('value'))} weight={_safe_str(feature.get('weight'))}"
            )

    if flags:
        for flag in flags:
            if isinstance(flag, Mapping):
                parts.append(
                    f"insufficient_data: {_safe_str(flag.get('dimension'))} {_safe_str(flag.get('reason'))}"
                )

    return "\n".join(parts)


def _feature_plain_language(feature: Mapping[str, Any]) -> str:
    """Comprehensive plain-language description for a risk feature."""
    if "plain_language" in feature and feature["plain_language"]:
        pl = _safe_str(feature["plain_language"]).strip()
        if not (pl.endswith("increased the score.") or pl.endswith("decreased the score.") or pl.endswith("affected the score.")):
            return pl

    name = _safe_str(feature.get("feature"), "feature")
    value = feature.get("value")
    weight = feature.get("weight")

    if isinstance(value, (int, float)):
        value_text = str(value)
    else:
        value_text = _safe_str(value, "unknown")

    direction = "increased" if isinstance(weight, (int, float)) and weight >= 0 else "decreased"

    if name == "breach_appearance_count":
        if isinstance(value, (int, float)) and value > 0:
            return f"Observed in {value_text} historical data breach(es), directly increasing credential exposure and compromise risk"
        return "No historical data breach appearances discovered across leak databases"
    elif name == "exposed_email_count":
        return f"Discovered {value_text} publicly exposed email address(es), expanding the social engineering and phishing attack surface"
    elif name == "open_ports_sensitive":
        return f"Detected {value_text} sensitive open network port(s) or service(s), creating immediate network ingress attack vectors"
    elif name == "subdomain_count":
        return f"Mapped {value_text} active subdomain(s), increasing external infrastructure footprint and perimeter complexity"
    elif name == "entity_count":
        return f"Target reconnaissance discovered {value_text} unique external asset(s) across the perimeter"
    elif name == "unknown_registrar":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "Domain registration details and registrar identity are masked or unknown, raising attribution opacity"
        return "Domain registrar attribution is verified and transparent"
    elif name == "recent_infrastructure_churn":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "High recent DNS or infrastructure churn detected, potentially indicating ephemeral hosting or evasive setup"
        return "Infrastructure hosting and DNS records exhibit long-term stability"
    elif name == "aws_infrastructure":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "Target utilizes cloud hosting infrastructure (AWS), requiring specialized IAM and cloud security review"
        return "Target does not rely on identified AWS cloud infrastructure"
    elif name == "injection_attempt_detected":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "CRITICAL: Prompt injection or active adversarial payload detected within reconnaissance input data"
        return "No adversarial prompt injection patterns detected"
    elif name == "domain_age_days":
        try:
            if value is None:
                raise TypeError("domain age is absent")
            days = float(value)
            years = days / 365.25
            return f"Domain has been registered for {value_text} days (~{years:.1f} years), indicating established historical reputation and stability"
        except (ValueError, TypeError):
            return f"Domain age is recorded at {value_text} days, contributing to domain reputation evaluation"
    elif name == "privacy_registrar_used":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "WHOIS privacy protection is enabled on the domain registrar, obscuring administrative ownership details"
        return "Domain registration contact information is publicly listed"
    elif name == "cloudflare_proxied":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "External web traffic is proxied through Cloudflare CDN/WAF, filtering edge attacks and obscuring origin IP addresses"
        return "Target infrastructure endpoints are directly exposed without CDN proxying"
    elif name == "ipv6_enabled":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "IPv6 networking capabilities are active on target endpoints, requiring dual-stack firewall validation"
        return "Target networking is currently restricted to IPv4 endpoints"
    elif name == "deliberate_test_target":
        if str(value).lower() in ("1", "true", "yes", "1.0"):
            return "Target is identified as a known security testbed or demonstration domain (e.g., scanme.nmap.org)"
        return "Target is evaluated as a standard production organization domain"

    readable_name = name.replace("_", " ").title()
    if isinstance(weight, (int, float)) and weight != 0:
        return f"{readable_name} (value={value_text}) {direction} the score"
    return f"{name}={value_text} {direction} the score"



# ---------------------------------------------------------------------------
# Fallback backend (deterministic, no external dependencies)
# ---------------------------------------------------------------------------


class FallbackBackend:
    """Deterministic fallback backend that produces honest attribution.

    Uses the dossier's own signed weights for feature attribution, which is
    more faithful than running a surrogate model on a cohort of one.
    """

    name = "deterministic_fallback"

    def __init__(self, predictor: Optional[PredictorAdapter] = None, risk_threshold: int = DEFAULT_RISK_THRESHOLD):
        self.predictor = predictor
        self.risk_threshold = risk_threshold
        self.initialized = False

    def initialize(self) -> JSONDict:
        self.initialized = True
        return {
            "backend": self.name,
            "initialized": True,
            "note": "Deterministic fallback backend using signed-weight attribution.",
        }

    def explore(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        scores = [float(d.get("risk_score", 0)) for d in dossiers if isinstance(d, Mapping)]
        targets = [str(d.get("target", "")) for d in dossiers if isinstance(d, Mapping)]
        features = []
        for d in dossiers:
            if isinstance(d, Mapping):
                for feature in d.get("risk_features", []) or []:
                    if isinstance(feature, Mapping):
                        features.append(_safe_str(feature.get("feature"), "unknown_feature"))

        return {
            "backend": self.name,
            "sample_count": len(dossiers),
            "unique_targets": sorted({t for t in targets if t}),
            "score_summary": {
                "min": _clip_score(min(scores)) if scores else 0,
                "max": _clip_score(max(scores)) if scores else 0,
                "mean": round(_mean_or_zero(scores), 2),
                "median": round(statistics.median(scores), 2) if scores else 0,
            },
            "feature_frequency": _frequency_map(features),
        }

    def examine(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        missing_target = 0
        missing_score = 0
        schema_warnings: List[str] = []

        for idx, dossier in enumerate(dossiers):
            if not isinstance(dossier, Mapping):
                schema_warnings.append(f"sample[{idx}] is not a mapping")
                continue
            if not dossier.get("target"):
                missing_target += 1
            if dossier.get("risk_score") is None:
                missing_score += 1
            if not isinstance(dossier.get("risk_features", []), list):
                schema_warnings.append(f"sample[{idx}].risk_features is not a list")

        quality_score = max(0, 100 - (missing_target * 10) - (missing_score * 10) - (len(schema_warnings) * 5))
        return {
            "backend": self.name,
            "quality_score": quality_score,
            "missing_target_count": missing_target,
            "missing_score_count": missing_score,
            "warnings": schema_warnings,
        }

    def explain(self, dossier: Mapping[str, Any]) -> JSONDict:
        """Return a structured explanation with full attribution."""
        risk_score = _clip_score(float(dossier.get("risk_score", 0) or 0))
        top_features = _top_features(dossier)
        feature_views: List[Mapping[str, Any]] = list(top_features)
        positive_evidence, negative_evidence = _split_evidence(feature_views)
        confidence = _compute_confidence(dossier)
        explanation = _build_explanation(dossier, feature_views)

        return {
            "backend": self.name,
            "risk_score": risk_score,
            "prediction": risk_score,
            "target": _safe_str(dossier.get("target"), "unknown"),
            "top_features": top_features,
            "positive_evidence": positive_evidence,
            "negative_evidence": negative_evidence,
            "confidence": round(confidence, 4),
            "explanation": explanation,
        }

    def expose(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        """Run fairness and robustness checks over dossier variants."""
        fairness = _fairness_check(dossiers)
        robustness = _robustness_check(dossiers)
        return {
            "backend": self.name,
            "fairness": fairness,
            "robustness": robustness,
        }


# ---------------------------------------------------------------------------
# Bounded Explabox backend (uses real library for cohort descriptives)
# ---------------------------------------------------------------------------


class ExplaboxBackend:
    """Backend that drives the real explabox library when available.

    Bounded integration: uses explabox for cohort-level dataset descriptives
    (box.explore()) and delegates per-dossier explain/expose to the
    deterministic fallback, because attribution from the dossier's real signed
    weights is more honest than a text-surrogate LIME model on a cohort of one.
    """

    name = "explabox"

    def __init__(self, predictor: Optional[PredictorAdapter] = None, risk_threshold: int = DEFAULT_RISK_THRESHOLD):
        self.predictor = predictor
        self.risk_threshold = risk_threshold
        self.initialized = False
        self._explabox_usable = False
        self._fallback = FallbackBackend(predictor=predictor, risk_threshold=risk_threshold)

    def initialize(self) -> JSONDict:
        self.initialized = True
        self._fallback.initialize()
        note = "Real Explabox library detected. Cohort descriptives via explabox; per-dossier attribution via signed weights."
        return {
            "backend": self.name,
            "initialized": True,
            "note": note,
        }

    def explore(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        """Try real explabox descriptives; fall back to deterministic if it fails."""
        if _EXPLABOX_AVAILABLE and len(dossiers) >= 1:
            try:
                return self._explabox_explore(dossiers)
            except Exception as exc:
                log.info("Explabox explore failed, falling back: %s", exc)
        return self._fallback.explore(dossiers)

    def examine(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        return self._fallback.examine(dossiers)

    def explain(self, dossier: Mapping[str, Any]) -> JSONDict:
        return self._fallback.explain(dossier)

    def expose(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        return self._fallback.expose(dossiers)

    def _explabox_explore(self, dossiers: Sequence[Mapping[str, Any]]) -> JSONDict:
        """Drive real explabox descriptives for a cohort of dossiers."""
        import pandas as pd  # type: ignore[import-untyped]

        rows = []
        labels = []
        for d in dossiers:
            if not isinstance(d, Mapping):
                continue
            features = d.get("risk_features", []) or []
            text_parts = []
            for f in features:
                if isinstance(f, Mapping):
                    text_parts.append(f"{_safe_str(f.get('feature', ''))}={_safe_str(f.get('value', ''))}")
            rows.append(" ".join(text_parts) or "no_features")
            score = float(d.get("risk_score", 0) or 0)
            labels.append(_risk_level(_clip_score(score)))

        if len(set(labels)) < 2:
            return self._fallback.explore(dossiers)

        df = pd.DataFrame({"text": rows, "label": labels})
        env = _explabox_pkg.import_data(df, data_cols="text", label_cols="label")
        box = _explabox_pkg.Explabox(ingestibles=_explabox_pkg.Ingestible(data=env))
        descriptives = box.explore()

        result: JSONDict = {
            "backend": self.name,
            "sample_count": len(dossiers),
            "note": "Descriptives from real Explabox library.",
        }

        if hasattr(descriptives, "to_dict"):
            result["descriptives"] = descriptives.to_dict()

        targets = sorted({str(d.get("target", "")) for d in dossiers if isinstance(d, Mapping)})
        result["unique_targets"] = targets
        scores = [float(d.get("risk_score", 0)) for d in dossiers if isinstance(d, Mapping)]
        if scores:
            result["score_summary"] = {
                "min": _clip_score(min(scores)),
                "max": _clip_score(max(scores)),
                "mean": round(_mean_or_zero(scores), 2),
                "median": round(statistics.median(scores), 2),
            }

        return result


# ---------------------------------------------------------------------------
# Shared internal helpers (used by both backends)
# ---------------------------------------------------------------------------


def _predict_score(dossier: Mapping[str, Any]) -> int:
    """Derive a score from the dossier using DeterministicScorer.

    Always uses the deterministic scoring engine. Never falls back to the
    dossier's declared risk_score, which would make fairness/robustness
    perturbations vacuous.
    """
    if _MIND_SCORING_AVAILABLE:
        risk_features = [
            dict(f) for f in dossier.get("risk_features", [])
            if isinstance(f, Mapping)
        ]
        result = _default_scorer.score(risk_features, score_mode="REAL")
        return result.risk_score

    # Fallback only if mind_profile is not importable (should not happen in production)
    features = dossier.get("risk_features", []) or []
    total = 15.0  # default intercept
    for feature in features:
        if isinstance(feature, Mapping):
            weight = feature.get("weight", 0)
            value = feature.get("value", 0)
            try:
                norm = float(value)
                w = float(weight)
            except (TypeError, ValueError):
                continue
            total += norm * w
    return _clip_score(total)


def _top_features(dossier: Mapping[str, Any], limit: int = 5) -> List[JSONDict]:
    """Extract the top risk features sorted by absolute contribution.

    Ranks by abs(normalized_value × weight), i.e. actual score contribution,
    not just abs(weight). A high-weight feature with near-zero normalized value
    should not rank above a lower-weight feature that moves the score more.
    """
    features = dossier.get("risk_features", []) or []
    scored: List[Tuple[float, JSONDict]] = []
    for feature in features:
        if not isinstance(feature, Mapping):
            continue
        weight = float(feature.get("weight", 0) or 0)
        raw_value = feature.get("value", 0)
        try:
            raw_value_f = float(raw_value)
        except (TypeError, ValueError):
            raw_value_f = 0.0

        # Use pre-computed contribution_points if available, else compute
        contribution = feature.get("contribution_points")
        if contribution is None and _MIND_SCORING_AVAILABLE:
            norm_val = normalise_value(
                _safe_str(feature.get("feature"), ""), raw_value_f
            )
            contribution = norm_val * weight
        elif contribution is None:
            contribution = raw_value_f * weight

        scored.append(
            (
                abs(float(contribution)),
                {
                    "feature": _safe_str(feature.get("feature"), "unknown_feature"),
                    "value": feature.get("value"),
                    "weight": weight,
                    "contribution_points": round(float(contribution), 4),
                    "plain_language": _feature_plain_language(feature),
                },
            )
        )
    scored.sort(key=lambda item: item[0], reverse=True)
    return [item[1] for item in scored[:limit]]


def _split_evidence(top_features: List[Mapping[str, Any]]) -> Tuple[List[str], List[str]]:
    """Split top features into positive and negative evidence lists."""
    positive: List[str] = []
    negative: List[str] = []
    for feat in top_features:
        plain = _safe_str(feat.get("plain_language"), "")
        if not plain:
            plain = f"{_safe_str(feat.get('feature'), 'feature')}={_safe_str(feat.get('value'), '?')}"
        weight = feat.get("weight", 0)
        if isinstance(weight, (int, float)) and weight >= 0:
            positive.append(plain)
        else:
            negative.append(plain)
    return positive, negative


def _frequency_map(values: Sequence[str]) -> JSONDict:
    counts: Dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


_FAIRNESS_IDENTITY_REPLACEMENTS = [
    ("corp", "llc"),
    ("inc", "gmbh"),
    ("company", "organization"),
    ("individual", "entity"),
    ("admin", "user"),
]

_FAIRNESS_REGION_MAP = {
    "us": "eu",
    "na": "emea",
    "america": "europe",
    "california": "germany",
    "west": "east",
}

_FAIRNESS_DOMAIN_REPLACEMENTS = [
    (".com", ".org"),
    (".net", ".io"),
    ("example", "test"),
    ("domain", "site"),
]


def _perturb_fairness(dossier: MutableMapping[str, Any], variant: str) -> MutableMapping[str, Any]:
    """Apply one synthetic counterfactual without changing evidence.

    The test attribute must not be legitimate evidence for the configured use
    case.  Operational scoring only permits the synthetic identity display
    field here; geography and target-domain variants are excluded because they
    can themselves be material infrastructure evidence.
    """
    perturbed = copy.deepcopy(dict(dossier))
    profile = perturbed.get("profile", {})
    if not isinstance(profile, MutableMapping):
        profile = {}
        perturbed["profile"] = profile

    changed_fields: List[str] = []

    if variant == "identity":
        current = _safe_str(profile.get("identity"), "")
        for old, new in _FAIRNESS_IDENTITY_REPLACEMENTS:
            if old in current:
                current = current.replace(old, new)
        if current == _safe_str(profile.get("identity"), ""):
            current = "[altered-identity]"
        profile["identity"] = current
        changed_fields.append("profile.identity")
    else:
        raise ValueError(f"unsupported fairness counterfactual: {variant}")

    perturbed["profile"] = profile
    perturbed["_fairness_changed_fields"] = changed_fields
    return perturbed


def _fairness_check(dossiers: Sequence[Mapping[str, Any]], threshold: float = DEFAULT_FAIRNESS_THRESHOLD) -> JSONDict:
    """Matched synthetic counterfactual test for non-evidentiary identity text.

    This is not a population-level fairness claim. Any mutation to risk
    features invalidates the test rather than being counted as a score change.
    """
    variants = ("identity",)

    if not dossiers:
        return {
            "passed": False,
            "test_type": "paired_sensitivity_test",
            "outcome": "INSUFFICIENT_SAMPLE",
            "notes": ["No dossiers supplied."],
            "max_score_delta": 0,
            "avg_score_delta": 0,
            "threshold": threshold,
            "flagged": False,
            "evaluated_variants": 0,
            "variant_details": [],
        }

    deltas: List[float] = []
    notes: List[str] = []
    variant_details: List[JSONDict] = []

    for dossier in dossiers:
        if not isinstance(dossier, Mapping):
            continue
        base_score = _predict_score(dossier)
        base_level = _risk_level(base_score)
        for variant in variants:
            perturbed = _perturb_fairness(dict(dossier), variant)
            evidence_unchanged = perturbed.get("risk_features", []) == dossier.get("risk_features", [])
            pert_score = _predict_score(perturbed)
            delta = abs(base_score - pert_score)
            decision_changed = _risk_level(pert_score) != base_level
            changed_fields = perturbed.get("_fairness_changed_fields", [])
            deltas.append(delta)
            notes.append(f"{variant}: Δ={delta:.2f}; evidence_unchanged={evidence_unchanged}")
            variant_details.append({
                "variant": variant,
                "original_score": base_score,
                "perturbed_score": pert_score,
                "delta": round(delta, 4),
                "decision_changed": decision_changed,
                "fields_changed": changed_fields,
                "evidence_unchanged": evidence_unchanged,
            })

    max_delta = max(deltas) if deltas else 0
    avg_delta = _mean_or_zero(deltas)
    evidence_mutated = any(not detail["evidence_unchanged"] for detail in variant_details)
    flagged = max_delta > threshold or evidence_mutated
    # This implementation does not rerun extraction/LLM processing. A zero
    # scoring delta is structurally expected and cannot establish fairness.
    passed = False

    return {
        "passed": passed,
        "test_type": "paired_sensitivity_test",
        "notes": notes[:10],
        "max_score_delta": round(max_delta, 4),
        "avg_score_delta": round(avg_delta, 4),
        "threshold": threshold,
        "flagged": flagged,
        "outcome": "INVALID_TEST" if evidence_mutated else "INCONCLUSIVE",
        "evaluated_variants": len(deltas),
        "variant_details": variant_details[:15],
    }


# ---------------------------------------------------------------------------
# Robustness analysis (structural perturbation testing)
# ---------------------------------------------------------------------------


def _perturb_robustness(dossier: MutableMapping[str, Any], variant: str) -> MutableMapping[str, Any]:
    """Apply a structural perturbation to a dossier copy."""
    perturbed = copy.deepcopy(dict(dossier))
    profile = perturbed.get("profile", {})
    if not isinstance(profile, MutableMapping):
        profile = {}
        perturbed["profile"] = profile

    if variant == "missing_profile_fields":
        for key in ("identity", "geo_temporal", "opsec_posture"):
            profile.pop(key, None)
    elif variant == "empty_technical_stack":
        profile["technical_stack"] = []
    elif variant == "removed_emails":
        for key in ("identity", "geo_temporal"):
            if key in profile:
                profile[key] = re.sub(r"\S+@\S+\.\S+", "[removed-email]", str(profile[key]))
    elif variant == "removed_whois":
        for key in ("identity", "geo_temporal"):
            if key in profile:
                text = str(profile[key])
                for token in ("whois", "WHOIS", "registrar", "registered"):
                    text = text.replace(token, "[removed]")
                profile[key] = text
    elif variant == "removed_dns":
        for key in ("identity", "geo_temporal", "opsec_posture"):
            if key in profile:
                text = str(profile[key])
                for token in ("dns", "DNS", "nameserver", "NS "):
                    text = text.replace(token, "[removed]")
                profile[key] = text

    perturbed["profile"] = profile
    return perturbed


def _robustness_check(dossiers: Sequence[Mapping[str, Any]], threshold: float = DEFAULT_ROBUSTNESS_THRESHOLD) -> JSONDict:
    """Test score stability under structural perturbations.

    Compound pass criteria (ALL must hold):
    - max score delta <= threshold
    - no risk-level flip (decision_flipped == False)
    - feature_stability >= 0.5 (top-k Jaccard)
    """
    if not dossiers:
        return {
            "passed": False,
            "outcome": "INSUFFICIENT_SAMPLE",
            "notes": ["No dossiers supplied."],
            "max_score_delta": 0,
            "avg_score_delta": 0,
            "threshold": threshold,
            "decision_flipped": False,
            "feature_stability": 1.0,
            "evaluated_variants": 0,
        }

    deltas: List[float] = []
    notes: List[str] = []
    any_decision_flip = False
    influence_details: List[JSONDict] = []

    for dossier in dossiers:
        if not isinstance(dossier, Mapping):
            continue
        base_score = _predict_score(dossier)
        base_features = dossier.get("risk_features", []) or []
        base_level = _risk_level(base_score)

        structural_variants = (
            "missing_profile_fields",
            "empty_technical_stack",
        )
        for variant in structural_variants:
            perturbed = _perturb_robustness(dict(dossier), variant)
            pert_score = _predict_score(perturbed)
            delta = abs(base_score - pert_score)
            pert_level = _risk_level(pert_score)
            if pert_level != base_level:
                any_decision_flip = True
            deltas.append(delta)
            notes.append(f"{variant}: Δ={delta:.2f}")

        # Perturbation: remove each feature one at a time (deletion fidelity)
        for idx, feature in enumerate(base_features):
            if not isinstance(feature, Mapping):
                continue
            perturbed = copy.deepcopy(dict(dossier))
            perturbed["risk_features"] = [
                f for i, f in enumerate(base_features) if i != idx and isinstance(f, Mapping)
            ]
            pert_score = _predict_score(perturbed)
            delta = abs(base_score - pert_score)
            pert_level = _risk_level(pert_score)
            influence_details.append({
                "test": "counterfactual_evidence_deletion",
                "feature": _safe_str(feature.get("feature"), "?"),
                "score_delta": round(delta, 4),
                "decision_changed": pert_level != base_level,
            })

        # Perturbation: empty risk_features
        perturbed = copy.deepcopy(dict(dossier))
        perturbed["risk_features"] = []
        pert_score = _predict_score(perturbed)
        delta = abs(base_score - pert_score)
        pert_level = _risk_level(pert_score)
        influence_details.append({
            "test": "all_evidence_deletion", "score_delta": round(delta, 4),
            "decision_changed": pert_level != base_level,
        })

        # Perturbation: zero out all weights
        perturbed = copy.deepcopy(dict(dossier))
        for f in perturbed.get("risk_features", []):
            if isinstance(f, MutableMapping):
                f["weight"] = 0
        pert_score = _predict_score(perturbed)
        delta = abs(base_score - pert_score)
        influence_details.append({
            "test": "zero_all_weights", "score_delta": round(delta, 4),
            "decision_changed": _risk_level(pert_score) != base_level,
        })

    # Feature stability: top-k Jaccard similarity between base and perturbed rankings
    # For each feature deletion, compute top-k features of perturbed dossier and
    # compare with base top-k features using Jaccard similarity.
    stability_scores: List[float] = []
    for dossier in dossiers:
        if not isinstance(dossier, Mapping):
            continue
        base_features = dossier.get("risk_features", []) or []
        base_top_feats = _top_features(dossier, limit=5)
        base_top_names = {f.get("feature", "") for f in base_top_feats}

        if not base_features or not base_top_names:
            stability_scores.append(1.0)
            continue

        jaccard_vals: List[float] = []
        for idx, feature in enumerate(base_features):
            if not isinstance(feature, Mapping):
                continue
            perturbed = copy.deepcopy(dict(dossier))
            perturbed["risk_features"] = [
                f for i, f in enumerate(base_features) if i != idx and isinstance(f, Mapping)
            ]
            pert_top_feats = _top_features(perturbed, limit=5)
            pert_top_names = {f.get("feature", "") for f in pert_top_feats}

            # Jaccard similarity
            intersection = base_top_names & pert_top_names
            union = base_top_names | pert_top_names
            jaccard = len(intersection) / len(union) if union else 1.0
            jaccard_vals.append(jaccard)

        stability_scores.append(_mean_or_zero(jaccard_vals) if jaccard_vals else 1.0)

    feature_stability = _mean_or_zero(stability_scores) if stability_scores else 1.0

    max_delta = max(deltas) if deltas else 0
    avg_delta = _mean_or_zero(deltas)

    # Only non-semantic structural invariance affects robustness PASS.
    delta_ok = max_delta <= threshold
    no_flip = not any_decision_flip
    stability_ok = feature_stability >= 0.5
    passed = bool(deltas) and delta_ok and no_flip and stability_ok

    return {
        "passed": passed,
        "notes": notes[:15],
        "max_score_delta": round(max_delta, 4),
        "avg_score_delta": round(avg_delta, 4),
        "threshold": threshold,
        "decision_flipped": any_decision_flip,
        "feature_stability": round(feature_stability, 4),
        "evaluated_variants": len(deltas),
        "outcome": "PASS" if passed else "FAIL",
        "counterfactual_influence": influence_details,
        "pass_criteria": {
            "delta_ok": delta_ok,
            "no_decision_flip": no_flip,
            "stability_ok": stability_ok,
        },
    }


# ---------------------------------------------------------------------------
# Main wrapper (auto-detects backend)
# ---------------------------------------------------------------------------


class ExplaboxWrapper:
    """Project-facing Stage 4 wrapper.

    Public methods return structured dictionaries and never write report files.
    Backend selection is automatic: ExplaboxBackend if explabox is importable,
    FallbackBackend otherwise. Override with USE_EXPLABOX_BACKEND=0 to force fallback.
    """

    def __init__(
        self,
        predictor: Optional[Any] = None,
        backend: Optional[Any] = None,
        risk_threshold: int = DEFAULT_RISK_THRESHOLD,
    ):
        self.predictor = PredictorAdapter(predictor) if predictor is not None else None
        self.risk_threshold = risk_threshold

        if backend is not None:
            self.backend = backend
        elif os.getenv("USE_EXPLABOX_BACKEND", "").lower() in ("0", "false", "no"):
            self.backend = FallbackBackend(
                predictor=self.predictor,
                risk_threshold=risk_threshold,
            )
        elif _EXPLABOX_AVAILABLE:
            self.backend = ExplaboxBackend(
                predictor=self.predictor,
                risk_threshold=risk_threshold,
            )
        else:
            self.backend = FallbackBackend(
                predictor=self.predictor,
                risk_threshold=risk_threshold,
            )
        self.initialized = False
        self.last_initialize_payload: Optional[JSONDict] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def initialize(self) -> JSONDict:
        """Initialize the backend once."""
        if self.initialized:
            return {
                "initialized": True,
                "backend": getattr(self.backend, "name", type(self.backend).__name__),
                "cached": True,
            }

        if hasattr(self.backend, "initialize"):
            payload = self.backend.initialize()
            if isinstance(payload, Mapping):
                self.last_initialize_payload = dict(payload)
        else:
            payload = {
                "backend": getattr(self.backend, "name", type(self.backend).__name__),
                "initialized": True,
            }
            self.last_initialize_payload = dict(payload)

        self.initialized = True
        return dict(payload) if isinstance(payload, Mapping) else {
            "backend": getattr(self.backend, "name", type(self.backend).__name__),
            "initialized": True,
        }

    # ------------------------------------------------------------------
    # Dataset level operations
    # ------------------------------------------------------------------

    def explore(self, dossiers: Sequence[DossierInput]) -> JSONDict:
        """Dataset overview: counts, score summary, feature frequency."""
        items = [self._coerce_dossier(item) for item in dossiers]
        self._ensure_initialized()
        if hasattr(self.backend, "explore"):
            return cast(JSONDict, self.backend.explore(items))
        return {
            "backend": getattr(self.backend, "name", type(self.backend).__name__),
            "sample_count": len(items),
        }

    def examine(self, dossiers: Sequence[DossierInput]) -> JSONDict:
        """Dataset health: missing fields, malformed items, warnings."""
        items = [self._coerce_dossier(item) for item in dossiers]
        self._ensure_initialized()
        if hasattr(self.backend, "examine"):
            return cast(JSONDict, self.backend.examine(items))
        return {
            "backend": getattr(self.backend, "name", type(self.backend).__name__),
            "quality_score": 100,
        }

    def expose(self, dossiers: Sequence[DossierInput]) -> JSONDict:
        """Fairness and robustness checks across a dossier set."""
        items = [self._coerce_dossier(item) for item in dossiers]
        self._ensure_initialized()
        if hasattr(self.backend, "expose"):
            return cast(JSONDict, self.backend.expose(items))
        return {
            "backend": getattr(self.backend, "name", type(self.backend).__name__),
            "fairness": {
                "passed": False, "outcome": "INCONCLUSIVE",
                "evaluated_variants": 0,
                "notes": ["Unavailable backend; audit is inconclusive."],
            },
            "robustness": {
                "passed": False, "outcome": "INCONCLUSIVE",
                "evaluated_variants": 0,
                "notes": ["Unavailable backend; audit is inconclusive."],
            },
        }

    # ------------------------------------------------------------------
    # Single-dossier explainability
    # ------------------------------------------------------------------

    def explain(self, dossier: DossierInput) -> JSONDict:
        """Explain one dossier."""
        item = self._coerce_dossier(dossier)
        self._ensure_initialized()
        if hasattr(self.backend, "explain"):
            return cast(JSONDict, self.backend.explain(item))
        return {
            "backend": getattr(self.backend, "name", type(self.backend).__name__),
            "target": _safe_str(item.get("target"), "unknown"),
            "prediction": _clip_score(item.get("risk_score", 0) or 0),
            "top_features": [],
        }

    # ------------------------------------------------------------------
    # High-level orchestration
    # ------------------------------------------------------------------

    def analyze(self, dossier: DossierInput, cohort: Optional[Sequence[DossierInput]] = None) -> JSONDict:
        """Run initialize, explore, examine, explain, and expose.

        Parameters
        ----------
        dossier:
            Primary dossier to explain.
        cohort:
            Optional batch for dataset-level analysis. If omitted, the single
            dossier is used as the cohort so the result remains useful.
        """
        primary = self._coerce_dossier(dossier)
        batch = [self._coerce_dossier(item) for item in (cohort or [primary])]

        initialize_payload = self.initialize()
        explore_payload = self.explore(batch)
        examine_payload = self.examine(batch)
        explain_payload = self.explain(primary)
        expose_payload = self.expose(batch)

        return {
            "initialize": initialize_payload,
            "explore": explore_payload,
            "examine": examine_payload,
            "explain": explain_payload,
            "expose": expose_payload,
        }

    # ------------------------------------------------------------------
    # Conversion / validation
    # ------------------------------------------------------------------

    def _coerce_dossier(self, item: DossierInput) -> JSONDict:
        dossier = _load_json(item)
        return self._validate_dossier_shape(dossier)

    def _validate_dossier_shape(self, dossier: MutableMapping[str, Any]) -> JSONDict:
        """Validate the minimum fields needed by the wrapper.

        This is intentionally lighter than the full shared-schema validation so
        the wrapper remains usable even if the Pydantic layer changes later.
        """
        required_top_level = ("target", "profile", "risk_score", "risk_features")
        missing = [field for field in required_top_level if field not in dossier]
        if missing:
            raise ValueError(f"Dossier missing required fields: {', '.join(missing)}")

        if not isinstance(dossier.get("profile"), Mapping):
            raise TypeError("dossier['profile'] must be a mapping")

        if not isinstance(dossier.get("risk_features"), list):
            raise TypeError("dossier['risk_features'] must be a list")

        # Normalize a few common field shapes so downstream methods have a
        # predictable structure.
        dossier = dict(dossier)
        dossier["risk_features"] = [f for f in dossier.get("risk_features", []) if isinstance(f, Mapping)]
        dossier["insufficient_data_flags"] = [f for f in _ensure_list(dossier.get("insufficient_data_flags")) if isinstance(f, Mapping)]
        return dossier

    def _ensure_initialized(self) -> None:
        if not self.initialized:
            self.initialize()


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def build_wrapper(predictor: Optional[Any] = None, backend: Optional[Any] = None) -> ExplaboxWrapper:
    return ExplaboxWrapper(predictor=predictor, backend=backend)


def run_analysis(input_path: DossierInput, output_path: Optional[Union[str, Path]] = None) -> JSONDict:
    """CLI-friendly helper that loads one dossier and runs the wrapper."""
    wrapper = ExplaboxWrapper()
    result = wrapper.analyze(input_path)

    if output_path is not None:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OSIRIS Stage 4 Explabox wrapper")
    parser.add_argument("--input", required=True, help="Path to dossier.json or a JSON string")
    parser.add_argument("--output", help="Optional output path for the structured analysis JSON")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    result = run_analysis(args.input, args.output)
    if args.output is None:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
