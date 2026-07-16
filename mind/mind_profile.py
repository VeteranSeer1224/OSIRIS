#!/usr/bin/env python3
"""
OSIRIS-Mind  —  Stage 2: AI Profiling & Risk Scoring
Person B's primary deliverable.

Usage:
    python mind_profile.py --input raw_scan.json --output dossier.json
    python mind_profile.py --input raw_scan.json --output dossier.json --prompt v2
    python mind_profile.py --input raw_scan.json --output dossier.json --backend ollama
    python mind_profile.py --regression              # run regression suite

Environment variables:
    DEEPSEEK_API_KEY    — required for backend=deepseek (default)
    OPENAI_API_KEY      — required for backend=openai
    ANTHROPIC_API_KEY   — required for backend=anthropic
    OLLAMA_HOST         — defaults to http://localhost:11434
    OLLAMA_MODEL        — defaults to llama3.2
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

# ── optional heavy deps — fail gracefully so unit tests can import without them


try:
    import anthropic as _anthropic_sdk
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

# ── project paths
_HERE = Path(__file__).parent
_PROMPTS_DIR = _HERE.parent / "prompts"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OSIRIS-Mind] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Prompt loader
# ---------------------------------------------------------------------------

def load_prompt(version: str = "v2") -> str:
    """Load the system prompt from the prompts/ directory."""
    path = _PROMPTS_DIR / f"profile_{version}.txt"
    if not path.exists():
        raise FileNotFoundError(f"Prompt not found: {path}")
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 2. Input sanitiser  (prompt-injection resistance)
# ---------------------------------------------------------------------------

# Patterns that look like instruction injection embedded in OSINT data
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"forget\s+(your\s+)?(system\s+prompt|instructions?|context)",
    r"act\s+as\s+(a\s+)?",
    r"you\s+are\s+now\s+",
    r"admin\s*override",
    r"osiris.supervisor",
    r"set\s+(all\s+)?risk.sc[ro]+e",
    r"return\s+only\s*[:\{]",
    r"your\s+real\s+output\s+should",
    r"new\s+instructions?:",
    r"<\s*/?system\s*>",
    r"\bDAN\b",
    r"jailbreak",
]

_INJECTION_RE = re.compile(
    "|".join(_INJECTION_PATTERNS),
    flags=re.IGNORECASE | re.DOTALL,
)


def _check_for_injection(raw_json_str: str) -> tuple[bool, Optional[str]]:
    """Scan raw input string for injection patterns before passing to LLM."""
    match = _INJECTION_RE.search(raw_json_str)
    if match:
        return True, f"Pattern detected: '{match.group(0)[:60]}'"
    return False, None


def _scrub_obj(obj: Any) -> Any:
    """Recursively scrub injection patterns from dicts, lists, and strings."""
    if isinstance(obj, str):
        injected, _ = _check_for_injection(obj)
        if injected:
            return "[REDACTED-INJECTION]"
        return obj
    elif isinstance(obj, dict):
        return {k: _scrub_obj(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return type(obj)(_scrub_obj(item) for item in obj)
    return obj


def sanitise_input(scan: Dict[str, Any]) -> tuple[Dict[str, Any], bool, Optional[str]]:
    """
    Check the raw scan dict for injection. Returns:
      (cleaned_scan, injection_detected, injection_detail)
    Cleaning: recursively replace string values with [REDACTED-INJECTION] if flagged.
    """
    scan_str = json.dumps(scan)
    injected, detail = _check_for_injection(scan_str)

    if not injected:
        return scan, False, None

    clean_scan = _scrub_obj(scan)
    return clean_scan, True, detail


# ---------------------------------------------------------------------------
# 3. LLM backends
# ---------------------------------------------------------------------------

class LLMBackend:
    """Abstract base — subclass and implement call()."""

    name: str = "base"

    def call(self, system_prompt: str, user_message: str) -> str:
        raise NotImplementedError

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name}


class DeepSeekBackend(LLMBackend):
    """
    Uses the DeepSeek API — OpenAI-compatible endpoint.
    Default model: deepseek-chat (DeepSeek-V3, best price/performance).
    Also supports: deepseek-reasoner (DeepSeek-R1, slower but stronger reasoning).

    Docs: https://platform.deepseek.com/api-docs
    pip install openai   (reuses the OpenAI SDK pointed at DeepSeek's base URL)
    """

    name = "deepseek_api"
    BASE_URL = "https://api.deepseek.com"
    DEFAULT_MODEL = "deepseek-chat"

    def __init__(self, model: Optional[str] = None):

        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "DeepSeek backend requires the OpenAI SDK.\n"
                "Install with:\n"
                "pip install openai"
            ) from exc

        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "DEEPSEEK_API_KEY not set. "
                "Get a key at https://platform.deepseek.com/api-keys"
            )
        self.client = OpenAI(
            api_key=api_key,
            base_url=self.BASE_URL,
        )
        self.model = model or self.DEFAULT_MODEL

    def call(self, system_prompt: str, user_message: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            # DeepSeek supports JSON mode the same way OpenAI does
            response_format={"type": "json_object"},
            max_tokens=2048,
        )
        return response.choices[0].message.content

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model": self.model, "base_url": self.BASE_URL}


class AnthropicBackend(LLMBackend):
    """Uses the Anthropic Messages API (claude-sonnet-4-6 by default)."""

    name = "anthropic_api"
    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, model: Optional[str] = None):
        if not _ANTHROPIC_AVAILABLE:
            raise ImportError("pip install anthropic")
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError("ANTHROPIC_API_KEY not set")
        self.client = _anthropic_sdk.Anthropic(api_key=api_key)
        self.model = model or self.DEFAULT_MODEL

    def call(self, system_prompt: str, user_message: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model": self.model}


class OpenAIBackend(LLMBackend):
    """Uses the OpenAI Chat Completions API."""

    name = "openai_api"
    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self, model: Optional[str] = None):
        
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "OpenAI backend requires the OpenAI SDK.\n"
                "Install with:\n"
                "pip install openai"
            ) from exc

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise EnvironmentError("OPENAI_API_KEY not set")
        self.client = OpenAI(api_key=api_key)
        self.model = model or self.DEFAULT_MODEL

    def call(self, system_prompt: str, user_message: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model": self.model}


class OllamaBackend(LLMBackend):
    """Calls a local Ollama instance — fully offline, free."""

    name = "ollama_local"
    DEFAULT_MODEL = "llama3.2"

    def __init__(self, model: Optional[str] = None):
        if not _REQUESTS_AVAILABLE:
            raise ImportError("pip install requests")
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", self.DEFAULT_MODEL)

    def call(self, system_prompt: str, user_message: str) -> str:
        payload = {
            "model": self.model,
            "stream": False,
            "options": {"temperature": 0.2},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        resp = _requests.post(
            f"{self.host}/api/chat",
            json=payload,
            timeout=180,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model": self.model, "host": self.host}


def get_backend(name: str, model: Optional[str] = None) -> LLMBackend:
    backends = {
        "deepseek":  DeepSeekBackend,
        "openai":    OpenAIBackend,
        "anthropic": AnthropicBackend,
        "ollama":    OllamaBackend,
    }
    cls = backends.get(name)
    if cls is None:
        raise ValueError(f"Unknown backend '{name}'. Choose: {list(backends)}")
    return cls(model=model)


# ---------------------------------------------------------------------------
# 4. Response parser & validator
# ---------------------------------------------------------------------------

def _strip_markdown_fencing(text: str) -> str:
    """Remove ```json ... ``` wrappers if the model added them despite instructions."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # drop first line (```json or ```) and last line (```)
        inner = lines[1:] if lines[-1].strip() == "```" else lines[1:]
        text = "\n".join(inner).rstrip("`").strip()
    return text


_REQUIRED_KEYS = {
    "target", "injection_detected", "profile",
    "risk_score", "risk_features", "executive_summary",
}

_REQUIRED_PROFILE_KEYS = {
    "identity", "geo_temporal",
    "technical_stack", "opsec_posture",
}

_REQUIRED_OCEAN_KEYS = {
    "openness", "conscientiousness", "extraversion",
    "agreeableness", "neuroticism", "rationale",
}


def parse_and_validate(raw_text: str, target: str) -> Dict[str, Any]:
    """
    Parse LLM output into a dict and validate required schema keys.
    Raises ValueError with a descriptive message on failure.
    """
    cleaned = _strip_markdown_fencing(raw_text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        # Try to salvage: find first '{' and last '}'
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start != -1 and end > start:
            try:
                data = json.loads(cleaned[start:end])
            except json.JSONDecodeError:
                raise ValueError(f"LLM returned non-JSON output: {exc}\n\nRaw:\n{raw_text[:500]}")
        else:
            raise ValueError(f"LLM returned non-JSON output: {exc}\n\nRaw:\n{raw_text[:500]}")

    missing_root = _REQUIRED_KEYS - set(data.keys())
    if missing_root:
        raise ValueError(f"Dossier missing required keys: {missing_root}")

    profile = data.get("profile", {})
    missing_profile = _REQUIRED_PROFILE_KEYS - set(profile.keys())
    if missing_profile:
        raise ValueError(f"profile missing required keys: {missing_profile}")

    # Legacy experimental OCEAN content may be parsed for backwards
    # compatibility, but it is not required for an operational dossier.
    if "ocean_psychology" in profile:
        ocean = profile["ocean_psychology"]
        missing_ocean = _REQUIRED_OCEAN_KEYS - set(ocean.keys())
        if missing_ocean:
            raise ValueError(f"ocean_psychology missing required keys: {missing_ocean}")

    score = data.get("risk_score")
    if not isinstance(score, (int, float)) or not (0 <= score <= 100):
        raise ValueError(f"risk_score must be 0-100, got: {score!r}")

    if not isinstance(data.get("risk_features"), list) or not data["risk_features"]:
        raise ValueError("risk_features must be a non-empty list")

    # Normalise: ensure target matches what we passed in
    data["target"] = target

    return data


# ---------------------------------------------------------------------------
# 5. Post-processing: add metadata, derive risk_level
# ---------------------------------------------------------------------------

def _risk_level(score: int) -> str:
    if score < 25:  return "LOW"
    if score < 50:  return "MEDIUM"
    if score < 75:  return "HIGH"
    return "CRITICAL"


def enrich_dossier(
    data: Dict[str, Any],
    scan: Dict[str, Any],
    backend: LLMBackend,
    prompt_version: str,
    run_start: float,
    injection_detected: bool,
    injection_detail: Optional[str],
) -> Dict[str, Any]:
    """Add metadata fields that the LLM doesn't produce.

    CRITICAL: Re-scores using DeterministicScorer to override any LLM-generated
    risk_score. The LLM extracts evidence and features; the deterministic engine
    is the sole authority for the final score.
    """
    data.setdefault("schema_version", "1.0")
    data["scan_date"] = scan.get("scan_date", "unknown")
    data["profiled_at"] = datetime.now(timezone.utc).isoformat()
    data["processing_time_seconds"] = round(time.time() - run_start, 2)

    # Merge injection detection: LLM may have set this too; OR with our pre-check
    data["injection_detected"] = data.get("injection_detected", False) or injection_detected
    if injection_detail and not data.get("injection_details"):
        data["injection_details"] = injection_detail

    # If injection was detected server-side, add it as a risk feature if LLM missed it
    if injection_detected:
        existing_features = {f["feature"] for f in data.get("risk_features", [])}
        if "injection_attempt_detected" not in existing_features:
            data["risk_features"].append({
                "feature": "injection_attempt_detected",
                "value": 1,
                "weight": DEFAULT_WEIGHTS.get("injection_attempt_detected", 15.0),
                "plain_language": "Prompt-injection pattern detected in scan data — adversary may be attempting to manipulate analysis.",
            })

    # ── DETERMINISTIC RE-SCORING ──
    # Override the LLM's risk_score with the deterministic scorer output.
    # The LLM extracts features; the scorer calculates the score.
    is_dry_run = backend.name == "dry_run"
    score_mode = "STUB" if is_dry_run else "REAL"
    scoring = _default_scorer.score(data.get("risk_features", []), score_mode=score_mode)

    data["risk_score"] = scoring.risk_score
    data["risk_level"] = scoring.risk_level
    data["score_mode"] = scoring.score_mode
    data["scoring_metadata"] = scoring.to_dict()

    # Update risk_features with normalized values and contribution points
    updated_features = []
    for c in scoring.contributions:
        # Find the original feature dict to preserve plain_language from LLM
        original = next(
            (f for f in data.get("risk_features", [])
             if isinstance(f, dict) and f.get("feature") == c.feature),
            {},
        )
        updated_features.append({
            "feature": c.feature,
            "value": c.raw_value,
            "weight": c.weight,
            "normalized_value": round(c.normalized_value, 6),
            "contribution_points": round(c.contribution_points, 4),
            "plain_language": original.get("plain_language", c.plain_language),
        })
    data["risk_features"] = updated_features

    data["model_metadata"] = {
        **backend.metadata(),
        "prompt_version": prompt_version,
        "run_timestamp": data["profiled_at"],
    }

    # Ensure insufficient_data_flags exists
    data.setdefault("insufficient_data_flags", [])

    return data


# ---------------------------------------------------------------------------
# 6. Main profile function
# ---------------------------------------------------------------------------

def profile(
    raw_scan_path: str | Path,
    output_path: str | Path,
    backend_name: str = "ollama",
    model: Optional[str] = None,
    prompt_version: str = "v2",
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Full OSIRIS-Mind pipeline for one target.
    Returns the dossier dict (also written to output_path).
    """
    run_start = time.time()

    # ── Load raw scan
    raw_scan_path = Path(raw_scan_path)
    log.info("Loading raw scan: %s", raw_scan_path)
    scan = json.loads(raw_scan_path.read_text(encoding="utf-8"))
    target = scan.get("target", "unknown")

    # ── Injection pre-check
    clean_scan, injected, injection_detail = sanitise_input(scan)
    if injected:
        log.warning("⚠  Injection pattern detected in input for target '%s': %s", target, injection_detail)

    # ── Load prompt
    system_prompt = load_prompt(prompt_version)
    log.info("Using prompt version: %s", prompt_version)

    # ── Build user message
    user_message = (
        "Analyse this OSINT scan data and return a dossier JSON "
        "matching your system prompt schema:\n\n"
        + json.dumps(clean_scan, indent=2, default=str)
    )

    if dry_run:
        log.info("DRY RUN — skipping LLM call. Returning stub dossier.")
        backend = type("StubBackend", (LLMBackend,), {
            "name": "dry_run",
            "metadata": lambda self: {"backend": "dry_run"},
        })()
        dossier = _stub_dossier(target, scan)
        dossier = enrich_dossier(
            dossier, scan, backend, prompt_version,
            run_start, injected, injection_detail,
        )
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(dossier, indent=2, default=str), encoding="utf-8")
        log.info("✓ Stub dossier written → %s", output_path)
        return dossier
    else:
        # ── LLM call
        backend = get_backend(backend_name, model)
        log.info("Calling LLM backend: %s", backend_name)
        raw_response = backend.call(system_prompt, user_message)
        log.info("LLM responded (%d chars)", len(raw_response))

        # ── Parse & validate
        try:
            dossier = parse_and_validate(raw_response, target)
        except ValueError as exc:
            log.error("Validation failed: %s", exc)
            log.error("Raw LLM output:\n%s", raw_response[:1000])
            raise

        # ── Enrich
        dossier = enrich_dossier(
            dossier, scan, backend, prompt_version,
            run_start, injected, injection_detail,
        )

        # ── Write output
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(dossier, indent=2, default=str), encoding="utf-8")
        log.info(
            "✓ Dossier written → %s  [risk_score=%d, level=%s, time=%.1fs]",
            output_path,
            dossier.get("risk_score", -1),
            dossier.get("risk_level", "?"),
            time.time() - run_start,
        )
        return dossier


# ---------------------------------------------------------------------------
# 7. Stub dossier (dry-run / fallback)
# ---------------------------------------------------------------------------

def _stub_dossier(target: str, scan: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a structurally valid dossier without calling an LLM — for testing.

    Uses the DeterministicScorer to compute risk_score from features,
    ensuring the stub score is exactly reconstructable from its contributions.
    """
    entity_count = len(scan.get("entities", []))
    risk_features = [
        {
            "feature": "entity_count",
            "value": entity_count,
            "weight": DEFAULT_WEIGHTS.get("entity_count", 2.0),
            "plain_language": f"Target has {entity_count} discovered entities.",
        }
    ]

    # Score deterministically from features
    scoring = _default_scorer.score(risk_features, score_mode="STUB")

    return {
        "target": target,
        "schema_version": "1.0",
        "injection_detected": False,
        "injection_details": None,
        "profile": {
            "identity": f"Stub profile for {target}. {entity_count} entities found.",
            "geo_temporal": "Temporal analysis unavailable in stub mode.",
            "technical_stack": ["unknown"],
            "opsec_posture": "Unable to assess OpSec posture in stub mode.",
        },
        "risk_score": scoring.risk_score,
        "risk_level": scoring.risk_level,
        "score_mode": scoring.score_mode,
        "scoring_metadata": scoring.to_dict(),
        "risk_features": [
            {
                "feature": c.feature,
                "value": c.raw_value,
                "weight": c.weight,
                "normalized_value": round(c.normalized_value, 6),
                "contribution_points": round(c.contribution_points, 4),
                "plain_language": c.plain_language,
            }
            for c in scoring.contributions
        ],
        "insufficient_data_flags": [
            {
                "dimension": "all",
                "reason": "Stub mode — no LLM call made",
                "fallback_value": "0.5 / neutral",
            }
        ],
        "executive_summary": (
            f"This is a stub dossier for {target} generated without an LLM call. "
            "Run without --dry-run to produce a real assessment."
        ),
    }


# ---------------------------------------------------------------------------
# 8. Feature normalisation  (Person C suggestion — implemented Week 2)
#
# Problem: raw feature values span incompatible scales.
#   domain_age_days     → 0 .. ~30,000   (days since registration)
#   breach_appearance_count → 0 .. ~5
#   exposed_email_count → 0 .. ~5
#   subdomain_count     → 0 .. ~50+
#   binary flags        → 0 or 1
#
# Without normalisation, domain_age_days dominates the weighted sum by
# orders of magnitude, making the score uninterpretable and the XAI
# attribution meaningless (Person C's exact concern).
#
# Method: per-feature Min-Max normalisation using KNOWN DOMAIN BOUNDS.
# We prefer domain-knowledge bounds over data-driven z-score here because:
#   (a) we may have only one target per run — no population to fit
#   (b) the bounds are stable and explainable to investigators
#   (c) it keeps score_from_features fully deterministic and reproducible
#
# Formula: norm = clamp((value - min) / (max - min), 0, 1)
# The LLM still produces raw values in risk_features (for audit trail).
# Normalisation happens only inside score_from_features / extract_feature_vector.
# ---------------------------------------------------------------------------

# Each entry: feature_name → (min, max)
# Values outside [min, max] are clamped, not rejected.
FEATURE_BOUNDS: Dict[str, tuple[float, float]] = {
    # ── Positive-risk features (higher raw value = more risk)
    "breach_appearance_count":      (0.0,   5.0),
    "exposed_email_count":          (0.0,   5.0),
    "open_ports_sensitive":         (0.0,   5.0),
    "subdomain_count":              (0.0,  50.0),
    "unknown_registrar":            (0.0,   1.0),   # binary
    "recent_infrastructure_churn":  (0.0,   1.0),   # binary
    "aws_infrastructure":           (0.0,   1.0),   # binary
    "injection_attempt_detected":   (0.0,   1.0),   # binary
    "deliberate_test_target":       (0.0,   1.0),   # binary (negative weight)
    "entity_count":                 (0.0, 200.0),
    # ── Negative-risk features (higher raw value = lower risk)
    "domain_age_days":              (0.0, 30000.0), # ~82 years max
    "privacy_registrar_used":       (0.0,   1.0),   # binary
    "cloudflare_proxied":           (0.0,   1.0),   # binary
    "ipv6_enabled":                 (0.0,   1.0),   # binary
}

# Features not in the table pass through as-is (assumed already 0-1 or binary).
_BOUNDS_FALLBACK: tuple[float, float] = (0.0, 1.0)


# ---------------------------------------------------------------------------
# 8b. Deterministic Scoring Engine
#
# The single source of truth for risk_score computation.
# The LLM extracts evidence; this engine calculates the score.
# Invariant: intercept + sum(contribution_points) == risk_score (within ±0.01)
# ---------------------------------------------------------------------------

# Default signed weights — positive means "increases risk", negative means "mitigates".
DEFAULT_WEIGHTS: Dict[str, float] = {
    "breach_appearance_count":      12.0,
    "exposed_email_count":           8.0,
    "open_ports_sensitive":         10.0,
    "subdomain_count":               3.0,
    "unknown_registrar":             6.0,
    "recent_infrastructure_churn":   7.0,
    "aws_infrastructure":            2.0,
    "injection_attempt_detected":   15.0,
    "deliberate_test_target":       -8.0,
    "entity_count":                  2.0,
    "domain_age_days":              -5.0,
    "privacy_registrar_used":       -3.0,
    "cloudflare_proxied":           -4.0,
    "ipv6_enabled":                 -1.0,
}

DEFAULT_INTERCEPT: float = 15.0
SCORER_VERSION: str = "1.0.0"

# Minimum number of features required for a confident score.
MIN_EVIDENCE_FEATURES: int = 2


@dataclass
class FeatureContribution:
    """One feature's exact contribution to the risk score."""
    feature: str
    raw_value: float
    normalized_value: float
    weight: float
    contribution_points: float  # = normalized_value * weight
    plain_language: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "raw_value": self.raw_value,
            "normalized_value": round(self.normalized_value, 6),
            "weight": self.weight,
            "contribution_points": round(self.contribution_points, 4),
            "plain_language": self.plain_language,
        }


@dataclass
class ScoringResult:
    """Complete deterministic scoring output with full audit trail."""
    risk_score: int           # Final clamped integer score [0, 100]
    risk_score_raw: float     # Pre-clamp float
    risk_level: str
    intercept: float
    contributions: list       # List[FeatureContribution]
    scorer_version: str
    evidence_sufficiency: float  # 0.0–1.0, fraction of known features present
    score_mode: str           # "REAL" | "STUB" | "FALLBACK"
    abstain: bool             # True if evidence is insufficient

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_score_raw": round(self.risk_score_raw, 4),
            "risk_level": self.risk_level,
            "intercept": self.intercept,
            "scorer_version": self.scorer_version,
            "evidence_sufficiency": round(self.evidence_sufficiency, 4),
            "score_mode": self.score_mode,
            "abstain": self.abstain,
            "contributions": [c.to_dict() for c in self.contributions],
            "reconstruction_check": {
                "intercept": self.intercept,
                "sum_contributions": round(sum(c.contribution_points for c in self.contributions), 4),
                "total_raw": round(self.risk_score_raw, 4),
                "total_clamped": self.risk_score,
            },
        }


class DeterministicScorer:
    """
    Deterministic, versioned scoring engine.

    The LLM extracts structured evidence and risk_features.
    This engine is the SOLE AUTHORITY for calculating risk_score.
    No LLM may independently generate or override the final score.

    Invariant:
        intercept + sum(normalized_value * weight for each feature) == risk_score_raw
        risk_score = clamp(round(risk_score_raw), 0, 100)
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        intercept: float = DEFAULT_INTERCEPT,
    ):
        self.weights = weights or dict(DEFAULT_WEIGHTS)
        self.intercept = intercept
        self.version = SCORER_VERSION

    def score(
        self,
        risk_features: List[Dict[str, Any]],
        score_mode: str = "REAL",
    ) -> ScoringResult:
        """
        Calculate risk_score deterministically from risk_features.

        Each feature's contribution = normalise(raw_value) * weight.
        Total = intercept + sum(contributions).

        Returns ScoringResult with full audit trail.
        """
        contributions: list = []
        known_features_present = 0

        for feat in risk_features:
            if not isinstance(feat, dict):
                continue
            name = feat.get("feature", "")
            if str(name).lower().startswith(("ocean_", "ideology")):
                # Psychological and ideology dimensions are experimental only;
                # never silently allow them into the operational score.
                continue
            raw_val = feat.get("value", 0)
            try:
                raw_val = float(raw_val)
            except (TypeError, ValueError):
                raw_val = 0.0

            # Use the feature's own weight if present, else default
            weight = self.weights.get(name)
            if weight is None:
                feat_weight = feat.get("weight", 0)
                try:
                    weight = float(feat_weight)
                except (TypeError, ValueError):
                    weight = 0.0

            if name in self.weights:
                known_features_present += 1

            norm_val = normalise_value(name, raw_val)
            contribution_points = norm_val * weight
            plain = feat.get("plain_language", f"{name}={raw_val}")

            contributions.append(FeatureContribution(
                feature=name,
                raw_value=raw_val,
                normalized_value=norm_val,
                weight=weight,
                contribution_points=contribution_points,
                plain_language=plain,
            ))

        total_contribution = sum(c.contribution_points for c in contributions)
        risk_score_raw = self.intercept + total_contribution
        risk_score = max(0, min(100, round(risk_score_raw)))

        # Evidence sufficiency: what fraction of known scorable features are present
        total_known = len(self.weights)
        evidence_sufficiency = known_features_present / total_known if total_known > 0 else 0.0
        abstain = (known_features_present < MIN_EVIDENCE_FEATURES
                   and score_mode != "STUB")

        return ScoringResult(
            risk_score=risk_score,
            risk_score_raw=risk_score_raw,
            risk_level=_risk_level(risk_score),
            intercept=self.intercept,
            contributions=contributions,
            scorer_version=self.version,
            evidence_sufficiency=evidence_sufficiency,
            score_mode=score_mode,
            abstain=abstain,
        )


# Module-level default scorer instance
_default_scorer = DeterministicScorer()


def normalise_value(feature: str, raw_value: float) -> float:
    """
    Min-Max normalise a single feature value to [0, 1] using FEATURE_BOUNDS.
    Unknown features are clamped to [0, 1] using the fallback bounds.
    """
    lo, hi = FEATURE_BOUNDS.get(feature, _BOUNDS_FALLBACK)
    if hi == lo:
        return 0.0
    return max(0.0, min(1.0, (raw_value - lo) / (hi - lo)))


def normalise_feature_vector(raw_vector: Dict[str, float]) -> Dict[str, float]:
    """
    Return a new dict with every value normalised to [0, 1].
    This is the vector Person C passes to Explabox — each dimension is
    now on the same scale, so SHAP/LIME attributions are directly comparable.
    """
    return {feat: normalise_value(feat, val) for feat, val in raw_vector.items()}


# ---------------------------------------------------------------------------
# 9. Explabox integration helpers  (Week 3 — Person C interface)
# ---------------------------------------------------------------------------

def extract_feature_vector(dossier: Dict[str, Any]) -> Dict[str, float]:
    """
    Convert risk_features into a flat {feature_name: raw_value} dict.
    Raw values are preserved here for audit trail.
    Use normalise_feature_vector() on the result before passing to Explabox.
    """
    return {
        f["feature"]: float(f["value"]) if isinstance(f["value"], (int, float)) else 0.0
        for f in dossier.get("risk_features", [])
    }


def score_from_features(feature_vector: Dict[str, float], dossier: Dict[str, Any]) -> float:
    """
    Re-derive risk_score from a RAW feature_vector using DeterministicScorer.

    Delegates to the same deterministic engine used by enrich_dossier(),
    ensuring exact score reconstruction.

    Returns a float in [0, 100].
    """
    # Reconstruct risk_features list from feature_vector + dossier weights
    risk_features = []
    weight_map = {
        f["feature"]: f.get("weight", DEFAULT_WEIGHTS.get(f["feature"], 0))
        for f in dossier.get("risk_features", [])
        if isinstance(f, dict)
    }
    for feat_name, raw_val in feature_vector.items():
        weight = weight_map.get(feat_name, DEFAULT_WEIGHTS.get(feat_name, 0))
        risk_features.append({
            "feature": feat_name,
            "value": raw_val,
            "weight": weight,
        })

    result = _default_scorer.score(risk_features, score_mode="REAL")
    return float(result.risk_score)


def build_explabox_dataset(dossier_paths: List[str | Path]) -> List[Dict[str, Any]]:
    """
    Load multiple dossiers and build a list of feature-vector + label records
    for Explabox's dataset. Call this from Person C's explain_wrap.py.

    Each record contains both raw_features (for audit) and features (normalised,
    for Explabox — all values in [0, 1] on a comparable scale).

    Returns:
        [
          {
            "target": "...",
            "raw_features":  {"domain_age_days": 10023.0, ...},  # original values
            "features":      {"domain_age_days": 0.334, ...},    # normalised [0,1]
            "risk_score": 72,
            "risk_level": "HIGH",
          },
          ...
        ]
    """
    records = []
    for path in dossier_paths:
        dossier = json.loads(Path(path).read_text(encoding="utf-8"))
        raw = extract_feature_vector(dossier)
        records.append({
            "target":          dossier["target"],
            "raw_features":    raw,
            "features":        normalise_feature_vector(raw),
            "risk_score":      dossier["risk_score"],
            "risk_level":      dossier.get("risk_level", "UNKNOWN"),
            "executive_summary": dossier.get("executive_summary", ""),
        })
    return records


# ---------------------------------------------------------------------------
# 9. Executive summary helper  (Week 3 — Person A integration)
# ---------------------------------------------------------------------------

def get_report_summary_block(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a compact dict that Person A's report_build.py can inject
    directly into their Jinja2 template context.
    """
    return {
        "target": dossier["target"],
        "risk_score": dossier["risk_score"],
        "risk_level": dossier.get("risk_level", "UNKNOWN"),
        "executive_summary": dossier.get("executive_summary", ""),
        "top_features": dossier.get("risk_features", [])[:3],
        "technical_stack": dossier.get("profile", {}).get("technical_stack", []),
        "opsec_posture": dossier.get("profile", {}).get("opsec_posture", ""),
        "identity": dossier.get("profile", {}).get("identity", ""),
        "injection_detected": dossier.get("injection_detected", False),
        "profiled_at": dossier.get("profiled_at", ""),
        "model_metadata": dossier.get("model_metadata", {}),
        "insufficient_data_flags": dossier.get("insufficient_data_flags", []),
    }


# ---------------------------------------------------------------------------
# 10. CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="OSIRIS-Mind: AI profiling and risk scoring stage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--input",    "-i", help="Path to raw_scan.json (Contract 1 input)")
    p.add_argument("--output",   "-o", help="Path to write dossier.json (Contract 2 output)")
    p.add_argument("--backend",  "-b", default="ollama",
                   choices=["deepseek", "openai", "anthropic", "ollama"],
                   help="LLM backend to use (default: ollama)")
    p.add_argument("--model",    "-m", default=None,
                   help="Model name override (e.g. deepseek-chat, deepseek-reasoner, gpt-4o, llama3.2)")
    p.add_argument("--prompt",   "-p", default="v2",
                   choices=["v1", "v2"],
                   help="Prompt version to use (default: v2)")
    p.add_argument("--dry-run",  action="store_true",
                   help="Skip LLM call; produce a stub dossier for testing")
    p.add_argument("--regression", action="store_true",
                   help="Run regression test suite against sample inputs")
    return p


def _run_regression():
    """
    Run all sample JSON files through the pipeline in dry-run mode
    and report score variance (real regression requires backend creds).
    """
    samples_dir = _HERE.parent / "schemas" / "samples"
    sample_files = list(samples_dir.glob("*.json"))
    if not sample_files:
        log.warning("No sample files found in %s", samples_dir)
        return

    log.info("Running regression on %d sample files…", len(sample_files))
    results = []
    for f in sample_files:
        try:
            scan = json.loads(f.read_text())
            stub = _stub_dossier(scan.get("target", f.stem), scan)
            results.append({
                "file": f.name,
                "target": stub["target"],
                "risk_score": stub["risk_score"],
                "entities": len(scan.get("entities", [])),
            })
        except Exception as exc:
            log.error("FAIL %s: %s", f.name, exc)
            results.append({"file": f.name, "error": str(exc)})

    log.info("Regression results:")
    for r in results:
        if "error" in r:
            log.error("  %-35s  ERROR: %s", r["file"], r["error"])
        else:
            log.info(
                "  %-35s  target=%-30s  score=%3d  entities=%d",
                r["file"], r["target"], r["risk_score"], r["entities"],
            )


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.regression:
        _run_regression()
        sys.exit(0)

    if not args.input:
        parser.error("--input is required (unless using --regression)")
    if not args.output:
        parser.error("--output is required (unless using --regression)")

    try:
        profile(
            raw_scan_path=args.input,
            output_path=args.output,
            backend_name=args.backend,
            model=args.model,
            prompt_version=args.prompt,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        log.error("Fatal error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
