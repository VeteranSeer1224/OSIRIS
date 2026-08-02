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
    OPENROUTER_API_KEY  — required for backend=openrouter
    OPENROUTER_MODEL    — optional; defaults to openai/gpt-oss-120b
    DEEPSEEK_API_KEY    — required for backend=deepseek
    OPENAI_API_KEY      — required for backend=openai
    ANTHROPIC_API_KEY   — required for backend=anthropic
    OLLAMA_HOST         — defaults to http://localhost:11434
    OLLAMA_MODEL        — defaults to llama3.2
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, cast
from dataclasses import dataclass
from artifact_io import atomic_write_json

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


def _load_project_dotenv() -> None:
    """Load repository-local .env values without overriding the process environment.

    This intentionally supports only simple KEY=VALUE entries, which is enough for
    API-key configuration without adding a runtime dependency. A shell-provided
    environment variable always takes precedence over a value in .env.
    """
    dotenv_path = _HERE.parent / ".env"
    if not dotenv_path.is_file():
        return

    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)


_load_project_dotenv()

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
        return {"backend": self.name, "model_name": "unknown"}


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
        return response.choices[0].message.content or ""

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model_name": self.model, "model": self.model, "base_url": self.BASE_URL}


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
        return str(response.content[0].text)

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model_name": self.model, "model": self.model}


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
        return response.choices[0].message.content or ""

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model_name": self.model, "model": self.model}


class OpenRouterBackend(LLMBackend):
    """Uses OpenRouter's OpenAI-compatible API for routed model access."""

    name = "openrouter_api"
    BASE_URL = "https://openrouter.ai/api/v1"
    DEFAULT_MODEL = "openai/gpt-oss-120b"

    def __init__(self, model: Optional[str] = None):
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ImportError(
                "OpenRouter backend requires the OpenAI SDK.\n"
                "Install with:\n"
                "pip install openai"
            ) from exc

        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "OPENROUTER_API_KEY not set. Add it to .env or your environment."
            )
        self.client = OpenAI(api_key=api_key, base_url=self.BASE_URL)
        self.model: str = model or os.getenv("OPENROUTER_MODEL") or self.DEFAULT_MODEL

    def call(self, system_prompt: str, user_message: str) -> str:
        # Not every OpenRouter model/provider supports OpenAI JSON mode. The
        # OSIRIS prompt and response validator still require a JSON dossier.
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,
            max_tokens=2048,
        )
        return response.choices[0].message.content or ""

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model_name": self.model, "model": self.model, "base_url": self.BASE_URL}


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
        return str(resp.json()["message"]["content"])

    def metadata(self) -> Dict[str, Any]:
        return {"backend": self.name, "model_name": self.model, "model": self.model, "host": self.host}


def get_backend(name: str, model: Optional[str] = None) -> LLMBackend:
    backends = {
        "deepseek":  DeepSeekBackend,
        "openai":    OpenAIBackend,
        "openrouter": OpenRouterBackend,
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


_REQUIRED_KEYS = {"target", "profile", "insufficient_data_flags", "executive_summary"}
_ALLOWED_MODEL_KEYS = set(_REQUIRED_KEYS)

_PROHIBITED_MODEL_KEYS = {
    "risk_score", "risk_level", "risk_features", "weights", "scoring_metadata",
    "ocean_psychology", "ideology",
}

_REQUIRED_PROFILE_KEYS = {
    "identity", "geo_temporal",
    "technical_stack", "opsec_posture",
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

    if not isinstance(data, dict):
        raise ValueError("LLM dossier root must be a JSON object")
    missing_root = _REQUIRED_KEYS - set(data.keys())
    if missing_root:
        raise ValueError(f"Dossier missing required keys: {missing_root}")

    prohibited_root = _PROHIBITED_MODEL_KEYS & set(data)
    if prohibited_root:
        raise ValueError(
            f"LLM response contains prohibited operational fields: {sorted(prohibited_root)}"
        )
    unexpected_root = set(data) - _ALLOWED_MODEL_KEYS
    if unexpected_root:
        raise ValueError(f"LLM response contains unexpected fields: {sorted(unexpected_root)}")
    profile = data.get("profile", {})
    if not isinstance(profile, dict):
        raise ValueError("profile must be a JSON object")
    missing_profile = _REQUIRED_PROFILE_KEYS - set(profile.keys())
    if missing_profile:
        raise ValueError(f"profile missing required keys: {missing_profile}")

    prohibited_profile = {"ocean_psychology", "ideology", "risk_score", "risk_features"} & set(profile)
    if prohibited_profile:
        raise ValueError(
            f"LLM profile contains prohibited fields: {sorted(prohibited_profile)}"
        )
    unexpected_profile = set(profile) - _REQUIRED_PROFILE_KEYS
    if unexpected_profile:
        raise ValueError(f"LLM profile contains unexpected fields: {sorted(unexpected_profile)}")
    if not isinstance(data.get("insufficient_data_flags"), list):
        raise ValueError("insufficient_data_flags must be a list")

    # Normalise: ensure target matches what we passed in
    data["target"] = target

    return data


MAX_LLM_ENTITIES = 200
MAX_LLM_EVENTS = 100
MAX_LLM_CONTEXT_BYTES = 100_000


def build_llm_context(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Build a bounded narrative context without raw SpiderFoot output."""
    entities = []
    for item in scan.get("entities", [])[:MAX_LLM_ENTITIES]:
        if not isinstance(item, dict):
            continue
        entities.append({
            "type": str(item.get("type", ""))[:64],
            "value": str(item.get("value", ""))[:500],
            "source_module": str(item.get("source_module", ""))[:128],
            "evidence_id": str(item.get("evidence_id", ""))[:128],
        })
    events = []
    for item in scan.get("events", [])[:MAX_LLM_EVENTS]:
        if not isinstance(item, dict):
            continue
        events.append({
            "type": str(item.get("type", ""))[:64],
            "entity": str(item.get("entity", ""))[:500],
            "observed_at": item.get("observed_at"),
            "source": str(item.get("source", ""))[:128],
        })
    context = {
        "target": str(scan.get("target", ""))[:500],
        "scan_date": scan.get("scan_date"),
        "entity_count": len(scan.get("entities", [])),
        "event_count": len(scan.get("events", [])),
        "entities_truncated": len(scan.get("entities", [])) > len(entities),
        "events_truncated": len(scan.get("events", [])) > len(events),
        "entities": entities,
        "events": events,
    }
    encoded = json.dumps(context, ensure_ascii=False, default=str).encode("utf-8")
    if len(encoded) > MAX_LLM_CONTEXT_BYTES:
        raise ValueError(
            f"bounded LLM context is {len(encoded)} bytes; maximum is {MAX_LLM_CONTEXT_BYTES}"
        )
    return context


def extract_deterministic_risk_features(
    scan: Dict[str, Any], *, injection_detected: bool = False
) -> List[Dict[str, Any]]:
    """Derive the complete operational feature vector from normalized evidence."""
    entities = [item for item in scan.get("entities", []) if isinstance(item, dict)]
    events = [item for item in scan.get("events", []) if isinstance(item, dict)]
    raw = scan.get("raw_module_output", {})
    records = raw.get("records", []) if isinstance(raw, dict) else []
    records = [item for item in records if isinstance(item, dict)]
    target = str(scan.get("target", "")).strip().lower().rstrip(".")

    values: Dict[str, tuple[float, str]] = {
        "entity_count": (
            float(len(entities)), f"Normalized evidence contains {len(entities)} unique entities."
        ),
    }
    breach_count = sum(1 for item in events if item.get("type") == "breach_appearance")
    if breach_count:
        values["breach_appearance_count"] = (
            float(breach_count), f"Evidence contains {breach_count} breach-appearance events."
        )
    email_count = sum(1 for item in entities if item.get("type") == "email")
    if email_count:
        values["exposed_email_count"] = (
            float(email_count), f"Evidence contains {email_count} unique email observations."
        )
    subdomain_count = sum(1 for item in entities if item.get("type") == "subdomain")
    if subdomain_count:
        values["subdomain_count"] = (
            float(subdomain_count), f"Evidence contains {subdomain_count} normalized subdomains."
        )
    ipv6 = any(
        item.get("type") == "ip" and ":" in str(item.get("value", "")) for item in entities
    )
    if ipv6:
        values["ipv6_enabled"] = (1.0, "At least one normalized IPv6 address was observed.")

    searchable = " ".join(
        str(item.get("data", ""))[:1000].lower() for item in records[:5_000]
    )
    if "cloudflare" in searchable:
        values["cloudflare_proxied"] = (1.0, "Cloudflare was explicitly observed in source records.")
    if "amazonaws.com" in searchable or "amazon web services" in searchable or re.search(r"\baws\b", searchable):
        values["aws_infrastructure"] = (1.0, "AWS infrastructure was explicitly observed in source records.")

    sensitive_ports = {21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379}
    observed_ports: set[int] = set()
    for item in records[:5_000]:
        record_type = str(item.get("type", "")).upper()
        if "PORT" not in record_type:
            continue
        for token in re.findall(r"\b\d{1,5}\b", str(item.get("data", ""))[:500]):
            port = int(token)
            if port in sensitive_ports:
                observed_ports.add(port)
    if observed_ports:
        values["open_ports_sensitive"] = (
            float(len(observed_ports)),
            f"Source records explicitly identify sensitive ports: {sorted(observed_ports)}.",
        )

    if target in {"scanme.nmap.org", "testphp.vulnweb.com"} or target.endswith(".example"):
        values["deliberate_test_target"] = (
            1.0, "Target matches the versioned deliberate-test target policy."
        )
    if injection_detected:
        values["injection_attempt_detected"] = (
            1.0, "Input sanitization detected an instruction-injection pattern."
        )

    return [
        {"feature": name, "value": value, "plain_language": plain}
        for name, (value, plain) in values.items()
    ]


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

    data["injection_detected"] = injection_detected
    data["injection_details"] = injection_detail
    deterministic_features = extract_deterministic_risk_features(
        scan, injection_detected=injection_detected
    )

    # ── DETERMINISTIC RE-SCORING ──
    # Override the LLM's risk_score with the deterministic scorer output.
    # The LLM extracts features; the scorer calculates the score.
    is_dry_run = backend.name == "dry_run"
    score_mode = "STUB" if is_dry_run else "REAL"
    scoring = _default_scorer.score(deterministic_features, score_mode=score_mode)

    data["risk_score"] = scoring.risk_score
    data["risk_level"] = scoring.risk_level
    data["score_mode"] = scoring.score_mode
    data["scoring_metadata"] = scoring.to_dict()

    # Update risk_features with normalized values and contribution points
    updated_features = []
    for c in scoring.contributions:
        # Find the original feature dict to preserve plain_language from LLM
        original = next(
            (f for f in deterministic_features
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

    model_metadata = backend.metadata()
    # `model_name` is the versioned typed-contract field. Accept the old
    # internal `model` spelling only while normalising legacy backend plugins.
    model_metadata["model_name"] = str(
        model_metadata.get("model_name") or model_metadata.pop("model", "unknown")
    )
    data["model_metadata"] = {
        **model_metadata,
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
    llm_context = build_llm_context(clean_scan)
    user_message = (
        "Analyse this OSINT scan data and return a dossier JSON "
        "matching your system prompt schema:\n\n"
        + json.dumps(llm_context, indent=2, default=str)
    )

    if dry_run:
        log.info("DRY RUN — skipping LLM call. Returning stub dossier.")
        backend = type("StubBackend", (LLMBackend,), {
            "name": "dry_run",
            "metadata": lambda self: {"backend": "dry_run", "model_name": "none"},
        })()
        dossier = _stub_dossier(target, scan)
        dossier = enrich_dossier(
            dossier, scan, backend, prompt_version,
            run_start, injected, injection_detail,
        )
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(output_path, dossier)
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
        atomic_write_json(output_path, dossier)
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
        if score_mode not in {"REAL", "STUB"}:
            raise ValueError("score_mode must be REAL or STUB")

        contributions: list = []
        known_features_present = 0
        seen_features: set[str] = set()

        for feat in risk_features:
            if not isinstance(feat, dict):
                raise ValueError("risk features must be objects")
            name = feat.get("feature")
            if not isinstance(name, str) or not name:
                raise ValueError("risk feature name must be a non-empty string")
            if name not in self.weights:
                raise ValueError(f"unsupported scoring feature: {name}")
            if name in seen_features:
                raise ValueError(f"duplicate scoring feature: {name}")
            seen_features.add(name)

            raw_val = feat.get("value")
            if isinstance(raw_val, bool):
                raise ValueError(f"scoring feature {name} must be numeric, not boolean")
            try:
                raw_val = float(cast(Any, raw_val))
            except (TypeError, ValueError):
                raise ValueError(f"scoring feature {name} must be numeric") from None
            if not math.isfinite(raw_val):
                raise ValueError(f"scoring feature {name} must be finite")

            # The versioned scorer registry, never the model payload, owns weights.
            weight = self.weights[name]
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
    Unknown features are rejected so a model cannot add an unreviewed score input.
    """
    if feature not in FEATURE_BOUNDS:
        raise ValueError(f"unsupported scoring feature: {feature}")
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
        raise ValueError(f"scoring feature {feature} must be numeric")
    if not math.isfinite(float(raw_value)):
        raise ValueError(f"scoring feature {feature} must be finite")
    lo, hi = FEATURE_BOUNDS[feature]
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
    features = dossier.get("risk_features", [])
    if not isinstance(features, list):
        raise ValueError("risk_features must be a list")
    result: Dict[str, float] = {}
    for feature in features:
        if not isinstance(feature, dict):
            raise ValueError("risk features must be objects")
        name = feature.get("feature")
        if not isinstance(name, str) or name not in DEFAULT_WEIGHTS:
            raise ValueError(f"unsupported scoring feature: {name}")
        if name in result:
            raise ValueError(f"duplicate scoring feature: {name}")
        value = feature.get("value")
        if isinstance(value, bool):
            raise ValueError(f"scoring feature {name} must be numeric, not boolean")
        try:
            numeric_value = float(cast(Any, value))
        except (TypeError, ValueError):
            raise ValueError(f"scoring feature {name} must be numeric") from None
        if not math.isfinite(numeric_value):
            raise ValueError(f"scoring feature {name} must be finite")
        result[name] = numeric_value
    return result


def score_from_features(feature_vector: Dict[str, float], dossier: Dict[str, Any]) -> float:
    """
    Re-derive risk_score from a RAW feature_vector using DeterministicScorer.

    Delegates to the same deterministic engine used by enrich_dossier(),
    ensuring exact score reconstruction.

    Returns a float in [0, 100].
    """
    # Reconstruct risk features from the vector. The scorer owns all weights;
    # model/dossier supplied weights are retained only as non-authoritative audit data.
    risk_features = []
    for feat_name, raw_val in feature_vector.items():
        risk_features.append({
            "feature": feat_name,
            "value": raw_val,
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
                   choices=["deepseek", "openai", "openrouter", "anthropic", "ollama"],
                   help="LLM backend to use (default: ollama)")
    p.add_argument("--model",    "-m", default=None,
                   help="Model name override (e.g. openai/gpt-oss-120b, deepseek-chat, gpt-4o, llama3.2)")
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
