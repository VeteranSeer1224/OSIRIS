"""
OSIRIS — Shared Pipeline Schema Models
Contract 1: RawScan       (Person A produces → Person B consumes)
Contract 2: Dossier       (Person B produces → Person C consumes)
Contract 3: ExplanationCards  (Person C produces → Person A consumes)

DO NOT change field names or remove fields unilaterally.
Open a PR and discuss as a team.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Contract 1 — raw_scan.json  (output of OSIRIS-Sense)
# ---------------------------------------------------------------------------

class EntityType(str, Enum):
    IP          = "ip"
    DOMAIN      = "domain"
    SUBDOMAIN   = "subdomain"
    EMAIL       = "email"
    SOCIAL      = "social_profile"
    USERNAME    = "username"
    URL         = "url"
    PHONE       = "phone"
    ADDRESS     = "address"
    LOCATION    = "location"
    PERSON      = "person"
    ORG         = "org"
    ORGANIZATION = "organization"
    ASN         = "asn"
    CERTIFICATE = "certificate"
    TECHNOLOGY  = "technology"
    DNS_RECORD  = "dns_record"
    CRYPTO_WALLET = "crypto_wallet"
    HASH        = "hash"
    VULN        = "vulnerability"
    UNKNOWN     = "unknown"


class EventType(str, Enum):
    DOMAIN_REGISTERED  = "domain_registered"
    BREACH_APPEARANCE  = "breach_appearance"
    DNS_CHANGE         = "dns_change"
    CERT_ISSUED        = "certificate_issued"
    SOCIAL_POST        = "social_post"
    WHOIS_UPDATE       = "whois_update"


class RawEntity(BaseModel):
    type: EntityType
    value: str
    source_module: Optional[str] = None     # e.g. "sfp_dns"
    source: Optional[str] = None            # e.g. "SpiderFoot"
    platform: Optional[str] = None          # e.g. "github" for social_profile
    metadata: Optional[Dict[str, Any]] = None
    evidence_id: Optional[str] = None
    evidence_sources: Optional[List[Dict[str, Any]]] = None


class RawEvent(BaseModel):
    date: str                                # ISO 8601 date or datetime string
    type: EventType
    entity: str
    source: Optional[str] = None            # e.g. "haveibeenpwned"
    detail: Optional[str] = None


class RawScan(BaseModel):
    target: str
    scan_date: datetime
    entities: List[RawEntity]
    events: List[RawEvent]
    raw_module_output: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Untouched SpiderFoot export kept for audit trail"
    )

    @field_validator("entities")
    @classmethod
    def at_least_one_entity(cls, v):
        if not v:
            raise ValueError("entities list must not be empty")
        return v


# ---------------------------------------------------------------------------
# Contract 2 — dossier.json  (output of OSIRIS-Mind)
# ---------------------------------------------------------------------------

class OceanProfile(BaseModel):
    openness: float = Field(..., ge=0.0, le=1.0)
    conscientiousness: float = Field(..., ge=0.0, le=1.0)
    extraversion: float = Field(..., ge=0.0, le=1.0)
    agreeableness: float = Field(..., ge=0.0, le=1.0)
    neuroticism: float = Field(..., ge=0.0, le=1.0)
    rationale: str          # plain-English explanation of these scores


class RiskFeature(BaseModel):
    feature: str            # machine-readable name, e.g. "breach_appearance_count"
    value: Union[float, int, str]
    weight: float           # signed contribution to final risk score
    plain_language: str     # human-readable description for XAI card
    normalized_value: Optional[float] = None
    contribution_points: Optional[float] = None


class ModelMetadata(BaseModel):
    model_name: str
    prompt_version: str
    temperature: Optional[float] = None
    run_timestamp: Optional[datetime] = None
    backend: Optional[str] = None           # "openai_api" | "ollama_local"


class InsufficientDataFlag(BaseModel):
    dimension: str
    reason: str
    fallback_value: Any


class DimensionProfile(BaseModel):
    """Six-dimension cognitive profile for a target entity."""
    identity: str
    geo_temporal: str
    # Experimental-only legacy fields. They are intentionally not required by
    # the operational schema and are never valid scoring inputs by default.
    ocean_psychology: Optional[OceanProfile] = None
    technical_stack: List[str]
    ideology: Optional[str] = None
    opsec_posture: str


class Dossier(BaseModel):
    target: str
    scan_date: datetime                     # inherited from upstream RawScan
    profiled_at: datetime
    profile: DimensionProfile
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str | None = None                      # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score_mode: Optional[str] = None                   # "REAL" | "STUB" | "FALLBACK"
    scoring_metadata: Optional[Dict[str, Any]] = None
    processing_time_seconds: Optional[float] = None
    injection_detected: bool = False
    injection_details: Optional[str] = None
    risk_features: List[RiskFeature]
    insufficient_data_flags: List[InsufficientDataFlag] = Field(default_factory=list)
    executive_summary: str                  # 2-3 sentence plain-language summary for Person A
    model_metadata: ModelMetadata
    schema_version: str = "1.0"

    @model_validator(mode="after")
    def derive_risk_level(self):
        if self.risk_score < 25:
            self.risk_level = "LOW"
        elif self.risk_score < 50:
            self.risk_level = "MEDIUM"
        elif self.risk_score < 75:
            self.risk_level = "HIGH"
        else:
            self.risk_level = "CRITICAL"
        return self


# ---------------------------------------------------------------------------
# Contract 3 — explanation_cards.json  (output of OSIRIS-Conscience)
# ---------------------------------------------------------------------------

class ExplanationFeature(BaseModel):
    feature: str
    contribution: str
    plain_language: str


class FairnessCheck(BaseModel):
    passed: bool
    flagged: bool = False
    notes: List[str] = Field(default_factory=list)
    max_score_delta: float = 0
    avg_score_delta: float = 0
    threshold: float = 10
    evaluated_variants: int = 0


class RobustnessCheck(BaseModel):
    passed: bool
    notes: List[str] = Field(default_factory=list)
    max_score_delta: float = 0
    avg_score_delta: float = 0
    threshold: float = 10
    decision_flipped: bool = False
    feature_stability: float = 1.0
    evaluated_variants: int = 0


class ExplanationCard(BaseModel):
    entity_id: str
    entity: str
    timestamp: str
    risk_score: int = Field(..., ge=0, le=100)
    top_features: List[ExplanationFeature]
    supporting_evidence: List[str]
    contradicting_evidence: List[str]
    explanation: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    fairness_check: FairnessCheck
    robustness_check: RobustnessCheck


class ExplanationCards(BaseModel):
    schema_version: str = "1.0"
    generated_at: str
    target: Optional[str] = None
    targets: List[str] = Field(default_factory=list)
    card_count: int = Field(..., ge=1)
    cards: List[ExplanationCard]
