"""Versioned, fail-closed case authorization for collection operations."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator


class CollectionMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class CaseStatus(str, Enum):
    APPROVED = "APPROVED"
    DRAFT = "DRAFT"
    SUSPENDED = "SUSPENDED"
    CLOSED = "CLOSED"


class AuthorizationError(ValueError):
    """Raised when collection is outside the approved case scope."""


class CaseAuthorization(BaseModel):
    schema_version: str = "1.0"
    case_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    purpose: str = Field(min_length=1)
    jurisdiction: str = Field(min_length=2)
    created_at: datetime
    created_by: str = Field(min_length=1)
    authorization_reference: str = Field(min_length=1)
    authorization_document_hash: str = Field(pattern=r"^sha256:[0-9a-fA-F]{64}$")
    allowed_collection_modes: list[CollectionMode] = Field(min_length=1)
    active_scanning_authorized: bool = False
    authorized_targets: list[str] = Field(min_length=1)
    excluded_targets: list[str] = Field(default_factory=list)
    valid_from: datetime
    expires_at: datetime
    data_retention_policy: str = Field(min_length=1)
    handling_marking: str = Field(min_length=1)
    approvers: list[str] = Field(default_factory=list)
    status: CaseStatus

    @field_validator("authorized_targets", "excluded_targets")
    @classmethod
    def normalize_targets(cls, targets: list[str]) -> list[str]:
        normalized = [target.strip().lower().rstrip(".") for target in targets if target.strip()]
        if not normalized and targets:
            raise ValueError("targets must contain non-empty values")
        return normalized

    @model_validator(mode="after")
    def validate_active_authorization(self) -> "CaseAuthorization":
        if self.expires_at <= self.valid_from:
            raise ValueError("expires_at must be later than valid_from")
        if self.active_scanning_authorized and CollectionMode.ACTIVE not in self.allowed_collection_modes:
            raise ValueError("active scanning requires active in allowed_collection_modes")
        return self


def load_case_authorization(path: str | Path) -> CaseAuthorization:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthorizationError(f"unable to load case authorization: {exc}") from exc
    try:
        return CaseAuthorization.model_validate(data)
    except Exception as exc:
        raise AuthorizationError(f"invalid case authorization: {exc}") from exc


def _target_matches(target: str, scope: str) -> bool:
    return target == scope or target.endswith("." + scope)


def validate_collection(
    authorization: CaseAuthorization,
    target: str,
    mode: CollectionMode,
    *,
    now: datetime | None = None,
) -> None:
    """Fail closed unless a target and collection mode are explicitly approved."""
    current = now or datetime.now(timezone.utc)
    if authorization.status is not CaseStatus.APPROVED:
        raise AuthorizationError("case status is not APPROVED")
    if current < authorization.valid_from or current >= authorization.expires_at:
        raise AuthorizationError("case authorization is outside its validity period")
    normalized_target = target.strip().lower().rstrip(".")
    if not normalized_target:
        raise AuthorizationError("target is empty")
    if any(_target_matches(normalized_target, blocked) for blocked in authorization.excluded_targets):
        raise AuthorizationError("target is explicitly excluded from authorization")
    if not any(_target_matches(normalized_target, allowed) for allowed in authorization.authorized_targets):
        raise AuthorizationError("target is outside authorized scope")
    if mode not in authorization.allowed_collection_modes:
        raise AuthorizationError(f"{mode.value} collection is not authorized")
    if mode is CollectionMode.ACTIVE and not authorization.active_scanning_authorized:
        raise AuthorizationError("active collection requires explicit active_scanning_authorized=true")
