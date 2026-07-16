from datetime import datetime, timedelta, timezone

import pytest

from case_authorization import (
    AuthorizationError,
    CaseAuthorization,
    CollectionMode,
    validate_collection,
)


def _authorization(**overrides):
    now = datetime.now(timezone.utc)
    data = {
        "case_id": "CASE-2026-0001",
        "title": "Authorized test",
        "purpose": "offline fixture verification",
        "jurisdiction": "IN",
        "created_at": now.isoformat(),
        "created_by": "test-analyst",
        "authorization_reference": "AUTH-TEST",
        "authorization_document_hash": "sha256:" + "a" * 64,
        "allowed_collection_modes": ["passive"],
        "active_scanning_authorized": False,
        "authorized_targets": ["example.test"],
        "valid_from": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "data_retention_policy": "test-policy",
        "handling_marking": "TLP:CLEAR",
        "status": "APPROVED",
    }
    data.update(overrides)
    return CaseAuthorization.model_validate(data)


def test_passive_collection_requires_matching_approved_scope():
    authorization = _authorization()
    validate_collection(authorization, "api.example.test", CollectionMode.PASSIVE)
    with pytest.raises(AuthorizationError, match="outside authorized scope"):
        validate_collection(authorization, "outside.test", CollectionMode.PASSIVE)


def test_active_collection_is_denied_without_explicit_authorization():
    with pytest.raises(AuthorizationError, match="active collection"):
        validate_collection(_authorization(), "example.test", CollectionMode.ACTIVE)


def test_expired_authorization_is_denied():
    now = datetime.now(timezone.utc)
    authorization = _authorization(
        valid_from=(now - timedelta(days=2)).isoformat(),
        expires_at=(now - timedelta(days=1)).isoformat(),
    )
    with pytest.raises(AuthorizationError, match="validity period"):
        validate_collection(authorization, "example.test", CollectionMode.PASSIVE)
