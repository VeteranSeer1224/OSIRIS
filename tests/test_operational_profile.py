import pytest

from mind.mind_profile import DeterministicScorer, _stub_dossier
from schemas.models import Dossier


def test_default_stub_omits_experimental_psychology_and_ideology():
    dossier = _stub_dossier("example.test", {"entities": []})
    assert "ocean_psychology" not in dossier["profile"]
    assert "ideology" not in dossier["profile"]


def test_operational_scorer_rejects_experimental_feature_names():
    with pytest.raises(ValueError, match="unsupported scoring feature"):
        DeterministicScorer().score([
            {"feature": "ocean_neuroticism", "value": 1, "weight": 100},
        ])


def test_operational_scorer_rejects_model_weight_unknown_features_and_duplicates():
    scorer = DeterministicScorer()
    with pytest.raises(ValueError, match="unsupported scoring feature"):
        scorer.score([{"feature": "model_injected", "value": 1, "weight": 10_000}])
    with pytest.raises(ValueError, match="duplicate scoring feature"):
        scorer.score([
            {"feature": "breach_appearance_count", "value": 5},
            {"feature": "breach_appearance_count", "value": 5},
        ])


def test_operational_scorer_uses_registry_weight_not_model_weight():
    result = DeterministicScorer().score([
        {"feature": "breach_appearance_count", "value": 5, "weight": 10_000},
    ])
    assert result.contributions[0].weight == 12.0
    assert result.risk_score == 27


def test_operational_scorer_rejects_unknown_or_invalid_observations():
    scorer = DeterministicScorer()
    for value in ("UNKNOWN", None, float("nan"), True):
        with pytest.raises(ValueError):
            scorer.score([{"feature": "open_ports_sensitive", "value": value}])
