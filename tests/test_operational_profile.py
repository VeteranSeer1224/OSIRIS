from mind.mind_profile import DeterministicScorer, _stub_dossier
from schemas.models import Dossier


def test_default_stub_omits_experimental_psychology_and_ideology():
    dossier = _stub_dossier("example.test", {"entities": []})
    assert "ocean_psychology" not in dossier["profile"]
    assert "ideology" not in dossier["profile"]


def test_operational_scorer_ignores_experimental_feature_names():
    result = DeterministicScorer().score([
        {"feature": "ocean_neuroticism", "value": 1, "weight": 100},
        {"feature": "ideology_alignment", "value": 1, "weight": 100},
    ])
    assert result.contributions == []
