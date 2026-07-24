"""Stage 4 tests: attribution, fairness, robustness, schema, backend selection."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from explabox_wrapper import (  # noqa: E402
    ExplaboxWrapper,
    ExplaboxBackend,
    FallbackBackend,
    _fairness_check,
    _robustness_check,
)
import explanation_card_build  # noqa: E402
from schema_validation import validate_explanation_cards  # noqa: E402


@pytest.fixture()
def sample_dossier() -> Dict[str, Any]:
    path = REPO_ROOT / "schemas" / "samples" / "sample_dossier.json"
    dossier = cast(Dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    dossier.setdefault("risk_level", "HIGH")
    dossier.setdefault("insufficient_data_flags", [])
    dossier.setdefault("executive_summary", "Sample executive summary for example.com.")
    return dossier


def test_feature_attribution_shape(sample_dossier: Dict[str, Any]) -> None:
    wrapper = ExplaboxWrapper(backend=FallbackBackend())
    explanation = wrapper.explain(sample_dossier)

    required = {
        "risk_score",
        "prediction",
        "top_features",
        "positive_evidence",
        "negative_evidence",
        "confidence",
        "explanation",
    }
    assert required.issubset(explanation.keys())
    assert explanation["risk_score"] == explanation["prediction"]
    assert explanation["top_features"]
    assert isinstance(explanation["confidence"], float)
    assert sample_dossier["target"] in explanation["explanation"]


def test_feature_attribution_grounded_in_dossier(sample_dossier: Dict[str, Any]) -> None:
    wrapper = ExplaboxWrapper(backend=FallbackBackend())
    explanation = wrapper.explain(sample_dossier)

    for feat in explanation["top_features"]:
        assert feat["feature"] in {
            f["feature"] for f in sample_dossier["risk_features"]
        }


def test_fairness_perturbation_metrics(sample_dossier: Dict[str, Any]) -> None:
    result = _fairness_check([sample_dossier], threshold=10)

    assert "max_score_delta" in result
    assert "avg_score_delta" in result
    assert "flagged" in result
    assert result["evaluated_variants"] == 1
    assert result["outcome"] == "INCONCLUSIVE"
    assert result["passed"] is False
    assert isinstance(result["passed"], bool)


def test_fairness_flags_when_threshold_exceeded() -> None:
    dossier = {
        "target": "stable.example",
        "profile": {"identity": "test", "geo_temporal": "US"},
        "risk_score": 50,
        "risk_features": [
            {"feature": "entity_count", "value": 10, "weight": 0.5},
        ],
    }
    # Any non-negative delta exceeds a negative threshold.
    result = _fairness_check([dossier], threshold=-1)
    assert result["flagged"] is True
    assert result["passed"] is False


def test_robustness_structural_variants(sample_dossier: Dict[str, Any]) -> None:
    result = _robustness_check([sample_dossier], threshold=100)

    assert result["evaluated_variants"] > 0
    assert "feature_stability" in result
    assert "decision_flipped" in result
    assert any("missing_profile_fields" in note for note in result["notes"])
    assert result["counterfactual_influence"]
    assert all(
        item["test"] in {
            "counterfactual_evidence_deletion",
            "all_evidence_deletion",
            "zero_all_weights",
        }
        for item in result["counterfactual_influence"]
    )


def test_robustness_detects_feature_removal_delta() -> None:
    dossier = {
        "target": "test.example",
        "profile": {},
        "risk_score": 50,
        "risk_features": [
            {"feature": "breach_appearance_count", "value": 3, "weight": 0.8},
            {"feature": "entity_count", "value": 10, "weight": 0.1},
        ],
    }
    result = _robustness_check([dossier], threshold=100)
    assert result["max_score_delta"] >= 0
    assert result["feature_stability"] <= 1.0


def test_explanation_cards_json_schema(sample_dossier: Dict[str, Any], tmp_path: Path) -> None:
    input_path = tmp_path / "dossier.json"
    input_path.write_text(json.dumps(sample_dossier), encoding="utf-8")

    config = explanation_card_build.BuildConfig(
        input_path=input_path,
        output_dir=tmp_path / "out",
    )
    artifacts = explanation_card_build.build_artifacts(config)
    validate_explanation_cards(artifacts.explanation_cards)

    card = artifacts.explanation_cards["cards"][0]
    assert card["entity_id"] == "example.com"
    assert card["fairness_check"]["passed"] is not None
    assert card["robustness_check"]["passed"] is not None


def test_backend_selection_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USE_EXPLABOX_BACKEND", "0")
    wrapper = ExplaboxWrapper()
    assert wrapper.backend.name == "deterministic_fallback"


def test_backend_selection_explicit_fallback() -> None:
    wrapper = ExplaboxWrapper(backend=FallbackBackend())
    init = wrapper.initialize()
    assert init["backend"] == "deterministic_fallback"


def test_backend_selection_explabox_when_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("USE_EXPLABOX_BACKEND", raising=False)
    wrapper = ExplaboxWrapper(
        backend=ExplaboxBackend(predictor=None),
    )
    assert wrapper.backend.name == "explabox"


def test_build_artifacts_writes_json_reports(tmp_path: Path, sample_dossier: Dict[str, Any]) -> None:
    input_path = tmp_path / "d.json"
    input_path.write_text(json.dumps(sample_dossier), encoding="utf-8")
    out = tmp_path / "outputs"

    config = explanation_card_build.BuildConfig(input_path=input_path, output_dir=out)
    artifacts = explanation_card_build.build_artifacts(config)
    paths = explanation_card_build.write_outputs(artifacts, out)

    assert paths["fairness_report_json"].exists()
    assert paths["robustness_report_json"].exists()
    fairness = json.loads(paths["fairness_report_json"].read_text(encoding="utf-8"))
    assert fairness["schema_version"] == "1.0"
    assert fairness["card_count"] >= 1
