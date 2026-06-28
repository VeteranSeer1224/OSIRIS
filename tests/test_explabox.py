"""Regression tests for OSIRIS Stage 4 explainability and card generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from explabox_wrapper import ExplaboxWrapper  # noqa: E402
import explanation_card_build  # noqa: E402


@pytest.fixture()
def sample_dossier() -> Dict[str, Any]:
    path = REPO_ROOT / "schemas" / "samples" / "sample_dossier.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture()
def sample_dossier_path(tmp_path: Path, sample_dossier: Dict[str, Any]) -> Path:
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(sample_dossier, indent=2), encoding="utf-8")
    return path


def test_wrapper_initialize_and_analyze_structure(sample_dossier: Dict[str, Any]) -> None:
    wrapper = ExplaboxWrapper()

    init_result = wrapper.initialize()
    analysis = wrapper.analyze(sample_dossier, cohort=[sample_dossier])

    assert init_result["initialized"] is True
    assert set(analysis.keys()) == {"initialize", "explore", "examine", "explain", "expose"}
    assert analysis["explain"]["target"] == sample_dossier["target"]


def test_explanation_generation_returns_features(sample_dossier: Dict[str, Any]) -> None:
    wrapper = ExplaboxWrapper()
    explanation = wrapper.explain(sample_dossier)

    assert explanation["target"] == sample_dossier["target"]
    assert isinstance(explanation["prediction"], int)
    assert explanation["top_features"]
    first = explanation["top_features"][0]
    assert {"feature", "value", "weight", "plain_language"}.issubset(first.keys())


def test_fairness_and_robustness_evaluations_are_structured(sample_dossier: Dict[str, Any]) -> None:
    wrapper = ExplaboxWrapper()
    exposure = wrapper.expose([sample_dossier])

    assert "fairness" in exposure
    assert "robustness" in exposure
    assert isinstance(exposure["fairness"]["passed"], bool)
    assert isinstance(exposure["robustness"]["passed"], bool)
    assert "notes" in exposure["fairness"]
    assert "notes" in exposure["robustness"]


def test_schema_validation_rejects_incomplete_dossier(sample_dossier: Dict[str, Any]) -> None:
    broken = dict(sample_dossier)
    broken.pop("risk_features", None)

    wrapper = ExplaboxWrapper()

    with pytest.raises(ValueError, match="missing required fields"):
        wrapper.analyze(broken)


def test_build_artifacts_writes_all_outputs(tmp_path: Path, sample_dossier_path: Path, sample_dossier: Dict[str, Any]) -> None:
    output_dir = tmp_path / "outputs"
    config = explanation_card_build.BuildConfig(
        input_path=sample_dossier_path,
        output_dir=output_dir,
        risk_threshold=70,
        max_top_features=5,
    )

    artifacts = explanation_card_build.build_artifacts(config)
    written = explanation_card_build.write_outputs(artifacts, output_dir)

    assert written["explanation_cards"].exists()
    assert written["fairness_report"].exists()
    assert written["robustness_report"].exists()

    cards = json.loads(written["explanation_cards"].read_text(encoding="utf-8"))
    assert cards["schema_version"] == "1.0"
    assert cards["card_count"] == 1
    assert cards["cards"][0]["entity"] == sample_dossier["target"]
    assert cards["cards"][0]["risk_score"] == sample_dossier["risk_score"]
    assert cards["cards"][0]["top_features"]

    fairness_md = written["fairness_report"].read_text(encoding="utf-8")
    robustness_md = written["robustness_report"].read_text(encoding="utf-8")
    assert fairness_md.startswith("# OSIRIS Fairness Report")
    assert robustness_md.startswith("# OSIRIS Robustness Report")


def test_build_artifacts_handles_input_missing_optional_fields(tmp_path: Path) -> None:
    dossier = {
        "target": "example.org",
        "risk_score": 19,
        "risk_features": [{"feature": "domain_age_days", "value": 1000, "weight": -0.2}],
    }
    input_path = tmp_path / "dossier.json"
    input_path.write_text(json.dumps(dossier), encoding="utf-8")

    config = explanation_card_build.BuildConfig(input_path=input_path, output_dir=tmp_path / "outputs")
    artifacts = explanation_card_build.build_artifacts(config)

    assert artifacts.explanation_cards["cards"][0]["entity"] == "example.org"
    assert artifacts.explanation_cards["cards"][0]["risk_score"] == 19


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
