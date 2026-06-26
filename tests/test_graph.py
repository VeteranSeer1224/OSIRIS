"""Regression tests for OSIRIS-Web Stage 3 graph construction."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import graph_build  # noqa: E402


@pytest.fixture()
def sample_raw_scan() -> Dict[str, Any]:
    path = REPO_ROOT / "schemas" / "samples" / "sample_raw_scan.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture()
def output_path(tmp_path: Path) -> Path:
    return tmp_path / "graph.html"


def test_build_graph_sample_counts(sample_raw_scan: Dict[str, Any]) -> None:
    graph, timeline = graph_build.build_graph(sample_raw_scan)

    assert graph.number_of_nodes() == 8
    assert graph.number_of_edges() == 9
    assert len(timeline) == 2
    assert timeline[0]["date"] == "2010-01-01"
    assert timeline[1]["date"] == "2022-05-14"


def test_graph_relationships_are_inferred(sample_raw_scan: Dict[str, Any]) -> None:
    graph, _ = graph_build.build_graph(sample_raw_scan)
    relations = {(u, v, data.get("relation")) for u, v, data in graph.edges(data=True)}

    expected_relations = {
        ("target", "domain:example.com", "observed"),
        ("target", "email:admin@example.com", "observed"),
        ("target", "ip:93.184.216.34", "resolved_for"),
        ("domain:example.com", "subdomain:mail.example.com", "belongs_to"),
        ("domain:example.com", "email:admin@example.com", "uses_domain"),
        ("email:admin@example.com", "event:1:breach_appearance:2022-05-14", "breach_appearance"),
    }

    assert expected_relations.issubset(relations)


def test_duplicate_entities_do_not_create_duplicate_nodes() -> None:
    scan = {
        "target": "example.com",
        "entities": [
            {"type": "domain", "value": "example.com"},
            {"type": "domain", "value": "example.com"},
            {"type": "email", "value": "admin@example.com"},
            {"type": "email", "value": "admin@example.com"},
        ],
        "events": [],
    }

    graph, _ = graph_build.build_graph(scan)

    assert graph.number_of_nodes() == 3  # target + one domain + one email
    assert len([n for n in graph.nodes if n.startswith("domain:")]) == 1
    assert len([n for n in graph.nodes if n.startswith("email:")]) == 1


def test_empty_input_is_handled_gracefully() -> None:
    scan = {"target": "empty.example", "entities": [], "events": []}

    graph, timeline = graph_build.build_graph(scan)

    assert graph.number_of_nodes() == 1
    assert graph.number_of_edges() == 0
    assert timeline == []


def test_render_graph_writes_html(sample_raw_scan: Dict[str, Any], output_path: Path) -> None:
    graph, timeline = graph_build.build_graph(sample_raw_scan)

    graph_build.render_graph(graph, timeline, output_path, "Test Graph")

    assert output_path.exists()
    html = output_path.read_text(encoding="utf-8")
    assert "Test Graph" in html
    assert "raw_scan.json" in html or "vis-network" in html


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
