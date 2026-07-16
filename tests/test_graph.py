"""Regression tests and unit tests for OSIRIS-Web Stage 3 graph construction and graph_utils."""

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
import graph_utils  # noqa: E402


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
    assert graph.number_of_edges() == 10
    assert len(timeline) == 2
    assert timeline[0]["date"] == "2010-01-01"
    assert timeline[1]["date"] == "2022-05-14"


def test_graph_relationships_are_inferred(sample_raw_scan: Dict[str, Any]) -> None:
    graph, _ = graph_build.build_graph(sample_raw_scan)
    relations = {(u, v, data.get("relation")) for u, v, data in graph.edges(data=True)}

    expected_relations = {
        ("target", "domain:example.com", "observed"),
        ("target", "email:admin@example.com", "observed"),
        ("ip:93.184.216.34", "target", "resolved_for"),
        ("subdomain:mail.example.com", "domain:example.com", "belongs_to"),
        ("email:admin@example.com", "domain:example.com", "uses_domain"),
        ("event:1:breach_appearance:2022-05-14", "email:admin@example.com", "breach_appearance"),
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


def test_duplicate_edges_are_prevented() -> None:
    entities = [
        {"type": "subdomain", "value": "mail.example.com"},
        {"type": "domain", "value": "example.com"},
        {"type": "subdomain", "value": "mail.example.com"},
    ]
    edges = graph_utils.infer_relationships(entities, target_val="example.com")
    # Verify that infer_relationships returns unique edges
    assert len(edges) == len(set(edges))


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
    html_content = output_path.read_text(encoding="utf-8")
    assert "Test Graph" in html_content
    assert "raw_scan.json" in html_content or "vis-network" in html_content
    assert "https://" not in html_content
    assert "http://" not in html_content


def test_graph_utils_social_profile_parsing() -> None:
    assert graph_utils.parse_social_host("https://github.com/user") == "github.com"
    assert graph_utils.parse_social_host("http://twitter.com/user") == "twitter.com"
    assert graph_utils.parse_social_host("linkedin.com/in/user") == "linkedin.com"
    assert graph_utils.parse_social_host("github.com/user") == "github.com"


def test_graph_utils_subdomain_extraction() -> None:
    assert graph_utils.extract_root_domain("mail.google.co.uk") == "google.co.uk"
    assert graph_utils.extract_root_domain("mail.example.com") == "example.com"
    assert graph_utils.extract_root_domain("example.com") == "example.com"


def test_graph_utils_entity_validation() -> None:
    assert graph_utils.validate_entity({"type": "domain", "value": "example.com"}) is True
    assert graph_utils.validate_entity({"type": "domain"}) is False
    assert graph_utils.validate_entity({"value": "example.com"}) is False
    assert graph_utils.validate_entity({"type": None, "value": "example.com"}) is False
    assert graph_utils.validate_entity("not a dict") is False


def test_graph_utils_canonical_matching() -> None:
    c1 = graph_utils.canonicalize_value("https://github.com/user")
    c2 = graph_utils.canonicalize_value("github.com/user/")
    c3 = graph_utils.canonicalize_value("http://github.com/user")
    assert c1 == c2 == c3 == "github.com/user"


def test_node_id_uniqueness() -> None:
    e1 = {"type": "domain", "value": "google.com"}
    e2 = {"type": "organization", "value": "google.com"}
    e3 = {"type": "email", "value": "admin@example.com"}

    id1 = graph_utils.node_id(e1)
    id2 = graph_utils.node_id(e2)
    id3 = graph_utils.node_id(e3)

    assert id1 == "domain:google.com"
    assert id2 == "organization:google.com"
    assert id3 == "email:admin@example.com"
    assert id1 != id2


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
