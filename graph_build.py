#!/usr/bin/env python3
"""
OSIRIS-Web  —  Stage 3: Graph Intelligence
Person C's graph deliverable.

Reads:
    raw_scan.json

Produces:
    graph.html

Responsibilities:
    - Load raw_scan.json
    - Validate input
    - Orchestrate graph construction using graph_utils
    - Export an interactive HTML graph

Usage:
    python graph_build.py --input raw_scan.json --output graph.html
    python graph_build.py --input schemas/samples/sample_raw_scan.json --output outputs/graph.html
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import networkx as nx
import graph_utils


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("raw_scan.json must contain a JSON object at the top level")
    return data


def build_graph(scan: Dict[str, Any]) -> Tuple[nx.DiGraph, List[Dict[str, Any]]]:
    """
    Orchestrate directed graph build and timeline extraction from raw scan.
    """
    if not isinstance(scan, dict):
        raise ValueError("Scan input must be a JSON dictionary")

    target_val = str(scan.get("target", "unknown_target")).strip() or "unknown_target"
    raw_entities = scan.get("entities", [])
    if not isinstance(raw_entities, list):
        raw_entities = []
    raw_events = scan.get("events", [])
    if not isinstance(raw_events, list):
        raw_events = []

    graph = nx.DiGraph()

    # 1. Add root target node
    graph_utils.add_target_node(graph, target_val)

    # 2. Add validated entity nodes
    for entity in raw_entities:
        graph_utils.add_entity_node(graph, entity)

    # 3. Infer relationships and add directed edges without duplicates
    relationships = graph_utils.infer_relationships(raw_entities, target_val)
    graph_utils.add_relationship_edges(graph, relationships)

    # 4. Link events and extract timeline
    timeline = graph_utils.process_events(graph, raw_events)

    return graph, timeline


def render_graph(
    graph: nx.DiGraph,
    timeline: List[Dict[str, Any]],
    output_path: Path,
    title: str,
) -> None:
    """
    Delegate HTML export to graph_utils.
    """
    graph_utils.render_graph(graph, timeline, output_path, title)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build OSIRIS Stage 3 graph.html from raw_scan.json")
    parser.add_argument("--input", default="raw_scan.json", help="Path to raw_scan.json")
    parser.add_argument("--output", default="graph.html", help="Output HTML file")
    parser.add_argument("--title", default="OSIRIS-Web — Graph Intelligence", help="Title for the output graph")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    scan = _read_json(input_path)
    graph, timeline = build_graph(scan)
    render_graph(graph, timeline, output_path, args.title)

    print(f"[OSIRIS-Web] Wrote {output_path}")
    print(f"[OSIRIS-Web] Nodes: {graph.number_of_nodes()}, Edges: {graph.number_of_edges()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
