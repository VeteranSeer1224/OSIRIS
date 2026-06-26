"""
graph_utils.py

Utility functions for OSIRIS Stage 3 (OSIRIS-Web)

Responsibilities
----------------
- Entity -> NetworkX node conversion
- Relationship detection
- Edge creation
- Timeline extraction
- Node styling
- Graph export
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

import networkx as nx


# -------------------------------------------------------------------
# Node Styling
# -------------------------------------------------------------------

ENTITY_COLORS = {
    "domain": "#4F81BD",
    "subdomain": "#6FA8DC",
    "ip": "#F6B26B",
    "email": "#93C47D",
    "social_profile": "#E06666",
    "url": "#8E7CC3",
    "phone": "#FFD966",
    "organization": "#76A5AF",
    "person": "#C27BA0",
    "other": "#999999",
}


ENTITY_SHAPES = {
    "domain": "dot",
    "subdomain": "dot",
    "ip": "triangle",
    "email": "box",
    "social_profile": "diamond",
    "url": "star",
    "phone": "square",
    "organization": "hexagon",
    "person": "ellipse",
    "other": "dot",
}


# -------------------------------------------------------------------
# Node Helpers
# -------------------------------------------------------------------

def node_id(entity: Dict) -> str:
    """
    Stable node identifier.
    """
    return entity["value"]


def node_attributes(entity: Dict) -> Dict:
    """
    Convert raw entity into NetworkX/PyVis node attributes.
    """

    entity_type = entity.get("type", "other")

    return {
        "label": entity["value"],
        "title": entity["value"],
        "entity_type": entity_type,
        "color": ENTITY_COLORS.get(entity_type, ENTITY_COLORS["other"]),
        "shape": ENTITY_SHAPES.get(entity_type, ENTITY_SHAPES["other"]),
    }


def add_entity_node(graph: nx.Graph, entity: Dict):
    """
    Add entity if it doesn't already exist.
    """

    nid = node_id(entity)

    if nid not in graph:
        graph.add_node(nid, **node_attributes(entity))


# -------------------------------------------------------------------
# Relationship Detection
# -------------------------------------------------------------------

def infer_relationships(entities: List[Dict]) -> List[Tuple[str, str, str]]:
    """
    Infer graph edges from entity values.

    Returns:
        (source, destination, relationship)
    """

    edges = []

    domains = {}
    emails = []
    socials = []

    for entity in entities:

        if entity["type"] in ("domain", "subdomain"):
            domains[entity["value"]] = entity

        elif entity["type"] == "email":
            emails.append(entity)

        elif entity["type"] == "social_profile":
            socials.append(entity)

    # --------------------------------------------------
    # Email -> Domain
    # --------------------------------------------------

    for email in emails:

        if "@" not in email["value"]:
            continue

        domain = email["value"].split("@")[-1]

        if domain in domains:

            edges.append(
                (
                    email["value"],
                    domain,
                    "belongs_to",
                )
            )

    # --------------------------------------------------
    # Subdomain -> Root Domain
    # --------------------------------------------------

    for domain in domains:

        parts = domain.split(".")

        if len(parts) < 3:
            continue

        parent = ".".join(parts[-2:])

        if parent in domains:

            edges.append(
                (
                    domain,
                    parent,
                    "subdomain_of",
                )
            )

    # --------------------------------------------------
    # Social Profile -> Domain
    # --------------------------------------------------

    for social in socials:

        value = social["value"]

        if "/" in value:

            platform = value.split("/")[0]

            if platform in domains:

                edges.append(
                    (
                        social["value"],
                        platform,
                        "hosted_on",
                    )
                )

    return edges


# -------------------------------------------------------------------
# Edge Helpers
# -------------------------------------------------------------------

def add_relationship_edges(graph: nx.Graph, relationships):

    for src, dst, relation in relationships:

        if src not in graph or dst not in graph:
            continue

        graph.add_edge(
            src,
            dst,
            relation=relation,
            title=relation,
        )


# -------------------------------------------------------------------
# Timeline
# -------------------------------------------------------------------

def extract_timeline(events: List[Dict]) -> List[Dict]:
    """
    Sort timeline chronologically.
    """

    return sorted(
        events,
        key=lambda e: e.get("date", ""),
    )


# -------------------------------------------------------------------
# Graph Export
# -------------------------------------------------------------------

def export_graph_html(net, output_path: Path):

    output_path.parent.mkdir(parents=True, exist_ok=True)

    net.write_html(str(output_path))


def export_graph_png(graph, output_path: Path):
    """
    Placeholder.

    PyVis cannot export PNG directly.

    Recommended approaches:

    - Playwright
    - Selenium
    - Puppeteer

    This function intentionally raises until a renderer
    is plugged in.
    """

    raise NotImplementedError(
        "Graph image export requires a browser renderer."
    )