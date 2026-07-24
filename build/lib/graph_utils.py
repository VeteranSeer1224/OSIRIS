"""
graph_utils.py

Utility functions for OSIRIS Stage 3 (OSIRIS-Web)

Responsibilities
----------------
- Entity validation
- Entity -> NetworkX node conversion (type:value IDs)
- Robust URL & domain parsing (urllib.parse, tldextract)
- Relationship detection & deduplication (set-based)
- Event linking & canonical matching
- Timeline extraction
- Node styling
- Graph export & rendering (PyVis & HTML fallback)
"""

from __future__ import annotations

import html
import json
import logging
import math
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import networkx as nx
import tldextract

# Use tldextract's packaged public-suffix snapshot only.  Graph construction is
# part of the offline demonstration path and must neither fetch a suffix list
# nor write a user-level cache as a side effect of parsing evidence.
_OFFLINE_TLD_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
)

try:
    from pyvis.network import Network  # type: ignore
    _PYVIS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    Network = None  # type: ignore
    _PYVIS_AVAILABLE = False


# -------------------------------------------------------------------
# Node Styling
# -------------------------------------------------------------------

ENTITY_COLORS = {
    "target": "#38bdf8",
    "domain": "#8b5cf6",
    "subdomain": "#6366f1",
    "ip": "#14b8a6",
    "email": "#f59e0b",
    "social_profile": "#ec4899",
    "url": "#a78bfa",
    "phone": "#eab308",
    "organization": "#06b6d4",
    "person": "#c084fc",
    "username": "#d946ef",
    "address": "#fb923c",
    "location": "#22c55e",
    "technology": "#2dd4bf",
    "dns_record": "#818cf8",
    "asn": "#0ea5e9",
    "certificate": "#f97316",
    "crypto_wallet": "#facc15",
    "event": "#64748b",
    "other": "#94a3b8",
    "unknown": "#94a3b8",
}

ENTITY_SHAPES = {
    "target": "hexagon",
    "domain": "dot",
    "subdomain": "dot",
    "ip": "triangle",
    "email": "box",
    "social_profile": "diamond",
    "url": "star",
    "phone": "square",
    "organization": "hexagon",
    "person": "ellipse",
    "username": "ellipse",
    "address": "box",
    "location": "diamond",
    "technology": "hexagon",
    "dns_record": "dot",
    "asn": "triangle",
    "certificate": "hexagon",
    "crypto_wallet": "diamond",
    "event": "diamond",
    "other": "dot",
    "unknown": "dot",
}


# -------------------------------------------------------------------
# Validation & Parsing Helpers
# -------------------------------------------------------------------

def validate_entity(entity: Any) -> bool:
    """
    Validate that entity is a dictionary containing non-empty 'type' and 'value'.
    Logs an explanatory warning and returns False if invalid.
    """
    if not isinstance(entity, dict):
        logging.warning("Skipping invalid entity: not a dictionary (%r)", entity)
        return False
    if "type" not in entity or "value" not in entity:
        logging.warning("Skipping entity missing 'type' or 'value': %r", entity)
        return False
    if entity["type"] is None or entity["value"] is None:
        logging.warning("Skipping entity with None 'type' or 'value': %r", entity)
        return False
    type_str = str(entity["type"]).strip()
    val_str = str(entity["value"]).strip()
    if not type_str or not val_str:
        logging.warning("Skipping entity with empty 'type' or 'value': %r", entity)
        return False
    return True


def canonicalize_value(val: str) -> str:
    """
    Canonicalize string representation for matching (URLs, emails, domains).
    Strips protocols, trailing slashes, and whitespace, converting to lowercase.
    """
    if not val or not isinstance(val, str):
        return ""
    v = val.strip().lower()
    if v.startswith("https://"):
        v = v[8:]
    elif v.startswith("http://"):
        v = v[7:]
    elif v.startswith("//"):
        v = v[2:]
    return v.rstrip("/")


def parse_social_host(value: str) -> Optional[str]:
    """
    Extract the hostname/platform from a social profile URL or hostname.

    Supports:
        https://github.com/user
        http://twitter.com/user
        github.com/user
        linkedin.com/in/user

    Safely ignores malformed SpiderFoot payloads such as JSON blobs,
    Python dict/list strings, multiline values, and invalid URLs.
    """
    if not isinstance(value, str):
        return None

    val = value.strip()

    if not val:
        return None

    # Reject obvious serialized objects or multiline payloads
    if (
        "\n" in val
        or val.startswith("{")
        or val.startswith("[")
        or val.startswith("('")
        or val.startswith('["')
    ):
        return None

    try:
        parsed = urlparse(val if "://" in val else f"//{val}")
    except ValueError:
        return None

    host = parsed.hostname

    if not host and parsed.netloc:
        host = parsed.netloc.split(":")[0].split("/")[0]

    if not host:
        return None

    host = host.strip().lower().rstrip(".")

    # Reject malformed hosts
    if (
        not host
        or " " in host
        or host.startswith("[")
        or host.endswith("]")
        or host.startswith("{")
        or host.startswith("(")
    ):
        return None

    return host


def extract_root_domain(domain_str: str) -> Optional[str]:
    """
    Extract registered root domain using tldextract.
    Example: mail.google.co.uk -> google.co.uk
    """
    if not domain_str or not isinstance(domain_str, str):
        return None
    val = domain_str.strip()
    if not val:
        return None
    ext = _OFFLINE_TLD_EXTRACTOR(val)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return None


def extract_domain(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None

    val = value.strip()

    if not val:
        return None

    if "@" in val:
        val = val.split("@", 1)[1]

    return parse_social_host(val)


# -------------------------------------------------------------------
# Node Helpers
# -------------------------------------------------------------------

def node_id(entity: Dict[str, Any]) -> str:
    """
    Stable node identifier formatted as type:value.
    """
    kind = str(entity.get("type", "unknown")).strip().lower()
    val = str(entity.get("value", "")).strip().lower()
    return f"{kind}:{val}"


def label_for_entity(entity: Dict[str, Any]) -> str:
    etype = str(entity.get("type", "unknown")).strip().lower()
    val = str(entity.get("value", "")).strip()
    if etype in {"domain", "subdomain", "ip", "email"}:
        return val
    if etype == "social_profile":
        return val.replace("https://", "").replace("http://", "")
    return val[:40] + ("…" if len(val) > 40 else "")


def entity_title(entity: Dict[str, Any]) -> str:
    parts = [f"Type: {entity.get('type', 'unknown')}", f"Value: {entity.get('value', '')}"]
    if entity.get("platform"):
        parts.append(f"Platform: {entity['platform']}")
    metadata = entity.get("metadata")
    if isinstance(metadata, dict) and metadata:
        parts.append(f"Metadata: {json.dumps(metadata, ensure_ascii=False)}")
    return "\n".join(parts)


def node_attributes(entity: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert raw entity into NetworkX/PyVis node attributes.
    """
    entity_type = str(entity.get("type", "other")).strip().lower()
    val = str(entity.get("value", "")).strip()
    return {
        "label": label_for_entity(entity),
        "title": entity_title(entity),
        "kind": entity_type,
        "group": entity_type,
        "color": ENTITY_COLORS.get(entity_type, ENTITY_COLORS["other"]),
        "shape": ENTITY_SHAPES.get(entity_type, ENTITY_SHAPES["other"]),
        "raw_value": val,
    }


def add_entity_node(graph: nx.DiGraph, entity: Dict[str, Any]) -> Optional[str]:
    """
    Add entity node to graph if valid and not already present. Returns node_id.
    """
    if not validate_entity(entity):
        return None
    nid = node_id(entity)
    if nid not in graph:
        graph.add_node(nid, **node_attributes(entity))
    return nid


def add_target_node(graph: nx.DiGraph, target_val: str) -> str:
    """
    Add root target node to graph. Returns node ID "target".
    """
    val = target_val.strip() if target_val else "unknown_target"
    if "target" not in graph:
        graph.add_node(
            "target",
            label=val,
            title=f"Target: {val}",
            kind="target",
            group="target",
            color=ENTITY_COLORS["target"],
            shape=ENTITY_SHAPES["target"],
            raw_value=val,
        )
    return "target"


# -------------------------------------------------------------------
# Relationship Detection & Edge Creation
# -------------------------------------------------------------------

def infer_relationships(entities: List[Dict[str, Any]], target_val: str = "") -> Set[Tuple[str, str, str]]:
    """
    Infer graph edges from entity values using a set to avoid duplicate edges.
    Returns set of tuples: (source_id, target_id, relation)
    """
    edges: Set[Tuple[str, str, str]] = set()
    valid_entities = [e for e in entities if validate_entity(e)]

    # Collect domains for matching
    domain_nodes: Dict[str, str] = {}  # domain_name -> node_id
    for entity in valid_entities:
        etype = str(entity.get("type", "")).strip().lower()
        val = str(entity.get("value", "")).strip().lower()
        nid = node_id(entity)
        if etype in ("domain", "subdomain"):
            domain_nodes[val] = nid

    target_domain = extract_domain(target_val) or target_val.strip().lower()

    for entity in valid_entities:
        etype = str(entity.get("type", "")).strip().lower()
        val = str(entity.get("value", "")).strip()
        nid = node_id(entity)

        # Direct observation from target to entity
        edges.add(("target", nid, "observed"))

        if etype == "subdomain":
            val_lower = val.lower()
            root = extract_root_domain(val_lower)
            if root and root in domain_nodes:
                parent_id = domain_nodes[root]
                if parent_id != nid:
                    edges.add((nid, parent_id, "belongs_to"))
            else:
                # Check against target domain or other known domains
                for d_val, d_id in domain_nodes.items():
                    if val_lower != d_val and val_lower.endswith("." + d_val):
                        edges.add((nid, d_id, "belongs_to"))
                        break

        elif etype == "email":
            email_domain = extract_domain(val)
            if email_domain and email_domain in domain_nodes:
                edges.add((nid, domain_nodes[email_domain], "uses_domain"))
            elif email_domain:
                # If domain not explicitly in entities, auto-created or checked against root
                root = extract_root_domain(email_domain)
                if root and root in domain_nodes:
                    edges.add((nid, domain_nodes[root], "uses_domain"))

        elif etype == "social_profile":
            host = parse_social_host(val)
            if host:
                matched_id = None
                if host in domain_nodes:
                    matched_id = domain_nodes[host]
                else:
                    root = extract_root_domain(host)
                    if root and root in domain_nodes:
                        matched_id = domain_nodes[root]
                if matched_id:
                    edges.add((nid, matched_id, "linked_to"))

        elif etype == "ip":
            edges.add((nid, "target", "resolved_for"))

    return edges


def add_relationship_edges(graph: nx.DiGraph, relationships: Iterable[Tuple[str, str, str]]) -> None:
    """
    Add inferred edges to the directed graph cleanly without duplicates.
    """
    for src, dst, relation in sorted(relationships):
        if src in graph and dst in graph:
            graph.add_edge(
                src,
                dst,
                label=relation,
                relation=relation,
                title=relation,
            )


# -------------------------------------------------------------------
# Event Linking & Timeline
# -------------------------------------------------------------------

def event_title(event: Dict[str, Any]) -> str:
    details = [f"Date: {event.get('date', '')}", f"Type: {event.get('type', 'event')}"]
    if event.get("entity"):
        details.append(f"Entity: {event['entity']}")
    if event.get("source"):
        details.append(f"Source: {event['source']}")
    if event.get("detail"):
        details.append(f"Detail: {event['detail']}")
    return "\n".join(details)


def process_events(graph: nx.DiGraph, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Process events, create event nodes in graph, perform canonical entity linking,
    and return sorted timeline.
    """
    timeline: List[Dict[str, Any]] = []
    sorted_events = sorted(
        [e for e in events if isinstance(e, dict)],
        key=lambda e: (str(e.get("date", "")), str(e.get("type", "")))
    )

    # Build canonical map of graph nodes for matching
    canonical_map: Dict[str, str] = {}  # canonical_val -> node_id
    for n_id, data in graph.nodes(data=True):
        if data.get("kind") in ("target", "event"):
            continue
        raw_val = data.get("raw_value") or data.get("label", "")
        c_val = canonicalize_value(raw_val)
        if c_val:
            canonical_map[c_val] = n_id

    for idx, event in enumerate(sorted_events):
        date = str(event.get("date", "")).strip()
        event_type = str(event.get("type", "event")).strip() or "event"
        entity_val = str(event.get("entity", "")).strip()
        source = str(event.get("source", "")).strip()
        detail = str(event.get("detail", "")).strip()

        event_node_id = f"event:{idx}:{event_type}:{date}"

        graph.add_node(
            event_node_id,
            label=f"{event_type}\n{date}".strip(),
            title=event_title(event),
            kind="event",
            group="event",
            color=ENTITY_COLORS["event"],
            shape=ENTITY_SHAPES["event"],
        )

        linked_node = "target"
        if entity_val:
            c_entity = canonicalize_value(entity_val)
            if c_entity in canonical_map:
                linked_node = canonical_map[c_entity]

        graph.add_edge(event_node_id, linked_node, label=event_type, relation=event_type, title=event_type)

        timeline.append({
            "date": date,
            "type": event_type,
            "entity": entity_val,
            "source": source,
            "detail": detail,
        })

    return timeline


def extract_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Sort timeline events chronologically.
    """
    return sorted(
        [e for e in events if isinstance(e, dict)],
        key=lambda e: str(e.get("date", "")),
    )


# -------------------------------------------------------------------
# Graph Export & Rendering
# -------------------------------------------------------------------

def graph_to_vis_payload(graph: nx.DiGraph) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for n_id, data in graph.nodes(data=True):
        nodes.append({
            "id": n_id,
            "label": data.get("label", n_id),
            "title": data.get("title", n_id),
            "kind": data.get("kind", data.get("group", "unknown")),
            "group": data.get("group", data.get("kind", "unknown")),
            "shape": data.get("shape", "dot"),
            "color": data.get("color"),
        })

    for source, target, data in graph.edges(data=True):
        edges.append({
            "from": source,
            "to": target,
            "label": data.get("label", ""),
            "title": data.get("relation", data.get("label", "")),
            "arrows": "to",
        })

    return nodes, edges


def timeline_html(timeline: List[Dict[str, Any]]) -> str:
    if not timeline:
        return '<p class="timeline-empty">No events were present in raw_scan.json.</p>'

    items = []
    for item in timeline:
        parts = [f"<strong>{html.escape(item.get('date', ''))}</strong>"]
        if item.get("type"):
            parts.append(f"<span>{html.escape(item['type'])}</span>")
        if item.get("entity"):
            parts.append(f"<code>{html.escape(item['entity'])}</code>")
        if item.get("source"):
            parts.append(f"<em>{html.escape(item['source'])}</em>")
        if item.get("detail"):
            parts.append(f"<div>{html.escape(item['detail'])}</div>")
        items.append("<li>" + " — ".join(parts) + "</li>")
    return '<ol class="timeline-list">' + "".join(items) + "</ol>"


def _safe_json_embed(data: Any) -> str:
    """Serialize data to JSON safe for embedding in HTML script blocks.

    Replaces < with \\u003c to prevent script injection through OSINT values.
    """
    raw = json.dumps(data, ensure_ascii=False)
    return raw.replace("<", "\\u003c").replace("</", "\\u003c/")


def _relationship_map_svg(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]) -> str:
    """Render a fixed-layout, print-friendly relationship map.

    The layout is intentionally deterministic: the target is centred and all
    observed entities are positioned around it. This avoids force-directed
    movement, overlapping controls, and browser-dependent presentation in an
    evidentiary review artifact.
    """
    width = 980
    height = 640
    centre_x = width // 2
    centre_y = height // 2
    target = next((node for node in nodes if node.get("id") == "target"), None)
    others = [node for node in nodes if node.get("id") != "target"]
    positions: Dict[str, Tuple[float, float]] = {}
    if target:
        positions[str(target["id"])] = (centre_x, centre_y)
    count = max(len(others), 1)
    for index, node in enumerate(others):
        angle = (2 * math.pi * index / count) - (math.pi / 2)
        positions[str(node["id"])] = (
            centre_x + 330 * math.cos(angle),
            centre_y + 220 * math.sin(angle),
        )

    edge_markup = []
    for edge in edges:
        source = positions.get(str(edge.get("from")))
        destination = positions.get(str(edge.get("to")))
        if not source or not destination:
            continue
        label = html.escape(str(edge.get("label", "related to")))
        label_x = (source[0] + destination[0]) / 2
        label_y = (source[1] + destination[1]) / 2
        label_width = max(48, min(130, len(str(edge.get("label", ""))) * 6.5 + 18))
        edge_markup.append(
            f'<line x1="{source[0]:.1f}" y1="{source[1]:.1f}" '
            f'x2="{destination[0]:.1f}" y2="{destination[1]:.1f}" '
            'class="relation" marker-end="url(#arrow)"/>'
            f'<rect x="{label_x - label_width / 2:.1f}" y="{label_y - 11:.1f}" '
            f'width="{label_width:.1f}" height="20" rx="4" class="relation-label-bg"/>'
            f'<text x="{label_x:.1f}" y="{label_y:.1f}" class="relation-label">{label}</text>'
        )

    def node_shape(shape: str, x: float, y: float) -> str:
        """Return entity-specific SVG geometry centred on ``x, y``."""
        if shape == "triangle":
            return f'<polygon points="{x:.1f},{y - 38:.1f} {x + 43:.1f},{y + 34:.1f} {x - 43:.1f},{y + 34:.1f}"/>'
        if shape == "diamond":
            return f'<polygon points="{x:.1f},{y - 40:.1f} {x + 45:.1f},{y:.1f} {x:.1f},{y + 40:.1f} {x - 45:.1f},{y:.1f}"/>'
        if shape == "star":
            points = []
            for point_index in range(10):
                angle = (-math.pi / 2) + point_index * math.pi / 5
                radius = 42 if point_index % 2 == 0 else 19
                points.append(f"{x + radius * math.cos(angle):.1f},{y + radius * math.sin(angle):.1f}")
            return f'<polygon points="{" ".join(points)}"/>'
        if shape == "square":
            return f'<rect x="{x - 38:.1f}" y="{y - 38:.1f}" width="76" height="76" rx="5"/>'
        if shape == "box":
            return f'<rect x="{x - 58:.1f}" y="{y - 34:.1f}" width="116" height="68" rx="9"/>'
        if shape == "hexagon":
            return (
                f'<polygon points="{x - 43:.1f},{y:.1f} {x - 22:.1f},{y - 37:.1f} '
                f'{x + 22:.1f},{y - 37:.1f} {x + 43:.1f},{y:.1f} '
                f'{x + 22:.1f},{y + 37:.1f} {x - 22:.1f},{y + 37:.1f}"/>'
            )
        if shape == "ellipse":
            return f'<ellipse cx="{x:.1f}" cy="{y:.1f}" rx="51" ry="35"/>'
        return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="38"/>'

    node_markup = []
    for node in nodes:
        node_id = str(node["id"])
        x, y = positions.get(node_id, (centre_x, centre_y))
        full_label = str(node.get("label", node_id))
        display_label = full_label if len(full_label) <= 25 else full_label[:22] + "…"
        label = html.escape(display_label)
        kind_value = str(node.get("kind", "other")).lower()
        kind = html.escape(kind_value.replace("_", " ").upper())
        shape = str(node.get("shape") or ENTITY_SHAPES.get(kind_value, "dot"))
        color = str(node.get("color") or ENTITY_COLORS.get(kind_value, ENTITY_COLORS["other"]))
        is_target = node_id == "target"
        css_class = "map-node target-node" if is_target else "map-node"
        node_markup.append(
            f'<g class="{css_class}" style="--node-color:{html.escape(color)}">'
            f'<title>{html.escape(full_label)} — {kind}</title>'
            f'<g class="node-shape">{node_shape(shape, x, y)}</g>'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="10" class="node-core"/>'
            f'<text x="{x:.1f}" y="{y + 58:.1f}" class="node-label">{label}</text>'
            f'<text x="{x:.1f}" y="{y + 75:.1f}" class="node-kind">{kind}</text>'
            '</g>'
        )

    return f'''<svg class="relationship-map" viewBox="0 0 {width} {height}" role="img" aria-label="Evidence relationship map">
  <defs>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#172036" stroke-width=".7"/></pattern>
    <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z"/></marker>
  </defs>
  <rect width="{width}" height="{height}" class="map-background"/>
  <rect width="{width}" height="{height}" fill="url(#grid)"/>
  {''.join(edge_markup)}
  {''.join(node_markup)}
</svg>'''


def render_fallback_html(
    output_path: Path,
    graph: nx.DiGraph,
    timeline: List[Dict[str, Any]],
    title: str,
) -> None:
    nodes, edges = graph_to_vis_payload(graph)
    timeline_markup = timeline_html(timeline)
    relationship_map = _relationship_map_svg(nodes, edges)
    observed_kinds = sorted({
        str(node.get("kind", "other")).lower()
        for node in nodes
    })
    legend_markup = "".join(
        f'<span><i class="legend-shape" style="--legend-color:{ENTITY_COLORS.get(kind, ENTITY_COLORS["other"])}"></i>'
        f'{html.escape(kind.replace("_", " "))}</span>'
        for kind in observed_kinds
    )

    # Keep generated evidence artifacts self-contained and suitable for review
    # or printing. The fixed SVG layout deliberately avoids animated or
    # force-directed behaviour.
    node_markup = "".join(
        f'<li><code>{html.escape(str(node["id"]))}</code> — '
        f'{html.escape(str(node["label"]))}</li>'
        for node in nodes
    )
    edge_markup = "".join(
        f'<li><code>{html.escape(str(edge["from"]))}</code> '
        f'— {html.escape(str(edge["label"]))} → '
        f'<code>{html.escape(str(edge["to"]))}</code></li>'
        for edge in edges
    )

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ margin: 0; font-family: Inter, "Segoe UI", Arial, sans-serif; background: #030712; color: #dbe5f2; }}
    .wrap {{ max-width: 1480px; margin: 0 auto; display: grid; grid-template-columns: minmax(0, 2.2fr) minmax(300px, .9fr); gap: 20px; padding: 24px; box-sizing: border-box; }}
    .panel {{ background: #0b1120; border: 1px solid #23304a; border-radius: 10px; overflow: hidden; box-shadow: 0 18px 50px rgba(0,0,0,.28); }}
    .panel h1, .panel h2 {{ margin: 0; padding: 15px 20px; border-bottom: 1px solid #23304a; font-weight: 600; }}
    .panel h1 {{ font-size: 22px; letter-spacing: .01em; background: #101a2f; color: #f8fafc; }}
    .panel h2 {{ font-size: 16px; color: #dbeafe; background: #101827; }}
    #network {{ padding: 20px; box-sizing: border-box; overflow: auto; }}
    .relationship-map {{ display: block; width: 100%; min-width: 720px; border: 1px solid #23304a; border-radius: 8px; background: #050914; }}
    .map-background {{ fill: #050914; }}
    .relation {{ stroke: #52627a; stroke-width: 1.4; }}
    #arrow {{ fill: #64748b; }}
    .relation-label-bg {{ fill: #0b1220; stroke: #293750; stroke-width: 1; }}
    .relation-label {{ fill: #b6c5d8; font: 600 10px Arial, sans-serif; text-anchor: middle; dominant-baseline: middle; }}
    .node-shape > * {{ fill: #0b1220; stroke: var(--node-color); stroke-width: 2.4; }}
    .node-core {{ fill: var(--node-color); stroke: #dbeafe; stroke-width: 1.4; }}
    .target-node .node-shape > * {{ fill: color-mix(in srgb, var(--node-color) 22%, #0b1220); stroke-width: 3; }}
    .node-label {{ fill: #f1f5f9; font: 600 13px Arial, sans-serif; text-anchor: middle; dominant-baseline: middle; paint-order: stroke; stroke: #050914; stroke-width: 4px; stroke-linejoin: round; }}
    .node-kind {{ fill: var(--node-color); font: 700 9px Arial, sans-serif; text-anchor: middle; letter-spacing: .12em; }}
    .graph-list {{ display: grid; gap: 18px; margin-top: 20px; }}
    .graph-list h2 {{ font-size: 15px; margin: 0; padding-bottom: 7px; border-bottom: 1px solid #23304a; color: #dbeafe; }}
    .graph-list ul {{ margin: 0; padding-left: 20px; }}
    .side {{ display: flex; flex-direction: column; }}
    .side .content {{ padding: 16px; overflow: auto; }}
    .meta {{ font-size: 13px; line-height: 1.5; color: #94a3b8; margin-bottom: 14px; }}
    .timeline-list {{ padding-left: 18px; margin: 0; display: grid; gap: 12px; }}
    .timeline-list li {{ line-height: 1.45; }}
    .timeline-list code, .graph-list code {{ background: #111c31; border: 1px solid #22314b; padding: 2px 5px; border-radius: 3px; color: #bae6fd; font-family: ui-monospace, monospace; }}
    .timeline-empty {{ color: #64748b; }}
    .legend {{ display: grid; grid-template-columns: 1fr 1fr; gap: 9px; margin-top: 18px; font-size: 12px; color: #aebdd0; }}
    .legend span {{ display: inline-flex; align-items: center; gap: 8px; }}
    .legend-shape {{ width: 10px; height: 10px; transform: rotate(45deg); border: 2px solid var(--legend-color); background: color-mix(in srgb, var(--legend-color) 25%, transparent); display: inline-block; }}
    @media (max-width: 980px) {{ .wrap {{ grid-template-columns: 1fr; padding: 12px; }} }}
    @media print {{ body {{ background:#fff; }} .wrap {{ display:block; max-width:none; padding:0; }} .panel {{ break-inside:avoid; box-shadow:none; margin-bottom:12px; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="panel">
      <h1>{html.escape(title)}</h1>
      <div id="network">
        <div class="meta">Relationship map generated from the normalized evidence record. Node placement is fixed for consistent review and print output.</div>
        {relationship_map}
        <div class="graph-list">
        <h2>Entities</h2><ul>{node_markup}</ul>
        <h2>Relationships</h2><ul>{edge_markup}</ul>
        </div>
      </div>
    </section>
    <aside class="panel side">
      <h2>Timeline</h2>
      <div class="content">
        <div class="meta">Events were read from <code>raw_scan.json</code> and attached to the graph as event nodes.</div>
        {timeline_markup}
        <div class="legend">
          {legend_markup}
        </div>
      </div>
    </aside>
  </div>
</body>
</html>
"""
    output_path.write_text(html_doc, encoding="utf-8")


def render_pyvis_html(
    output_path: Path,
    graph: nx.DiGraph,
    timeline: List[Dict[str, Any]],
    title: str,
) -> None:
    # Inline vis-network so the artifact remains interactive when opened from
    # disk and never requires a CDN or a companion ``lib/`` directory.
    net = Network(
        height="760px",
        width="100%",
        bgcolor="#0b1020",
        font_color="#e5e7eb",
        directed=True,
        heading=title,
        cdn_resources="in_line",
    )
    net.toggle_physics(True)
    net.barnes_hut(gravity=-25000, spring_length=120, damping=0.15)

    for n_id, data in graph.nodes(data=True):
        net.add_node(
            n_id,
            label=html.escape(str(data.get("label", n_id))),
            title=html.escape(str(data.get("title", n_id))),
            color=data.get("color", ENTITY_COLORS.get(data.get("kind", "unknown"), ENTITY_COLORS["unknown"])),
            shape=data.get("shape", ENTITY_SHAPES.get(data.get("kind", "unknown"), ENTITY_SHAPES["unknown"])),
            group=data.get("group", data.get("kind", "unknown")),
        )

    for source, target, data in graph.edges(data=True):
        net.add_edge(source, target, label=data.get("label", ""), title=data.get("relation", ""), arrows="to")

    net.set_options(json.dumps({
        "interaction": {"hover": True, "navigationButtons": True, "keyboard": True},
        "physics": {"stabilization": True},
        "edges": {"smooth": {"type": "dynamic"}},
        "nodes": {"font": {"color": "#e5e7eb"}},
    }))

    html_content = net.generate_html(notebook=False)
    # PyVis 0.3.x still injects Bootstrap resources for its optional UI even
    # with ``cdn_resources='in_line'``. They are not required for rendering
    # the network and would make a local artifact depend on the network.
    html_content = re.sub(
        r'<script[^>]+src=["\']https?://[^>]+>\s*</script>|'
        r'<link[^>]+href=["\']https?://[^>]*>',
        "",
        html_content,
        flags=re.IGNORECASE,
    )
    if "<title>" not in html_content:
        html_content = html_content.replace("<head>", f"<head>\n<title>{html.escape(title)}</title>")
    if "<h1></h1>" in html_content:
        html_content = html_content.replace("<h1></h1>", f"<h1>{html.escape(title)}</h1>")
    timeline_markup = timeline_html(timeline)
    if "</body>" in html_content:
        extra = f"""
        <section style="margin:16px; padding:16px; background:#111827; border:1px solid #243043; border-radius:16px; color:#e5e7eb; font-family:Arial,sans-serif;">
          <h2 style="margin-top:0">Timeline</h2>
          <p style="color:#cbd5e1">Events were read from <code>raw_scan.json</code> and attached to the graph as event nodes.</p>
          {timeline_markup}
        </section>
        """
        html_content = html_content.replace("</body>", extra + "\n</body>")
    output_path.write_text(html_content, encoding="utf-8")


def export_graph_html(net: Any, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(net, "write_html"):
        net.write_html(str(output_path))
    elif hasattr(net, "save_graph"):
        net.save_graph(str(output_path))
    else:
        output_path.write_text(str(net), encoding="utf-8")


def render_graph(
    graph: nx.DiGraph,
    timeline: List[Dict[str, Any]],
    output_path: Path,
    title: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    render_fallback_html(output_path, graph, timeline, title)
