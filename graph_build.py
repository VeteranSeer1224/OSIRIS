#!/usr/bin/env python3
"""
OSIRIS-Web  —  Stage 3: Graph Intelligence
Person C's graph deliverable.

Reads:
    raw_scan.json

Produces:
    graph.html

Responsibilities:
    - Read all entities
    - Read all events
    - Build a NetworkX graph
    - Create edges between related entities
    - Export an interactive HTML graph (PyVis when available, fallback HTML otherwise)
    - Avoid hardcoded demo data

Usage:
    python graph_build.py --input raw_scan.json --output graph.html
    python graph_build.py --input schemas/samples/sample_raw_scan.json --output outputs/graph.html
"""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import networkx as nx

try:
    from pyvis.network import Network  # type: ignore
    _PYVIS_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    Network = None  # type: ignore
    _PYVIS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NODE_STYLE = {
    "target": {"color": "#7c3aed", "shape": "dot"},
    "domain": {"color": "#2563eb", "shape": "dot"},
    "subdomain": {"color": "#1d4ed8", "shape": "dot"},
    "ip": {"color": "#0f766e", "shape": "dot"},
    "email": {"color": "#c2410c", "shape": "dot"},
    "social_profile": {"color": "#be185d", "shape": "dot"},
    "event": {"color": "#6b7280", "shape": "diamond"},
    "unknown": {"color": "#374151", "shape": "dot"},
}

DEFAULT_RELATION = "observed"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("raw_scan.json must contain a JSON object at the top level")
    return data


def _safe_str(value: Any) -> str:
    return "" if value is None else str(value)


def _normalize_type(entity_type: Any) -> str:
    value = _safe_str(entity_type).strip().lower()
    return value if value else "unknown"


def _node_id(kind: str, value: str) -> str:
    return f"{kind}:{value.strip().lower()}"


def _label_for_entity(entity_type: str, value: str) -> str:
    if entity_type in {"domain", "subdomain", "ip", "email"}:
        return value
    if entity_type == "social_profile":
        return value.replace("https://", "").replace("http://", "")
    return value[:40] + ("…" if len(value) > 40 else "")


def _entity_title(entity: Dict[str, Any]) -> str:
    parts = [f"Type: {entity.get('type', 'unknown')}", f"Value: {entity.get('value', '')}"]
    if entity.get("platform"):
        parts.append(f"Platform: {entity['platform']}")
    metadata = entity.get("metadata")
    if isinstance(metadata, dict) and metadata:
        parts.append(f"Metadata: {json.dumps(metadata, ensure_ascii=False)}")
    return "\n".join(parts)


def _event_title(event: Dict[str, Any]) -> str:
    details = [f"Date: {event.get('date', '')}", f"Type: {event.get('type', 'event')}"]
    if event.get("entity"):
        details.append(f"Entity: {event['entity']}")
    if event.get("source"):
        details.append(f"Source: {event['source']}")
    if event.get("detail"):
        details.append(f"Detail: {event['detail']}")
    return "\n".join(details)


def _extract_domain(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None
    if "@" in value:
        value = value.split("@", 1)[1]
    value = value.split("/", 1)[0]
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        return value.lower()
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or ""
    return host.lower() if host else None


def _looks_like_subdomain(candidate: str, parent_domain: str) -> bool:
    candidate = candidate.lower().strip()
    parent_domain = parent_domain.lower().strip()
    return candidate != parent_domain and candidate.endswith("." + parent_domain)


def _event_sort_key(event: Dict[str, Any]) -> Tuple[str, str]:
    date = _safe_str(event.get("date", ""))
    event_type = _safe_str(event.get("type", ""))
    return (date, event_type)


def _parse_scan_date(scan_date: Any) -> str:
    if isinstance(scan_date, str) and scan_date:
        return scan_date
    if isinstance(scan_date, datetime):
        return scan_date.isoformat()
    return ""


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph(scan: Dict[str, Any]) -> Tuple[nx.Graph, List[Dict[str, Any]]]:
    target = _safe_str(scan.get("target", "unknown_target")).strip() or "unknown_target"
    entities = scan.get("entities", []) or []
    events = scan.get("events", []) or []

    graph = nx.Graph()
    timeline: List[Dict[str, Any]] = []

    # Root node
    graph.add_node(
        "target",
        label=target,
        title=f"Target: {target}",
        kind="target",
        group="target",
        shape=NODE_STYLE["target"]["shape"],
    )

    # Entity index for relationship inference
    entity_index: Dict[str, Dict[str, Any]] = {}
    domain_nodes: List[str] = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_type = _normalize_type(entity.get("type"))
        value = _safe_str(entity.get("value", "")).strip()
        if not value:
            continue
        node_id = _node_id(entity_type, value)
        entity_index[node_id] = entity

        if node_id not in graph:
            style = NODE_STYLE.get(entity_type, NODE_STYLE["unknown"])
            graph.add_node(
                node_id,
                label=_label_for_entity(entity_type, value),
                title=_entity_title(entity),
                kind=entity_type,
                group=entity_type,
                shape=style["shape"],
            )
        if entity_type in {"domain", "subdomain"}:
            domain_nodes.append(node_id)

        # direct observation edge from target to every entity
        graph.add_edge(
            "target",
            node_id,
            label=DEFAULT_RELATION,
            relation=DEFAULT_RELATION,
        )

    # Relationship inference based on entity content
    domain_values = [str(entity.get("value", "")).strip().lower() for entity in entities if _normalize_type(entity.get("type")) == "domain"]
    target_domain = _extract_domain(target) or target.lower()

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        etype = _normalize_type(entity.get("type"))
        value = _safe_str(entity.get("value", "")).strip()
        if not value:
            continue
        node_id = _node_id(etype, value)

        if etype == "subdomain":
            for d in domain_values + [target_domain]:
                if d and _looks_like_subdomain(value.lower(), d):
                    parent_id = _node_id("domain", d)
                    if parent_id not in graph:
                        graph.add_node(
                            parent_id,
                            label=d,
                            title=f"Domain: {d}",
                            kind="domain",
                            group="domain",
                            shape=NODE_STYLE["domain"]["shape"],
                        )
                    graph.add_edge(node_id, parent_id, label="belongs_to", relation="belongs_to")
                    break

        elif etype == "email":
            email_domain = _extract_domain(value)
            if email_domain:
                parent_id = _node_id("domain", email_domain)
                if parent_id not in graph:
                    graph.add_node(
                        parent_id,
                        label=email_domain,
                        title=f"Domain: {email_domain}",
                        kind="domain",
                        group="domain",
                        shape=NODE_STYLE["domain"]["shape"],
                    )
                graph.add_edge(node_id, parent_id, label="uses_domain", relation="uses_domain")

        elif etype == "social_profile":
            host = _extract_domain(value)
            if host:
                matched = None
                for d in domain_values + [target_domain]:
                    if d and (host == d or host.endswith("." + d) or d.endswith("." + host)):
                        matched = d
                        break
                if matched:
                    parent_id = _node_id("domain", matched)
                    if parent_id not in graph:
                        graph.add_node(
                            parent_id,
                            label=matched,
                            title=f"Domain: {matched}",
                            kind="domain",
                            group="domain",
                            shape=NODE_STYLE["domain"]["shape"],
                        )
                    graph.add_edge(node_id, parent_id, label="linked_to", relation="linked_to")

        elif etype == "ip":
            graph.add_edge(node_id, "target", label="resolved_for", relation="resolved_for")

    # Event nodes and timeline
    for idx, event in enumerate(sorted(events, key=_event_sort_key)):
        if not isinstance(event, dict):
            continue
        date = _safe_str(event.get("date", "")).strip()
        event_type = _safe_str(event.get("type", "event")).strip() or "event"
        entity_value = _safe_str(event.get("entity", "")).strip()
        source = _safe_str(event.get("source", "")).strip()
        detail = _safe_str(event.get("detail", "")).strip()
        event_node_id = f"event:{idx}:{event_type}:{date}"

        graph.add_node(
            event_node_id,
            label=f"{event_type}\n{date}".strip(),
            title=_event_title(event),
            kind="event",
            group="event",
            shape=NODE_STYLE["event"]["shape"],
        )

        linked_node = None
        if entity_value:
            # Link to the best matching known entity, or create an inferred node if needed.
            for candidate in graph.nodes:
                if candidate == "target":
                    continue
                candidate_data = graph.nodes[candidate]
                if candidate_data.get("kind") in {"event", "target"}:
                    continue
                if _safe_str(candidate_data.get("label", "")).strip().lower() == entity_value.lower():
                    linked_node = candidate
                    break

            if linked_node is None:
                # Fall back to the target node so the event is still represented.
                linked_node = "target"

        else:
            linked_node = "target"

        graph.add_edge(event_node_id, linked_node, label=event_type, relation=event_type)

        timeline.append(
            {
                "date": date,
                "type": event_type,
                "entity": entity_value,
                "source": source,
                "detail": detail,
            }
        )

    return graph, timeline


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _graph_to_vis_payload(graph: nx.Graph) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for node_id, data in graph.nodes(data=True):
        node = {
            "id": node_id,
            "label": data.get("label", node_id),
            "title": data.get("title", node_id),
            "group": data.get("group", data.get("kind", "unknown")),
            "shape": data.get("shape", "dot"),
        }
        nodes.append(node)

    for source, target, data in graph.edges(data=True):
        edges.append(
            {
                "from": source,
                "to": target,
                "label": data.get("label", ""),
                "title": data.get("relation", data.get("label", "")),
                "arrows": "to",
            }
        )

    return nodes, edges


def _timeline_html(timeline: List[Dict[str, Any]]) -> str:
    if not timeline:
        return "<p class=\"timeline-empty\">No events were present in raw_scan.json.</p>"

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
    return "<ol class=\"timeline-list\">" + "".join(items) + "</ol>"


def _render_fallback_html(
    output_path: Path,
    graph: nx.Graph,
    timeline: List[Dict[str, Any]],
    title: str,
) -> None:
    nodes, edges = _graph_to_vis_payload(graph)
    nodes_json = json.dumps(nodes, ensure_ascii=False)
    edges_json = json.dumps(edges, ensure_ascii=False)
    timeline_markup = _timeline_html(timeline)

    html_doc = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html.escape(title)}</title>
  <script src=\"https://unpkg.com/vis-network/standalone/umd/vis-network.min.js\"></script>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ margin: 0; font-family: Arial, sans-serif; background: #0b1020; color: #e5e7eb; }}
    .wrap {{ display: grid; grid-template-columns: 2fr 1fr; gap: 16px; padding: 16px; min-height: 100vh; box-sizing: border-box; }}
    .panel {{ background: #111827; border: 1px solid #243043; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,.25); }}
    .panel h1, .panel h2 {{ margin: 0; padding: 14px 16px; border-bottom: 1px solid #243043; }}
    #network {{ height: calc(100vh - 32px); min-height: 760px; }}
    .side {{ display: flex; flex-direction: column; }}
    .side .content {{ padding: 16px; overflow: auto; }}
    .meta {{ font-size: 14px; line-height: 1.5; color: #cbd5e1; margin-bottom: 14px; }}
    .timeline-list {{ padding-left: 18px; margin: 0; display: grid; gap: 12px; }}
    .timeline-list li {{ line-height: 1.45; }}
    .timeline-list code {{ background: #1f2937; padding: 2px 6px; border-radius: 999px; }}
    .timeline-empty {{ color: #94a3b8; }}
    .legend {{ display: grid; gap: 8px; margin-top: 16px; font-size: 13px; color: #cbd5e1; }}
    .legend span {{ display: inline-flex; align-items: center; gap: 8px; }}
    .dot {{ width: 10px; height: 10px; border-radius: 999px; display: inline-block; }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"panel\">
      <h1>{html.escape(title)}</h1>
      <div id=\"network\"></div>
    </section>
    <aside class=\"panel side\">
      <h2>Timeline</h2>
      <div class=\"content\">
        <div class=\"meta\">Events were read from <code>raw_scan.json</code> and attached to the graph as event nodes.</div>
        {timeline_markup}
        <div class=\"legend\">
          <span><i class=\"dot\" style=\"background:#2563eb\"></i>domain</span>
          <span><i class=\"dot\" style=\"background:#1d4ed8\"></i>subdomain</span>
          <span><i class=\"dot\" style=\"background:#0f766e\"></i>ip</span>
          <span><i class=\"dot\" style=\"background:#c2410c\"></i>email</span>
          <span><i class=\"dot\" style=\"background:#be185d\"></i>social_profile</span>
          <span><i class=\"dot\" style=\"background:#6b7280\"></i>event</span>
        </div>
      </div>
    </aside>
  </div>
  <script>
    const nodes = new vis.DataSet({nodes_json});
    const edges = new vis.DataSet({edges_json});
    const container = document.getElementById('network');
    const data = {{ nodes, edges }};
    const options = {{
      physics: {{ stabilization: true, barnesHut: {{ gravitationalConstant: -25000, springLength: 120 }} }},
      interaction: {{ hover: true, navigationButtons: true, keyboard: true }},
      nodes: {{ font: {{ color: '#e5e7eb' }}, borderWidth: 1 }},
      edges: {{ color: {{ color: '#94a3b8' }}, smooth: {{ type: 'dynamic' }} }},
    }};
    new vis.Network(container, data, options);
  </script>
</body>
</html>
"""
    output_path.write_text(html_doc, encoding="utf-8")


def _render_pyvis_html(
    output_path: Path,
    graph: nx.Graph,
    timeline: List[Dict[str, Any]],
    title: str,
) -> None:
    net = Network(height="760px", width="100%", bgcolor="#0b1020", font_color="#e5e7eb", directed=False)
    net.toggle_physics(True)
    net.barnes_hut(gravity=-25000, spring_length=120, damping=0.15)

    for node_id, data in graph.nodes(data=True):
        style = NODE_STYLE.get(data.get("kind", "unknown"), NODE_STYLE["unknown"])
        net.add_node(
            node_id,
            label=data.get("label", node_id),
            title=data.get("title", node_id),
            color=style["color"],
            shape=style["shape"],
            group=data.get("group", data.get("kind", "unknown")),
        )

    for source, target, data in graph.edges(data=True):
        net.add_edge(source, target, label=data.get("label", ""), title=data.get("relation", ""), arrows="to")

    net.set_options(
        """
        var options = {
          interaction: { hover: true, navigationButtons: true, keyboard: true },
          physics: { stabilization: true },
          edges: { smooth: { type: 'dynamic' } },
          nodes: { font: { color: '#e5e7eb' } }
        }
        """
    )

    html_content = net.generate_html(notebook=False)
    timeline_markup = _timeline_html(timeline)
    if "</body>" in html_content:
        extra = f"""
        <section style=\"margin:16px; padding:16px; background:#111827; border:1px solid #243043; border-radius:16px; color:#e5e7eb; font-family:Arial,sans-serif;\">
          <h2 style=\"margin-top:0\">Timeline</h2>
          <p style=\"color:#cbd5e1\">Events were read from <code>raw_scan.json</code> and attached to the graph as event nodes.</p>
          {timeline_markup}
        </section>
        """
        html_content = html_content.replace("</body>", extra + "\n</body>")
    output_path.write_text(html_content, encoding="utf-8")


def render_graph(
    graph: nx.Graph,
    timeline: List[Dict[str, Any]],
    output_path: Path,
    title: str,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if _PYVIS_AVAILABLE:
        try:
            _render_pyvis_html(output_path, graph, timeline, title)
            return
        except Exception:
            # Fallback to a direct HTML renderer if PyVis has runtime issues.
            pass
    _render_fallback_html(output_path, graph, timeline, title)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


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
