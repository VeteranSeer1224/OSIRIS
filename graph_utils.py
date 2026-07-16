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
    "target": "#7c3aed",
    "domain": "#4F81BD",
    "subdomain": "#6FA8DC",
    "ip": "#F6B26B",
    "email": "#93C47D",
    "social_profile": "#E06666",
    "url": "#8E7CC3",
    "phone": "#FFD966",
    "organization": "#76A5AF",
    "person": "#C27BA0",
    "event": "#6b7280",
    "other": "#999999",
    "unknown": "#374151",
}

ENTITY_SHAPES = {
    "target": "dot",
    "domain": "dot",
    "subdomain": "dot",
    "ip": "triangle",
    "email": "box",
    "social_profile": "diamond",
    "url": "star",
    "phone": "square",
    "organization": "hexagon",
    "person": "ellipse",
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


def render_fallback_html(
    output_path: Path,
    graph: nx.DiGraph,
    timeline: List[Dict[str, Any]],
    title: str,
) -> None:
    nodes, edges = graph_to_vis_payload(graph)
    timeline_markup = timeline_html(timeline)

    # Keep generated evidence artifacts self-contained.  A static SVG is less
    # feature-rich than a JavaScript graph, but it is deterministic, works
    # without network access, and cannot load a remote dependency.
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
    body {{ margin: 0; font-family: Arial, sans-serif; background: #0b1020; color: #e5e7eb; }}
    .wrap {{ display: grid; grid-template-columns: 2fr 1fr; gap: 16px; padding: 16px; min-height: 100vh; box-sizing: border-box; }}
    .panel {{ background: #111827; border: 1px solid #243043; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,.25); }}
    .panel h1, .panel h2 {{ margin: 0; padding: 14px 16px; border-bottom: 1px solid #243043; }}
    #network {{ min-height: 760px; padding: 16px; box-sizing: border-box; overflow: auto; }}
    .graph-list {{ display: grid; gap: 14px; }}
    .graph-list ul {{ margin: 0; padding-left: 20px; }}
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
  <div class="wrap">
    <section class="panel">
      <h1>{html.escape(title)}</h1>
      <div id="network" class="graph-list">
        <h2>Entities</h2><ul>{node_markup}</ul>
        <h2>Relationships</h2><ul>{edge_markup}</ul>
      </div>
    </section>
    <aside class="panel side">
      <h2>Timeline</h2>
      <div class="content">
        <div class="meta">Events were read from <code>raw_scan.json</code> and attached to the graph as event nodes.</div>
        {timeline_markup}
        <div class="legend">
          <span><i class="dot" style="background:#2563eb"></i>domain</span>
          <span><i class="dot" style="background:#1d4ed8"></i>subdomain</span>
          <span><i class="dot" style="background:#0f766e"></i>ip</span>
          <span><i class="dot" style="background:#c2410c"></i>email</span>
          <span><i class="dot" style="background:#be185d"></i>social_profile</span>
          <span><i class="dot" style="background:#6b7280"></i>event</span>
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
    net = Network(height="760px", width="100%", bgcolor="#0b1020", font_color="#e5e7eb", directed=True, heading=title)
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
