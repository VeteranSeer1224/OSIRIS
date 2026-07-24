"""
OSIRIS — Conference XAI Analyst Dashboard Generator
Generates a standalone, offline, dark-themed HTML dashboard with glassmorphism design.
Contains all 10 required sections for auditable, deterministic explainable AI.
"""

import html as html_mod
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _escape(val: Any) -> str:
    if val is None:
        return ""
    return html_mod.escape(str(val))


def _number(value: Any, default: float = 0.0) -> float:
    """Coerce untrusted numeric display values without allowing template errors."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def generate_dashboard_html(
    raw_scan: Dict[str, Any],
    dossier: Dict[str, Any],
    explanation_cards: Dict[str, Any],
    report: Dict[str, Any],
    lineage: Dict[str, Any],
    output_path: Path,
) -> Path:
    target = _escape(dossier.get("target") or raw_scan.get("target") or "Unknown Target")
    score = _number(dossier.get("risk_score", 0))
    level = _escape((dossier.get("risk_level") or "UNKNOWN").upper())
    score_mode = _escape((dossier.get("score_mode") or "UNKNOWN").upper())
    
    scoring_metadata = dossier.get("scoring_metadata", {})
    intercept = _number(scoring_metadata.get("intercept", 15.0), 15.0)
    scorer_version = _escape(scoring_metadata.get("scorer_version", "1.0.0"))
    evidence_sufficiency = _number(scoring_metadata.get("evidence_sufficiency", 1.0), 1.0)
    abstain = scoring_metadata.get("abstain", False)

    # Audit gate info
    audit_gate = report.get("audit_gate", {})
    gate_status = _escape(audit_gate.get("status", "UNKNOWN"))
    failed_conds = audit_gate.get("failed_conditions", [])

    # Card info
    cards = explanation_cards.get("cards", [])
    matched_card = next((c for c in cards if c.get("entity") == dossier.get("target")), cards[0] if cards else {})
    fairness = matched_card.get("fairness_check", {})
    robustness = matched_card.get("robustness_check", {})

    # Build Waterfall HTML
    contributions = scoring_metadata.get("contributions", [])
    waterfall_rows = []
    running_sum = intercept
    waterfall_rows.append(f"""
        <div class="waterfall-bar-row">
            <span class="w-label">Base Intercept (Prior)</span>
            <div class="w-track">
                <div class="w-bar base" style="width: min(100%, {max(0, intercept)}%)">{intercept:.2f}</div>
            </div>
            <span class="w-val">+{intercept:.2f}</span>
        </div>
    """)

    for c in contributions:
        c_name = _escape(c.get("feature", "unknown"))
        c_pts = _number(c.get("contribution_points", 0.0))
        if abs(c_pts) < 0.001:
            continue
        running_sum += c_pts
        bar_class = "pos" if c_pts > 0 else "neg"
        bar_width = min(100, abs(c_pts) * 2)
        waterfall_rows.append(f"""
            <div class="waterfall-bar-row" title="{_escape(c.get('plain_language', ''))}">
                <span class="w-label">{c_name}</span>
                <div class="w-track">
                    <div class="w-bar {bar_class}" style="width: {bar_width}%">{c_pts:+.2f}</div>
                </div>
                <span class="w-val">{c_pts:+.2f}</span>
            </div>
        """)
    waterfall_rows.append(f"""
        <div class="waterfall-bar-row total">
            <span class="w-label">Final Risk Score</span>
            <div class="w-track">
                <div class="w-bar total" style="width: min(100%, {score}%)">{score}</div>
            </div>
            <span class="w-val">={score} ({level})</span>
        </div>
    """)

    # Build Evidence Ledger Table
    ledger_rows = []
    entities_by_type: dict[str, list[dict[str, Any]]] = {}
    for ent in raw_scan.get("entities", []):
        if isinstance(ent, dict):
            e_type = ent.get("type", "unknown")
            entities_by_type.setdefault(e_type, []).append(ent)

    risk_features = dossier.get("risk_features", [])
    for rf in risk_features:
        if not isinstance(rf, dict):
            continue
        f_name = _escape(rf.get("feature", ""))
        f_val = _escape(rf.get("value", ""))
        f_norm = _number(rf.get("normalized_value", 0.0))
        f_wt = _number(rf.get("weight", 0.0))
        f_pts = _number(rf.get("contribution_points", 0.0))
        if f_pts is None:
            f_pts = f_norm * f_wt if f_norm is not None else 0.0
        f_desc = _escape(rf.get("plain_language", ""))

        # Try linking to evidence sightings
        matching_evs = []
        for e_list in entities_by_type.values():
            for e in e_list:
                # simple matching heuristic for ledger linkage
                if f_name.startswith(e.get("type", "")) or e.get("type", "") in f_name:
                    matching_evs.append(e)

        ev_html = []
        if matching_evs:
            for e in matching_evs[:3]:
                e_id = _escape(e.get("evidence_id", "N/A"))
                e_val = _escape(e.get("value", ""))
                e_src = _escape(e.get("source_module", e.get("source", "recon")))
                ev_html.append(f"<code>{e_id}</code> ({e_val} via {e_src})")
        else:
            ev_html.append("<code>dossier-derived</code>")

        ledger_rows.append(f"""
            <tr>
                <td><strong>{f_name}</strong></td>
                <td>{f_val}</td>
                <td>{f_norm:.4f}</td>
                <td>{f_wt:+.2f}</td>
                <td><strong style="color: {'#f87171' if f_pts > 0 else '#60a5fa'}">{f_pts:+.2f}</strong></td>
                <td>{f_desc}</td>
                <td><div class="ev-list">{'<br/>'.join(ev_html)}</div></td>
            </tr>
        """)

    # Build Why / Why Not
    why_rows = []
    why_not_rows = []
    for rf in risk_features:
        if not isinstance(rf, dict):
            continue
        f_name = _escape(rf.get("feature", ""))
        f_pts = _number(rf.get("contribution_points", 0.0))
        f_desc = _escape(rf.get("plain_language", ""))
        if f_pts > 0.01:
            why_rows.append(f"<li><strong>{f_name} (+{f_pts:.2f} pts):</strong> {f_desc}</li>")
        else:
            why_not_rows.append(f"<li><strong>{f_name} ({f_pts:+.2f} pts):</strong> {f_desc}</li>")

    # Build Counterfactuals
    cf_rows = []
    if score < 25:
        target_bound, target_lvl, needed_pts = 25, "MEDIUM", 25 - score
    elif score < 50:
        target_bound_up, target_lvl_up, needed_pts_up = 50, "HIGH", 50 - score
        target_bound_dn, target_lvl_dn, needed_pts_dn = 24, "LOW", score - 24
        cf_rows.append(f"<li>To drop to <strong>{target_lvl_dn}</strong> (&le; {target_bound_dn}), reduce risk score by <strong>{needed_pts_dn:.2f} points</strong>.</li>")
        target_bound, target_lvl, needed_pts = target_bound_up, target_lvl_up, needed_pts_up
    elif score < 75:
        target_bound_up, target_lvl_up, needed_pts_up = 75, "CRITICAL", 75 - score
        target_bound_dn, target_lvl_dn, needed_pts_dn = 49, "MEDIUM", score - 49
        cf_rows.append(f"<li>To drop to <strong>{target_lvl_dn}</strong> (&le; {target_bound_dn}), reduce risk score by <strong>{needed_pts_dn:.2f} points</strong>.</li>")
        target_bound, target_lvl, needed_pts = target_bound_up, target_lvl_up, needed_pts_up
    else:
        target_bound, target_lvl, needed_pts = 74, "HIGH", score - 74
        cf_rows.append(f"<li>To drop from CRITICAL to <strong>{target_lvl}</strong> (&le; {target_bound}), reduce risk score by <strong>{needed_pts:.2f} points</strong>.</li>")
        needed_pts = -1 # skip increase

    if needed_pts > 0:
        cf_rows.append(f"<li>To reach <strong>{target_lvl}</strong> (&ge; {target_bound}), risk score must increase by <strong>{needed_pts:.2f} points</strong>.</li>")

    # Find single features that could flip boundary
    for rf in risk_features:
        if not isinstance(rf, dict):
            continue
        f_name = _escape(rf.get("feature", ""))
        f_pts = _number(rf.get("contribution_points", 0.0))
        if abs(f_pts) >= abs(needed_pts) and needed_pts != -1:
            cf_rows.append(f"<li>&rarr; Eliminating feature <code>{f_name}</code> ({f_pts:+.2f} pts) alone would cross a risk level threshold.</li>")

    # Fairness Table
    fairness_details = fairness.get("variant_details", [])
    fairness_rows = []
    for fd in fairness_details:
        if not isinstance(fd, dict):
            continue
        var_name = _escape(fd.get("variant", ""))
        orig_s = _number(fd.get("original_score", 0))
        pert_s = _number(fd.get("perturbed_score", 0))
        delta_s = _number(fd.get("delta", 0.0))
        flip_s = fd.get("decision_changed", False)
        fields_c = _escape(", ".join(fd.get("fields_changed", [])))
        fairness_rows.append(f"""
            <tr>
                <td><strong>{var_name}</strong></td>
                <td>{orig_s} &rarr; {pert_s}</td>
                <td><strong>{delta_s:.2f}</strong></td>
                <td><span class="badge {'badge-red' if flip_s else 'badge-green'}">{'FLIPPED' if flip_s else 'STABLE'}</span></td>
                <td><small>{fields_c}</small></td>
            </tr>
        """)
    if not fairness_rows:
        fairness_rows.append("<tr><td colspan='5'>No paired sensitivity test variant details recorded.</td></tr>")

    # Robustness criteria
    rob_crit = robustness.get("pass_criteria", {})
    fairness_passed = (
        fairness.get("passed") is True
        and _number(fairness.get("evaluated_variants"), 0) > 0
    )
    robustness_passed = (
        robustness.get("passed") is True
        and _number(robustness.get("evaluated_variants"), 0) > 0
    )
    rob_delta_ok = rob_crit.get("delta_ok", False)
    rob_no_flip = rob_crit.get("no_decision_flip", not robustness.get("decision_flipped", False))
    rob_stab_ok = rob_crit.get("stability_ok", _number(robustness.get("feature_stability"), 0) >= 0.5)

    # Lineage Rows
    model_meta = dossier.get("model_metadata", {})
    hashes = lineage.get("artifact_hashes", {})
    hash_rows = []
    for k, h in hashes.items():
        hash_rows.append(f"<tr><td><code>{_escape(k)}</code></td><td><code>{_escape(h)}</code></td></tr>")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
    <title>OSIRIS XAI Analyst Dashboard — {target}</title>
    <style>
        :root {{
            --bg-main: #0a0e1a;
            --bg-panel: rgba(17, 24, 39, 0.7);
            --border-panel: rgba(255, 255, 255, 0.1);
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-pos: #ef4444;
            --accent-neg: #3b82f6;
            --accent-ok: #10b981;
            --accent-warn: #f59e0b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-main);
            color: var(--text-main);
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; display: grid; gap: 24px; }}
        .header-panel {{
            background: var(--bg-panel);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-panel);
            border-radius: 16px;
            padding: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
        }}
        .header-title h1 {{ font-size: 28px; font-weight: 700; margin-bottom: 4px; }}
        .header-title p {{ color: var(--text-muted); font-size: 14px; }}
        .header-stats {{ display: flex; gap: 20px; align-items: center; }}
        .stat-box {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-panel);
            border-radius: 12px;
            padding: 12px 20px;
            text-align: center;
        }}
        .stat-box .label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; }}
        .stat-box .val {{ font-size: 24px; font-weight: 700; }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-green {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #059669; }}
        .badge-yellow {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #d97706; }}
        .badge-red {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #dc2626; }}
        .badge-blue {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #2563eb; }}
        
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
        @media (max-width: 1024px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
        
        .panel {{
            background: var(--bg-panel);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-panel);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.37);
        }}
        .panel h2 {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-panel);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        /* Waterfall Chart */
        .waterfall-bar-row {{
            display: grid;
            grid-template-columns: 240px 1fr 80px;
            align-items: center;
            gap: 12px;
            margin-bottom: 8px;
            font-size: 13px;
        }}
        .w-track {{
            background: rgba(0, 0, 0, 0.4);
            border-radius: 6px;
            height: 20px;
            overflow: hidden;
            display: flex;
            align-items: center;
            padding: 2px;
        }}
        .w-bar {{
            height: 100%;
            border-radius: 4px;
            font-size: 11px;
            display: flex;
            align-items: center;
            padding-left: 6px;
            color: #fff;
            font-weight: 600;
        }}
        .w-bar.base {{ background: #4b5563; }}
        .w-bar.pos {{ background: var(--accent-pos); }}
        .w-bar.neg {{ background: var(--accent-neg); }}
        .w-bar.total {{ background: #8b5cf6; }}
        .waterfall-bar-row.total {{ font-weight: 700; border-top: 1px solid var(--border-panel); padding-top: 8px; margin-top: 8px; }}
        
        /* Tables */
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }}
        th {{ color: var(--text-muted); font-weight: 600; background: rgba(0, 0, 0, 0.2); }}
        tr:hover td {{ background: rgba(255, 255, 255, 0.03); }}
        code {{ background: rgba(0, 0, 0, 0.5); padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #93c5fd; }}
        
        .ev-list {{ max-height: 80px; overflow-y: auto; font-size: 11px; }}
        ul {{ padding-left: 20px; }}
        li {{ margin-bottom: 8px; font-size: 13px; }}
        
        .ethics-banner {{
            background: linear-gradient(90deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.8) 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 16px 20px;
            font-size: 13px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- 10. Ethics Banner -->
        <div class="ethics-banner">
            <div>
                <strong>STAGE 0 ETHICAL SCOPE:</strong> Passive reconnaissance &amp; explainable profiling only.
                Target: <code>{target}</code> | Scope: Authorized Research / Self-Assessment.
            </div>
            <span class="badge badge-blue">PASSIVE COLLECTION</span>
        </div>

        <!-- 1. Decision Header -->
        <div class="header-panel">
            <div class="header-title">
                <h1>OSIRIS XAI Analyst Dashboard</h1>
                <p>Target Entity: <strong>{target}</strong> | Profiled At: {_escape(dossier.get('profiled_at', 'unknown'))}</p>
            </div>
            <div class="header-stats">
                <div class="stat-box">
                    <div class="label">Score Mode</div>
                    <div class="val" style="font-size: 16px;"><span class="badge {'badge-green' if score_mode == 'REAL' else ('badge-yellow' if score_mode == 'STUB' else 'badge-red')}">{score_mode}</span></div>
                </div>
                <div class="stat-box">
                    <div class="label">Evidence Sufficiency</div>
                    <div class="val" style="font-size: 18px; color: {'#10b981' if evidence_sufficiency >= 0.6 else '#fbbf24'}">{evidence_sufficiency*100:.0f}%</div>
                </div>
                <div class="stat-box">
                    <div class="label">Abstain Status</div>
                    <div class="val" style="font-size: 16px;"><span class="badge {'badge-red' if abstain else 'badge-green'}">{'ABSTAINED' if abstain else 'EVALUATED'}</span></div>
                </div>
                <div class="stat-box">
                    <div class="label">Risk Level</div>
                    <div class="val" style="color: {'#ef4444' if level in ('HIGH', 'CRITICAL') else ('#f59e0b' if level == 'MEDIUM' else '#10b981')}">{level}</div>
                </div>
                <div class="stat-box">
                    <div class="label">Risk Score</div>
                    <div class="val" style="font-size: 28px; color: {'#ef4444' if score >= 75 else ('#f59e0b' if score >= 50 else '#34d399')}">{score} <span style="font-size: 14px; font-weight: normal; color: var(--text-muted)">/ 100</span></div>
                </div>
            </div>
        </div>

        <!-- 8. Audit Gate Banner -->
        <div class="panel" style="border-color: {'#059669' if gate_status == 'PASS' else '#dc2626'}; background: {'rgba(6, 78, 59, 0.3)' if gate_status == 'PASS' else 'rgba(127, 29, 29, 0.3)'};">
            <h2 style="border-bottom: none; margin-bottom: 0;">
                <span>Stage 4 Audit Gate Verification: <strong style="color: {'#34d399' if gate_status == 'PASS' else '#f87171'}">{gate_status}</strong></span>
                <span class="badge {'badge-green' if gate_status == 'PASS' else 'badge-red'}">GATE {gate_status}</span>
            </h2>
            {f'<ul style="margin-top: 12px; color: #fca5a5;">' + ''.join(f'<li>{_escape(c)}</li>' for c in failed_conds) + '</ul>' if failed_conds else '<p style="margin-top: 8px; font-size: 13px; color: #a7f3d0;">All required explanation cards are present, reconstructable within tolerance, and passed paired sensitivity and robustness tests.</p>'}
        </div>

        <!-- 2. Score Waterfall -->
        <div class="panel">
            <h2>
                <span>Exact Score Waterfall Decomposition</span>
                <span style="font-size: 12px; font-weight: normal; color: var(--text-muted)">Deterministic Engine: v{scorer_version} (Intercept + Sum = Score)</span>
            </h2>
            <div style="margin-top: 16px;">
                {''.join(waterfall_rows)}
            </div>
        </div>

        <!-- 4. Why / Why Not & 5. Counterfactuals -->
        <div class="grid-2">
            <div class="panel">
                <h2>Top Positive Risk Factors (Why)</h2>
                <ul>{''.join(why_rows) if why_rows else '<li>No positive risk contributors found.</li>'}</ul>
                <h2 style="margin-top: 20px;">Mitigating &amp; Zeroed Factors (Why Not)</h2>
                <ul>{''.join(why_not_rows) if why_not_rows else '<li>No mitigating factors found.</li>'}</ul>
            </div>
            <div class="panel">
                <h2>Counterfactual Sensitivity Analysis</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">Minimal modifications required to cross boundary thresholds:</p>
                <ul>{''.join(cf_rows) if cf_rows else '<li>No counterfactual transitions available.</li>'}</ul>
            </div>
        </div>

        <!-- 6. Fairness Tests & 7. Robustness Tests -->
        <div class="grid-2">
            <div class="panel">
                <h2>
                    <span>Fairness Paired Sensitivity Test</span>
                    <span class="badge {'badge-green' if fairness_passed else 'badge-red'}">{'PASSED' if fairness_passed else 'INCONCLUSIVE / FLAGGED'}</span>
                </h2>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Evaluates score deltas under identity, geo-temporal, and domain alterations (Threshold &le; {fairness.get('threshold', 10)}):</p>
                <table>
                    <thead>
                        <tr><th>Variant</th><th>Scores</th><th>&Delta;</th><th>Status</th><th>Fields Modified</th></tr>
                    </thead>
                    <tbody>{''.join(fairness_rows)}</tbody>
                </table>
            </div>
            <div class="panel">
                <h2>
                    <span>Compound Robustness Verification</span>
                    <span class="badge {'badge-green' if robustness_passed else 'badge-red'}">{'PASSED' if robustness_passed else 'INCONCLUSIVE / FAILED'}</span>
                </h2>
                <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">Evaluates structural stability and feature ranking consistency across {robustness.get('evaluated_variants', 0)} perturbations:</p>
                <ul>
                    <li><strong>Max Score Delta:</strong> {robustness.get('max_score_delta', 0):.2f} / Threshold {robustness.get('threshold', 10)} <span class="badge {'badge-green' if rob_delta_ok else 'badge-red'}">{'OK' if rob_delta_ok else 'EXCEEDED'}</span></li>
                    <li><strong>Decision Level Flip:</strong> {'YES (FLIPPED)' if not rob_no_flip else 'NO (STABLE)'} <span class="badge {'badge-green' if rob_no_flip else 'badge-red'}">{'OK' if rob_no_flip else 'FLIPPED'}</span></li>
                    <li><strong>Top-K Feature Ranking Stability:</strong> {robustness.get('feature_stability', 1.0)*100:.1f}% (Top-5 Jaccard) <span class="badge {'badge-green' if rob_stab_ok else 'badge-red'}">{'OK (&ge;50%)' if rob_stab_ok else 'LOW (<50%)'}</span></li>
                </ul>
            </div>
        </div>

        <!-- 3. Evidence Ledger -->
        <div class="panel">
            <h2>Evidence Ledger &amp; Feature Provenance</h2>
            <table>
                <thead>
                    <tr>
                        <th>Feature Name</th>
                        <th>Raw Value</th>
                        <th>Norm</th>
                        <th>Weight</th>
                        <th>Points</th>
                        <th>Plain Language Description</th>
                        <th>Evidence Sightings (OSINT Provenance)</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(ledger_rows) if ledger_rows else '<tr><td colspan="7">No risk features recorded in dossier.</td></tr>'}
                </tbody>
            </table>
        </div>

        <!-- 9. Lineage Manifest -->
        <div class="panel">
            <h2>Cryptographic Lineage &amp; Execution Manifest</h2>
            <div class="grid-2" style="margin-top: 12px; font-size: 13px;">
                <div>
                    <p><strong>Pipeline Schema Version:</strong> <code>{_escape(lineage.get('schema_version', '1.0'))}</code></p>
                    <p><strong>Run ID:</strong> <code>{_escape(lineage.get('run_id', 'unknown'))}</code></p>
                    <p><strong>Generated At:</strong> {_escape(lineage.get('generated_at', 'unknown'))}</p>
                    <p><strong>Model Backend:</strong> <code>{_escape(model_meta.get('backend', 'unknown'))}</code> ({_escape(model_meta.get('model_name', 'dry_run'))})</p>
                    <p><strong>Prompt Version:</strong> <code>{_escape(model_meta.get('prompt_version', 'v1.0'))}</code></p>
                </div>
                <div>
                    <table>
                        <thead><tr><th>Artifact Name</th><th>SHA-256 Hash</th></tr></thead>
                        <tbody>{''.join(hash_rows) if hash_rows else '<tr><td colspan="2">No artifact hashes recorded.</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""
    output_path.write_text(html_content, encoding="utf-8")
    return output_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate OSIRIS XAI Dashboard")
    parser.add_argument("--output-dir", required=True, help="Path to pipeline output directory containing artifacts")
    args = parser.parse_args()
    
    out_dir = Path(args.output_dir)
    raw_scan = json.loads((out_dir / "raw_scan.json").read_text(encoding="utf-8"))
    dossier = json.loads((out_dir / "dossier.json").read_text(encoding="utf-8"))
    explanation_cards = json.loads((out_dir / "explanation_cards.json").read_text(encoding="utf-8"))
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    
    lineage_file = out_dir / "lineage.json"
    if lineage_file.exists():
        lineage = json.loads(lineage_file.read_text(encoding="utf-8"))
    else:
        lineage = {
            "schema_version": "1.0",
            "run_id": "manual-run",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifact_hashes": {},
        }
        
    dashboard_path = out_dir / "xai_dashboard.html"
    generate_dashboard_html(raw_scan, dossier, explanation_cards, report, lineage, dashboard_path)
    print(f"XAI Dashboard generated at: {dashboard_path}")
