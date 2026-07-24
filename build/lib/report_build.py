import html as html_mod
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from schema_validation import validate_report
from release_policy import ReleaseContext, evaluate_release, require_release
import logging

logger = logging.getLogger(__name__)

SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
    "info": 1
}


def classify_entity(entity):
    entity_type = entity.get("type", "")

    if entity_type in ["ip", "domain"]:
        return "infrastructure"

    if entity_type in ["email", "username", "social_profile"]:
        return "identity"

    if entity_type in ["organization", "address", "phone"]:
        return "organization"

    if entity_type in ["technology", "certificate"]:
        return "technology"

    return "other"


def build_summary(scan):
    entities = scan.get("entities", [])
    events = scan.get("events", [])

    entity_counter: Counter[str] = Counter()

    for entity in entities:
        entity_counter[entity["type"]] += 1

    return {
        "target": scan.get("target"),
        "scan_date": scan.get("scan_date"),
        "total_entities": len(entities),
        "total_events": len(events),
        "entity_breakdown": dict(entity_counter)
    }


CATEGORY_FEATURE_MAP = {
    "infrastructure": ["subdomain_count", "open_ports_sensitive", "recent_infrastructure_churn", "aws_infrastructure", "ipv6_enabled", "cloudflare_proxied", "entity_count"],
    "identity": ["exposed_email_count", "breach_appearance_count"],
    "technology": ["open_ports_sensitive", "aws_infrastructure", "cloudflare_proxied", "deliberate_test_target"],
    "organization": ["unknown_registrar", "privacy_registrar_used", "domain_age_days", "entity_count"],
    "other": ["injection_attempt_detected", "entity_count"]
}


def build_findings(scan, dossier=None, explanation_cards=None):
    findings = []
    entities = scan.get("entities", [])
    grouped: dict[str, list[dict[str, Any]]] = {}

    for entity in entities:
        category = classify_entity(entity)
        grouped.setdefault(category, [])
        grouped[category].append(entity)

    # Extract risk features from dossier if available
    dossier_features = dossier.get("risk_features", []) if isinstance(dossier, dict) else []
    cards_list = explanation_cards.get("cards", []) if isinstance(explanation_cards, dict) else []
    confidence = cards_list[0].get("confidence", 0.85) if cards_list and isinstance(cards_list[0], dict) else 0.85

    for category, values in grouped.items():
        # Match XAI features to category
        relevant_feature_names = CATEGORY_FEATURE_MAP.get(category, ["entity_count"])
        matching_features = [
            f for f in dossier_features
            if isinstance(f, dict) and (f.get("feature") in relevant_feature_names or f.get("feature") == "injection_attempt_detected")
        ]

        # Determine dynamic severity based on XAI feature attribution and heuristics
        severity = "info"
        if any(isinstance(f, dict) and f.get("feature") == "injection_attempt_detected" and f.get("value") in (1, True, "1") for f in matching_features):
            severity = "critical"
        elif any(isinstance(f, dict) and float(f.get("weight", 0) or 0) >= 0.3 for f in matching_features):
            severity = "high"
        elif any(isinstance(f, dict) and float(f.get("weight", 0) or 0) >= 0.1 for f in matching_features) or len(values) >= 10:
            severity = "medium"
        elif any(isinstance(f, dict) and float(f.get("weight", 0) or 0) < 0 for f in matching_features):
            severity = "low"
        elif category in ("infrastructure", "identity") and len(values) > 0:
            severity = "medium"

        # Construct comprehensive natural-language XAI explanation for the finding
        if matching_features:
            feat_details = "; ".join(f"{f.get('feature', 'unknown')} (weight {float(f.get('weight', 0) or 0):+.2f})" for f in matching_features)
            pl_details = " ".join(str(f.get("plain_language", "")).strip() for f in matching_features if f.get("plain_language"))
            xai_explanation = (
                f"{category.title()} perimeter profile ({len(values)} asset{'s' if len(values) != 1 else ''}) evaluated with XAI attribution: "
                f"{feat_details}. {pl_details}".strip()
            )
        elif isinstance(dossier, dict):
            risk_lvl = str(dossier.get("risk_level", "UNKNOWN")).upper()
            risk_sc = dossier.get("risk_score", 0)
            xai_explanation = (
                f"Discovered {len(values)} {category} asset(s) contributing to the target's overall {risk_lvl} risk rating ({risk_sc}/100). "
                f"Each asset expands the external attack footprint and reconnaissance profile."
            )
        else:
            xai_explanation = (
                f"Discovered {len(values)} {category} asset(s) during Stage 1 reconnaissance. "
                f"Run pipeline with Stage 2/4 enabled for deep XAI feature attribution and scoring."
            )

        # Enrich items — only include xai_context if backed by matching features.
        # Do NOT fabricate analysis claims ("evaluated for ports", "evaluated for CVEs")
        # when no corresponding feature data exists.
        enriched_items = []
        matching_feature_names = {f.get("feature", "") for f in matching_features}
        for item in values:
            if not isinstance(item, dict):
                enriched_items.append(item)
                continue
            item_copy = dict(item)
            val_str = str(item_copy.get("value", ""))

            if matching_features:
                # Build context only from actual feature evidence
                feat_summaries = [str(f.get("plain_language", f.get("feature", ""))) for f in matching_features if f.get("plain_language")]
                if feat_summaries:
                    item_copy["xai_context"] = f"Asset ({val_str}): " + "; ".join(feat_summaries[:2])
                else:
                    item_copy["xai_context"] = f"Asset ({val_str}) — contributing feature data available."
            else:
                item_copy["xai_context"] = f"Asset ({val_str}) — not evaluated (no corresponding feature data)."

            enriched_items.append(item_copy)

        findings.append({
            "title": f"{category.title()} Assets Discovered",
            "severity": severity,
            "count": len(enriched_items),
            "category": category,
            "xai_explanation": xai_explanation,
            "xai_confidence": confidence,
            "attributed_features": matching_features,
            "items": enriched_items
        })

    return findings


def calculate_risk(findings):
    score = 0

    for finding in findings:
        severity = finding.get("severity", "info")
        score += SEVERITY_SCORES.get(severity, 1)

    if score >= 50:
        rating = "critical"
    elif score >= 30:
        rating = "high"
    elif score >= 15:
        rating = "medium"
    else:
        rating = "low"

    return {
        "score": score,
        "rating": rating
    }


def build_report(
    scan,
    dossier=None,
    explanation_cards=None,
    case_authorization=None,
    evidence_integrity=None,
    *,
    release_context: ReleaseContext | None = None,
):
    """Build Stage 5 report. When a dossier is supplied, XAI cards are mandatory.

    The audit gate is checked but does NOT block report generation.
    A failed gate produces a report with prominent failure status.
    """
    summary = build_summary(scan)
    findings = build_findings(scan, dossier=dossier, explanation_cards=explanation_cards)
    audit_gate_result = None

    if dossier is not None:
        risk = {
            "score": dossier.get("risk_score", 0),
            "rating": (dossier.get("risk_level") or "UNKNOWN").lower(),
            "source": "OSIRIS-Mind",
            "score_mode": dossier.get("score_mode", "UNKNOWN"),
        }
        if explanation_cards is None:
            raise ValueError(
                "Stage 4 audit gate: dossier risk scores require explanation_cards.json"
            )
        audit_gate_result = _assert_explanation_gate(dossier, explanation_cards)
    else:
        risk = calculate_risk(findings)
        risk["source"] = "entity_severity_heuristic"

    xai_audit = _build_xai_audit_section(dossier, explanation_cards)

    report = {
        "report_metadata": {
            "generated_at": datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generator": "OSIRIS",
            "version": "1.0"
        },
        "summary": summary,
        "risk_assessment": risk,
        "findings": findings,
        "events": scan.get("events", []),
        "raw_statistics": {
            "entity_count": len(scan.get("entities", [])),
            "event_count": len(scan.get("events", []))
        }
    }

    if audit_gate_result is not None:
        report["audit_gate"] = audit_gate_result

    if dossier is not None:
        report["dossier_summary"] = {
            "target": dossier.get("target"),
            "executive_summary": dossier.get("executive_summary", ""),
            "risk_level": dossier.get("risk_level"),
            "profiled_at": dossier.get("profiled_at"),
            "score_mode": dossier.get("score_mode", "UNKNOWN"),
        }

    if xai_audit is not None:
        report["xai_audit"] = xai_audit

    if case_authorization is not None:
        report["case_authorization"] = case_authorization
    if evidence_integrity is not None:
        report["evidence_integrity"] = evidence_integrity

    # Every report is evaluated by the same policy.  Legacy pipeline output
    # remains available only as a clearly marked technical-review artifact.
    report["release_decision"] = evaluate_release(release_context).as_dict()

    disclaimer_path = Path(__file__).resolve().parent / "DISCLAIMER.md"
    if disclaimer_path.exists():
        report["disclaimer_appendix"] = disclaimer_path.read_text(encoding="utf-8")
    else:
        report["disclaimer_appendix"] = None

    validate_report(report)

    return report


def _assert_explanation_gate(dossier, explanation_cards):
    """Real audit gate: checks card existence, score match, fairness, and robustness.

    Returns an AuditGateResult dict with status PASS, FAIL, or BLOCKED.
    Does NOT raise an exception — the report is still generated but with
    the gate result prominently displayed.
    """
    target = dossier.get("target")
    dossier_score = dossier.get("risk_score", 0)
    cards = explanation_cards.get("cards", []) if isinstance(explanation_cards, dict) else []

    failed_conditions: List[str] = []
    matched_card = None
    for card in cards:
        if card.get("entity") == target:
            matched_card = card
            break

    if matched_card is None:
        failed_conditions.append(f"No explanation card found for target '{target}'")
        return {
            "status": "BLOCKED",
            "passed": False,
            "failed_conditions": failed_conditions,
        }

    # The explanation is authoritative only when it is an exact rendering of
    # the deterministic dossier decision; a tolerance masks broken lineage.
    card_score = matched_card.get("risk_score", -1)
    if card_score != dossier_score:
        failed_conditions.append(
            f"Card score ({card_score}) does not match dossier score ({dossier_score})"
        )

    metadata = dossier.get("scoring_metadata")
    if not isinstance(metadata, dict):
        failed_conditions.append("Scoring metadata is missing")
    else:
        try:
            intercept = float(metadata["intercept"])
            contributions = metadata["contributions"]
            total = intercept + sum(float(item["contribution_points"]) for item in contributions)
            reconstructed = max(0, min(100, round(total)))
            if reconstructed != dossier_score:
                failed_conditions.append(
                    f"Score reconstruction ({reconstructed}) does not match dossier score ({dossier_score})"
                )
            declared_raw = metadata.get("risk_score_raw")
            if declared_raw is not None and abs(float(declared_raw) - total) > 1e-9:
                failed_conditions.append("Signed contribution total does not match declared raw score")
        except (KeyError, TypeError, ValueError):
            failed_conditions.append("Scoring metadata is incomplete or invalid")

    # Fairness check
    fairness = matched_card.get("fairness_check")
    if not _audit_control_passed(fairness):
        failed_conditions.append("Fairness sensitivity test missing, unevaluated, or failed")

    # Robustness check
    robustness = matched_card.get("robustness_check")
    if not _audit_control_passed(robustness):
        failed_conditions.append("Robustness check missing, unevaluated, or failed")

    if failed_conditions:
        return {
            "status": "FAIL",
            "passed": False,
            "failed_conditions": failed_conditions,
        }

    return {
        "status": "PASS",
        "passed": True,
        "failed_conditions": [],
    }


def _audit_control_passed(control) -> bool:
    if not isinstance(control, dict) or control.get("passed") is not True:
        return False
    try:
        return int(control.get("evaluated_variants", 0)) > 0
    except (TypeError, ValueError):
        return False


def _build_xai_audit_section(dossier, explanation_cards):
    if explanation_cards is None:
        return None

    cards = explanation_cards.get("cards", [])
    return {
        "schema_version": explanation_cards.get("schema_version", "1.0"),
        "generated_at": explanation_cards.get("generated_at"),
        "card_count": explanation_cards.get("card_count", len(cards)),
        "overall_fairness_passed": bool(cards) and all(
            isinstance(card, dict) and _audit_control_passed(card.get("fairness_check"))
            for card in cards
        ),
        "overall_robustness_passed": bool(cards) and all(
            isinstance(card, dict) and _audit_control_passed(card.get("robustness_check"))
            for card in cards
        ),
        "cards": cards,
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def export_misp(
    report,
    output_path,
    *,
    release_context: ReleaseContext | None = None,
):
    """
    Exports the report findings to a MISP-compatible JSON format.

    This is an external dissemination path and is never available for a
    blocked, stub, fallback, unsigned, or unauthorized report.
    """
    require_release(report, "MISP export", context=release_context)
    misp_event = {
        "Event": {
            "info": f"OSIRIS Scan - {report['summary']['target']}",
            "date": report['summary']['scan_date'][:10],
            "analysis": "2",
            "threat_level_id": "3",
            "Attribute": []
        }
    }
    
    # Map findings to MISP attributes
    for finding in report.get("findings", []):
        for item in finding.get("items", []):
            val_str = str(item.get("value", ""))
            if "[REDACTED-INJECTION]" in val_str:
                continue
            attr = {
                "type": "other",
                "value": val_str,
                "comment": f"Source: {item.get('source', 'unknown')}"
            }
            if item.get("type") == "ip":
                attr["type"] = "ip-dst"
            elif item.get("type") in ["domain", "subdomain"]:
                attr["type"] = "domain"
            elif item.get("type") == "email":
                attr["type"] = "email-src"
            elif item.get("type") == "url":
                attr["type"] = "url"
                
            misp_event["Event"]["Attribute"].append(attr)

    save_json(misp_event, output_path)
    return output_path


def export_pdf(
    report,
    output_path,
    *,
    release_context: ReleaseContext | None = None,
):
    """
    Exports the report to PDF using WeasyPrint.
    Falls back to a warning and basic text file if not installed.

    All attacker-controlled values are escaped with html.escape() to prevent XSS.
    """
    import html as html_mod
    target = html_mod.escape(str(report.get("summary", {}).get("target", "Unknown")))
    release = evaluate_release(release_context)
    html_content = f"<html><head><title>OSIRIS Report: {target}</title></head>"
    html_content += f"<body><h1>OSIRIS Report: {target}</h1>"

    if not release.passed:
        html_content += (
            "<div style='background:#7f1d1d;color:white;padding:16px;border-radius:8px;"
            "margin:16px 0;font-size:18px;text-align:center;'><strong>NOT CLEARED FOR "
            "DISSEMINATION</strong><br/>AUDIT STATUS: FAILED OR BLOCKED<br/>FOR TECHNICAL "
            "REVIEW ONLY</div>"
        )
        html_content += "<h2>Release-policy reasons</h2><ul>"
        for reason in release.reasons:
            html_content += f"<li>{html_mod.escape(reason)}</li>"
        html_content += "</ul>"

    # Audit gate banner
    gate = report.get("audit_gate")
    if gate:
        gate_status = gate.get("status", "UNKNOWN")
        if gate_status == "PASS":
            gate_color = "#16a34a"
        elif gate_status == "FAIL":
            gate_color = "#dc2626"
        else:
            gate_color = "#d97706"
        html_content += f"<div style='background:{gate_color};color:white;padding:16px;border-radius:8px;margin:16px 0;font-size:20px;text-align:center;'>"
        html_content += f"<strong>AUDIT GATE: {html_mod.escape(gate_status)}</strong>"
        if gate.get("failed_conditions"):
            html_content += "<ul style='text-align:left;font-size:14px;margin-top:8px;'>"
            for cond in gate["failed_conditions"]:
                html_content += f"<li>{html_mod.escape(str(cond))}</li>"
            html_content += "</ul>"
        html_content += "</div>"

    # Score mode badge
    score_mode = report.get("risk_assessment", {}).get("score_mode", "")
    if score_mode:
        badge_color = {"REAL": "#16a34a", "STUB": "#d97706", "FALLBACK": "#dc2626"}.get(score_mode, "#6b7280")
        html_content += f"<p><span style='background:{badge_color};color:white;padding:4px 10px;border-radius:4px;font-size:12px;'>{html_mod.escape(score_mode)}</span></p>"

    html_content += "<h2>Executive Summary</h2>"
    summary = report.get("summary", {})
    html_content += f"<p>Scan Date: {html_mod.escape(str(summary.get('scan_date', '')))}</p>"
    html_content += f"<p>Total Entities: {html_mod.escape(str(summary.get('total_entities', '')))}</p>"

    risk = report.get("risk_assessment", {})
    html_content += f"<h2>Risk Assessment</h2><p>Level: {html_mod.escape(str(risk.get('rating', '')))} (Score: {html_mod.escape(str(risk.get('score', '')))})</p>"

    xai = report.get("xai_audit")
    if xai:
        html_content += "<h2>Explainability Audit (Stage 4)</h2>"
        html_content += f"<p>Cards: {xai.get('card_count', 0)} | "
        html_content += f"Fairness passed: {xai.get('overall_fairness_passed')} | "
        html_content += f"Robustness passed: {xai.get('overall_robustness_passed')}</p>"
        for card in xai.get("cards", []):
            html_content += f"<h3>{html_mod.escape(str(card.get('entity', '')))}</h3>"
            html_content += f"<p>Score: {html_mod.escape(str(card.get('risk_score', '')))} | Confidence: {html_mod.escape(str(card.get('confidence', '')))}</p>"
            html_content += f"<p>{html_mod.escape(str(card.get('explanation', '')))}</p>"

    html_content += "<h2>Findings Appendix</h2>"
    for finding in report.get("findings", []):
        sev_color = "#dc2626" if finding.get("severity") in ("critical", "high") else ("#d97706" if finding.get("severity") == "medium" else "#2563eb")
        html_content += f"<h3>{html_mod.escape(str(finding.get('title', '')))} (<span style='color: {sev_color}; text-transform: uppercase;'>{html_mod.escape(str(finding.get('severity', 'info')))}</span>)</h3>"
        if finding.get("xai_explanation"):
            html_content += f"<p style='background: #f8fafc; padding: 8px; border-left: 4px solid {sev_color};'><strong>Explainability Analysis:</strong> {html_mod.escape(str(finding.get('xai_explanation', '')))}</p>"
        html_content += "<ul>"
        for item in finding.get("items", []):
            html_content += f"<li><strong>{html_mod.escape(str(item.get('type', '')))}:</strong> {html_mod.escape(str(item.get('value', '')))}</li>"
        html_content += "</ul>"

    if report.get("disclaimer_appendix"):
        escaped_disclaimer = html_mod.escape(report["disclaimer_appendix"])
        html_content += "<h2>Appendix: Stage 0 Ethical Scope &amp; Disclaimer</h2>"
        html_content += f"<pre style='white-space: pre-wrap; background: #f1f5f9; padding: 12px; border-radius: 6px;'>{escaped_disclaimer}</pre>"

    html_content += "</body></html>"

    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(output_path)
    except ImportError:
        logger.warning("WeasyPrint not found. Generating a basic HTML file instead of PDF.")
        out_path = Path(output_path).with_suffix(".html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return out_path

    return output_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "scan_file",
        help="raw_scan.json generated by sense_clean.py"
    )

    parser.add_argument(
        "output_file",
        help="report output path"
    )

    args = parser.parse_args()

    scan = load_json(args.scan_file)

    report = build_report(scan)

    save_json(report, args.output_file)

    print(
        f"Report written to {args.output_file}"
    )
