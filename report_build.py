import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from schema_validation import validate_report
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

    entity_counter = Counter()

    for entity in entities:
        entity_counter[entity["type"]] += 1

    return {
        "target": scan.get("target"),
        "scan_date": scan.get("scan_date"),
        "total_entities": len(entities),
        "total_events": len(events),
        "entity_breakdown": dict(entity_counter)
    }


def build_findings(scan):
    findings = []

    entities = scan.get("entities", [])

    grouped = {}

    for entity in entities:
        category = classify_entity(entity)

        grouped.setdefault(category, [])
        grouped[category].append(entity)

    for category, values in grouped.items():
        findings.append({
            "title": f"{category.title()} Assets Discovered",
            "severity": "info",
            "count": len(values),
            "category": category,
            "items": values
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


def build_report(scan):
    summary = build_summary(scan)
    findings = build_findings(scan)
    risk = calculate_risk(findings)

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

    validate_report(report)

    return report


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def export_misp(report, output_path):
    """
    Exports the report findings to a MISP-compatible JSON format.
    """
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
            attr = {
                "type": "other",
                "value": str(item.get("value", "")),
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


def export_pdf(report, output_path):
    """
    Exports the report to PDF using WeasyPrint.
    Falls back to a warning and basic text file if not installed.
    """
    target = report.get("summary", {}).get("target", "Unknown")
    html_content = f"<html><head><title>OSIRIS Report: {target}</title></head>"
    html_content += f"<body><h1>OSIRIS Report: {target}</h1>"
    
    html_content += "<h2>Executive Summary</h2>"
    summary = report.get("summary", {})
    html_content += f"<p>Scan Date: {summary.get('scan_date')}</p>"
    html_content += f"<p>Total Entities: {summary.get('total_entities')}</p>"
    
    risk = report.get("risk_assessment", {})
    html_content += f"<h2>Risk Assessment</h2><p>Level: {risk.get('rating')} (Score: {risk.get('score')})</p>"
    
    html_content += "<h2>Findings Appendix</h2>"
    for finding in report.get("findings", []):
        html_content += f"<h3>{finding.get('title')}</h3><ul>"
        for item in finding.get("items", []):
            html_content += f"<li>{item.get('type')}: {item.get('value')}</li>"
        html_content += "</ul>"
    
    html_content += "</body></html>"
    
    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(output_path)
    except ImportError:
        logger.warning("WeasyPrint not found. Generating a basic HTML file instead of PDF.")
        # Fallback to saving html, changing extension to .html
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