import csv
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

IPV4_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

ENTITY_MAP = {
    "INTERNET_NAME": "domain",
    "DOMAIN_NAME": "domain",
    "DOMAIN": "domain",
    "HOST": "domain",
    "AFFILIATE_INTERNET_NAME": "domain",
    "CO_HOSTED_SITE": "domain",
    "URL": "url",
    "URL_STATIC": "url",
    "URL_FORM": "url",
    "INTERNET_NAME_UNRESOLVED": "domain",
    "HOSTNAME": "domain",

    "IP_ADDRESS": "ip",
    "IPV6_ADDRESS": "ip",
    "AFFILIATE_IPADDR": "ip",

    "EMAILADDR": "email",
    "EMAIL_ADDRESS": "email",
    "EMAIL": "email",
    "ACCOUNT_EXTERNAL": "social_profile",
    "USERNAME": "username",

    "PHONE_NUMBER": "phone",
    "PHYSICAL_ADDRESS": "address",
    "GEOINFO": "location",

    "HUMAN_NAME": "person",
    "COMPANY_NAME": "organization",

    "BGP_AS": "asn",
    "BGP_AS_OWNER": "organization",
    "BGP_AS_MEMBER": "organization",
    "NETBLOCK_OWNER": "organization",

    "SSL_CERTIFICATE_RAW": "certificate",
    "SSL_CERTIFICATE_ISSUED": "certificate",

    "WEBSERVER_TECHNOLOGY": "technology",
    "SOFTWARE_USED": "technology",

    "DNS_TEXT": "dns_record",
    "DNS_MX": "dns_record",
    "DNS_NS": "dns_record",
    "DNS_SPF": "dns_record",
    "DNS_AAAA": "dns_record",
    "DNS_CNAME": "dns_record",
    "DNS_A": "dns_record",

    "CRYPTOCURRENCY_ADDRESS": "crypto_wallet",
}


def clean_entity_value(entity_type: str, value: str):
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    # Reject giant blobs immediately
    if len(value) > 500:
        return None

    # Reject multiline payloads
    if "\n" in value:
        return None

    # Reject JSON / Python objects
    if value.startswith("{") or value.startswith("["):
        return None

    if entity_type == "domain":
        m = DOMAIN_RE.search(value)
        return m.group(0).lower() if m else None

    if entity_type == "email":
        m = EMAIL_RE.search(value)
        return m.group(0).lower() if m else None

    if entity_type == "ip":
        # Check if value or any extracted token is a valid IPv4 or IPv6 address using ipaddress module
        for token in value.split():
            token = token.strip("()[],;\"'")
            try:
                ip_obj = ipaddress.ip_address(token)
                return str(ip_obj)
            except ValueError:
                pass
        return None

    if entity_type == "social_profile":
        return value

    return value


def get_osiris_type(sf_type):
    sf_type_upper = (sf_type or "").upper()
    sf_type_clean = sf_type_upper.replace(" ", "_")

    for key, value in ENTITY_MAP.items():
        key_clean = key.replace(" ", "_")
        if key_clean in sf_type_clean or key in sf_type_upper:
            return value

    return "unknown"


def normalize_entities(raw_data):
    entities_map = {}
    unknown_entities = []

    for item in raw_data:
        sf_type = item.get("type", "")
        raw_value = item.get("data", "")

        osiris_type = get_osiris_type(sf_type)
        sf_value = clean_entity_value(osiris_type, raw_value)

        if sf_value is None:
            continue

        if osiris_type == "unknown":
            unknown_entities.append({
                "module": item.get("module"),
                "type": sf_type or "unknown",
                "value": sf_value,
                "source": item.get("source")
            })
            continue

        key = (osiris_type, sf_value)
        sighting = {
            "module": item.get("module"),
            "source": item.get("source"),
            "sf_type": sf_type,
            "updated": item.get("updated"),
        }

        if key not in entities_map:
            evidence_id = f"ev-{hashlib.sha256(f'{osiris_type}:{sf_value}'.encode('utf-8')).hexdigest()[:16]}"
            entities_map[key] = {
                "type": osiris_type,
                "value": sf_value,
                "source_module": item.get("module"),
                "source": item.get("source"),
                "platform": None,
                "metadata": {
                    "source_module": item.get("module"),
                    "source": item.get("source"),
                    "sightings_count": 1,
                },
                "evidence_id": evidence_id,
                "evidence_sources": [sighting],
            }
        else:
            # Aggregate sightings across multiple modules discovering the same entity
            entities_map[key]["evidence_sources"].append(sighting)
            entities_map[key]["metadata"]["sightings_count"] = len(entities_map[key]["evidence_sources"])

    entities = list(entities_map.values())
    return entities, unknown_entities


def extract_events(raw_data):
    events = []

    default_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for item in raw_data:
        sf_type = item.get("type", "")
        module = item.get("module", "")
        value = clean_entity_value(
            get_osiris_type(sf_type),
            item.get("data", "")
        )

        if value is None:
            continue

        # Use the SpiderFoot-provided timestamp if available
        updated_raw = item.get("updated", "")
        if updated_raw:
            try:
                # SpiderFoot CSV format: "2026-06-29 09:51:23"
                dt = datetime.strptime(updated_raw, "%Y-%m-%d %H:%M:%S")
                event_time = dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, TypeError):
                event_time = default_time
        else:
            event_time = default_time

        sf_upper = sf_type.upper()

        event_type = None

        if "DOMAIN_REGISTRAR" in sf_upper:
            event_type = "domain_registered"
        elif "DOMAIN_WHOIS" in sf_upper:
            event_type = "whois_update"
        elif "SSL_CERTIFICATE" in sf_upper:
            event_type = "certificate_issued"
        elif "DNS" in sf_upper:
            event_type = "dns_change"
        elif "BREACH" in sf_upper:
            event_type = "breach_appearance"

        if event_type:
            events.append({
                "date": event_time,
                "type": event_type,
                "entity": value,
                "source": module,
                "detail": f"Derived from {sf_type}"
            })

    return events


def load_spiderfoot_input(path):
    """
    Load a SpiderFoot export from either a CSV or JSON file.

    SpiderFoot CSV columns: Updated, Type, Module, Source, F/P, Data
    Returns a list of dicts with keys: type, module, source, data
    """
    path = str(path)

    if path.lower().endswith(".csv"):
        rows = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip false positives if flagged
                if row.get("F/P", "0").strip() == "1":
                    continue
                rows.append({
                    "type": row.get("Type", "").strip(),
                    "module": row.get("Module", "").strip(),
                    "source": row.get("Source", "").strip(),
                    "data": row.get("Data", "").strip(),
                    "updated": row.get("Updated", "").strip(),
                })
        return rows
    else:
        # Assume JSON
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def generate_raw_scan(target, spiderfoot_input):
    if isinstance(spiderfoot_input, (str, Path)) or hasattr(spiderfoot_input, "__fspath__"):
        raw_data = load_spiderfoot_input(spiderfoot_input)
    else:
        raw_data = spiderfoot_input

    # If the input is already a processed raw_scan dict (e.g. outputs/raw_scan.json),
    # validate and return it directly instead of re-processing it as SpiderFoot data.
    if isinstance(raw_data, dict) and "entities" in raw_data:
        from case_authorization import require_same_target
        from schema_validation import validate_raw_scan
        validate_raw_scan(raw_data)
        require_same_target(target, str(raw_data.get("target", "")))
        return raw_data

    entities, unknown_entities = normalize_entities(raw_data)

    from schema_validation import validate_raw_scan  # noqa: F811

    scan = {
        "target": target,
        "scan_date": datetime.now(
            timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entities": entities,
        "events": extract_events(raw_data),
        "raw_module_output": {
            "note": "Untouched SpiderFoot export preserved for audit.",
            "raw_record_count": len(raw_data),
            "records": raw_data,
            "unknown_entities": unknown_entities
        }
    }

    validate_raw_scan(scan)

    return scan


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("input")
    parser.add_argument("output")

    args = parser.parse_args()

    scan = generate_raw_scan(
        args.target,
        args.input
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(scan, f, indent=4)
