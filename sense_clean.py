import csv
import json
from datetime import datetime, timezone
from pathlib import Path

ENTITY_MAP = {
    "INTERNET_NAME": "domain",
    "DOMAIN_NAME": "domain",
    "DOMAIN": "domain",
    "HOST": "domain",
    "AFFILIATE_INTERNET_NAME": "domain",
    "CO_HOSTED_SITE": "domain",

    "IP_ADDRESS": "ip",
    "IPV6_ADDRESS": "ip",
    "IP": "ip",

    "EMAILADDR": "email",
    "EMAIL_ADDRESS": "email",
    "EMAIL": "email",
    "ACCOUNT_EXTERNAL": "social_profile",
    "USERNAME": "username",

    "PHONE_NUMBER": "phone",
    "PHYSICAL_ADDRESS": "address",

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


def get_osiris_type(sf_type):
    sf_type_upper = (sf_type or "").upper()
    sf_type_clean = sf_type_upper.replace(" ", "_")

    for key, value in ENTITY_MAP.items():
        key_clean = key.replace(" ", "_")
        if key_clean in sf_type_clean or key in sf_type_upper:
            return value

    return "unknown"


def normalize_entities(raw_data):
    entities = []
    unknown_entities = []

    seen = set()

    for item in raw_data:
        sf_type = item.get("type", "")
        sf_type_descr = item.get("type_descr", "")
        sf_value = item.get("data", "")

        if not sf_value:
            continue

        osiris_type = get_osiris_type(sf_type)
        if osiris_type == "unknown" and sf_type_descr:
            osiris_type = get_osiris_type(sf_type_descr)

        if osiris_type == "unknown":
            unknown_entities.append({
                "module": item.get("module"),
                "type": sf_type or sf_type_descr,
                "value": sf_value,
                "source": item.get("source")
            })
            continue

        key = (osiris_type, sf_value)

        if key in seen:
            continue

        seen.add(key)

        entities.append({
            "type": osiris_type,
            "value": sf_value,
            "source_module": item.get("module"),
            "source": item.get("source"),
            "platform": None,
            "metadata": {
                "source_module": item.get("module"),
                "source": item.get("source")
            }
        })

    return entities, unknown_entities


def extract_events(raw_data):
    events = []
    
    default_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for item in raw_data:
        sf_type = item.get("type", "")
        value = item.get("data", "")
        module = item.get("module", "")
        
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
    if isinstance(spiderfoot_input, str):
        raw_data = load_spiderfoot_input(spiderfoot_input)
    else:
        raw_data = spiderfoot_input

    # If the input is already a processed raw_scan dict (e.g. outputs/raw_scan.json),
    # validate and return it directly instead of re-processing it as SpiderFoot data.
    if isinstance(raw_data, dict) and "entities" in raw_data:
        from schema_validation import validate_raw_scan
        validate_raw_scan(raw_data)
        return raw_data

    entities, unknown_entities = normalize_entities(raw_data)

    from schema_validation import validate_raw_scan

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