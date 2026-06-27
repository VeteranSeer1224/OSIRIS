import json
from datetime import datetime, timezone
from pathlib import Path

ENTITY_MAP = {
    "INTERNET_NAME": "domain",
    "DOMAIN_NAME": "domain",
    "AFFILIATE_INTERNET_NAME": "domain",
    "CO_HOSTED_SITE": "domain",

    "IP_ADDRESS": "ip",
    "IPV6_ADDRESS": "ip",

    "EMAILADDR": "email",
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
    sf_type = (sf_type or "").upper()

    for key, value in ENTITY_MAP.items():
        if key in sf_type:
            return value

    return "unknown"


def normalize_entities(raw_data):
    entities = []
    unknown_entities = []

    seen = set()

    for item in raw_data:
        sf_type = item.get("type", "")
        sf_value = item.get("data", "")

        if not sf_value:
            continue

        osiris_type = get_osiris_type(sf_type)

        if osiris_type == "unknown":
            unknown_entities.append({
                "module": item.get("module"),
                "type": sf_type,
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
            "source": item.get("source")
        })

    return entities, unknown_entities


def extract_events(raw_data):
    events = []

    for item in raw_data:
        sf_type = item.get("type", "")
        value = item.get("data", "")

        sf_upper = sf_type.upper()

        if "DOMAIN_REGISTRAR" in sf_upper:
            events.append({
                "event_type": "domain_registration",
                "value": value
            })

        elif "DOMAIN_WHOIS" in sf_upper:
            events.append({
                "event_type": "whois_record",
                "value": value
            })

        elif "SSL_CERTIFICATE" in sf_upper:
            events.append({
                "event_type": "certificate_discovered",
                "value": value
            })

        elif "DNS" in sf_upper:
            events.append({
                "event_type": "dns_record_discovered",
                "value": value
            })

        elif "BREACH" in sf_upper:
            events.append({
                "event_type": "breach",
                "value": value
            })

    return events


def generate_raw_scan(target, spiderfoot_json):
    if isinstance(spiderfoot_json, str):
        with open(spiderfoot_json, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    else:
        raw_data = spiderfoot_json

    entities, unknown_entities = normalize_entities(raw_data)

    return {
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