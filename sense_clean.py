import json
import csv
import argparse
from datetime import datetime, timezone
import re

def load_spiderfoot_data(filepath):
    """Loads raw SpiderFoot export data and standardizes keys to lowercase."""
    raw_data = []
    try:
        if filepath.endswith('.json'):
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Standardize JSON keys to lowercase
                raw_data = [{k.lower(): v for k, v in item.items()} for item in data]
                
        elif filepath.endswith('.csv'):
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                # Standardize CSV headers to lowercase
                for row in reader:
                    clean_row = {k.lower(): v for k, v in row.items() if k is not None}
                    raw_data.append(clean_row)
        else:
            print("Unsupported file format. Please provide a .json or .csv export.")
    except Exception as e:
        print(f"Error loading file: {e}")
    return raw_data

def get_osiris_type(sf_type):
    """Fuzzy matching to catch prefixed SpiderFoot types (e.g., AFFILIATE_INTERNET_NAME)."""
    sf_type = sf_type.upper()
    if 'INTERNET_NAME' in sf_type or 'DOMAIN_NAME' in sf_type:
        return 'domain'
    if 'IP_ADDRESS' in sf_type or 'IPV6_ADDRESS' in sf_type:
        return 'ip'
    if 'EMAILADDR' in sf_type:
        return 'email'
    if 'ACCOUNT_EXTERNAL' in sf_type:
        return 'social_profile'
    return None

def normalize_entities(raw_data):
    """Maps SpiderFoot's messy data types into OSIRIS Contract 1 entities."""
    entities = []
    seen_values = set()

    for item in raw_data:
        sf_type = item.get('type', '')
        sf_value = item.get('data', '')
        
        # Determine platform if it's a social profile
        platform = None
        if 'ACCOUNT_EXTERNAL' in sf_type.upper():
            if 'github.com' in sf_value.lower():
                platform = 'github'
            elif 'twitter.com' in sf_value.lower() or 'x.com' in sf_value.lower():
                platform = 'twitter'

        # Subdomain check
        osiris_type = get_osiris_type(sf_type)
        if osiris_type == 'domain' and sf_value.count('.') > 1:
            osiris_type = 'subdomain'

        if osiris_type and sf_value not in seen_values:
            entity = {"type": osiris_type, "value": sf_value}
            if platform:
                entity["platform"] = platform
            
            entities.append(entity)
            seen_values.add(sf_value)
            
    return entities

def extract_events(raw_data):
    """Extracts specific events like WHOIS dates and breach timestamps."""
    events = []
    
    for item in raw_data:
        sf_type = item.get('type', '').upper()
        sf_data = item.get('data', '')
        sf_module = item.get('module', '').lower()

        # Extract WHOIS Registration Dates (Catches DOMAIN_WHOIS, AFFILIATE_DOMAIN_WHOIS, etc.)
        if 'DOMAIN_WHOIS' in sf_type and 'Creation Date' in sf_data:
            match = re.search(r'Creation Date:.*?(\d{4}-\d{2}-\d{2})', sf_data)
            if match:
                events.append({
                    "date": match.group(1),
                    "type": "domain_registered",
                    "entity": item.get('source', 'unknown_domain') # 'source' column in CSV holds the root domain
                })

        # Extract Data Breach Appearances
        if 'LEAKSITE_CONTENT' in sf_type or 'haveibeenpwned' in sf_module:
            match = re.search(r'(\d{4}-\d{2}-\d{2})', sf_data)
            events.append({
                "date": match.group(1) if match else "Unknown",
                "type": "breach_appearance",
                "entity": item.get('source', 'unknown_email'),
                "source": sf_module
            })

    return events

def generate_raw_scan(target, raw_filepath):
    """Main function to generate the raw_scan.json contract."""
    raw_data = load_spiderfoot_data(raw_filepath)
    
    if not raw_data:
        return None

    # Construct the final JSON shape mandated by Contract 1
    osiris_scan = {
        "target": target,
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entities": normalize_entities(raw_data),
        "events": extract_events(raw_data),
        "raw_module_output": {
            "note": "untouched SpiderFoot export, kept for audit trail",
            "raw_record_count": len(raw_data)
        }
    }
    
    return osiris_scan

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normalize SpiderFoot output into OSIRIS Contract 1.")
    parser.add_argument("-t", "--target", required=True, help="The scan target (e.g., example.com)")
    parser.add_argument("-i", "--input", required=True, help="Path to raw SpiderFoot JSON/CSV export")
    parser.add_argument("-o", "--output", default="raw_scan.json", help="Output file path")
    
    args = parser.parse_args()
    
    final_contract = generate_raw_scan(args.target, args.input)
    
    if final_contract:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(final_contract, f, indent=2)
        print(f"Success! Normalized data saved to {args.output}")