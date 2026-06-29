from jsonschema import validate, ValidationError


RAW_SCAN_SCHEMA = {
    "type": "object",
    "required": [
        "target",
        "scan_date",
        "entities",
        "events"
    ],
    "properties": {
        "target": {
            "type": "string"
        },
        "scan_date": {
            "type": "string"
        },
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "type",
                    "value"
                ],
                "properties": {
                    "type": {
                        "type": "string"
                    },
                    "value": {
                        "type": "string"
                    },
                    "source": {},
                    "source_module": {}
                }
            }
        },
        "events": {
            "type": "array"
        },
        "raw_module_output": {
            "type": "object"
        }
    }
}


REPORT_SCHEMA = {
    "type": "object",
    "required": [
        "report_metadata",
        "summary",
        "risk_assessment",
        "findings"
    ],
    "properties": {
        "report_metadata": {
            "type": "object"
        },
        "summary": {
            "type": "object"
        },
        "risk_assessment": {
            "type": "object"
        },
        "findings": {
            "type": "array"
        },
        "events": {
            "type": "array"
        }
    }
}


def validate_raw_scan(scan):
    try:
        validate(
            instance=scan,
            schema=RAW_SCAN_SCHEMA
        )
        return True
    except ValidationError as e:
        raise ValueError(
            f"Raw scan schema error: {e.message}"
        )


def validate_report(report):
    try:
        validate(
            instance=report,
            schema=REPORT_SCHEMA
        )
        return True
    except ValidationError as e:
        raise ValueError(
            f"Report schema error: {e.message}"
        )