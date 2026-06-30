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
            "minItems": 1,
            "items": {
                "type": "object",
                "required": [
                    "type",
                    "value"
                ],
                "properties": {
                    "type": { "type": "string" },
                    "value": { "type": "string" },
                    "source_module": { "type": ["string", "null"] },
                    "source": { "type": ["string", "null"] },
                    "platform": { "type": ["string", "null"] },
                    "metadata": { "type": ["object", "null"] }
                }
            }
        },
        "events": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "date",
                    "type",
                    "entity"
                ],
                "properties": {
                    "date": { "type": "string" },
                    "type": { "type": "string" },
                    "entity": { "type": "string" },
                    "source": { "type": ["string", "null"] },
                    "detail": { "type": ["string", "null"] }
                }
            }
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
        },
        "dossier_summary": {
            "type": "object"
        },
        "xai_audit": {
            "type": "object"
        },
        "disclaimer_appendix": {
            "type": ["string", "null"]
        }
    }
}


DOSSIER_SCHEMA = {
    "type": "object",
    "required": [
        "target",
        "scan_date",
        "profiled_at",
        "profile",
        "risk_score",
        "risk_features",
        "executive_summary",
        "model_metadata"
    ],
    "properties": {
        "target": { "type": "string" },
        "scan_date": { "type": "string" },
        "profiled_at": { "type": "string" },
        "risk_score": { "type": "integer" },
        "risk_level": { "type": ["string", "null"] },
        "injection_detected": { "type": "boolean" },
        "injection_details": { "type": ["string", "null"] },
        "profile": { "type": "object" },
        "risk_features": { "type": "array" },
        "insufficient_data_flags": { "type": "array" },
        "executive_summary": { "type": "string" },
        "model_metadata": { "type": "object" },
        "schema_version": { "type": "string" }
    }
}


EXPLANATION_CARDS_SCHEMA = {
    "type": "object",
    "required": ["schema_version", "generated_at", "card_count", "cards"],
    "properties": {
        "schema_version": {"type": "string"},
        "generated_at": {"type": "string"},
        "target": {"type": "string"},
        "targets": {"type": "array"},
        "card_count": {"type": "integer", "minimum": 1},
        "cards": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": [
                    "entity_id",
                    "entity",
                    "timestamp",
                    "risk_score",
                    "top_features",
                    "supporting_evidence",
                    "contradicting_evidence",
                    "explanation",
                    "confidence",
                    "fairness_check",
                    "robustness_check",
                ],
                "properties": {
                    "entity_id": {"type": "string"},
                    "entity": {"type": "string"},
                    "timestamp": {"type": "string"},
                    "risk_score": {"type": "integer"},
                    "top_features": {"type": "array"},
                    "supporting_evidence": {"type": "array"},
                    "contradicting_evidence": {"type": "array"},
                    "explanation": {"type": "string"},
                    "confidence": {"type": "number"},
                    "fairness_check": {"type": "object"},
                    "robustness_check": {"type": "object"},
                },
            },
        },
    },
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


def validate_dossier(dossier):
    try:
        validate(
            instance=dossier,
            schema=DOSSIER_SCHEMA
        )
        return True
    except ValidationError as e:
        raise ValueError(
            f"Dossier schema error: {e.message}"
        )


def validate_explanation_cards(cards):
    try:
        validate(
            instance=cards,
            schema=EXPLANATION_CARDS_SCHEMA
        )
        return True
    except ValidationError as e:
        raise ValueError(
            f"Explanation cards schema error: {e.message}"
        )