\"\"\"
DEPRECATED — This file is not imported by any module in the OSIRIS pipeline.

Schema validation is handled by:
  - schema_validation.py  (jsonschema-based validation)
  - schemas/models.py     (Pydantic models)

This file is kept for reference only. Do not add new schemas here.
\"\"\"

RAW_SCAN_SCHEMA = {
    "target": str,
    "scan_date": str,
    "entities": list,
    "events": list,
    "raw_module_output": dict,
}


ENTITY_SCHEMA = {
    "type": str,
    "value": str,
    "source_module": (str, type(None)),
    "source": (str, type(None))
}


EVENT_SCHEMA = {
    "event_type": str,
    "value": str
}


RAW_MODULE_OUTPUT_SCHEMA = {
    "note": str,
    "raw_record_count": int,
    "records": list,
    "unknown_entities": list
}