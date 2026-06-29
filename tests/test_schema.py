from schema_validation import (
    validate_raw_scan,
    validate_report
)


def test_raw_scan_schema():
    scan = {
        "target": "example.com",
        "scan_date": "2026-06-29",
        "entities": [],
        "events": []
    }

    assert validate_raw_scan(scan)


def test_report_schema():
    report = {
        "report_metadata": {},
        "summary": {},
        "risk_assessment": {},
        "findings": []
    }

    assert validate_report(report)