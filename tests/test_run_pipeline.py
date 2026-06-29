import json
import os
import sys
from pathlib import Path

# Add root directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from run_pipeline import pipeline_from_existing_scan

def test_pipeline_end_to_end(tmp_path):
    # Create a mock spiderfoot_json output
    sf_data = [
        {
            "type": "DOMAIN_NAME",
            "data": "example.com",
            "module": "sfp_test"
        },
        {
            "type": "IP_ADDRESS",
            "data": "93.184.216.34",
            "module": "sfp_test"
        }
    ]
    
    sf_file = tmp_path / "sf_output.json"
    with open(sf_file, "w") as f:
        json.dump(sf_data, f)
        
    results = pipeline_from_existing_scan(
        target="example.com",
        spiderfoot_json=str(sf_file),
        output_dir=str(tmp_path),
        do_export_pdf=True,
        do_export_misp=True
    )
    
    # Assert expected outputs are generated
    assert "raw_scan" in results
    assert "report" in results
    assert "pdf_report" in results
    assert "misp_export" in results
    
    # Assert files actually exist
    assert Path(results["raw_scan"]).exists()
    assert Path(results["report"]).exists()
    assert Path(results["pdf_report"]).exists()
    assert Path(results["misp_export"]).exists()
    
    # Check JSON validity of the MISP export
    with open(results["misp_export"]) as f:
        misp = json.load(f)
        assert "Event" in misp
