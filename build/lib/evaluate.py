import json
import tempfile
from pathlib import Path
from report_build import build_report
from mind.mind_profile import profile
from explanation_card_build import BuildConfig, build_artifacts


DATASET_DIR = Path("evaluation datasets")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_evaluation():
    datasets = sorted(list(DATASET_DIR.glob("*.json")))

    print(f"Found {len(datasets)} datasets\n")

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        for dataset in datasets:
            scan = load_json(dataset)
            
            dossier_out = tmp_path / f"{dataset.stem}_dossier.json"
            dossier = profile(
                raw_scan_path=dataset,
                output_path=dossier_out,
                dry_run=True
            )
            
            cfg = BuildConfig(input_path=dossier_out, output_dir=tmp_path / dataset.stem)
            arts = build_artifacts(cfg)
            explanation_cards = arts.explanation_cards

            report = build_report(scan, dossier=dossier, explanation_cards=explanation_cards)

            print("=" * 60)
            print(f"Dataset: {dataset.name}")
            print(f"Entities: {report['summary']['total_entities']}")
            print(f"Events: {report['summary']['total_events']}")
            print(f"Risk Rating: {report['risk_assessment']['rating']}")
            if report.get("xai_audit"):
                xai = report["xai_audit"]
                fair_status = "PASS" if xai.get("overall_fairness_passed") else "FAIL"
                rob_status = "PASS" if xai.get("overall_robustness_passed") else "FAIL"
                print(f"XAI Cards Generated: {xai.get('card_count')} | Fairness: {fair_status} | Robustness: {rob_status}")
            print("=" * 60)
            print()


if __name__ == "__main__":
    run_evaluation()