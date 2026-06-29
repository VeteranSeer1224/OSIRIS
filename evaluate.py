import json
from pathlib import Path
from report_build import build_report


DATASET_DIR = Path("evaluation_datasets")


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def run_evaluation():
    datasets = list(
        DATASET_DIR.glob("*.json")
    )

    print(f"Found {len(datasets)} datasets\n")

    for dataset in datasets:
        scan = load_json(dataset)

        report = build_report(scan)

        print("=" * 60)
        print(f"Dataset: {dataset.name}")
        print(
            f"Entities: {report['summary']['total_entities']}"
        )
        print(
            f"Events: {report['summary']['total_events']}"
        )
        print(
            f"Risk Rating: "
            f"{report['risk_assessment']['rating']}"
        )
        print("=" * 60)
        print()


if __name__ == "__main__":
    run_evaluation()