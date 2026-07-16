# Offline conference demo runbook

Run from a prepared environment with project dependencies installed:

```bash
bash scripts/run_conference_demo.sh
```

The demo replays `samples/spiderfoot_small.json`; it does not contact
SpiderFoot or any external service. It deliberately uses STUB scoring, so the
PDF is marked review-only and external export remains prohibited. It then
builds/verifies a local Ed25519-signed capsule.

Do not describe this as a legal-admissibility demonstration. The script is an
engineering continuity demo only; see `docs/audits/final_readiness_report.md`.
