# OSIRIS threat model

Status: living document, 2026-07-16. This describes the current local/offline
implementation and its known gaps; it is not a claim of production readiness.

| Threat | Asset / attack path | Preventive and detective controls | Residual risk / test coverage |
| --- | --- | --- | --- |
| Malicious OSINT content and stored XSS | Raw sources rendered in graph, dashboard or report | HTML escaping, safe graph serialization, dashboard CSP, no remote graph scripts | Browser-level tests are pending; unit tests cover script payloads. |
| Indirect prompt injection | Instructions embedded in source text influence model output | Current pipeline flags injection; strict evidence-constrained LLM boundary is still incomplete | High; prompt-injection fixture suite remains planned. |
| SSRF / unrestricted URL fetch | Collector or adapter fetches attacker-supplied location | Active SpiderFoot execution requires authorization; no general URL adapter is implemented | High for future adapters; enforce allowlists/timeouts before enabling. |
| Unauthorized scanning / scope bypass | Operator invokes live collection outside case target/time/mode | Versioned authorization validates APPROVED state, scope, exclusions, expiry and active permission | Direct SpiderFoot path is unit covered; role/OIDC controls are pending. |
| Evidence tampering / replay | Raw bytes or released files changed after collection | Immutable local writes, SHA-256 verified raw reads, signed capsule manifest and verifier | Local filesystem lacks object lock/trusted timestamp; tamper tests cover raw/capsule bytes. |
| Insider modification / copied explanation | A report/card is edited or paired with another run | Case/run IDs travel through principal artifacts; exact score reconstruction gate | Full cross-artifact consistency verifier and custody signatures are pending. |
| Evidence duplication / source poisoning | Repeated observations inflate score or copied sources appear independent | Entity aggregation is present; deterministic corroboration layer is not implemented | Medium/high; independent-source reconciliation tests are pending. |
| Stale/conflicting evidence | Historical or contradictory source is treated as current | Not implemented as normalized assertion policy | High; release policy should remain blocked when evidence integrity/provenance is absent. |
| Schema downgrade / malformed data | Old or invalid artifact bypasses checks | Pydantic/JSON schema validation and version fields | Migration policy and signed schema registry are pending. |
| Report-gate bypass / unauthorized export | Caller invokes PDF/MISP function directly | Central release policy; MISP raises on blocked reports; PDF becomes review-only | STIX/OpenCTI paths are not implemented; negative tests cover MISP. |
| Compromised signing key | Development key signs an attacker capsule | Ed25519 local key mode with restrictive file permission | No KMS, keyless signing, revocation or RFC 3161 timestamp yet. |
| Dependency compromise / secrets | Malicious package or committed credential | Pinned requirements and canonical project metadata | Lockfile, SBOM, secret scan and dependency audit CI are pending. |
| Unsafe subprocess / archive extraction | Shell injection or zip-slip in future collection/import | Subprocess arguments are list-based in current runner; no archive importer | Static analysis and adversarial archive tests are pending. |
| Model/prompt drift | Different model or prompt changes conclusions | Model and prompt fields are recorded in lineage | Baseline comparison and model approval policy are pending. |
| PII and log leakage | Evidence/logs exported to unauthorized audience | Handling marking exists in authorization model | RBAC, tenant isolation, retention/legal hold and redaction are pending. |
| Denial of service | Oversized evidence, graph, or model inputs exhaust resources | No production resource quotas | High for deployment; queue limits and size caps are pending. |

## Security invariants

1. Live collection fails closed without an approved, in-scope, unexpired active
   authorization.
2. A blocked, STUB, FALLBACK, unsigned, unauthorized, or integrity-unverified
   report cannot use the MISP dissemination path.
3. Raw evidence and capsules must fail verification after byte modification.
4. Generated graph and dashboard artifacts must not load remote dependencies.

## Required verification before a pilot

Run the entire test suite, validate a signed capsule and a deliberate tamper
failure, then independently review the unimplemented controls above. Do not
interpret a passing local-development test suite as legal admissibility or
authorization for collection.
