export type RiskFeature = {
  name: string;
  label: string;
  value: number;
  contribution: number;
  direction: "increase" | "decrease";
  evidence: string;
};

export type GraphNode = {
  id: string;
  label: string;
  type: "target" | "domain" | "dns" | "asn" | "certificate" | "event";
  x: number;
  y: number;
  evidence: string;
};

export type GraphEdge = {
  from: string;
  to: string;
  label: string;
};

export const caseRecord = {
  id: "CASE-2026-0042",
  title: "Example Domain Assessment",
  target: "example.com",
  owner: "A. Sharma",
  jurisdiction: "IN",
  handling: "TLP:AMBER",
  status: "Review required",
  openedAt: "24 Jul 2026",
  authorization: "Approved · passive collection",
  authorizationExpires: "31 Aug 2026",
  purpose: "Authorized infrastructure exposure assessment",
};

export const pipelineStages = [
  { name: "Foundation", detail: "Scope authorized", status: "complete", duration: "0.4s" },
  { name: "Sense", detail: "5 observations preserved", status: "complete", duration: "2.1s" },
  { name: "Mind", detail: "OpenRouter · gpt-oss-120b", status: "complete", duration: "18.4s" },
  { name: "Web", detail: "7 nodes · 6 relationships", status: "complete", duration: "0.8s" },
  { name: "Conscience", detail: "1 review exception", status: "warning", duration: "4.6s" },
  { name: "Report", detail: "Review-only bundle", status: "complete", duration: "1.3s" },
] as const;

export const evidenceItems = [
  {
    id: "EV-8D3F-001",
    type: "DOMAIN",
    value: "example.com",
    source: "sfp_dns",
    observed: "24 Jul 2026 · 10:26 UTC",
    integrity: "Verified",
    confidence: 1,
    hash: "4bfe87c70ab17c5b9d301a6b667056f85832a55a1ad13d1cf17c56d93fe72291",
  },
  {
    id: "EV-8D3F-002",
    type: "DNS RECORD",
    value: "mail.example.com",
    source: "sfp_dns",
    observed: "24 Jul 2026 · 10:26 UTC",
    integrity: "Verified",
    confidence: 0.98,
    hash: "b8ae8beabf4ad96ac0d4c3a4e2993713a58bfd16114df7a173d88239b75d8f40",
  },
  {
    id: "EV-8D3F-003",
    type: "ASN",
    value: "AS15169",
    source: "sfp_bgp",
    observed: "24 Jul 2026 · 10:26 UTC",
    integrity: "Verified",
    confidence: 0.92,
    hash: "7fe01388fb832750347b06967a7df8c5935cf24ed15673077da44af125f6e7e8",
  },
  {
    id: "EV-8D3F-004",
    type: "CERTIFICATE",
    value: "certificate-data",
    source: "sfp_ssl",
    observed: "24 Jul 2026 · 10:26 UTC",
    integrity: "Verified",
    confidence: 0.96,
    hash: "d91ea756e89fa3e460e56bace4aff9a5e1828943c9b22603dce33e19bbcfaa03",
  },
];

export const riskFeatures: RiskFeature[] = [
  {
    name: "base_intercept",
    label: "Baseline prior",
    value: 15,
    contribution: 15,
    direction: "increase",
    evidence: "SCORER-1.0.0",
  },
  {
    name: "exposed_services",
    label: "Exposed services",
    value: 3,
    contribution: 11.4,
    direction: "increase",
    evidence: "EV-8D3F-002",
  },
  {
    name: "certificate_age",
    label: "Certificate age",
    value: 24,
    contribution: 7.2,
    direction: "increase",
    evidence: "EV-8D3F-004",
  },
  {
    name: "domain_age",
    label: "Established domain age",
    value: 10980,
    contribution: -8.6,
    direction: "decrease",
    evidence: "EV-8D3F-001",
  },
  {
    name: "corroboration",
    label: "Source corroboration",
    value: 2,
    contribution: -3.1,
    direction: "decrease",
    evidence: "EV-8D3F-001",
  },
];

export const graphNodes: GraphNode[] = [
  { id: "target", label: "example.com", type: "target", x: 430, y: 260, evidence: "Case target" },
  { id: "domain", label: "example.com", type: "domain", x: 430, y: 76, evidence: "EV-8D3F-001" },
  { id: "dns", label: "mail.example.com", type: "dns", x: 708, y: 170, evidence: "EV-8D3F-002" },
  { id: "asn", label: "AS15169", type: "asn", x: 704, y: 398, evidence: "EV-8D3F-003" },
  { id: "certificate", label: "certificate-data", type: "certificate", x: 430, y: 480, evidence: "EV-8D3F-004" },
  { id: "event-cert", label: "certificate issued", type: "event", x: 152, y: 398, evidence: "EV-8D3F-004" },
  { id: "event-dns", label: "DNS change", type: "event", x: 152, y: 170, evidence: "EV-8D3F-002" },
];

export const graphEdges: GraphEdge[] = [
  { from: "target", to: "domain", label: "observed" },
  { from: "target", to: "dns", label: "resolves to" },
  { from: "target", to: "asn", label: "announced by" },
  { from: "target", to: "certificate", label: "presents" },
  { from: "certificate", to: "event-cert", label: "derived event" },
  { from: "dns", to: "event-dns", label: "derived event" },
];

export const recentCases = [
  { id: "CASE-2026-0042", target: "example.com", owner: "A. Sharma", status: "Review required", risk: 22, updated: "2m ago" },
  { id: "CASE-2026-0039", target: "acme-labs.test", owner: "M. Lewis", status: "In progress", risk: 61, updated: "3h ago" },
  { id: "CASE-2026-0037", target: "northstar.test", owner: "A. Sharma", status: "Closed", risk: 34, updated: "Yesterday" },
  { id: "CASE-2026-0034", target: "sandbox.example", owner: "R. Chen", status: "Blocked", risk: 78, updated: "22 Jul" },
];

export const activity = [
  { title: "Evidence integrity verified", meta: "4 artifacts · SHA-256", time: "10:27" },
  { title: "Conscience review completed", meta: "Fairness check inconclusive", time: "10:27" },
  { title: "Dossier generated", meta: "openai/gpt-oss-120b", time: "10:26" },
  { title: "Raw evidence preserved", meta: "Append-only local store", time: "10:26" },
];
