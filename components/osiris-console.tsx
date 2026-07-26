"use client";

import {
  Activity,
  Archive,
  ArrowDownToLine,
  ArrowRight,
  BadgeCheck,
  Blocks,
  BookOpen,
  Box,
  BrainCircuit,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  ClipboardCheck,
  Clock3,
  Command,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCheck2,
  FileJson2,
  FileText,
  Filter,
  Fingerprint,
  FolderKanban,
  Gauge,
  GitBranch,
  Hash,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  MoreHorizontal,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Play,
  Plus,
  Radar,
  RefreshCw,
  Scale,
  Search,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  Upload,
  UserRoundCheck,
  X,
  Zap,
} from "lucide-react";
import {
  ChangeEvent,
  DragEvent,
  KeyboardEvent,
  ReactNode,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  activity,
  caseRecord,
  evidenceItems,
  graphEdges,
  graphNodes,
  pipelineStages,
  recentCases,
  riskFeatures,
  type GraphNode,
} from "@/lib/demo-data";

type View =
  | "overview"
  | "cases"
  | "collection"
  | "evidence"
  | "graph"
  | "xai"
  | "reports"
  | "integrity";

type Toast = { title: string; detail: string } | null;
type ImportedArtifact = {
  name: string;
  size: number;
  hash: string;
  kind: string;
  records: number;
  importedAt: string;
};

const navItems: {
  id: View;
  label: string;
  icon: typeof LayoutDashboard;
  section?: string;
}[] = [
  { id: "overview", label: "Overview", icon: LayoutDashboard, section: "Workspace" },
  { id: "cases", label: "Cases", icon: FolderKanban },
  { id: "collection", label: "Collection", icon: Radar, section: "Investigation" },
  { id: "evidence", label: "Evidence", icon: Database },
  { id: "graph", label: "Relationship graph", icon: Network },
  { id: "xai", label: "XAI review", icon: BrainCircuit, section: "Review" },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "integrity", label: "Integrity", icon: Fingerprint },
];

const viewMeta: Record<View, { eyebrow: string; title: string; description: string }> = {
  overview: {
    eyebrow: "Investigation workspace",
    title: "Operational overview",
    description: "A concise view of scope, pipeline state, evidence, and review posture.",
  },
  cases: {
    eyebrow: "Case management",
    title: "Authorized investigations",
    description: "Open, review, and manage scoped cases without losing evidentiary context.",
  },
  collection: {
    eyebrow: "Sense + Mind",
    title: "Configure a collection run",
    description: "Stage an authorized scan and its analysis model before execution.",
  },
  evidence: {
    eyebrow: "Evidence store",
    title: "Observed facts",
    description: "Inspect preserved observations, provenance, and integrity metadata.",
  },
  graph: {
    eyebrow: "OSIRIS-Web",
    title: "Relationship intelligence",
    description: "Explore deterministic relationships without obscuring the source evidence.",
  },
  xai: {
    eyebrow: "OSIRIS-Conscience",
    title: "Explainability review",
    description: "Reconstruct the score and inspect every audit gate before release.",
  },
  reports: {
    eyebrow: "OSIRIS-Report",
    title: "Review and export",
    description: "Prepare human-readable and structured artifacts under release policy.",
  },
  integrity: {
    eyebrow: "Evidence capsule",
    title: "Integrity and provenance",
    description: "Verify hashes, lineage, signatures, and case consistency.",
  },
};

function cx(...classes: Array<string | false | null | undefined>) {
  return classes.filter(Boolean).join(" ");
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

async function sha256(value: string | ArrayBuffer) {
  const input =
    typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  const digest = await crypto.subtle.digest("SHA-256", input);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function StatusBadge({
  tone,
  children,
}: {
  tone: "good" | "warning" | "danger" | "neutral" | "info";
  children: ReactNode;
}) {
  return <span className={`status-badge ${tone}`}>{children}</span>;
}

function MetricCard({
  label,
  value,
  detail,
  icon,
  accent = "cyan",
}: {
  label: string;
  value: string;
  detail: string;
  icon: ReactNode;
  accent?: "cyan" | "violet" | "amber" | "green";
}) {
  return (
    <article className="metric-card">
      <div className={`metric-icon ${accent}`}>{icon}</div>
      <div>
        <p className="metric-label">{label}</p>
        <strong className="metric-value">{value}</strong>
        <p className="metric-detail">{detail}</p>
      </div>
    </article>
  );
}

function SectionHeader({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="section-header">
      <div>
        <h2>{title}</h2>
        {detail ? <p>{detail}</p> : null}
      </div>
      {action}
    </div>
  );
}

function EmptyState({
  icon,
  title,
  detail,
  action,
}: {
  icon: ReactNode;
  title: string;
  detail: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{detail}</p>
      {action}
    </div>
  );
}

export function OsirisConsole() {
  const [view, setView] = useState<View>("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [toast, setToast] = useState<Toast>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<(typeof evidenceItems)[number] | null>(
    null,
  );
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(graphNodes[0]);
  const [importedArtifacts, setImportedArtifacts] = useState<ImportedArtifact[]>([]);
  const fileInput = useRef<HTMLInputElement>(null);

  const navigate = (next: View) => {
    setView(next);
    setMobileNavOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const notify = (title: string, detail: string) => {
    setToast({ title, detail });
    window.setTimeout(() => setToast(null), 3600);
  };

  useEffect(() => {
    const handleKey = (event: globalThis.KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setSearchOpen((value) => !value);
      }
      if (event.key === "Escape") {
        setSearchOpen(false);
        setSelectedEvidence(null);
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const handleImport = async (file?: File) => {
    if (!file) return;
    try {
      const raw = await file.text();
      const parsed = JSON.parse(raw);
      const hash = await sha256(raw);
      const kind =
        parsed?.entities && parsed?.raw_module_output
          ? "Raw scan"
          : parsed?.risk_features
            ? "Dossier"
            : parsed?.cards
              ? "Explanation cards"
              : parsed?.report_metadata
                ? "Report"
                : "JSON artifact";
      const records = Array.isArray(parsed)
        ? parsed.length
        : Array.isArray(parsed?.entities)
          ? parsed.entities.length
          : Array.isArray(parsed?.cards)
            ? parsed.cards.length
            : Object.keys(parsed ?? {}).length;
      setImportedArtifacts((current) => [
        {
          name: file.name,
          size: file.size,
          hash,
          kind,
          records,
          importedAt: "Just now",
        },
        ...current,
      ]);
      setView("evidence");
      notify("Artifact imported", `${file.name} was parsed and hashed locally.`);
    } catch {
      notify("Import failed", "Choose a valid OSIRIS JSON artifact.");
    }
  };

  const handleDrop = (event: DragEvent<HTMLElement>) => {
    event.preventDefault();
    void handleImport(event.dataTransfer.files[0]);
  };

  const downloadJson = (name: string, payload: unknown) => {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    URL.revokeObjectURL(url);
    notify("Download prepared", `${name} was generated in your browser.`);
  };

  return (
    <div className="app-shell">
      <aside
        className={cx(
          "sidebar",
          sidebarCollapsed && "collapsed",
          mobileNavOpen && "mobile-open",
        )}
      >
        <div className="brand-row">
          <button className="brand" onClick={() => navigate("overview")} aria-label="OSIRIS home">
            <span className="brand-mark">
              <span />
            </span>
            <span className="brand-copy">
              <strong>OSIRIS</strong>
              <small>Investigation console</small>
            </span>
          </button>
          <button
            className="icon-button sidebar-collapse"
            onClick={() => setSidebarCollapsed((value) => !value)}
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {sidebarCollapsed ? <PanelLeftOpen size={17} /> : <PanelLeftClose size={17} />}
          </button>
        </div>

        <button className="new-case-button" onClick={() => navigate("collection")}>
          <Plus size={17} />
          <span>New investigation</span>
        </button>

        <nav className="primary-nav" aria-label="Primary navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.id}>
                {item.section ? <p className="nav-section">{item.section}</p> : null}
                <button
                  className={cx("nav-item", view === item.id && "active")}
                  onClick={() => navigate(item.id)}
                  title={sidebarCollapsed ? item.label : undefined}
                >
                  <Icon size={18} strokeWidth={1.8} />
                  <span>{item.label}</span>
                  {item.id === "xai" ? <i className="nav-alert" /> : null}
                </button>
              </div>
            );
          })}
        </nav>

        <div className="sidebar-case">
          <div className="case-monogram">EX</div>
          <div className="case-copy">
            <small>Active case</small>
            <strong>example.com</strong>
            <span>{caseRecord.id}</span>
          </div>
          <ChevronRight size={16} />
        </div>

        <div className="sidebar-footer">
          <div className="system-state">
            <span className="pulse-dot" />
            <div>
              <strong>Local workspace</strong>
              <small>Review-only mode</small>
            </div>
          </div>
          <button className="icon-button" aria-label="Settings">
            <Settings2 size={17} />
          </button>
        </div>
      </aside>

      {mobileNavOpen ? (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={() => setMobileNavOpen(false)}
        />
      ) : null}

      <main className={cx("main-shell", sidebarCollapsed && "sidebar-is-collapsed")}>
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="icon-button mobile-menu"
              onClick={() => setMobileNavOpen(true)}
              aria-label="Open navigation"
            >
              <Menu size={19} />
            </button>
            <div className="case-switcher">
              <span className="case-switcher-mark">EX</span>
              <div>
                <small>{caseRecord.id}</small>
                <strong>{caseRecord.target}</strong>
              </div>
              <ChevronDown size={15} />
            </div>
          </div>

          <div className="topbar-actions">
            <button className="search-trigger" onClick={() => setSearchOpen(true)}>
              <Search size={16} />
              <span>Search cases, evidence, entities…</span>
              <kbd>
                <Command size={11} /> K
              </kbd>
            </button>
            <button
              className="icon-button"
              aria-label="Import artifact"
              onClick={() => fileInput.current?.click()}
            >
              <Upload size={18} />
            </button>
            <input
              ref={fileInput}
              type="file"
              accept=".json,application/json"
              hidden
              onChange={(event: ChangeEvent<HTMLInputElement>) =>
                void handleImport(event.target.files?.[0])
              }
            />
            <button className="analyst-avatar" aria-label="Analyst profile">
              AS
            </button>
          </div>
        </header>

        <div className="page">
          <div className="page-heading">
            <div>
              <p className="eyebrow">{viewMeta[view].eyebrow}</p>
              <h1>{viewMeta[view].title}</h1>
              <p>{viewMeta[view].description}</p>
            </div>
            <div className="heading-actions">
              <StatusBadge tone="warning">
                <ShieldAlert size={13} /> Review required
              </StatusBadge>
              <button className="button secondary" onClick={() => fileInput.current?.click()}>
                <Upload size={15} /> Import artifact
              </button>
              {view !== "collection" ? (
                <button className="button primary" onClick={() => navigate("collection")}>
                  <Play size={15} /> Configure run
                </button>
              ) : null}
            </div>
          </div>

          {view === "overview" ? (
            <Overview navigate={navigate} notify={notify} />
          ) : null}
          {view === "cases" ? <Cases navigate={navigate} /> : null}
          {view === "collection" ? <Collection notify={notify} /> : null}
          {view === "evidence" ? (
            <Evidence
              imported={importedArtifacts}
              onImport={() => fileInput.current?.click()}
              onDrop={handleDrop}
              onSelect={setSelectedEvidence}
            />
          ) : null}
          {view === "graph" ? (
            <GraphView selected={selectedNode} onSelect={setSelectedNode} />
          ) : null}
          {view === "xai" ? <XaiReview navigate={navigate} /> : null}
          {view === "reports" ? (
            <Reports
              notify={notify}
              onDownload={() =>
                downloadJson("osiris-review-bundle.json", {
                  case: caseRecord,
                  evidence: evidenceItems,
                  risk_features: riskFeatures,
                  release: { status: "BLOCKED", reason: "Human review required" },
                })
              }
            />
          ) : null}
          {view === "integrity" ? <Integrity notify={notify} /> : null}
        </div>
      </main>

      {searchOpen ? (
        <CommandPalette
          query={searchQuery}
          setQuery={setSearchQuery}
          onClose={() => setSearchOpen(false)}
          navigate={navigate}
        />
      ) : null}

      {selectedEvidence ? (
        <EvidenceDrawer item={selectedEvidence} onClose={() => setSelectedEvidence(null)} />
      ) : null}

      {toast ? (
        <div className="toast" role="status">
          <span>
            <Check size={15} />
          </span>
          <div>
            <strong>{toast.title}</strong>
            <p>{toast.detail}</p>
          </div>
          <button onClick={() => setToast(null)} aria-label="Dismiss notification">
            <X size={15} />
          </button>
        </div>
      ) : null}
    </div>
  );
}

function Overview({
  navigate,
  notify,
}: {
  navigate: (view: View) => void;
  notify: (title: string, detail: string) => void;
}) {
  return (
    <div className="content-stack">
      <section className="case-banner">
        <div className="case-banner-main">
          <div className="case-kicker">
            <span className="live-indicator" />
            Active investigation
          </div>
          <h2>{caseRecord.title}</h2>
          <p>{caseRecord.purpose}</p>
          <div className="case-meta-row">
            <span>
              <UserRoundCheck size={14} /> {caseRecord.owner}
            </span>
            <span>
              <Scale size={14} /> {caseRecord.jurisdiction}
            </span>
            <span>
              <LockKeyhole size={14} /> {caseRecord.handling}
            </span>
            <span>
              <Clock3 size={14} /> Opened {caseRecord.openedAt}
            </span>
          </div>
        </div>
        <div className="authorization-card">
          <div className="authorization-icon">
            <ShieldCheck size={20} />
          </div>
          <div>
            <small>Collection authority</small>
            <strong>{caseRecord.authorization}</strong>
            <span>Expires {caseRecord.authorizationExpires}</span>
          </div>
          <button onClick={() => navigate("cases")} aria-label="Review authorization">
            <ChevronRight size={17} />
          </button>
        </div>
      </section>

      <section className="metrics-grid">
        <MetricCard
          label="Risk score"
          value="22 / 100"
          detail="Low · deterministic"
          icon={<Gauge size={19} />}
          accent="cyan"
        />
        <MetricCard
          label="Evidence"
          value="4 verified"
          detail="5 raw observations"
          icon={<Database size={19} />}
          accent="violet"
        />
        <MetricCard
          label="Relationships"
          value="7 nodes"
          detail="6 evidence-backed edges"
          icon={<GitBranch size={19} />}
          accent="green"
        />
        <MetricCard
          label="Audit posture"
          value="1 exception"
          detail="Fairness review pending"
          icon={<ClipboardCheck size={19} />}
          accent="amber"
        />
      </section>

      <div className="overview-grid">
        <section className="panel pipeline-panel">
          <SectionHeader
            title="Pipeline trace"
            detail="Latest run · 24 Jul 2026, 10:26 UTC"
            action={
              <button className="text-button" onClick={() => navigate("collection")}>
                Open run <ArrowRight size={14} />
              </button>
            }
          />
          <div className="pipeline-track">
            {pipelineStages.map((stage, index) => (
              <button
                className="pipeline-stage"
                key={stage.name}
                onClick={() =>
                  navigate(
                    stage.name === "Sense"
                      ? "evidence"
                      : stage.name === "Web"
                        ? "graph"
                        : stage.name === "Conscience"
                          ? "xai"
                          : stage.name === "Report"
                            ? "reports"
                            : "collection",
                  )
                }
              >
                <div className="stage-marker-wrap">
                  <span className={cx("stage-marker", stage.status)}>
                    {stage.status === "complete" ? <Check size={13} /> : <ShieldAlert size={13} />}
                  </span>
                  {index < pipelineStages.length - 1 ? <i /> : null}
                </div>
                <div className="stage-copy">
                  <div>
                    <strong>{stage.name}</strong>
                    <small>{stage.duration}</small>
                  </div>
                  <p>{stage.detail}</p>
                </div>
                <ChevronRight size={15} />
              </button>
            ))}
          </div>
        </section>

        <section className="panel activity-panel">
          <SectionHeader title="Recent activity" detail="Immutable run log" />
          <div className="activity-list">
            {activity.map((item, index) => (
              <div className="activity-item" key={item.title}>
                <span className={cx("activity-marker", index === 1 && "warning")} />
                <div>
                  <strong>{item.title}</strong>
                  <p>{item.meta}</p>
                </div>
                <time>{item.time}</time>
              </div>
            ))}
          </div>
          <button
            className="button tertiary full-width"
            onClick={() => notify("Audit log is current", "No unverified activity was detected.")}
          >
            <Activity size={15} /> Verify activity log
          </button>
        </section>
      </div>

      <div className="overview-grid balanced">
        <section className="panel">
          <SectionHeader
            title="Evidence snapshot"
            detail="Preserved observations"
            action={
              <button className="text-button" onClick={() => navigate("evidence")}>
                View all <ArrowRight size={14} />
              </button>
            }
          />
          <div className="compact-evidence-list">
            {evidenceItems.slice(0, 3).map((item) => (
              <button key={item.id} onClick={() => navigate("evidence")}>
                <span className={`entity-token ${item.type.toLowerCase().replace(" ", "-")}`}>
                  <CircleDot size={15} />
                </span>
                <span>
                  <strong>{item.value}</strong>
                  <small>
                    {item.type} · {item.source}
                  </small>
                </span>
                <BadgeCheck size={17} />
              </button>
            ))}
          </div>
        </section>

        <section className="panel audit-callout">
          <div className="audit-callout-icon">
            <BrainCircuit size={22} />
          </div>
          <div>
            <p className="eyebrow">Human decision point</p>
            <h2>One gate needs analyst attention</h2>
            <p>
              The scoring-only fairness check is inconclusive. Review the methodology before
              dissemination.
            </p>
            <button className="button secondary" onClick={() => navigate("xai")}>
              Open XAI review <ArrowRight size={15} />
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}

function Cases({ navigate }: { navigate: (view: View) => void }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("All statuses");
  const filtered = recentCases.filter(
    (item) =>
      (item.target.toLowerCase().includes(query.toLowerCase()) ||
        item.id.toLowerCase().includes(query.toLowerCase())) &&
      (status === "All statuses" || item.status === status),
  );

  return (
    <div className="content-stack">
      <section className="metrics-grid three">
        <MetricCard
          label="Open cases"
          value="12"
          detail="3 awaiting review"
          icon={<FolderKanban size={19} />}
        />
        <MetricCard
          label="Active authorizations"
          value="8"
          detail="2 expire this month"
          icon={<ShieldCheck size={19} />}
          accent="green"
        />
        <MetricCard
          label="Blocked releases"
          value="2"
          detail="Controls operating normally"
          icon={<ShieldAlert size={19} />}
          accent="amber"
        />
      </section>

      <section className="panel">
        <SectionHeader
          title="Case register"
          detail={`${filtered.length} investigations`}
          action={
            <button className="button primary" onClick={() => navigate("collection")}>
              <Plus size={15} /> New case
            </button>
          }
        />
        <div className="table-toolbar">
          <label className="field-with-icon grow">
            <Search size={15} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search case ID or target"
            />
          </label>
          <label className="select-field">
            <Filter size={15} />
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option>All statuses</option>
              <option>Review required</option>
              <option>In progress</option>
              <option>Closed</option>
              <option>Blocked</option>
            </select>
          </label>
        </div>
        <div className="data-table-wrap">
          <table className="data-table cases-table">
            <thead>
              <tr>
                <th>Case</th>
                <th>Owner</th>
                <th>Status</th>
                <th>Risk</th>
                <th>Updated</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.id}>
                  <td>
                    <button className="table-primary" onClick={() => navigate("overview")}>
                      <span className="case-table-mark">{item.target.slice(0, 2).toUpperCase()}</span>
                      <span>
                        <strong>{item.target}</strong>
                        <small>{item.id}</small>
                      </span>
                    </button>
                  </td>
                  <td>{item.owner}</td>
                  <td>
                    <StatusBadge
                      tone={
                        item.status === "Blocked"
                          ? "danger"
                          : item.status === "Review required"
                            ? "warning"
                            : item.status === "Closed"
                              ? "neutral"
                              : "info"
                      }
                    >
                      {item.status}
                    </StatusBadge>
                  </td>
                  <td>
                    <span className={cx("risk-number", item.risk > 70 && "high")}>
                      {item.risk}
                    </span>
                  </td>
                  <td className="muted-cell">{item.updated}</td>
                  <td>
                    <button className="icon-button subtle" aria-label={`Open ${item.id}`}>
                      <ChevronRight size={16} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Collection({ notify }: { notify: (title: string, detail: string) => void }) {
  const [target, setTarget] = useState("example.com");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(true);
  const [collectionMode, setCollectionMode] = useState("Passive");
  const [provider, setProvider] = useState("OpenRouter");
  const [model, setModel] = useState("openai/gpt-oss-120b");
  const [modules, setModules] = useState(["DNS", "WHOIS", "Certificates"]);
  const [runState, setRunState] = useState<"idle" | "staging" | "ready">("idle");

  const moduleOptions = ["DNS", "WHOIS", "Certificates", "BGP / ASN", "Web metadata", "Breach data"];

  const stageRun = () => {
    if (!target.trim() || !authorizationConfirmed) {
      notify("Run not staged", "A target and confirmed authorization are required.");
      return;
    }
    setRunState("staging");
    window.setTimeout(() => {
      setRunState("ready");
      notify("Run configuration validated", "Copy the command or execute it in your OSIRIS host.");
    }, 900);
  };

  const command = `.venv/bin/python run_pipeline.py --target ${target || "example.com"} --output-dir outputs/${target || "case"} --case-authorization case-authorization.json --mind-live --mind-backend ${provider.toLowerCase()} --mind-model ${model}`;

  return (
    <div className="collection-layout">
      <div className="content-stack">
        <section className="panel form-panel">
          <SectionHeader
            title="1. Scope and authority"
            detail="Collection stays disabled until the case scope is explicit."
          />
          <div className="form-grid">
            <label className="form-field span-two">
              <span>Target</span>
              <div className="input-shell">
                <Radar size={16} />
                <input value={target} onChange={(event) => setTarget(event.target.value)} />
                <StatusBadge tone="good">In scope</StatusBadge>
              </div>
              <small>Domain, IP address, or organization covered by the authorization.</small>
            </label>
            <label className="form-field">
              <span>Case ID</span>
              <input value={caseRecord.id} readOnly />
            </label>
            <label className="form-field">
              <span>Jurisdiction</span>
              <input value={caseRecord.jurisdiction} readOnly />
            </label>
          </div>
          <label className="authorization-check">
            <input
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
            />
            <span className="custom-check">
              <Check size={13} />
            </span>
            <span>
              <strong>I confirm this target is covered by the approved case authorization.</strong>
              <small>
                OSIRIS will preserve the authorization reference in the generated lineage.
              </small>
            </span>
          </label>
        </section>

        <section className="panel form-panel">
          <SectionHeader
            title="2. Collection profile"
            detail="Select the minimum sources required for the stated purpose."
          />
          <div className="segmented-control" role="group" aria-label="Collection mode">
            {["Fixture replay", "Passive", "Active"].map((mode) => (
              <button
                key={mode}
                className={collectionMode === mode ? "active" : ""}
                onClick={() => setCollectionMode(mode)}
              >
                {mode}
              </button>
            ))}
          </div>
          <div className="module-grid">
            {moduleOptions.map((module) => (
              <button
                className={cx("module-option", modules.includes(module) && "selected")}
                key={module}
                onClick={() =>
                  setModules((current) =>
                    current.includes(module)
                      ? current.filter((value) => value !== module)
                      : [...current, module],
                  )
                }
              >
                <span>
                  {module === "DNS" ? (
                    <Network size={17} />
                  ) : module === "Certificates" ? (
                    <KeyRound size={17} />
                  ) : module === "BGP / ASN" ? (
                    <GitBranch size={17} />
                  ) : (
                    <Blocks size={17} />
                  )}
                </span>
                <strong>{module}</strong>
                <i>{modules.includes(module) ? <Check size={13} /> : null}</i>
              </button>
            ))}
          </div>
          {collectionMode === "Active" ? (
            <div className="inline-warning">
              <ShieldAlert size={17} />
              <div>
                <strong>Active collection requires explicit authorization.</strong>
                <p>The backend will reject this run unless active scanning is allowed.</p>
              </div>
            </div>
          ) : null}
        </section>

        <section className="panel form-panel">
          <SectionHeader
            title="3. Analysis model"
            detail="LLM extraction is separated from deterministic scoring."
          />
          <div className="form-grid">
            <label className="form-field">
              <span>Provider</span>
              <select value={provider} onChange={(event) => setProvider(event.target.value)}>
                <option>OpenRouter</option>
                <option>OpenAI</option>
                <option>Ollama</option>
                <option>Anthropic</option>
              </select>
            </label>
            <label className="form-field">
              <span>Model</span>
              <input value={model} onChange={(event) => setModel(event.target.value)} />
            </label>
          </div>
          <div className="model-note">
            <BrainCircuit size={18} />
            <div>
              <strong>Deterministic score authority remains enabled.</strong>
              <p>The model extracts structured features; it cannot directly set the final score.</p>
            </div>
          </div>
        </section>
      </div>

      <aside className="run-summary panel">
        <div className="run-summary-head">
          <div className="summary-orbit">
            <Zap size={18} />
          </div>
          <div>
            <p className="eyebrow">Run summary</p>
            <h2>{target || "Untitled target"}</h2>
          </div>
        </div>
        <dl className="summary-list">
          <div>
            <dt>Mode</dt>
            <dd>{collectionMode}</dd>
          </div>
          <div>
            <dt>Sources</dt>
            <dd>{modules.length} selected</dd>
          </div>
          <div>
            <dt>Model</dt>
            <dd>{model}</dd>
          </div>
          <div>
            <dt>Authority</dt>
            <dd>{authorizationConfirmed ? "Confirmed" : "Missing"}</dd>
          </div>
          <div>
            <dt>Release mode</dt>
            <dd>Review-only</dd>
          </div>
        </dl>
        <div className="command-preview">
          <div>
            <TerminalSquare size={14} />
            <span>Execution command</span>
          </div>
          <code>{command}</code>
          <button
            onClick={() => {
              void navigator.clipboard.writeText(command);
              notify("Command copied", "Paste it into the authorized OSIRIS host.");
            }}
          >
            Copy
          </button>
        </div>
        <button
          className="button primary full-width large"
          onClick={stageRun}
          disabled={runState === "staging"}
        >
          {runState === "staging" ? (
            <>
              <RefreshCw className="spin" size={16} /> Validating…
            </>
          ) : runState === "ready" ? (
            <>
              <CheckCircle2 size={16} /> Configuration ready
            </>
          ) : (
            <>
              <Play size={16} /> Validate and stage run
            </>
          )}
        </button>
        <p className="run-disclaimer">
          This browser workspace prepares the run. Collection executes only on your authorized
          OSIRIS backend.
        </p>
      </aside>
    </div>
  );
}

function Evidence({
  imported,
  onImport,
  onDrop,
  onSelect,
}: {
  imported: ImportedArtifact[];
  onImport: () => void;
  onDrop: (event: DragEvent<HTMLElement>) => void;
  onSelect: (item: (typeof evidenceItems)[number]) => void;
}) {
  const [query, setQuery] = useState("");
  const [dragging, setDragging] = useState(false);
  const filtered = evidenceItems.filter(
    (item) =>
      item.value.toLowerCase().includes(query.toLowerCase()) ||
      item.type.toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="content-stack">
      <section
        className={cx("drop-zone", dragging && "dragging")}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          setDragging(false);
          onDrop(event);
        }}
      >
        <div className="drop-icon">
          <Upload size={20} />
        </div>
        <div>
          <strong>Import an OSIRIS artifact</strong>
          <p>Drop raw_scan.json, dossier.json, explanation cards, or a report here.</p>
        </div>
        <button className="button secondary" onClick={onImport}>
          Choose JSON file
        </button>
      </section>

      {imported.length ? (
        <section className="panel">
          <SectionHeader title="Imported in this session" detail="Parsed and hashed locally" />
          <div className="artifact-strip">
            {imported.map((item) => (
              <article key={`${item.name}-${item.hash}`}>
                <FileJson2 size={19} />
                <div>
                  <strong>{item.name}</strong>
                  <small>
                    {item.kind} · {item.records} records · {formatBytes(item.size)}
                  </small>
                </div>
                <StatusBadge tone="good">SHA-256</StatusBadge>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="panel">
        <SectionHeader
          title="Evidence register"
          detail={`${filtered.length} normalized observations · source bytes preserved separately`}
          action={
            <button className="button tertiary">
              <ArrowDownToLine size={15} /> Export index
            </button>
          }
        />
        <div className="table-toolbar">
          <label className="field-with-icon grow">
            <Search size={15} />
            <input
              placeholder="Search value or entity type"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <button className="button tertiary">
            <SlidersHorizontal size={15} /> Filters
          </button>
        </div>
        <div className="data-table-wrap">
          <table className="data-table evidence-table">
            <thead>
              <tr>
                <th>Observation</th>
                <th>Source</th>
                <th>Observed</th>
                <th>Confidence</th>
                <th>Integrity</th>
                <th aria-label="Open" />
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={item.id} onClick={() => onSelect(item)}>
                  <td>
                    <div className="observation-cell">
                      <span className={`entity-token ${item.type.toLowerCase().replace(" ", "-")}`}>
                        <CircleDot size={14} />
                      </span>
                      <span>
                        <strong>{item.value}</strong>
                        <small>
                          {item.type} · {item.id}
                        </small>
                      </span>
                    </div>
                  </td>
                  <td>
                    <code className="inline-code">{item.source}</code>
                  </td>
                  <td className="muted-cell">{item.observed}</td>
                  <td>
                    <div className="confidence-cell">
                      <span>
                        <i style={{ width: `${item.confidence * 100}%` }} />
                      </span>
                      {Math.round(item.confidence * 100)}%
                    </div>
                  </td>
                  <td>
                    <StatusBadge tone="good">
                      <BadgeCheck size={13} /> {item.integrity}
                    </StatusBadge>
                  </td>
                  <td>
                    <ChevronRight size={15} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function GraphView({
  selected,
  onSelect,
}: {
  selected: GraphNode | null;
  onSelect: (node: GraphNode) => void;
}) {
  const [visibleTypes, setVisibleTypes] = useState<string[]>([
    "target",
    "domain",
    "dns",
    "asn",
    "certificate",
    "event",
  ]);
  const [showLabels, setShowLabels] = useState(true);
  const nodes = graphNodes.filter((node) => visibleTypes.includes(node.type));
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graphEdges.filter((edge) => nodeIds.has(edge.from) && nodeIds.has(edge.to));
  const byId = Object.fromEntries(graphNodes.map((node) => [node.id, node]));

  const shape = (node: GraphNode) => {
    const common = {
      className: `graph-node-shape ${node.type}`,
      vectorEffect: "non-scaling-stroke" as const,
    };
    if (node.type === "asn") {
      return (
        <polygon
          {...common}
          points={`${node.x},${node.y - 28} ${node.x + 32},${node.y + 25} ${node.x - 32},${node.y + 25}`}
        />
      );
    }
    if (node.type === "certificate" || node.type === "target") {
      return (
        <polygon
          {...common}
          points={`${node.x - 31},${node.y} ${node.x - 16},${node.y - 28} ${node.x + 16},${node.y - 28} ${node.x + 31},${node.y} ${node.x + 16},${node.y + 28} ${node.x - 16},${node.y + 28}`}
        />
      );
    }
    if (node.type === "event") {
      return (
        <rect {...common} x={node.x - 26} y={node.y - 26} width="52" height="52" rx="5" />
      );
    }
    if (node.type === "dns") {
      return (
        <rect {...common} x={node.x - 35} y={node.y - 24} width="70" height="48" rx="12" />
      );
    }
    return <circle {...common} cx={node.x} cy={node.y} r="28" />;
  };

  return (
    <div className="graph-layout">
      <section className="panel graph-panel">
        <div className="graph-toolbar">
          <div>
            <StatusBadge tone="good">
              <BadgeCheck size={13} /> 6 evidence-backed edges
            </StatusBadge>
            <span>Fixed evidentiary layout</span>
          </div>
          <div>
            <label className="compact-toggle">
              <input
                type="checkbox"
                checked={showLabels}
                onChange={(event) => setShowLabels(event.target.checked)}
              />
              <span />
              Labels
            </label>
            <button className="icon-button subtle" aria-label="Graph options">
              <MoreHorizontal size={18} />
            </button>
          </div>
        </div>

        <div className="graph-canvas">
          <svg viewBox="0 0 860 560" role="img" aria-label="Evidence relationship graph">
            <defs>
              <pattern id="console-grid" width="28" height="28" patternUnits="userSpaceOnUse">
                <path d="M28 0H0V28" fill="none" stroke="rgba(98,126,163,.10)" />
              </pattern>
              <marker id="console-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4">
                <path d="M0 0L8 4L0 8Z" fill="#53657c" />
              </marker>
            </defs>
            <rect width="860" height="560" rx="12" fill="url(#console-grid)" />
            {edges.map((edge) => {
              const from = byId[edge.from];
              const to = byId[edge.to];
              const x = (from.x + to.x) / 2;
              const y = (from.y + to.y) / 2;
              return (
                <g key={`${edge.from}-${edge.to}`}>
                  <line
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    className="graph-edge"
                    markerEnd="url(#console-arrow)"
                  />
                  {showLabels ? (
                    <g className="edge-label">
                      <rect x={x - 39} y={y - 10} width="78" height="20" rx="5" />
                      <text x={x} y={y + 1}>
                        {edge.label}
                      </text>
                    </g>
                  ) : null}
                </g>
              );
            })}
            {nodes.map((node) => (
              <g
                key={node.id}
                className={cx("graph-node", selected?.id === node.id && "selected")}
                onClick={() => onSelect(node)}
                role="button"
                tabIndex={0}
                onKeyDown={(event: KeyboardEvent<SVGGElement>) => {
                  if (event.key === "Enter" || event.key === " ") onSelect(node);
                }}
              >
                {shape(node)}
                <circle cx={node.x} cy={node.y} r="7" className="graph-node-core" />
                <text x={node.x} y={node.y + 46} className="graph-node-label">
                  {node.label}
                </text>
                <text x={node.x} y={node.y + 61} className={`graph-node-type ${node.type}`}>
                  {node.type.toUpperCase()}
                </text>
              </g>
            ))}
          </svg>
        </div>

        <div className="graph-legend">
          {["target", "domain", "dns", "asn", "certificate", "event"].map((type) => (
            <button
              key={type}
              className={cx(!visibleTypes.includes(type) && "disabled")}
              onClick={() =>
                setVisibleTypes((current) =>
                  current.includes(type)
                    ? current.filter((value) => value !== type)
                    : [...current, type],
                )
              }
            >
              <i className={type} />
              {type === "dns" ? "DNS record" : type}
            </button>
          ))}
        </div>
      </section>

      <aside className="panel graph-inspector">
        {selected ? (
          <>
            <div className="inspector-heading">
              <span className={`inspector-entity ${selected.type}`}>
                <CircleDot size={18} />
              </span>
              <div>
                <small>{selected.type}</small>
                <h2>{selected.label}</h2>
              </div>
              <button className="icon-button subtle" aria-label="Open full record">
                <ExternalLink size={16} />
              </button>
            </div>
            <dl className="inspector-list">
              <div>
                <dt>Entity ID</dt>
                <dd>{selected.id}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{selected.evidence}</dd>
              </div>
              <div>
                <dt>Integrity</dt>
                <dd>
                  <StatusBadge tone="good">Verified</StatusBadge>
                </dd>
              </div>
              <div>
                <dt>Relationships</dt>
                <dd>
                  {
                    graphEdges.filter(
                      (edge) => edge.from === selected.id || edge.to === selected.id,
                    ).length
                  }
                </dd>
              </div>
            </dl>
            <div className="inspector-section">
              <h3>Connected entities</h3>
              {graphEdges
                .filter((edge) => edge.from === selected.id || edge.to === selected.id)
                .map((edge) => {
                  const related = byId[edge.from === selected.id ? edge.to : edge.from];
                  return (
                    <button key={`${edge.from}-${edge.to}`} onClick={() => onSelect(related)}>
                      <span className={`entity-dot ${related.type}`} />
                      <span>
                        <strong>{related.label}</strong>
                        <small>{edge.label}</small>
                      </span>
                      <ChevronRight size={14} />
                    </button>
                  );
                })}
            </div>
            <div className="source-grounding">
              <FileCheck2 size={17} />
              <div>
                <strong>Source grounded</strong>
                <p>This node resolves to preserved evidence in the case store.</p>
              </div>
            </div>
          </>
        ) : (
          <EmptyState
            icon={<Network size={22} />}
            title="Select an entity"
            detail="Inspect its provenance and evidence-backed relationships."
          />
        )}
      </aside>
    </div>
  );
}

function XaiReview({ navigate }: { navigate: (view: View) => void }) {
  const max = Math.max(...riskFeatures.map((feature) => Math.abs(feature.contribution)));
  return (
    <div className="content-stack">
      <section className="xai-summary">
        <div className="score-orbit">
          <svg viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="48" className="score-track" />
            <circle
              cx="60"
              cy="60"
              r="48"
              className="score-progress"
              pathLength="100"
              strokeDasharray="22 100"
            />
          </svg>
          <div>
            <strong>22</strong>
            <span>/ 100</span>
          </div>
        </div>
        <div className="xai-summary-copy">
          <p className="eyebrow">Deterministic risk result</p>
          <h2>Low risk, with limited evidence coverage</h2>
          <p>
            The score is reconstructed from signed feature contributions. The LLM extracted the
            evidence features but did not set this result.
          </p>
          <div className="xai-tags">
            <StatusBadge tone="good">Score reconstructs exactly</StatusBadge>
            <StatusBadge tone="info">Scorer v1.0.0</StatusBadge>
            <StatusBadge tone="warning">Evidence sufficiency 43%</StatusBadge>
          </div>
        </div>
        <div className="xai-model-card">
          <span>
            <Sparkles size={16} />
          </span>
          <div>
            <small>Extraction model</small>
            <strong>openai/gpt-oss-120b</strong>
            <p>via OpenRouter · prompt v2</p>
          </div>
        </div>
      </section>

      <div className="xai-grid">
        <section className="panel feature-panel">
          <SectionHeader
            title="Score reconstruction"
            detail="Intercept + signed contributions = 21.9 → 22"
          />
          <div className="waterfall">
            {riskFeatures.map((feature) => (
              <div className="waterfall-row" key={feature.name}>
                <div>
                  <strong>{feature.label}</strong>
                  <small>{feature.evidence}</small>
                </div>
                <div className="waterfall-track">
                  <span className="waterfall-zero" />
                  <i
                    className={feature.direction}
                    style={{
                      width: `${(Math.abs(feature.contribution) / max) * 48}%`,
                    }}
                  />
                </div>
                <strong
                  className={feature.contribution < 0 ? "negative-number" : "positive-number"}
                >
                  {feature.contribution > 0 ? "+" : ""}
                  {feature.contribution.toFixed(1)}
                </strong>
              </div>
            ))}
          </div>
          <div className="reconstruction-check">
            <Hash size={17} />
            <span>
              <strong>15 + 11.4 + 7.2 − 8.6 − 3.1 = 21.9</strong>
              <small>Rounded final score: 22 · reconstruction PASS</small>
            </span>
            <BadgeCheck size={19} />
          </div>
        </section>

        <section className="panel gate-panel">
          <SectionHeader title="Audit gates" detail="Release policy inputs" />
          <div className="gate-list">
            <div className="gate-item pass">
              <span>
                <Check size={14} />
              </span>
              <div>
                <strong>Score reconstruction</strong>
                <p>Exact deterministic replay</p>
              </div>
              <StatusBadge tone="good">Pass</StatusBadge>
            </div>
            <div className="gate-item warning">
              <span>
                <ShieldAlert size={14} />
              </span>
              <div>
                <strong>Fairness sensitivity</strong>
                <p>Scoring-only test is inconclusive</p>
              </div>
              <StatusBadge tone="warning">Review</StatusBadge>
            </div>
            <div className="gate-item pass">
              <span>
                <Check size={14} />
              </span>
              <div>
                <strong>Robustness</strong>
                <p>No decision boundary flip</p>
              </div>
              <StatusBadge tone="good">Pass</StatusBadge>
            </div>
            <div className="gate-item pass">
              <span>
                <Check size={14} />
              </span>
              <div>
                <strong>Evidence integrity</strong>
                <p>All referenced hashes verify</p>
              </div>
              <StatusBadge tone="good">Pass</StatusBadge>
            </div>
          </div>
          <div className="release-block">
            <LockKeyhole size={19} />
            <div>
              <strong>Dissemination remains blocked</strong>
              <p>Resolve or accept the fairness limitation with documented human review.</p>
            </div>
          </div>
          <button className="button secondary full-width" onClick={() => navigate("reports")}>
            Continue to review bundle <ArrowRight size={15} />
          </button>
        </section>
      </div>

      <section className="panel explanation-panel">
        <SectionHeader title="Analyst explanation" detail="Grounded in normalized evidence" />
        <div className="explanation-content">
          <div className="explanation-line" />
          <div>
            <p>
              <strong>example.com received a score of 22 (LOW).</strong> The primary upward
              drivers were three externally observed services and certificate-age evidence.
              Established domain age and corroboration across preserved sources reduced the
              result.
            </p>
            <p>
              The result should be interpreted cautiously because evidence coverage is limited.
              No psychological or ideology attributes contributed to operational scoring.
            </p>
            <div className="citation-row">
              {["EV-8D3F-001", "EV-8D3F-002", "EV-8D3F-004"].map((id) => (
                <button key={id} onClick={() => navigate("evidence")}>
                  <Database size={13} /> {id}
                </button>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

function Reports({
  notify,
  onDownload,
}: {
  notify: (title: string, detail: string) => void;
  onDownload: () => void;
}) {
  const reports = [
    {
      name: "Investigation report",
      file: "report.pdf",
      detail: "Human-readable technical review",
      icon: FileText,
      status: "Review-only",
      action: () => window.print(),
    },
    {
      name: "Structured report",
      file: "report.json",
      detail: "Versioned machine-readable contract",
      icon: FileJson2,
      status: "Ready",
      action: onDownload,
    },
    {
      name: "XAI explanation cards",
      file: "explanation_cards.json",
      detail: "Attribution and audit details",
      icon: BrainCircuit,
      status: "Ready",
      action: onDownload,
    },
    {
      name: "MISP export",
      file: "misp_export.json",
      detail: "Threat-intelligence dissemination",
      icon: ExternalLink,
      status: "Blocked",
      action: () =>
        notify("Export blocked by policy", "Human fairness review is required before MISP export."),
    },
  ];

  return (
    <div className="reports-layout">
      <section className="panel report-preview">
        <div className="report-paper">
          <header>
            <div className="report-wordmark">
              <span className="brand-mark small">
                <span />
              </span>
              <strong>OSIRIS</strong>
            </div>
            <span>TECHNICAL REVIEW ONLY</span>
          </header>
          <div className="report-title">
            <p>INVESTIGATION DOSSIER</p>
            <h2>Example Domain Assessment</h2>
            <span>{caseRecord.id} · 24 July 2026</span>
          </div>
          <div className="report-rule" />
          <div className="report-summary-grid">
            <div>
              <small>Target</small>
              <strong>example.com</strong>
            </div>
            <div>
              <small>Risk posture</small>
              <strong>22 · LOW</strong>
            </div>
            <div>
              <small>Handling</small>
              <strong>{caseRecord.handling}</strong>
            </div>
          </div>
          <h3>Executive summary</h3>
          <p>
            This review-only assessment consolidates authorized public-source observations,
            deterministic scoring, and evidence-linked explanations for example.com.
          </p>
          <div className="report-placeholder wide" />
          <div className="report-placeholder medium" />
          <h3>Evidence posture</h3>
          <div className="report-mini-table">
            <span>Verified evidence objects</span>
            <strong>4</strong>
            <span>Evidence sufficiency</span>
            <strong>43%</strong>
            <span>Release decision</span>
            <strong className="blocked-text">BLOCKED</strong>
          </div>
          <footer>
            <span>Generated by OSIRIS Evidence Platform</span>
            <span>Page 1 of 6</span>
          </footer>
        </div>
      </section>

      <aside className="content-stack report-actions">
        <section className="panel">
          <SectionHeader title="Generated artifacts" detail="Latest review bundle" />
          <div className="report-list">
            {reports.map((item) => {
              const Icon = item.icon;
              return (
                <button key={item.name} onClick={item.action}>
                  <span className="report-file-icon">
                    <Icon size={18} />
                  </span>
                  <span>
                    <strong>{item.name}</strong>
                    <small>
                      {item.file} · {item.detail}
                    </small>
                  </span>
                  <StatusBadge
                    tone={
                      item.status === "Blocked"
                        ? "danger"
                        : item.status === "Review-only"
                          ? "warning"
                          : "good"
                    }
                  >
                    {item.status}
                  </StatusBadge>
                  {item.status === "Blocked" ? <LockKeyhole size={15} /> : <Download size={15} />}
                </button>
              );
            })}
          </div>
        </section>

        <section className="panel release-decision">
          <div className="release-decision-icon">
            <ShieldAlert size={21} />
          </div>
          <div>
            <p className="eyebrow">Release decision</p>
            <h2>Blocked pending review</h2>
            <p>
              PDF remains available for technical review. Structured dissemination is disabled.
            </p>
          </div>
          <dl>
            <div>
              <dt>Audit gate</dt>
              <dd>1 exception</dd>
            </div>
            <div>
              <dt>Score mode</dt>
              <dd>REAL</dd>
            </div>
            <div>
              <dt>Authorization</dt>
              <dd>Approved</dd>
            </div>
            <div>
              <dt>Integrity</dt>
              <dd>PASS</dd>
            </div>
          </dl>
        </section>
      </aside>
    </div>
  );
}

function Integrity({ notify }: { notify: (title: string, detail: string) => void }) {
  const [input, setInput] = useState("example.com");
  const [digest, setDigest] = useState("");
  const calculate = async () => {
    setDigest(await sha256(input));
    notify("SHA-256 calculated", "The value was processed locally in your browser.");
  };

  return (
    <div className="content-stack">
      <section className="integrity-hero">
        <div className="integrity-shield">
          <ShieldCheck size={28} />
          <span />
        </div>
        <div>
          <p className="eyebrow">Capsule verification result</p>
          <h2>Evidence integrity verified</h2>
          <p>
            Manifest signature, artifact hashes, byte lengths, and case/run consistency all pass.
          </p>
        </div>
        <StatusBadge tone="good">
          <BadgeCheck size={14} /> PASS
        </StatusBadge>
      </section>

      <div className="integrity-grid">
        <section className="panel">
          <SectionHeader title="Verification controls" detail="Local-development evidence capsule" />
          <div className="control-checks">
            {[
              ["Manifest signature", "Ed25519 signature valid"],
              ["Artifact completeness", "12 of 12 expected files"],
              ["Content hashes", "All SHA-256 digests match"],
              ["Case consistency", `${caseRecord.id} across all artifacts`],
              ["Run consistency", "cd73ade6… across all artifacts"],
              ["Unexpected files", "None detected"],
            ].map(([name, detail]) => (
              <div key={name}>
                <span>
                  <Check size={14} />
                </span>
                <div>
                  <strong>{name}</strong>
                  <p>{detail}</p>
                </div>
                <StatusBadge tone="good">Pass</StatusBadge>
              </div>
            ))}
          </div>
        </section>

        <section className="panel lineage-card">
          <SectionHeader title="Lineage" detail="PROV-O compatible run trace" />
          <div className="lineage-flow">
            {[
              ["Raw evidence", Database],
              ["Normalized scan", FileJson2],
              ["Dossier", BrainCircuit],
              ["Review bundle", Archive],
            ].map(([label, Icon], index) => {
              const Component = Icon as typeof Database;
              return (
                <div className="lineage-step" key={label as string}>
                  <span>
                    <Component size={17} />
                  </span>
                  <strong>{label as string}</strong>
                  {index < 3 ? <ChevronRight size={15} /> : null}
                </div>
              );
            })}
          </div>
          <dl className="inspector-list">
            <div>
              <dt>Case ID</dt>
              <dd>{caseRecord.id}</dd>
            </div>
            <div>
              <dt>Run ID</dt>
              <dd>cd73ade6-549d…</dd>
            </div>
            <div>
              <dt>Signing key</dt>
              <dd>local-dev-ed25519</dd>
            </div>
            <div>
              <dt>Generated</dt>
              <dd>24 Jul 2026 · 10:27 UTC</dd>
            </div>
          </dl>
        </section>
      </div>

      <section className="panel hash-tool">
        <SectionHeader
          title="SHA-256 workbench"
          detail="Calculate a digest locally without sending data anywhere."
        />
        <div className="hash-input-row">
          <label className="form-field grow">
            <span>Text to hash</span>
            <input value={input} onChange={(event) => setInput(event.target.value)} />
          </label>
          <button className="button primary" onClick={() => void calculate()}>
            <Hash size={15} /> Calculate
          </button>
        </div>
        {digest ? (
          <div className="hash-result">
            <Fingerprint size={17} />
            <code>{digest}</code>
            <button
              onClick={() => {
                void navigator.clipboard.writeText(digest);
                notify("Digest copied", "SHA-256 copied to the clipboard.");
              }}
            >
              Copy
            </button>
          </div>
        ) : null}
      </section>
    </div>
  );
}

function CommandPalette({
  query,
  setQuery,
  onClose,
  navigate,
}: {
  query: string;
  setQuery: (value: string) => void;
  onClose: () => void;
  navigate: (view: View) => void;
}) {
  const options = [
    ...navItems.map((item) => ({
      title: item.label,
      detail: viewMeta[item.id].description,
      view: item.id,
      icon: item.icon,
    })),
    ...recentCases.map((item) => ({
      title: item.target,
      detail: `${item.id} · ${item.status}`,
      view: "overview" as View,
      icon: FolderKanban,
    })),
  ].filter(
    (item) =>
      item.title.toLowerCase().includes(query.toLowerCase()) ||
      item.detail.toLowerCase().includes(query.toLowerCase()),
  );

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="command-palette" onMouseDown={(event) => event.stopPropagation()}>
        <div className="command-input">
          <Search size={18} />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search the investigation workspace…"
          />
          <kbd>ESC</kbd>
        </div>
        <div className="command-results">
          <p>Quick navigation</p>
          {options.slice(0, 8).map((item, index) => {
            const Icon = item.icon;
            return (
              <button
                key={`${item.title}-${index}`}
                onClick={() => {
                  navigate(item.view);
                  onClose();
                }}
              >
                <span>
                  <Icon size={17} />
                </span>
                <div>
                  <strong>{item.title}</strong>
                  <small>{item.detail}</small>
                </div>
                <ArrowRight size={15} />
              </button>
            );
          })}
          {!options.length ? (
            <EmptyState
              icon={<Search size={20} />}
              title="No matching records"
              detail="Try a case ID, target, feature, or workspace name."
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function EvidenceDrawer({
  item,
  onClose,
}: {
  item: (typeof evidenceItems)[number];
  onClose: () => void;
}) {
  return (
    <>
      <button className="drawer-backdrop" onClick={onClose} aria-label="Close evidence details" />
      <aside className="evidence-drawer">
        <header>
          <div>
            <p className="eyebrow">Evidence observation</p>
            <h2>{item.value}</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="drawer-content">
          <div className="evidence-identity">
            <span className={`entity-token ${item.type.toLowerCase().replace(" ", "-")}`}>
              <CircleDot size={17} />
            </span>
            <div>
              <strong>{item.type}</strong>
              <p>{item.id}</p>
            </div>
            <StatusBadge tone="good">
              <BadgeCheck size={13} /> Verified
            </StatusBadge>
          </div>
          <dl className="drawer-details">
            <div>
              <dt>Source module</dt>
              <dd>{item.source}</dd>
            </div>
            <div>
              <dt>Observed</dt>
              <dd>{item.observed}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{Math.round(item.confidence * 100)}%</dd>
            </div>
            <div>
              <dt>Handling</dt>
              <dd>{caseRecord.handling}</dd>
            </div>
          </dl>
          <div className="hash-block">
            <div>
              <Hash size={14} />
              <span>SHA-256</span>
            </div>
            <code>{item.hash}</code>
          </div>
          <section className="drawer-section">
            <h3>Provenance</h3>
            <div className="provenance-line">
              <span>
                <Radar size={15} />
              </span>
              <div>
                <strong>SpiderFoot observation</strong>
                <p>Preserved as immutable source bytes</p>
              </div>
            </div>
            <div className="provenance-line">
              <span>
                <SlidersHorizontal size={15} />
              </span>
              <div>
                <strong>Normalized entity</strong>
                <p>Mapped to OSIRIS evidence contract</p>
              </div>
            </div>
            <div className="provenance-line">
              <span>
                <BadgeCheck size={15} />
              </span>
              <div>
                <strong>Integrity verified</strong>
                <p>Hash and byte length match</p>
              </div>
            </div>
          </section>
        </div>
      </aside>
    </>
  );
}
