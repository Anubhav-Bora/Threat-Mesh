import { useEffect, useMemo, useState } from "react";
import {
  Bot,
  CircleHelp,
  Crosshair,
  FileCode2,
  FileText,
  Globe2,
  Hexagon,
  Menu,
  Search,
  Settings,
  ShieldCheck,
  Swords,
  X,
} from "lucide-react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useApiMode, useFeedStatus, useSummary } from "../hooks/useThreatData";
import { formatRelative } from "../utils/format";
import { Logo } from "./Logo";

const navigation = [
  { to: "/", label: "Operations", icon: Globe2, end: true },
  { to: "/campaigns", label: "Campaigns", icon: Swords },
  { to: "/attack", label: "MITRE ATT&CK", icon: Hexagon },
  { to: "/indicators", label: "Indicators", icon: Crosshair },
  { to: "/reports", label: "Intel reports", icon: FileText },
  { to: "/rules", label: "Detection rules", icon: FileCode2 },
  { to: "/assistant", label: "Ask ThreatMesh", icon: Bot },
];

const routeMeta: Record<
  string,
  { eyebrow: string; title: string; description: string }
> = {
  "/": {
    eyebrow: "Threat intelligence",
    title: "Threat operations",
    description:
      "Geospatial OSINT, enriched and correlated in one analyst workspace.",
  },
  "/campaigns": {
    eyebrow: "Correlation",
    title: "Campaign intelligence",
    description:
      "Infrastructure communities inferred from repeated indicator, malware-family, or ASN evidence.",
  },
  "/attack": {
    eyebrow: "Behavior",
    title: "MITRE ATT&CK coverage",
    description:
      "Observed techniques mapped from malware and campaign evidence.",
  },
  "/indicators": {
    eyebrow: "Investigation",
    title: "Indicator explorer",
    description: "Search, validate, and trace normalized OSINT evidence.",
  },
  "/reports": {
    eyebrow: "Intelligence products",
    title: "CTI reports",
    description: "Fact-grounded reporting prepared for analyst review.",
  },
  "/rules": {
    eyebrow: "Detection engineering",
    title: "Detection candidates",
    description: "Versionable Sigma and Suricata content for human validation.",
  },
  "/assistant": {
    eyebrow: "Retrieval-first AI",
    title: "Ask ThreatMesh",
    description:
      "Retrieval-bounded answers with server-validated evidence IDs.",
  },
  "/settings": {
    eyebrow: "Workspace",
    title: "Data & integrations",
    description: "Inspect runtime configuration and data source health.",
  },
};

export function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const apiMode = useApiMode();
  const feedStatus = useFeedStatus();
  const summaryQuery = useSummary();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [query, setQuery] = useState("");
  const meta = routeMeta[location.pathname] ?? routeMeta["/"]!;

  useEffect(() => {
    setMobileOpen(false);
    setCommandOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen((value) => !value);
      }
      if (event.key === "Escape") setCommandOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const commandItems = useMemo(
    () =>
      navigation.filter((item) =>
        item.label.toLowerCase().includes(query.toLowerCase()),
      ),
    [query],
  );
  const latestPipelineRun = useMemo(() => {
    const runs = feedStatus.data?.data ?? [];
    return runs
      .map((run) => run.completedAt ?? run.startedAt)
      .sort(
        (left, right) => new Date(right).getTime() - new Date(left).getTime(),
      )[0];
  }, [feedStatus.data]);
  const feedRuns = feedStatus.data?.data ?? [];
  const inferredSeededDemo =
    feedRuns.length > 0 &&
    feedRuns.every((run) => run.feed.toLowerCase().startsWith("demo-"));
  const corpusMode =
    summaryQuery.data?.mode === "live"
      ? summaryQuery.data.data.corpusMode
      : apiMode === "demo"
        ? "demo"
        : inferredSeededDemo
          ? "demo"
          : "unknown";
  const analysisScope = summaryQuery.data?.data.analysisScope;
  const dataModeLabel =
    apiMode === "checking"
      ? "Connecting"
      : apiMode === "error"
        ? "API degraded"
        : apiMode === "demo"
          ? "Bundled demo data"
          : corpusMode === "demo"
            ? "Seeded demo via API"
            : corpusMode === "mixed"
              ? analysisScope === "live"
                ? "Mixed corpus · live-only analytics"
                : "Mixed demo + live corpus"
              : corpusMode === "live"
                ? "Live feed corpus"
                : corpusMode === "empty"
                  ? "Empty API corpus"
                  : "API connected";

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className={`sidebar ${mobileOpen ? "sidebar--open" : ""}`}>
        <div className="sidebar__top">
          <Logo />
          <button
            className="icon-button sidebar__close"
            type="button"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>
        <div className="workspace-switcher">
          <div className="workspace-switcher__icon">
            <ShieldCheck size={17} />
          </div>
          <div>
            <span>Workspace</span>
            <strong>Global SOC</strong>
          </div>
        </div>
        <nav className="sidebar__nav" aria-label="Primary navigation">
          <span className="sidebar__label">Intelligence</span>
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `nav-link ${isActive ? "nav-link--active" : ""}`
              }
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar__footer">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              `nav-link ${isActive ? "nav-link--active" : ""}`
            }
          >
            <Settings size={18} />
            <span>Settings</span>
          </NavLink>
          <a
            className="nav-link"
            href="https://github.com/mitre-attack/attack-stix-data"
            target="_blank"
            rel="noreferrer"
          >
            <CircleHelp size={18} />
            <span>Data methodology</span>
          </a>
          <div className="analyst-card">
            <span className="analyst-card__avatar">TM</span>
            <div>
              <strong>ThreatMesh Analyst</strong>
              <span>Open-source workspace</span>
            </div>
            <span
              className="status-dot status-dot--online"
              aria-label="Online"
            />
          </div>
        </div>
      </aside>

      {mobileOpen && (
        <button
          className="sidebar-scrim"
          type="button"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <div className="app-main">
        <header className="topbar">
          <button
            className="icon-button topbar__menu"
            type="button"
            onClick={() => setMobileOpen(true)}
            aria-label="Open navigation"
          >
            <Menu size={20} />
          </button>
          <div className="page-heading">
            <span>{meta.eyebrow}</span>
            <h1>{meta.title}</h1>
          </div>
          <button
            className="command-trigger"
            type="button"
            onClick={() => setCommandOpen(true)}
          >
            <Search size={16} />
            <span>Search workspace</span>
            <kbd>Ctrl K</kbd>
          </button>
          <div
            className={`data-mode data-mode--${apiMode === "demo" || corpusMode === "demo" || corpusMode === "mixed" ? "demo" : apiMode}`}
            title={
              apiMode === "error"
                ? "One or more API requests failed; no synthetic records were substituted."
                : apiMode === "demo"
                  ? "One or more resources uses the bundled deterministic demo dataset."
                  : corpusMode === "demo"
                    ? "The API is connected and the stored corpus is seeded synthetic demo data."
                    : corpusMode === "mixed"
                      ? analysisScope === "live"
                        ? "The API corpus contains demo and live records; operational analytics use live records only."
                        : "The API corpus contains both seeded demo and live feed records."
                      : "Connected to ThreatMesh API"
            }
          >
            <span className="status-dot" />
            {dataModeLabel}
          </div>
        </header>

        <main id="main-content" className="content">
          <div className="page-intro">
            <p>{meta.description}</p>
            <span className="freshness">
              <span className="status-dot status-dot--online" />
              {apiMode === "live"
                ? latestPipelineRun
                  ? `Pipeline updated ${formatRelative(latestPipelineRun)}`
                  : "No feed run recorded"
                : apiMode === "demo"
                  ? "Bundled demo snapshot"
                  : apiMode === "error"
                    ? "API request failure"
                    : "Checking pipeline"}
            </span>
          </div>
          <Outlet />
        </main>
      </div>

      {commandOpen && (
        <div
          className="command-overlay"
          role="presentation"
          onMouseDown={() => setCommandOpen(false)}
        >
          <div
            className="command-dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Search workspace"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="command-dialog__input">
              <Search size={19} />
              <input
                autoFocus
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Go to a workspace…"
                aria-label="Search navigation"
              />
              <kbd>Esc</kbd>
            </div>
            <div className="command-dialog__results">
              <span className="command-dialog__label">Navigate</span>
              {commandItems.map(({ to, label, icon: Icon }) => (
                <button key={to} type="button" onClick={() => navigate(to)}>
                  <Icon size={18} />
                  <span>{label}</span>
                  <small>Open</small>
                </button>
              ))}
              {commandItems.length === 0 && (
                <p className="command-empty">No workspace matches “{query}”.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
