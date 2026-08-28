import {
  Check,
  CircleDot,
  Cloud,
  Copy,
  Database,
  ExternalLink,
  Globe2,
  KeyRound,
  LockKeyhole,
  Map,
  Server,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { API_BASE_URL } from "../api/client";
import { Badge, CopyButton, PanelHeader } from "../components/UI";
import { useApiMode, useFeedStatus, useSummary } from "../hooks/useThreatData";

const feeds = [
  {
    name: "URLhaus",
    detail: "Malicious URL payload delivery",
    auth: "Free Auth-Key",
    slug: "urlhaus",
  },
  {
    name: "ThreatFox",
    detail: "Malware-tagged IOCs",
    auth: "Free Auth-Key",
    slug: "threatfox",
  },
  {
    name: "Feodo Tracker",
    detail: "Active botnet C2 infrastructure",
    auth: "No key",
    slug: "feodo",
  },
];

export default function SettingsPage() {
  const mode = useApiMode();
  const feedStatusQuery = useFeedStatus();
  const summaryQuery = useSummary();
  const feedRuns = feedStatusQuery.data?.data ?? [];
  const inferredSeededDemo =
    feedRuns.length > 0 &&
    feedRuns.every((run) => run.feed.toLowerCase().startsWith("demo-"));
  const summaryCorpusMode = summaryQuery.data?.data.corpusMode;
  const analysisScope = summaryQuery.data?.data.analysisScope;
  const corpusMode =
    !summaryCorpusMode || summaryCorpusMode === "unknown"
      ? inferredSeededDemo
        ? "demo"
        : "unknown"
      : summaryCorpusMode;
  const hasArcGisKey = Boolean(import.meta.env.VITE_ARCGIS_API_KEY?.trim());
  return (
    <div className="settings-page">
      <section className="panel environment-panel">
        <PanelHeader eyebrow="Runtime" title="Workspace environment" />
        <div className="environment-grid">
          <div>
            <span className="environment-icon">
              <Server size={19} />
            </span>
            <div>
              <span>API endpoint</span>
              <code>{API_BASE_URL}</code>
            </div>
            <Badge
              tone={
                mode === "live"
                  ? "success"
                  : mode === "demo"
                    ? "info"
                    : "warning"
              }
              dot
            >
              {mode === "live" ? "connected" : mode}
            </Badge>
          </div>
          <div>
            <span className="environment-icon">
              <Map size={19} />
            </span>
            <div>
              <span>ArcGIS basemap</span>
              <strong>
                {hasArcGisKey
                  ? "Public imagery · credentials available"
                  : "Public ArcGIS World Imagery"}
              </strong>
            </div>
            <Badge tone={hasArcGisKey ? "success" : "neutral"}>
              {hasArcGisKey ? "configured" : "optional"}
            </Badge>
          </div>
          <div>
            <span className="environment-icon">
              <Database size={19} />
            </span>
            <div>
              <span>Dataset</span>
              <strong>
                {mode === "demo"
                  ? "Bundled deterministic demo"
                  : corpusMode === "demo"
                    ? "Seeded demo via API"
                    : corpusMode === "mixed"
                      ? analysisScope === "live"
                        ? "Mixed records · live-only analytics"
                        : "Mixed demo + live records"
                      : corpusMode === "live"
                        ? "Live feed records"
                        : mode === "live"
                          ? "API-backed dataset · provenance pending"
                          : mode === "error"
                            ? "API request failed"
                            : "Checking API dataset"}
              </strong>
            </div>
            <Badge
              tone={
                mode === "demo" || corpusMode === "demo"
                  ? "info"
                  : mode === "error"
                    ? "critical"
                    : corpusMode === "mixed"
                      ? "warning"
                      : "success"
              }
            >
              {mode === "demo"
                ? "demo"
                : corpusMode === "demo"
                  ? "seeded demo"
                  : corpusMode === "mixed"
                    ? "mixed"
                    : corpusMode === "live"
                      ? "live feeds"
                      : mode === "live"
                        ? "API"
                        : mode === "error"
                          ? "error"
                          : "checking"}
            </Badge>
          </div>
        </div>
      </section>

      <div className="settings-grid">
        <section className="panel setup-card setup-card--wide">
          <div className="setup-card__head">
            <span className="setup-icon setup-icon--map">
              <Globe2 size={20} />
            </span>
            <div>
              <span className="eyebrow">Optional ArcGIS credentials</span>
              <h2>ArcGIS Location Platform</h2>
            </div>
            <Badge tone={hasArcGisKey ? "success" : "neutral"} dot>
              {hasArcGisKey ? "Connected" : "Not required"}
            </Badge>
          </div>
          <p>
            ThreatMesh works without a key by using public ArcGIS World Imagery
            with the ArcGIS Boundaries and Places reference layer. The 3D globe
            intentionally uses these public services in both configurations; add
            a restricted key only for premium ArcGIS services you introduce
            later.
          </p>
          {!hasArcGisKey && (
            <ol className="setup-steps">
              <li>
                <span>1</span>
                <div>
                  <strong>Create a Location Platform account</strong>
                  <p>
                    Open the ArcGIS Location Platform dashboard and create an
                    account/project.
                  </p>
                  <a
                    href="https://location.arcgis.com/"
                    target="_blank"
                    rel="noreferrer"
                  >
                    Open Location Platform <ExternalLink size={13} />
                  </a>
                </div>
              </li>
              <li>
                <span>2</span>
                <div>
                  <strong>Create and restrict an API key</strong>
                  <p>
                    Allow only the basemap privileges you need. Add your local
                    and deployed origins as HTTP referrer restrictions.
                  </p>
                </div>
              </li>
              <li>
                <span>3</span>
                <div>
                  <strong>Add the browser configuration</strong>
                  <div className="env-snippet">
                    <code>VITE_ARCGIS_API_KEY=your_restricted_key</code>
                    <CopyButton text="VITE_ARCGIS_API_KEY=" label="" />
                  </div>
                  <p>
                    Vite embeds this value at build time. For Compose, run{" "}
                    <code>docker compose up --build -d frontend</code>; for the
                    local Vite server, restart it.
                  </p>
                </div>
              </li>
            </ol>
          )}
          <div className="security-notice">
            <TriangleAlert size={17} />
            <div>
              <strong>A Vite browser variable is not a secret</strong>
              <span>
                The key is visible in the built JavaScript by design. Referrer
                restrictions and least-privilege scopes are the protection;
                never place unrestricted service credentials here.
              </span>
            </div>
          </div>
        </section>

        <section className="panel setup-card">
          <div className="setup-card__head">
            <span className="setup-icon setup-icon--ai">
              <Cloud size={20} />
            </span>
            <div>
              <span className="eyebrow">Backend integration</span>
              <h2>Gemini report writer</h2>
            </div>
          </div>
          <p>
            The frontend never receives this secret. Configure it only in the
            FastAPI environment.
          </p>
          <ol className="compact-steps">
            <li>
              <span>1</span>
              <p>Open Google AI Studio and sign in.</p>
            </li>
            <li>
              <span>2</span>
              <p>Create a Gemini API key.</p>
            </li>
            <li>
              <span>3</span>
              <p>
                Set <code>LLM_PROVIDER=gemini</code> and{" "}
                <code>GEMINI_API_KEY=your_key</code> in the root{" "}
                <code>.env</code>. With Compose, recreate the service using{" "}
                <code>docker compose up -d backend</code>; restart a local
                backend process normally.
              </p>
            </li>
          </ol>
          <a
            className="button button--ghost"
            href="https://aistudio.google.com/app/apikey"
            target="_blank"
            rel="noreferrer"
          >
            Google AI Studio <ExternalLink size={14} />
          </a>
          <div className="privacy-inline">
            <LockKeyhole size={15} />
            Free-tier cloud prompts may be used by the provider. Use public
            OSINT only.
          </div>
        </section>

        <section className="panel setup-card">
          <div className="setup-card__head">
            <span className="setup-icon setup-icon--local">
              <Server size={20} />
            </span>
            <div>
              <span className="eyebrow">Private fallback</span>
              <h2>Local Ollama</h2>
            </div>
          </div>
          <p>
            For sensitive or offline data, keep generation on your own machine
            with the provider toggle.
          </p>
          <div className="env-block">
            <div>
              <code>LLM_PROVIDER=ollama</code>
              <Copy size={13} />
            </div>
            <div>
              <code>OLLAMA_MODEL=llama3.1:8b</code>
              <Copy size={13} />
            </div>
          </div>
          <div className="requirement-list">
            <span>
              <Check size={14} />
              No cloud account
            </span>
            <span>
              <Check size={14} />
              Data stays local
            </span>
            <span>
              <CircleDot size={14} />
              Requires local compute
            </span>
          </div>
        </section>
      </div>

      <section className="panel feeds-panel">
        <PanelHeader
          eyebrow="Public OSINT"
          title="Data source operations"
          action={
            <span className="panel-context">
              <ShieldCheck size={14} />
              Passive collection only
            </span>
          }
        />
        <div className="feeds-table">
          <div className="feeds-table__head">
            <span>Source</span>
            <span>Coverage</span>
            <span>Authentication</span>
            <span>Latest run</span>
          </div>
          {feeds.map((feed) => {
            const run = feedRuns.find((item) =>
              item.feed.toLowerCase().includes(feed.slug),
            );
            const status =
              mode === "demo" ? "reference" : (run?.status ?? "not run");
            const tone =
              status === "succeeded"
                ? "success"
                : status === "failed"
                  ? "critical"
                  : status === "partial"
                    ? "warning"
                    : status === "running"
                      ? "info"
                      : "neutral";
            return (
              <div key={feed.name}>
                <strong>{feed.name}</strong>
                <span>{feed.detail}</span>
                <span>
                  <KeyRound size={13} />
                  {feed.auth}
                </span>
                <Badge tone={tone} dot>
                  {status}
                </Badge>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
