import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ChevronRight,
  Download,
  FileCode2,
  Filter,
  GitBranch,
  Search,
  ShieldCheck,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Badge, CopyButton, EmptyState, SkeletonRows } from "../components/UI";
import { useRules } from "../hooks/useThreatData";
import { markSyntheticArtifact } from "../utils/artifacts";
import { downloadText, formatRelative } from "../utils/format";

const RULE_GENERATION_COMMAND = `$env:ADMIN_API_KEY = Read-Host 'Enter the same ADMIN_API_KEY value from .env'
$headers = @{'X-API-Key' = $env:ADMIN_API_KEY}
Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/api/v1/rules/generate' -Headers $headers -ContentType 'application/json' -Body '{"minimum_confidence":70,"limit":500}'`;

export default function RulesPage() {
  const query = useRules();
  const rules = useMemo(() => query.data?.data ?? [], [query.data]);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filtered = useMemo(
    () =>
      rules.filter(
        (rule) =>
          (type === "all" || rule.type === type) &&
          `${rule.name} ${rule.malwareFamily} ${rule.tags.join(" ")}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [rules, search, type],
  );
  const selected = rules.find((rule) => rule.id === selectedId) ?? filtered[0];
  const selectedContent = selected
    ? markSyntheticArtifact(selected.content, selected.type, selected.isDemo)
    : "";

  if (query.isLoading)
    return (
      <section className="panel">
        <SkeletonRows count={8} />
      </section>
    );
  if (query.isError)
    return (
      <section className="panel">
        <EmptyState
          title="Detection rule request failed"
          description="The API returned an error. ThreatMesh did not substitute illustrative rule candidates."
        />
      </section>
    );
  if (query.data?.mode === "live" && rules.length === 0)
    return (
      <section className="panel">
        <EmptyState
          title="No detection candidates generated"
          description="Generate rules from high-confidence, well-tagged observations. ThreatMesh treats every generated rule as a candidate requiring analyst validation before operational use."
        />
        <div className="operator-instruction">
          <strong>PowerShell · authenticated operator request</strong>
          <code>{RULE_GENERATION_COMMAND}</code>
          <CopyButton text={RULE_GENERATION_COMMAND} label="Copy command" />
          <span>Paste the root .env value when PowerShell prompts.</span>
        </div>
      </section>
    );

  return (
    <div className="rules-page">
      <section className="rule-summary-grid">
        <article className="mini-stat">
          <span className="mini-stat__icon mini-stat__icon--purple">
            <FileCode2 size={18} />
          </span>
          <div>
            <span>Total candidates</span>
            <strong>
              {rules.filter((rule) => rule.requiresReview).length}
            </strong>
          </div>
          <small>Versioned content</small>
        </article>
        <article className="mini-stat">
          <span className="mini-stat__icon mini-stat__icon--amber">
            <AlertTriangle size={18} />
          </span>
          <div>
            <span>Awaiting review</span>
            <strong>{rules.length}</strong>
          </div>
          <small>Human validation</small>
        </article>
        <article className="review-policy">
          <ShieldCheck size={20} />
          <div>
            <strong>Review gate enforced</strong>
            <span>Generated rules never deploy autonomously.</span>
          </div>
        </article>
      </section>
      <div className="rules-layout">
        <section className="panel rule-index">
          <div className="rule-toolbar">
            <label className="search-field">
              <Search size={16} />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search rule content"
                aria-label="Search detection rules"
              />
            </label>
            <Link
              to="/settings"
              className="button button--primary button--small"
            >
              <ShieldCheck size={15} />
              Operator setup
            </Link>
          </div>
          <div className="rule-filters">
            <Filter size={14} />
            <button
              type="button"
              className={type === "all" ? "is-active" : ""}
              onClick={() => setType("all")}
            >
              All
            </button>
            <button
              type="button"
              className={type === "sigma" ? "is-active" : ""}
              onClick={() => setType("sigma")}
            >
              Sigma
            </button>
            <button
              type="button"
              className={type === "suricata" ? "is-active" : ""}
              onClick={() => setType("suricata")}
            >
              Suricata
            </button>
          </div>
          <div className="rule-list">
            {filtered.map((rule) => (
              <button
                key={rule.id}
                type="button"
                className={selected?.id === rule.id ? "is-selected" : ""}
                onClick={() => setSelectedId(rule.id)}
              >
                <span className={`rule-type-icon rule-type-icon--${rule.type}`}>
                  {rule.type === "sigma" ? "Σ" : "S"}
                </span>
                <div>
                  <strong>{rule.name}</strong>
                  <span>
                    {rule.malwareFamily} ·{" "}
                    {rule.corroboratingSources.length > 0
                      ? `${rule.corroboratingSources.length} evidence source${rule.corroboratingSources.length === 1 ? "" : "s"}`
                      : `${rule.indicatorCount} indicator${rule.indicatorCount === 1 ? "" : "s"}`}
                  </span>
                  <small>Updated {formatRelative(rule.updatedAt)}</small>
                  {rule.isDemo && <small>Synthetic demo evidence</small>}
                </div>
                <Badge tone={rule.requiresReview ? "warning" : "neutral"} dot>
                  {rule.requiresReview
                    ? "review required"
                    : "review flag not set"}
                </Badge>
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
        </section>

        {selected && (
          <section className="panel rule-detail">
            <header className="rule-detail__header">
              <div>
                <div className="tag-list">
                  {selected.isDemo && <Badge tone="info">Synthetic demo</Badge>}
                  <Badge tone="purple">{selected.type}</Badge>
                  <Badge tone={selected.severity}>{selected.severity}</Badge>
                  <Badge
                    tone={selected.requiresReview ? "warning" : "neutral"}
                    dot
                  >
                    {selected.requiresReview
                      ? "review required"
                      : "review flag not set"}
                  </Badge>
                </div>
                <h2>{selected.name}</h2>
                <span>{selected.id} · revision candidate</span>
              </div>
              <div>
                <CopyButton text={selectedContent} />
                <button
                  className="button button--ghost button--small"
                  type="button"
                  onClick={() =>
                    downloadText(
                      selectedContent,
                      `${selected.isDemo ? "synthetic-demo-" : ""}${selected.id}.${selected.type === "sigma" ? "yml" : "rules"}`,
                    )
                  }
                >
                  <Download size={14} />
                  Download
                </button>
              </div>
            </header>
            <div className="rule-warning">
              <AlertTriangle size={17} />
              <div>
                <strong>
                  Auto-generated candidate — human review required
                </strong>
                <span>
                  Validate syntax, environmental fit, performance, and
                  false-positive behavior in a non-production environment.
                </span>
              </div>
            </div>
            <div className="code-window">
              <div className="code-window__bar">
                <span>
                  <i />
                  <i />
                  <i />
                </span>
                <strong>
                  {selected.id}.{selected.type === "sigma" ? "yml" : "rules"}
                </strong>
                <span>{selected.content.split("\n").length} lines</span>
              </div>
              <pre>
                <code>{selected.content}</code>
              </pre>
            </div>
            <div className="rule-metadata">
              <div>
                <span>False-positive risk</span>
                <strong
                  className={
                    selected.falsePositiveRisk
                      ? `risk risk--${selected.falsePositiveRisk}`
                      : "risk"
                  }
                >
                  {selected.falsePositiveRisk ?? "Not assessed"}
                </strong>
              </div>
              <div>
                <span>Evidence scope</span>
                <strong>
                  {selected.corroboratingSources.length > 0
                    ? `${selected.corroboratingSources.length} corroborating source${selected.corroboratingSources.length === 1 ? "" : "s"}`
                    : `${selected.indicatorCount} indicator${selected.indicatorCount === 1 ? "" : "s"}`}
                </strong>
              </div>
              <div>
                <span>Malware context</span>
                <strong>{selected.malwareFamily}</strong>
              </div>
            </div>
            <div className="rule-tags">
              <span>Tags</span>
              {selected.tags.map((tag) => (
                <Badge key={tag}>{tag}</Badge>
              ))}
            </div>
            <footer className="rule-actions">
              <div>
                <GitBranch size={16} />
                <span>Detection-as-code workflow</span>
              </div>
              <Badge tone="neutral">Read-only analyst view</Badge>
            </footer>
          </section>
        )}
      </div>
    </div>
  );
}
