import { useState } from "react";
import {
  Bot,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Download,
  FileClock,
  LockKeyhole,
  Sparkles,
  Terminal,
} from "lucide-react";
import { Badge, CopyButton, EmptyState, SkeletonRows } from "../components/UI";
import { useReport, useReports } from "../hooks/useThreatData";
import type { ThreatReport } from "../types";
import { markSyntheticArtifact } from "../utils/artifacts";
import { downloadText, formatDate, formatIsoUtc } from "../utils/format";

const REPORT_COMMAND = `$env:ADMIN_API_KEY = Read-Host 'Enter the same ADMIN_API_KEY value from .env'
$headers = @{'X-API-Key' = $env:ADMIN_API_KEY}
Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/api/v1/reports' -Headers $headers -ContentType 'application/json' -Body '{}'`;

function reportMarkdown(report: ThreatReport) {
  const narrative = report.content?.trim()
    ? `# ${report.title}\n\n**Reporting period (UTC):** ${formatIsoUtc(report.periodStart)} – ${formatIsoUtc(report.periodEnd)}  \n**Created (UTC):** ${formatIsoUtc(report.createdAt)}  \n**Review state:** Not persisted by the API\n\n${report.content.trim()}\n`
    : `# ${report.title}\n\n**Reporting period (UTC):** ${formatIsoUtc(report.periodStart)} – ${formatIsoUtc(report.periodEnd)}  \n**Created (UTC):** ${formatIsoUtc(report.createdAt)}  \n**Review state:** Not persisted by the API\n\n## Executive summary\n\n${report.executiveSummary}\n\n## Key findings\n\n${report.keyFindings.map((item) => `- ${item}`).join("\n")}\n\n## Recommendations\n\n${report.recommendations.map((item) => `- ${item}`).join("\n")}\n\n---\nGenerated from deterministic ThreatMesh aggregates. AI-authored language requires analyst review.\n`;
  return markSyntheticArtifact(narrative, "markdown", report.isDemo);
}

export default function ReportsPage() {
  const query = useReports();
  const reports = query.data?.data ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showNew, setShowNew] = useState(false);
  const selected =
    reports.find((report) => report.id === selectedId) ?? reports[0];
  const requiresDetail = query.data?.mode === "live" && Boolean(selected);
  const detailQuery = useReport(requiresDetail ? selected?.id : undefined);
  const report = requiresDetail ? detailQuery.data?.data : selected;
  const isAiGenerated =
    report?.generatedBy === "gemini" || report?.generatedBy === "ollama";

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
          title="Report library request failed"
          description="The API returned an error. ThreatMesh did not replace the report library with demo content."
        />
      </section>
    );
  if (query.data?.mode === "live" && reports.length === 0)
    return (
      <section className="panel">
        <EmptyState
          title="No CTI reports generated"
          description="Complete an ingestion period, then run the report generator with Gemini or the local Ollama provider. Every draft should be reviewed before publication."
        />
        <div className="operator-instruction">
          <strong>PowerShell · authenticated operator request</strong>
          <code>{REPORT_COMMAND}</code>
          <CopyButton text={REPORT_COMMAND} label="Copy command" />
          <span>Paste the root .env value when PowerShell prompts.</span>
        </div>
      </section>
    );

  return (
    <div className="reports-layout">
      <aside className="panel report-index">
        <div className="report-index__head">
          <div>
            <span className="eyebrow">Report library</span>
            <strong>{reports.length} products</strong>
          </div>
          <button
            className="button button--primary button--small"
            type="button"
            onClick={() => setShowNew(true)}
          >
            <Terminal size={15} />
            Operator guide
          </button>
        </div>
        <div className="report-list">
          {reports.map((report) => (
            <button
              key={report.id}
              type="button"
              className={selected?.id === report.id ? "is-selected" : ""}
              onClick={() => setSelectedId(report.id)}
            >
              <span className="report-list__icon report-list__icon--draft">
                <FileClock size={18} />
              </span>
              <div>
                <strong>{report.title}</strong>
                <span>
                  {formatDate(report.periodStart, "MMM d")} –{" "}
                  {formatDate(report.periodEnd, "MMM d, yyyy")}
                </span>
                <small>Generated · review required</small>
                {report.isDemo && <small>Synthetic demo evidence</small>}
              </div>
              <ChevronRight size={16} />
            </button>
          ))}
        </div>
        <div className="privacy-card">
          <LockKeyhole size={18} />
          <div>
            <strong>Provider-aware privacy</strong>
            <span>
              Cloud generation uses public OSINT only. Switch to Ollama for
              private data.
            </span>
          </div>
        </div>
      </aside>

      {requiresDetail && detailQuery.isLoading && (
        <section className="panel report-document">
          <SkeletonRows count={8} />
        </section>
      )}

      {requiresDetail && detailQuery.isError && (
        <section className="panel report-document">
          <EmptyState
            title="Report narrative unavailable"
            description="The report summary loaded, but its generated Markdown could not be retrieved. No placeholder narrative or reconstructed download is being shown."
          />
        </section>
      )}

      {report && !detailQuery.isError && (
        <article className="panel report-document">
          <header className="report-document__header">
            <div>
              <div className="tag-list">
                {report.isDemo && <Badge tone="info">Synthetic demo</Badge>}
                <Badge tone="warning" dot>
                  review required
                </Badge>
                <Badge tone="purple">
                  {isAiGenerated ? (
                    <Bot size={12} />
                  ) : (
                    <CheckCircle2 size={12} />
                  )}
                  {report.generatedBy === "demo"
                    ? "deterministic demo"
                    : report.generatedBy}
                </Badge>
              </div>
              <h2>{report.title}</h2>
              <div className="report-byline">
                <span>
                  <CalendarDays size={14} />
                  {formatDate(report.periodStart)} —{" "}
                  {formatDate(report.periodEnd)}
                </span>
              </div>
            </div>
            <button
              className="button button--ghost"
              type="button"
              onClick={() =>
                downloadText(
                  reportMarkdown(report),
                  `${report.isDemo ? "synthetic-demo-" : ""}${report.id}.md`,
                  "text/markdown",
                )
              }
            >
              <Download size={16} />
              Markdown
            </button>
          </header>
          <div className="grounding-banner">
            {isAiGenerated ? (
              <Sparkles size={18} />
            ) : (
              <CheckCircle2 size={18} />
            )}
            <div>
              <strong>
                {isAiGenerated
                  ? "AI-assisted, fact-grounded narrative"
                  : report.isDemo
                    ? "Deterministic synthetic narrative · no LLM call"
                    : "Analyst-authored, fact-grounded narrative"}
              </strong>
              <span>
                {isAiGenerated
                  ? "Prose is generated only from deterministic aggregates and retrieved evidence. The model does not score threats, attribute actors, or make response decisions."
                  : report.isDemo
                    ? "This portfolio report was assembled from the synthetic seed corpus without calling a language model."
                    : "This narrative is stored as analyst-authored content; deterministic ThreatMesh facts remain separately inspectable."}
              </span>
            </div>
          </div>
          <section className="report-section">
            <span className="report-section__number">01</span>
            <div>
              <h3>Executive summary</h3>
              <p className="report-lead">
                {detailQuery.isLoading
                  ? "Retrieving report narrative…"
                  : report.executiveSummary}
              </p>
            </div>
          </section>
          {report.keyFindings.length > 0 && (
            <section className="report-section">
              <span className="report-section__number">02</span>
              <div>
                <h3>Key findings</h3>
                <ol className="finding-list">
                  {report.keyFindings.map((finding, index) => (
                    <li key={finding}>
                      <span>{String(index + 1).padStart(2, "0")}</span>
                      <p>{finding}</p>
                    </li>
                  ))}
                </ol>
              </div>
            </section>
          )}
          {report.topFamilies.length > 0 && (
            <section className="report-section">
              <span className="report-section__number">03</span>
              <div>
                <h3>Observed family volume</h3>
                <div className="report-bars">
                  {report.topFamilies.map((family) => (
                    <div key={family.name}>
                      <div>
                        <span>{family.name}</span>
                        <strong>{family.count}</strong>
                      </div>
                      <div>
                        <span
                          style={{
                            width: `${(family.count / (report.topFamilies[0]?.count || 1)) * 100}%`,
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          )}
          {report.recommendations.length > 0 && (
            <section className="report-section">
              <span className="report-section__number">04</span>
              <div>
                <h3>Recommended analyst actions</h3>
                <ul className="recommendation-list">
                  {report.recommendations.map((item) => (
                    <li key={item}>
                      <CheckCircle2 size={17} />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          )}
          <footer className="report-document__footer">
            <span>ThreatMesh intelligence product · {report.id}</span>
            <span>
              {report.isDemo
                ? "Synthetic documentation corpus"
                : "Public OSINT"}
              {" · Analyst review required"}
            </span>
          </footer>
        </article>
      )}

      {showNew && (
        <div
          className="modal-overlay"
          role="presentation"
          onMouseDown={() => setShowNew(false)}
        >
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="Report generation operator guide"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <span className="modal__icon">
              <Sparkles size={24} />
            </span>
            <h2>Generate from an operator shell</h2>
            <p>
              Report generation is an authenticated backend operation. The
              browser intentionally does not store or submit the admin key.
            </p>
            <div className="operator-instruction">
              <strong>PowerShell · authenticated operator request</strong>
              <code>{REPORT_COMMAND}</code>
              <CopyButton text={REPORT_COMMAND} label="Copy command" />
              <span>Paste the root .env value when PowerShell prompts.</span>
            </div>
            <div className="modal__notice">
              <LockKeyhole size={15} />
              Gemini free-tier prompts may be retained by Google. Send public
              OSINT only.
            </div>
            <div className="modal__actions">
              <button
                className="button button--ghost"
                type="button"
                onClick={() => setShowNew(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
