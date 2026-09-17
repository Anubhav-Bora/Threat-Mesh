import { useEffect, useState } from "react";
import {
  Bot,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Download,
  FileClock,
  LockKeyhole,
  Sparkles,
} from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { threatApi } from "../api/client";
import { Badge, EmptyState, SkeletonRows } from "../components/UI";
import { useReport, useReports } from "../hooks/useThreatData";
import type { ThreatReport } from "../types";
import { markSyntheticArtifact } from "../utils/artifacts";
import { downloadText, formatDate, formatIsoUtc } from "../utils/format";

function ManualReportPanel({
  onReportGenerated,
}: {
  onReportGenerated?: (reportId: string) => Promise<void> | void;
}) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const runReport = async () => {
    setIsGenerating(true);
    setError(null);
    setNotice(null);
    try {
      const generated = await threatApi.generateWeeklyReport();
      setNotice("Generated " + generated.data.title + ".");
      if (onReportGenerated) await onReportGenerated(generated.data.id);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "The report could not be generated.",
      );
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <section className="report-schedule" aria-labelledby="manual-report-title">
      <div className="report-schedule__head">
        <div>
          <span className="eyebrow">On-demand intelligence</span>
          <strong id="manual-report-title">Weekly report</strong>
        </div>
        <Badge tone="success" dot>
          Manual
        </Badge>
      </div>
      <div className="report-schedule__provider report-schedule__provider--ready">
        <Sparkles size={14} />
        <span>Reporting window</span>
        <strong>Previous complete week</strong>
      </div>
      <p className="report-schedule__message">
        Generate a fresh evidence-bounded report when needed. No cron job or
        persistent scheduler is required.
      </p>
      {notice && (
        <p className="report-schedule__success" role="status">
          <CheckCircle2 size={14} />
          {notice}
        </p>
      )}
      {error && (
        <p
          className="report-schedule__message report-schedule__message--error"
          role="alert"
        >
          {error}
        </p>
      )}
      <button
        className="button button--primary"
        type="button"
        disabled={isGenerating}
        onClick={() => void runReport()}
      >
        <Sparkles size={15} />
        {isGenerating ? "Generating report..." : "Generate weekly report"}
      </button>
    </section>
  );
}
function reportMarkdown(report: ThreatReport) {
  const narrative = report.content?.trim()
    ? `# ${report.title}\n\n**Reporting period (UTC):** ${formatIsoUtc(report.periodStart)} – ${formatIsoUtc(report.periodEnd)}  \n**Created (UTC):** ${formatIsoUtc(report.createdAt)}  \n**Review state:** Not persisted by the API\n\n${report.content.trim()}\n`
    : `# ${report.title}\n\n**Reporting period (UTC):** ${formatIsoUtc(report.periodStart)} – ${formatIsoUtc(report.periodEnd)}  \n**Created (UTC):** ${formatIsoUtc(report.createdAt)}  \n**Review state:** Not persisted by the API\n\n## Executive summary\n\n${report.executiveSummary}\n\n## Key findings\n\n${report.keyFindings.map((item) => `- ${item}`).join("\n")}\n\n## Recommendations\n\n${report.recommendations.map((item) => `- ${item}`).join("\n")}\n\n---\nGenerated from deterministic ThreatMesh aggregates. AI-authored language requires analyst review.\n`;
  return markSyntheticArtifact(narrative, "markdown", report.isDemo);
}

export default function ReportsPage() {
  const [searchParams] = useSearchParams();
  const citedReportId = searchParams.get("report");
  const query = useReports();
  const reports = query.data?.data ?? [];
  const [selectedId, setSelectedId] = useState<string | null>(citedReportId);
  useEffect(() => {
    setSelectedId(citedReportId);
  }, [citedReportId]);
  const selectedSummary =
    selectedId === null
      ? reports[0]
      : reports.find((report) => report.id === selectedId);
  const resolvedReportId = selectedId ?? selectedSummary?.id;
  const requiresDetail =
    query.data?.mode === "live" && Boolean(resolvedReportId);
  const detailQuery = useReport(requiresDetail ? resolvedReportId : undefined);
  const report = requiresDetail
    ? (detailQuery.data?.data ?? undefined)
    : selectedSummary;
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
  return (
    <div className="reports-layout">
      <aside className="panel report-index">
        <div className="report-index__head">
          <div>
            <span className="eyebrow">Report library</span>
            <strong>{reports.length} products</strong>
          </div>
        </div>
        <ManualReportPanel
          onReportGenerated={async (reportId: string) => {
            await query.refetch();
            setSelectedId(reportId);
          }}
        />
        <div className="report-list">
          {reports.length === 0 && (
            <p className="report-list__empty">
              Generated weekly drafts will appear here.
            </p>
          )}
          {reports.map((report) => (
            <button
              key={report.id}
              type="button"
              className={selectedSummary?.id === report.id ? "is-selected" : ""}
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
                <small>
                  {report.cadence === "weekly" ? "Weekly" : "Monthly"} draft ·
                  review required
                </small>
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
            description="This report could not be retrieved or the cited snapshot no longer exists. No unrelated placeholder narrative is being shown."
          />
        </section>
      )}

      {citedReportId && !requiresDetail && !report && (
        <section className="panel report-document">
          <EmptyState
            title="Report snapshot unavailable"
            description="This evidence link does not match a report in the current corpus. No unrelated report has been substituted."
          />
        </section>
      )}

      {!citedReportId && !report && (
        <section className="panel report-document report-document--empty">
          <EmptyState
            title="No reports generated yet"
            description="Generate a weekly draft when you need one. Reports use the current OSINT corpus and remain review-required until an analyst approves them."
          />
        </section>
      )}

      {report && !detailQuery.isError && (
        <article className="panel report-document">
          <header className="report-document__header">
            <div>
              <div className="tag-list">
                {report.isDemo && <Badge tone="info">Synthetic demo</Badge>}
                <Badge tone="neutral">
                  {report.cadence === "weekly" ? "Weekly" : "Monthly"}
                </Badge>
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
    </div>
  );
}
