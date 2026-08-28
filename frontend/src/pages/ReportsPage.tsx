import { type FormEvent, useEffect, useState } from "react";
import {
  Bot,
  CalendarClock,
  CalendarDays,
  CheckCircle2,
  ChevronRight,
  Download,
  FileClock,
  LockKeyhole,
  Sparkles,
} from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { ApiRequestError, threatApi } from "../api/client";
import { Badge, EmptyState, SkeletonRows } from "../components/UI";
import {
  useReport,
  useReports,
  useReportSchedule,
} from "../hooks/useThreatData";
import type { ReportCadence, ReportSchedule, ThreatReport } from "../types";
import { markSyntheticArtifact } from "../utils/artifacts";
import { downloadText, formatDate, formatIsoUtc } from "../utils/format";

const WEEKDAY_LABELS: Record<string, string> = {
  mon: "Monday",
  tue: "Tuesday",
  wed: "Wednesday",
  thu: "Thursday",
  fri: "Friday",
  sat: "Saturday",
  sun: "Sunday",
};

function scheduledHour(schedule: ReportSchedule) {
  return `${String(schedule.hourUtc).padStart(2, "0")}:00 ${schedule.timezone}`;
}

function scheduleSummary(schedule: ReportSchedule, cadence = schedule.cadence) {
  if (cadence === "monthly") {
    const day =
      schedule.monthlyDay === 1 ? "first day" : `day ${schedule.monthlyDay}`;
    return `On the ${day} of each month at ${scheduledHour(schedule)}`;
  }
  const weekday =
    WEEKDAY_LABELS[schedule.weeklyDay.toLowerCase()] ?? schedule.weeklyDay;
  return `Every ${weekday} at ${scheduledHour(schedule)}`;
}

function nextRunLabel(schedule: ReportSchedule) {
  if (!schedule.nextRunAt) return "Waiting for the scheduler";
  const nextRun = new Date(schedule.nextRunAt);
  if (Number.isNaN(nextRun.getTime())) return "Next run unavailable";
  try {
    return new Intl.DateTimeFormat("en-US", {
      timeZone: schedule.timezone,
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
      timeZoneName: "short",
    }).format(nextRun);
  } catch {
    return nextRun.toISOString();
  }
}

function ReportSchedulePanel() {
  const scheduleQuery = useReportSchedule();
  const [savedSchedule, setSavedSchedule] = useState<ReportSchedule | null>(
    null,
  );
  const schedule = savedSchedule ?? scheduleQuery.data?.data;
  const [cadence, setCadence] = useState<ReportCadence>("weekly");
  const [showAuthorization, setShowAuthorization] = useState(false);
  const [adminKey, setAdminKey] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveNotice, setSaveNotice] = useState<string | null>(null);
  const hasPendingChange = Boolean(schedule && cadence !== schedule.cadence);

  useEffect(() => {
    if (schedule) setCadence(schedule.cadence);
  }, [schedule]);

  const closeAuthorization = () => {
    if (isSaving) return;
    setAdminKey("");
    setSaveError(null);
    setShowAuthorization(false);
  };

  const applySchedule = async (requestKey: string) => {
    if (!schedule) return;
    setAdminKey("");
    setSaveError(null);
    setSaveNotice(null);
    setIsSaving(true);
    try {
      const result = await threatApi.updateReportSchedule(cadence, requestKey);
      setSavedSchedule(result.data);
      setCadence(result.data.cadence);
      setSaveNotice(
        `${result.data.cadence === "weekly" ? "Weekly" : "Monthly"} automatic reporting is now active.`,
      );
      setShowAuthorization(false);
      void scheduleQuery.refetch();
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        setSaveError("The administrator key was not accepted. Try again.");
      } else if (error instanceof ApiRequestError && error.status === 503) {
        setSaveError(
          "Schedule changes are disabled until an administrator key is configured on the backend.",
        );
      } else {
        setSaveError("The schedule could not be saved. No change was applied.");
      }
    } finally {
      setAdminKey("");
      setIsSaving(false);
    }
  };

  const authorizeSave = () => {
    if (!schedule) return;
    if (!schedule.adminAuthRequired) {
      void applySchedule("");
      return;
    }
    setAdminKey("");
    setSaveError(null);
    setSaveNotice(null);
    setShowAuthorization(true);
  };

  const saveSchedule = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const requestKey = adminKey.trim();
    if (!requestKey) return;
    await applySchedule(requestKey);
  };

  return (
    <section
      className="report-schedule"
      aria-labelledby="report-schedule-title"
    >
      <div className="report-schedule__head">
        <div>
          <span className="eyebrow">Automatic reports</span>
          <strong id="report-schedule-title">Generation schedule</strong>
        </div>
        {schedule && (
          <Badge tone={schedule.schedulerRunning ? "success" : "warning"} dot>
            {schedule.schedulerRunning ? "running" : "paused"}
          </Badge>
        )}
      </div>

      {scheduleQuery.isLoading && (
        <p className="report-schedule__message">Loading schedule...</p>
      )}
      {scheduleQuery.isError && (
        <p className="report-schedule__message report-schedule__message--error">
          The automatic schedule is unavailable. Existing reports remain
          accessible.
        </p>
      )}

      {schedule && (
        <>
          <div
            className={`report-schedule__provider ${
              schedule.providerConfigured
                ? "report-schedule__provider--ready"
                : "report-schedule__provider--warning"
            }`}
          >
            <Sparkles size={14} />
            <span>AI provider</span>
            <strong>
              {schedule.providerConfigured ? "Ready" : "Not configured"}
            </strong>
          </div>

          <div
            className="report-schedule__choices"
            role="group"
            aria-label="Report generation cadence"
          >
            {(["weekly", "monthly"] as const).map((option) => (
              <button
                key={option}
                type="button"
                className={cadence === option ? "is-selected" : ""}
                aria-pressed={cadence === option}
                disabled={isSaving}
                onClick={() => {
                  setCadence(option);
                  setSaveNotice(null);
                }}
              >
                <strong>{option === "weekly" ? "Weekly" : "Monthly"}</strong>
                <span>
                  {option === "weekly"
                    ? (WEEKDAY_LABELS[schedule.weeklyDay.toLowerCase()] ??
                      schedule.weeklyDay)
                    : schedule.monthlyDay === 1
                      ? "First day"
                      : `Day ${schedule.monthlyDay}`}
                </span>
              </button>
            ))}
          </div>

          <div className="report-schedule__next">
            <CalendarClock size={16} />
            <div>
              <span>{hasPendingChange ? "Pending cadence" : "Next draft"}</span>
              <strong>
                {hasPendingChange
                  ? "Save to calculate next run"
                  : nextRunLabel(schedule)}
              </strong>
              <small>{scheduleSummary(schedule, cadence)}</small>
            </div>
          </div>

          {!schedule.schedulerRunning && (
            <p className="report-schedule__message report-schedule__message--warning">
              The backend scheduler is paused. The cadence is retained, but no
              report will run until scheduling is enabled.
            </p>
          )}
          {!schedule.providerConfigured && (
            <p className="report-schedule__message report-schedule__message--warning">
              Automatic drafts cannot run until Gemini or Ollama is configured
              on the backend.
            </p>
          )}

          {saveNotice && (
            <p className="report-schedule__success" role="status">
              <CheckCircle2 size={14} />
              {saveNotice}
            </p>
          )}
          {saveError && !showAuthorization && (
            <p
              className="report-schedule__message report-schedule__message--error"
              role="alert"
            >
              {saveError}
            </p>
          )}

          <button
            className="button button--primary button--small report-schedule__save"
            type="button"
            disabled={
              !hasPendingChange ||
              scheduleQuery.data?.mode === "demo" ||
              isSaving
            }
            onClick={authorizeSave}
          >
            {isSaving ? "Saving..." : "Save schedule"}
          </button>
          <p className="report-schedule__policy">
            Drafts use the latest completed reporting window and always require
            analyst review.
          </p>
        </>
      )}

      {showAuthorization && schedule && (
        <div
          className="modal-overlay"
          role="presentation"
          onMouseDown={closeAuthorization}
        >
          <form
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="Authorize schedule change"
            aria-describedby="schedule-authorization-description"
            onSubmit={saveSchedule}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <span className="modal__icon">
              <LockKeyhole size={23} />
            </span>
            <h2>Authorize schedule change</h2>
            <p id="schedule-authorization-description">
              Changing the automatic cadence affects report generation and AI
              usage. Enter the administrator key for this request only.
            </p>
            <label>
              Administrator key
              <input
                type="password"
                name="administrator-key"
                autoComplete="off"
                value={adminKey}
                disabled={isSaving}
                onChange={(event) => setAdminKey(event.target.value)}
                autoFocus
              />
            </label>
            <div className="modal__notice">
              <LockKeyhole size={15} />
              Used once to authorize this schedule change. It is never saved in
              browser storage.
            </div>
            {saveError && (
              <p className="modal__error" role="alert">
                {saveError}
              </p>
            )}
            <div className="modal__actions">
              <button
                className="button button--ghost"
                type="button"
                disabled={isSaving}
                onClick={closeAuthorization}
              >
                Cancel
              </button>
              <button
                className="button button--primary"
                type="submit"
                disabled={!adminKey.trim() || isSaving}
              >
                {isSaving ? "Saving..." : "Apply schedule"}
              </button>
            </div>
          </form>
        </div>
      )}
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
        <ReportSchedulePanel />
        <div className="report-list">
          {reports.length === 0 && (
            <p className="report-list__empty">
              Scheduled drafts will appear here after their first completed run.
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
            title="No scheduled reports yet"
            description="ThreatMesh will create the first draft at the next automatic run. Reports use the current OSINT corpus and remain review-required until an analyst approves them."
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
