import { useMemo, useState } from "react";
import {
  Activity,
  Clock3,
  Crosshair,
  Filter,
  Globe2,
  Radio,
  ShieldCheck,
  Swords,
  X,
} from "lucide-react";
import { AreaTrendChart } from "../components/Charts";
import { IndicatorDetail } from "../components/IndicatorDetail";
import { type MapMode, ThreatMap } from "../components/ThreatMap";
import {
  Badge,
  EmptyState,
  KpiCard,
  PanelHeader,
  SkeletonRows,
} from "../components/UI";
import {
  useFeedStatus,
  useIndicators,
  useSummary,
} from "../hooks/useThreatData";
import type { ActivityEvent, Indicator, MapFilters } from "../types";
import { formatNumber, formatRelative, rangeToDays } from "../utils/format";

const initialFilters: MapFilters = {
  malwareFamily: "all",
  country: "all",
  source: "all",
  minConfidence: 50,
  range: "30d",
};

export default function DashboardPage() {
  const summaryQuery = useSummary();
  const requestedProvenance =
    summaryQuery.data?.data.analysisScope === "live" ? "live" : "all";
  const indicatorsQuery = useIndicators(
    requestedProvenance,
    summaryQuery.isSuccess,
  );
  const feedStatusQuery = useFeedStatus();
  const [filters, setFilters] = useState<MapFilters>(initialFilters);
  const [mode, setMode] = useState<MapMode>("clusters");
  const [selected, setSelected] = useState<Indicator | null>(null);
  const [showFilters, setShowFilters] = useState(false);
  const indicators = useMemo(
    () => indicatorsQuery.data?.data ?? [],
    [indicatorsQuery.data],
  );
  const isLive = indicatorsQuery.data?.mode === "live";
  const indicatorTotal = indicatorsQuery.data?.total ?? indicators.length;
  const summary =
    !isLive || summaryQuery.data?.mode === "live"
      ? summaryQuery.data?.data
      : undefined;
  const isOperationalLive = summary?.analysisScope === "live";
  const feedRuns = useMemo(
    () => feedStatusQuery.data?.data ?? [],
    [feedStatusQuery.data],
  );
  const analyticalFeedRuns = useMemo(
    () =>
      summary?.analysisScope === "live"
        ? feedRuns.filter((run) => !run.feed.toLowerCase().startsWith("demo-"))
        : feedRuns,
    [feedRuns, summary?.analysisScope],
  );
  const inferredSeededDemo =
    feedRuns.length > 0 &&
    feedRuns.every((run) => run.feed.toLowerCase().startsWith("demo-"));
  const corpusLabel =
    summary?.corpusMode === "mixed"
      ? summary.analysisScope === "live"
        ? "Mixed corpus · live-only analytics"
        : "Mixed corpus"
      : summary?.corpusMode === "demo" || inferredSeededDemo
        ? "Seeded demo via API"
        : "API connected";
  const analysisIndicators = useMemo(
    () =>
      isLive && summary?.analysisScope === "live"
        ? indicators.filter((item) => !item.isDemo)
        : indicators,
    [indicators, isLive, summary?.analysisScope],
  );
  const analysisTotal =
    isLive && summary?.analysisScope === "live"
      ? summary.liveIocs
      : indicatorTotal;
  const isAnalysisSampled = isLive && analysisTotal > analysisIndicators.length;
  const analysisSampleLabel = `Latest ${formatNumber(analysisIndicators.length)} of ${formatNumber(analysisTotal)}`;

  const options = useMemo(
    () => ({
      families: [
        ...new Set(analysisIndicators.map((item) => item.malwareFamily)),
      ].sort(),
      countries: [
        ...new Set(analysisIndicators.map((item) => item.country)),
      ].sort(),
      sources: [
        ...new Set(analysisIndicators.map((item) => item.sourceFeed)),
      ].sort(),
    }),
    [analysisIndicators],
  );

  const visibleCount = useMemo(() => {
    const days = rangeToDays(filters.range);
    const cutoff = Date.now() - days * 86_400_000;
    return analysisIndicators.filter(
      (item) =>
        item.confidence >= filters.minConfidence &&
        (filters.malwareFamily === "all" ||
          item.malwareFamily === filters.malwareFamily) &&
        (filters.country === "all" || item.country === filters.country) &&
        (filters.source === "all" || item.sourceFeed === filters.source) &&
        (!Number.isFinite(days) || new Date(item.lastSeen).getTime() >= cutoff),
    ).length;
  }, [analysisIndicators, filters]);

  const liveActivity = useMemo<ActivityEvent[]>(() => {
    if (analyticalFeedRuns.length > 0) {
      return analyticalFeedRuns.slice(0, 5).map((run) => ({
        id: `feed-${run.id}`,
        timestamp: run.completedAt ?? run.startedAt,
        kind: "ingested",
        title: `${run.feed} ${run.status}`,
        detail: `${run.received} received · ${run.inserted} new · ${run.updated} updated`,
        severity:
          run.status === "failed"
            ? "critical"
            : run.status === "partial"
              ? "high"
              : run.status === "running"
                ? "medium"
                : "low",
      }));
    }
    return [...analysisIndicators]
      .sort(
        (left, right) =>
          new Date(right.lastSeen).getTime() -
          new Date(left.lastSeen).getTime(),
      )
      .slice(0, 5)
      .map((item) => ({
        id: `observed-${item.id}`,
        timestamp: item.lastSeen,
        kind: "ingested",
        title: `${item.malwareFamily} ${item.type.toUpperCase()} observed`,
        detail: `${item.value} · ${item.sourceFeed}`,
        severity:
          item.confidence >= 70
            ? "high"
            : item.confidence >= 40
              ? "medium"
              : "low",
      }));
  }, [analysisIndicators, analyticalFeedRuns]);

  const liveFamilies = useMemo(() => {
    const cutoff = Date.now() - 30 * 86_400_000;
    const counts = new Map<string, number>();
    analysisIndicators
      .filter((item) => new Date(item.lastSeen).getTime() >= cutoff)
      .forEach((item) =>
        counts.set(
          item.malwareFamily,
          (counts.get(item.malwareFamily) ?? 0) + 1,
        ),
      );
    return [...counts.entries()]
      .map(([name, value]) => ({ name, value, delta: null as number | null }))
      .sort((left, right) => right.value - left.value)
      .slice(0, 5);
  }, [analysisIndicators]);

  const liveTrend = useMemo(() => {
    const now = Date.now();
    const start = now - 24 * 3_600_000;
    const bucketMs = 2 * 3_600_000;
    const buckets = Array.from({ length: 12 }, (_, index) => ({
      label: new Date(start + index * bucketMs).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      value: 0,
      high: 0,
    }));
    analysisIndicators.forEach((item) => {
      const timestamp = new Date(item.lastSeen).getTime();
      const index = Math.floor((timestamp - start) / bucketMs);
      const bucket = buckets[index];
      if (bucket) {
        bucket.value += 1;
        if (item.confidence >= 70) bucket.high += 1;
      }
    });
    return buckets;
  }, [analysisIndicators]);

  const activity = liveActivity;
  const families = liveFamilies;
  const trend = liveTrend;
  const latestFeedRunMap = new Map<string, (typeof feedRuns)[number]>();
  analyticalFeedRuns.forEach((run) => {
    const feedKey = run.feed.toLowerCase().replace(/^demo-/, "");
    if (!latestFeedRunMap.has(feedKey)) latestFeedRunMap.set(feedKey, run);
  });
  const latestFeedRuns = [...latestFeedRunMap.values()];
  const feedHealth =
    summaryQuery.data?.mode === "live" ? summary?.feedHealth : null;
  const latestFeedTimestamp = latestFeedRuns
    .map((run) => run.completedAt ?? run.startedAt)
    .sort(
      (left, right) => new Date(right).getTime() - new Date(left).getTime(),
    )[0];
  const ingestedLastHour = analyticalFeedRuns
    .filter(
      (run) => new Date(run.startedAt).getTime() >= Date.now() - 3_600_000,
    )
    .reduce((count, run) => count + run.inserted + run.updated, 0);

  if (summaryQuery.isLoading || indicatorsQuery.isLoading)
    return (
      <div className="dashboard-grid">
        <section className="panel panel--wide">
          <SkeletonRows count={8} />
        </section>
      </div>
    );
  if (summaryQuery.isError)
    return (
      <section className="panel">
        <EmptyState
          title="Operational summary unavailable"
          description="ThreatMesh could not determine corpus provenance or the authoritative analysis scope, so the dashboard has not mixed or mapped unscoped observations."
        />
      </section>
    );
  if (indicatorsQuery.isError)
    return (
      <section className="panel">
        <EmptyState
          title="Indicator API request failed"
          description="ThreatMesh received an API error and did not substitute demo records. Check backend logs and retry once the service is healthy."
        />
      </section>
    );
  if (indicatorsQuery.data?.mode === "live" && indicators.length === 0) {
    return (
      <section className="panel">
        <EmptyState
          allowSync
          title="No intelligence has been ingested yet"
          description="The API is connected and returned an empty dataset. Start the OSINT feed sync, or run the ingestion worker from the project stack."
        />
      </section>
    );
  }

  return (
    <div className="dashboard-page">
      <section className="kpi-grid" aria-label="Threat intelligence summary">
        <KpiCard
          label="IOC observations"
          value={
            summary?.analysisScope === "live"
              ? summary.liveIocs
              : (summary?.totalObservations ?? analysisIndicators.length)
          }
          trend={null}
          helper={
            isLive && summary?.analysisScope === "live"
              ? "live-only source rows"
              : isLive
                ? "source observation rows"
                : "vs previous 30 days"
          }
          icon={Crosshair}
          accent="teal"
        />
        <KpiCard
          label="High-confidence observations"
          value={
            summary?.highConfidence ??
            indicators.filter((item) => item.confidence >= 70).length
          }
          trend={null}
          helper="confidence score ≥70"
          icon={ShieldCheck}
          accent="violet"
        />
        <KpiCard
          label="Campaign communities"
          value={summary?.activeCampaigns ?? 0}
          trend={null}
          helper="correlation leads"
          icon={Swords}
          accent="amber"
        />
        <KpiCard
          label="Observed countries"
          value={summary?.affectedCountries ?? options.countries.length}
          trend={null}
          helper="approximate host locations"
          icon={Globe2}
          accent="blue"
        />
      </section>

      <div className="dashboard-grid">
        <section className="panel map-panel">
          <PanelHeader
            eyebrow={
              isAnalysisSampled
                ? `Geospatial activity · ${analysisSampleLabel} sample`
                : summary?.analysisScope === "live" &&
                    summary.corpusMode === "mixed"
                  ? "Geospatial activity · live-only"
                  : "Geospatial activity"
            }
            title="Infrastructure activity map"
            action={
              <div className="map-panel__actions">
                <Badge tone="success" dot>
                  {formatNumber(visibleCount)} visible
                </Badge>
                <button
                  className={`button button--ghost button--small ${showFilters ? "is-active" : ""}`}
                  type="button"
                  onClick={() => setShowFilters((value) => !value)}
                >
                  <Filter size={15} />
                  Filters
                </button>
              </div>
            }
          />
          <div
            className={`map-filter-bar ${showFilters ? "map-filter-bar--open" : ""}`}
          >
            <label>
              <span>Malware family</span>
              <select
                value={filters.malwareFamily}
                onChange={(event) =>
                  setFilters({ ...filters, malwareFamily: event.target.value })
                }
              >
                <option value="all">All families</option>
                {options.families.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Country</span>
              <select
                value={filters.country}
                onChange={(event) =>
                  setFilters({ ...filters, country: event.target.value })
                }
              >
                <option value="all">All countries</option>
                {options.countries.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <label>
              <span>Source</span>
              <select
                value={filters.source}
                onChange={(event) =>
                  setFilters({ ...filters, source: event.target.value })
                }
              >
                <option value="all">All sources</option>
                {options.sources.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <label className="confidence-filter">
              <span>
                Minimum confidence <strong>{filters.minConfidence}%</strong>
              </span>
              <input
                type="range"
                min="40"
                max="95"
                step="5"
                value={filters.minConfidence}
                onChange={(event) =>
                  setFilters({
                    ...filters,
                    minConfidence: Number(event.target.value),
                  })
                }
              />
            </label>
            <button
              className="icon-button"
              type="button"
              onClick={() => setFilters(initialFilters)}
              title="Reset filters"
              aria-label="Reset filters"
            >
              <X size={16} />
            </button>
          </div>
          <ThreatMap
            indicators={analysisIndicators}
            filters={filters}
            mode={mode}
            onModeChange={setMode}
            onSelect={setSelected}
          />
          <div className="time-controller">
            <div>
              <Clock3 size={15} />
              <span>Observation window</span>
            </div>
            <div
              className="segment-control"
              aria-label="Observation time window"
            >
              {(["24h", "7d", "30d", "90d", "all"] as const).map((range) => (
                <button
                  type="button"
                  key={range}
                  onClick={() => setFilters({ ...filters, range })}
                  className={filters.range === range ? "is-active" : ""}
                >
                  {range === "all" ? "All" : range}
                </button>
              ))}
            </div>
            <span className="time-controller__hint">
              Filters the ArcGIS layer by last observed time
            </span>
          </div>
        </section>

        <aside className="panel activity-panel">
          <PanelHeader
            eyebrow="Pipeline pulse"
            title="Latest activity"
            action={
              <span className="live-pill">
                <Radio size={12} />
                {isLive ? corpusLabel : "Bundled demo · illustrative"}
              </span>
            }
          />
          <div className="activity-list">
            {activity.map((event) => (
              <article className="activity-item" key={event.id}>
                <span
                  className={`activity-item__marker activity-item__marker--${event.severity}`}
                />
                <div>
                  <div>
                    <strong>{event.title}</strong>
                    <time>{formatRelative(event.timestamp)}</time>
                  </div>
                  <p>{event.detail}</p>
                </div>
              </article>
            ))}
          </div>
          <div className="pipeline-health">
            <div>
              <span>
                <Activity size={15} />
                {isOperationalLive
                  ? "Authoritative feed health"
                  : "Illustrative pipeline health"}
              </span>
              <strong>
                {isOperationalLive
                  ? feedHealth === null
                    ? "—"
                    : `${feedHealth}%`
                  : `${summary?.feedHealth ?? 99.2}%`}
              </strong>
            </div>
            <div className="health-track">
              <span
                style={{
                  width: `${isOperationalLive ? (feedHealth ?? 0) : (summary?.feedHealth ?? 99.2)}%`,
                }}
              />
            </div>
            <p>
              {isOperationalLive
                ? latestFeedRuns.length
                  ? `${formatNumber(ingestedLastHour)} observations normalized in the last hour. Latest run ${formatRelative(latestFeedTimestamp!)}. Health uses the server's configured source-freshness policy.`
                  : "No feed run telemetry yet. Health is calculated by the API from configured-source freshness."
                : `${formatNumber(summary?.ingestionLastHour ?? 0)} synthetic observations in the latest demo run. This value does not measure external-source freshness.`}
            </p>
          </div>
        </aside>

        <section className="panel trend-panel">
          <PanelHeader
            eyebrow={
              summary?.analysisScope === "live" &&
              summary.corpusMode === "mixed"
                ? isAnalysisSampled
                  ? `Live-only telemetry · ${analysisSampleLabel} sample`
                  : "Live-only 24-hour telemetry"
                : isAnalysisSampled
                  ? `24-hour telemetry · ${analysisSampleLabel} sample`
                  : "24-hour telemetry"
            }
            title="Observation timestamps"
            action={
              <div className="chart-legend">
                <span>
                  <i className="chart-dot chart-dot--all" />
                  All loaded observations
                </span>
                <span>
                  <i className="chart-dot chart-dot--high" />
                  High confidence
                </span>
              </div>
            }
          />
          <AreaTrendChart data={trend} />
        </section>

        <section className="panel families-panel">
          <PanelHeader
            eyebrow="Normalized labels"
            title="Top malware families"
            action={
              <span className="panel-context">
                {summary?.analysisScope === "live" &&
                summary.corpusMode === "mixed"
                  ? isAnalysisSampled
                    ? `Live-only · ${analysisSampleLabel} sample`
                    : "Live-only · last 30 days"
                  : isAnalysisSampled
                    ? `${analysisSampleLabel} sample`
                    : "Last 30 days"}
              </span>
            }
          />
          <div className="family-bars">
            {families.map((family, index) => (
              <div className="family-row" key={family.name}>
                <span className="family-row__rank">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <div>
                  <div>
                    <strong>{family.name}</strong>
                    {family.delta === null ? (
                      <span>current</span>
                    ) : (
                      <span
                        className={family.delta >= 0 ? "positive" : "negative"}
                      >
                        {family.delta > 0 ? "+" : ""}
                        {family.delta}%
                      </span>
                    )}
                  </div>
                  <div className="bar-track">
                    <span
                      style={{
                        width: `${(family.value / (families[0]?.value || 1)) * 100}%`,
                      }}
                    />
                  </div>
                </div>
                <b>{family.value}</b>
              </div>
            ))}
          </div>
        </section>
      </div>

      {selected && (
        <>
          <button
            className="drawer-scrim"
            type="button"
            aria-label="Close indicator detail"
            onClick={() => setSelected(null)}
          />
          <IndicatorDetail
            indicator={selected}
            onClose={() => setSelected(null)}
          />
        </>
      )}
    </div>
  );
}
