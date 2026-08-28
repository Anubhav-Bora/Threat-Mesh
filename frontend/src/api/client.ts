import {
  demoCampaigns,
  demoIndicators,
  demoReports,
  demoRules,
  demoSummary,
  demoTechniques,
} from "../data/mockData";
import type {
  AssistantAnswer,
  AttackTechnique,
  Campaign,
  DetectionRule,
  FeedRun,
  Indicator,
  ReportCadence,
  ReportSchedule,
  SummaryStats,
  ThreatReport,
} from "../types";

export type DataMode = "checking" | "live" | "demo" | "error";
export interface ApiResult<T> {
  data: T;
  mode: "live" | "demo";
  reason?: string;
  total?: number;
  limit?: number;
  offset?: number;
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "/api/v1").replace(
  /\/$/,
  "",
);
const FORCE_DEMO =
  String(import.meta.env.VITE_DEMO_MODE).toLowerCase() === "true";
const failingResources = new Set<string>();
const errorResources = new Set<string>();
let dataMode: DataMode = FORCE_DEMO ? "demo" : "checking";
let hasLiveResponse = false;
const listeners = new Set<() => void>();

const updateMode = () => {
  const next: DataMode =
    FORCE_DEMO || failingResources.size > 0
      ? "demo"
      : errorResources.size > 0
        ? "error"
        : hasLiveResponse
          ? "live"
          : "checking";
  if (next !== dataMode) {
    dataMode = next;
    listeners.forEach((listener) => listener());
  }
};

const markResource = (resource: string, failed: boolean) => {
  if (failed) failingResources.add(resource);
  else failingResources.delete(resource);
  errorResources.delete(resource);
  updateMode();
};

const markError = (resource: string) => {
  failingResources.delete(resource);
  errorResources.add(resource);
  updateMode();
};

export const apiModeStore = {
  subscribe(listener: () => void) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  getSnapshot: () => dataMode,
};

const safeString = (value: unknown, fallback = "") =>
  typeof value === "string" ? value : value == null ? fallback : String(value);
const safeNumber = (value: unknown, fallback = 0) => {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
};
const optionalNumber = (value: unknown): number | null => {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
};
const safeArray = (value: unknown): unknown[] =>
  Array.isArray(value) ? value : [];
const get = (source: Record<string, any>, ...keys: string[]) => {
  for (const key of keys)
    if (source[key] !== undefined && source[key] !== null) return source[key];
  return undefined;
};

const normalizeReportProvider = (
  value: unknown,
): ThreatReport["generatedBy"] => {
  const provider = safeString(value, "analyst").toLowerCase();
  return provider === "gemini" || provider === "ollama" || provider === "demo"
    ? provider
    : "analyst";
};

function listPayload(payload: any): any[] {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.features)) return payload.features;
  return [];
}

function normalizeIndicator(raw: any, index: number): Indicator {
  const properties = raw?.properties ?? raw ?? {};
  const coordinates = raw?.geometry?.coordinates ?? [];
  const confidence = safeNumber(
    get(properties, "confidence", "confidence_score"),
    0,
  );
  const techniqueValue = get(
    properties,
    "techniqueIds",
    "technique_ids",
    "attack_technique_ids",
  );
  const tagsValue = get(properties, "tags");
  return {
    id: safeString(get(properties, "id"), `ioc-${index}`),
    value: safeString(
      get(properties, "value", "ioc_value"),
      "Unknown indicator",
    ),
    type: safeString(
      get(properties, "type", "ioc_type"),
      "ip",
    ) as Indicator["type"],
    malwareFamily: safeString(
      get(properties, "malwareFamily", "malware_family"),
      "Unknown",
    ),
    firstSeen: safeString(
      get(properties, "firstSeen", "first_seen"),
      new Date().toISOString(),
    ),
    lastSeen: safeString(
      get(properties, "lastSeen", "last_seen"),
      new Date().toISOString(),
    ),
    sourceFeed: safeString(
      get(properties, "sourceFeed", "source_feed"),
      "OSINT",
    ),
    confidence,
    isDemo:
      get(properties, "isDemo", "is_demo") === undefined
        ? undefined
        : Boolean(get(properties, "isDemo", "is_demo")),
    country: safeString(get(properties, "country"), "Unknown"),
    countryCode: safeString(
      get(properties, "countryCode", "country_code"),
      "XX",
    ),
    city: safeString(get(properties, "city"), "Unknown"),
    asn: safeString(get(properties, "asn"), "Unknown"),
    asnOrg: safeString(get(properties, "asnOrg", "asn_org"), "Unknown network"),
    latitude: optionalNumber(
      get(properties, "latitude", "lat") ?? coordinates[1],
    ),
    longitude: optionalNumber(
      get(properties, "longitude", "lon", "lng") ?? coordinates[0],
    ),
    locationPrecisionKm: optionalNumber(
      get(properties, "locationPrecisionKm", "location_precision_km"),
    ),
    techniqueIds: safeArray(techniqueValue).map(String),
    campaignId:
      safeString(get(properties, "campaignId", "campaign_id", "cluster_id")) ||
      undefined,
    status: get(properties, "status")
      ? (safeString(get(properties, "status")) as Indicator["status"])
      : null,
    corroboratingFeeds: optionalNumber(
      get(properties, "corroboratingFeeds", "corroborating_feeds"),
    ),
    tags: safeArray(tagsValue).map(String),
  };
}

function normalizeCampaign(raw: any, index: number): Campaign {
  const context = get(raw, "observedContext", "observed_context") ?? {};
  const evidence =
    get(raw, "relationshipEvidence", "relationship_evidence") ?? {};
  const uniqueIndicatorCount = safeNumber(
    get(raw, "uniqueIndicatorCount", "unique_indicator_count"),
  );
  const observationCount = safeNumber(
    get(raw, "observationCount", "observation_count"),
    uniqueIndicatorCount,
  );
  const averageIocConfidenceValue = get(
    raw,
    "averageIocConfidence",
    "average_ioc_confidence",
  );
  return {
    id: safeString(get(raw, "id"), `campaign-${index}`),
    label: safeString(get(raw, "label", "name"), "Untitled campaign"),
    actor: safeString(get(raw, "actor", "attribution"), "Unattributed"),
    isDemo: get(raw, "isDemo", "is_demo") === true,
    firstSeen: safeString(
      get(raw, "firstSeen", "first_seen"),
      new Date().toISOString(),
    ),
    lastSeen: safeString(
      get(raw, "lastSeen", "last_seen"),
      new Date().toISOString(),
    ),
    uniqueIndicatorCount,
    observationCount,
    averageIocConfidence: safeNumber(averageIocConfidenceValue),
    averageIocConfidenceAvailable:
      averageIocConfidenceValue !== undefined &&
      averageIocConfidenceValue !== null,
    volumeTier:
      uniqueIndicatorCount >= 50
        ? "large"
        : uniqueIndicatorCount >= 20
          ? "medium"
          : "small",
    malwareFamilies: safeArray(
      get(context, "malwareFamilies", "malware_families"),
    ).map(String),
    countries: safeArray(get(context, "countries")).map(String),
    techniqueIds: safeArray(get(context, "techniqueIds", "technique_ids")).map(
      String,
    ),
    observedAsns: safeArray(get(context, "asns")).map(String),
    observedSources: safeArray(get(context, "sources")).map(String),
    relationshipEvidence: {
      repeatedIndicators: safeArray(
        get(evidence, "repeatedIndicators", "repeated_indicators"),
      ).map((item: any) => ({
        iocType: safeString(get(item, "iocType", "ioc_type"), "indicator"),
        indicatorKey: safeString(
          get(item, "indicatorKey", "indicator_key"),
          "normalized indicator",
        ),
        observationCount: safeNumber(
          get(item, "observationCount", "observation_count"),
        ),
      })),
      malwareFamilies: safeArray(
        get(evidence, "malwareFamilies", "malware_families"),
      ).map((item: any) => ({
        value: safeString(item?.value, "Unknown family"),
        uniqueIndicatorCount: safeNumber(
          get(item, "uniqueIndicatorCount", "unique_indicator_count"),
        ),
      })),
      asns: safeArray(get(evidence, "asns")).map((item: any) => ({
        value: safeString(item?.value, "Unknown ASN"),
        uniqueIndicatorCount: safeNumber(
          get(item, "uniqueIndicatorCount", "unique_indicator_count"),
        ),
      })),
    },
    summary: safeString(
      get(raw, "summary", "summary_text"),
      "Analysis pending.",
    ),
  };
}

function normalizeTechnique(raw: any, index: number): AttackTechnique {
  const observations = safeNumber(get(raw, "observations", "count"));
  const previous = get(raw, "previousObservations", "previous_observations");
  const tacticValue = get(raw, "tactics", "tactic");
  const tactics = (
    Array.isArray(tacticValue)
      ? tacticValue
      : safeString(tacticValue, "Other").split(",")
  )
    .map((tactic) => displayTactic(safeString(tactic).trim()))
    .filter(Boolean);
  return {
    id: safeString(get(raw, "id", "techniqueId", "technique_id"), `T-${index}`),
    tactic: tactics[0] ?? "Other",
    tactics,
    name: safeString(get(raw, "name"), "Unknown technique"),
    description: safeString(get(raw, "description")),
    observations,
    previousObservations:
      previous === undefined ? observations : safeNumber(previous),
    hasBaseline: previous !== undefined,
    severity: safeString(
      get(raw, "severity"),
      "medium",
    ) as AttackTechnique["severity"],
    malwareFamilies: safeArray(
      get(raw, "malwareFamilies", "malware_families"),
    ).map(String),
  };
}

function displayTactic(value: string): string {
  const labels: Record<string, string> = {
    reconnaissance: "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    execution: "Execution",
    persistence: "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    discovery: "Discovery",
    "lateral-movement": "Lateral Movement",
    collection: "Collection",
    "command-and-control": "Command and Control",
    exfiltration: "Exfiltration",
    impact: "Impact",
  };
  return labels[value.toLowerCase()] ?? value;
}

function markdownSection(markdown: string, headings: string[]): string {
  if (!markdown) return "";
  const expected = new Set(headings.map((heading) => heading.toLowerCase()));
  const sections = markdown.split(/(?=^#{1,6}\s+)/gm);
  for (const section of sections) {
    const [heading = "", ...body] = section.split(/\r?\n/);
    const label = heading
      .replace(/^#{1,6}\s+/, "")
      .replace(/\s+#+\s*$/, "")
      .trim()
      .toLowerCase();
    if (expected.has(label)) return body.join("\n").trim();
  }
  return "";
}

function plainMarkdown(value: string): string {
  return value
    .replace(/```[\s\S]*?```/g, "")
    .replace(/\[([^\]]+)]\([^)]+\)/g, "$1")
    .replace(/^\s*>\s?/gm, "")
    .replace(/[*_`~]/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function markdownList(section: string): string[] {
  const items: string[] = [];
  for (const line of section.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:[-*+] |\d+[.)]\s+)(.+)$/);
    if (match?.[1]) {
      items.push(match[1].trim());
    } else if (line.trim() && items.length > 0) {
      items[items.length - 1] += ` ${line.trim()}`;
    }
  }
  if (items.length > 0) return items.map(plainMarkdown).filter(Boolean);
  return section
    .split(/\n\s*\n/)
    .map(plainMarkdown)
    .filter(Boolean);
}

function normalizeReport(raw: any, index: number): ThreatReport {
  const facts = get(raw, "factsJson", "facts_json") ?? {};
  const reportText = safeString(get(raw, "reportText", "report_text"));
  const cadence = safeString(get(raw, "cadence"), "weekly").toLowerCase();
  const executiveSection = markdownSection(reportText, ["Executive Summary"]);
  const findingsSection = markdownSection(reportText, ["Key Findings"]);
  const prioritiesSection = markdownSection(reportText, [
    "Detection Priorities",
    "Recommendations",
  ]);
  const relatedCampaigns = safeArray(get(facts, "notable_campaigns"));
  return {
    id: safeString(get(raw, "id"), `report-${index}`),
    cadence: cadence === "monthly" ? "monthly" : "weekly",
    title: safeString(get(raw, "title"), "Threat intelligence report"),
    periodStart: safeString(
      get(raw, "periodStart", "period_start"),
      new Date().toISOString(),
    ),
    periodEnd: safeString(
      get(raw, "periodEnd", "period_end"),
      new Date().toISOString(),
    ),
    createdAt: safeString(
      get(raw, "createdAt", "created_at"),
      new Date().toISOString(),
    ),
    status: "generated",
    isDemo: get(raw, "isDemo", "is_demo") === true,
    executiveSummary: safeString(
      get(raw, "executiveSummary", "executive_summary"),
      executiveSection
        ? plainMarkdown(executiveSection)
        : reportText
          ? "The generated narrative does not expose a distinct Executive Summary section. Download the original Markdown to review it without transformation."
          : "Open this report to retrieve its narrative.",
    ),
    content: reportText || undefined,
    keyFindings: safeArray(
      get(raw, "keyFindings", "key_findings") ??
        (findingsSection ? markdownList(findingsSection) : []),
    ).map(String),
    recommendations: safeArray(
      get(raw, "recommendations") ??
        (prioritiesSection ? markdownList(prioritiesSection) : []),
    ).map(String),
    topFamilies: safeArray(
      get(raw, "topFamilies", "top_families") ??
        get(facts, "top_malware_families_by_observation") ??
        get(facts, "top_malware_families"),
    ).map((item: any) =>
      Array.isArray(item)
        ? { name: safeString(item[0]), count: safeNumber(item[1]) }
        : { name: safeString(item?.name), count: safeNumber(item?.count) },
    ),
    relatedCampaignIds: safeArray(
      get(raw, "relatedCampaignIds", "related_campaign_ids") ??
        relatedCampaigns.map((campaign: any) => campaign?.id),
    )
      .filter((id) => id !== undefined && id !== null)
      .map(String),
    generatedBy: normalizeReportProvider(
      get(raw, "generatedBy", "generated_by", "provider"),
    ),
  };
}

function normalizeReportSchedule(raw: any): ReportSchedule {
  const cadence = safeString(get(raw, "cadence"), "weekly").toLowerCase();
  const nextRunAt = safeString(get(raw, "nextRunAt", "next_run_at"));
  return {
    cadence: cadence === "monthly" ? "monthly" : "weekly",
    schedulerRunning: Boolean(
      get(raw, "schedulerRunning", "scheduler_running"),
    ),
    providerConfigured: Boolean(
      get(raw, "providerConfigured", "provider_configured"),
    ),
    adminAuthRequired: Boolean(
      get(raw, "adminAuthRequired", "admin_auth_required"),
    ),
    nextRunAt: nextRunAt || null,
    timezone: safeString(get(raw, "timezone"), "UTC"),
    hourUtc: safeNumber(get(raw, "hourUtc", "hour_utc")),
    weeklyDay: safeString(get(raw, "weeklyDay", "weekly_day"), "mon"),
    monthlyDay: safeNumber(get(raw, "monthlyDay", "monthly_day"), 1),
    updatedAt: safeString(get(raw, "updatedAt", "updated_at")),
  };
}

function normalizeRule(raw: any, index: number): DetectionRule {
  const ruleType = safeString(
    get(raw, "type", "rule_type"),
    "sigma",
  ) as DetectionRule["type"];
  const iocId = safeString(get(raw, "iocId", "ioc_id"));
  const corroboratingSources = safeArray(
    get(raw, "corroboratingSources", "corroborating_sources"),
  ).map(String);
  const requiresReview = get(raw, "requiresReview", "requires_review");
  const risk = safeString(get(raw, "falsePositiveRisk", "false_positive_risk"));
  return {
    id: safeString(get(raw, "id"), `rule-${index}`),
    name: safeString(
      get(raw, "name"),
      `${ruleType === "sigma" ? "Sigma" : "Suricata"} candidate for IOC ${iocId || index}`,
    ),
    type: ruleType,
    severity: safeString(
      get(raw, "severity"),
      "medium",
    ) as DetectionRule["severity"],
    requiresReview: requiresReview !== false,
    isDemo: get(raw, "isDemo", "is_demo") === true,
    malwareFamily: safeString(
      get(raw, "malwareFamily", "malware_family"),
      "Unknown",
    ),
    updatedAt: safeString(
      get(raw, "updatedAt", "updated_at", "generated_at"),
      new Date().toISOString(),
    ),
    indicatorCount: safeNumber(
      get(raw, "indicatorCount", "indicator_count"),
      1,
    ),
    corroboratingSources,
    falsePositiveRisk: ["low", "medium", "high"].includes(risk)
      ? (risk as DetectionRule["falsePositiveRisk"])
      : null,
    content: safeString(get(raw, "content", "ruleText", "rule_text")),
    tags: safeArray(get(raw, "tags")).map(String),
  };
}

function normalizeFeedRun(raw: any, index: number): FeedRun {
  return {
    id: safeString(get(raw, "id"), `feed-run-${index}`),
    feed: safeString(get(raw, "feed", "feed_name"), "unknown"),
    status: safeString(get(raw, "status"), "unknown"),
    startedAt: safeString(
      get(raw, "startedAt", "started_at"),
      new Date().toISOString(),
    ),
    completedAt:
      safeString(get(raw, "completedAt", "completed_at")) || undefined,
    received: safeNumber(get(raw, "received", "received_count")),
    inserted: safeNumber(get(raw, "inserted", "inserted_count")),
    updated: safeNumber(get(raw, "updated", "updated_count")),
    rejected: safeNumber(get(raw, "rejected", "rejected_count")),
    duplicatesCollapsed: safeNumber(
      get(raw, "duplicatesCollapsed", "duplicates_collapsed"),
    ),
    error: safeString(get(raw, "error")) || undefined,
  };
}

export class ApiRequestError extends Error {
  constructor(
    public readonly status: number,
    message = `API request failed (${status})`,
  ) {
    super(message);
    this.name = "ApiRequestError";
  }
}

async function request<T>(
  path: string,
  init?: RequestInit,
  timeoutMs = 8000,
): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...init?.headers,
      },
      signal: controller.signal,
    });
    if (response.ok) hasLiveResponse = true;
    if (!response.ok) throw new ApiRequestError(response.status);
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  } finally {
    window.clearTimeout(timeout);
  }
}

async function withFallback<T>(
  resource: string,
  fallback: T,
  loader: () => Promise<T>,
): Promise<ApiResult<T>> {
  if (FORCE_DEMO)
    return { data: fallback, mode: "demo", reason: "Demo mode is enabled" };
  try {
    const data = await loader();
    hasLiveResponse = true;
    markResource(resource, false);
    return { data, mode: "live" };
  } catch (error) {
    const gatewayUnavailable =
      error instanceof ApiRequestError &&
      [502, 503, 504].includes(error.status);
    const canUseOfflineDemo =
      !hasLiveResponse && (error instanceof TypeError || gatewayUnavailable);
    if (!canUseOfflineDemo) {
      markError(resource);
      throw error;
    }
    markResource(resource, true);
    return {
      data: fallback,
      mode: "demo",
      reason:
        error instanceof Error
          ? error.message
          : "ThreatMesh API transport unavailable",
    };
  }
}

async function loadIndicators(
  provenance: "all" | "live" | "demo" = "all",
): Promise<ApiResult<Indicator[]>> {
  if (FORCE_DEMO) {
    return {
      data: demoIndicators,
      mode: "demo",
      reason: "Demo mode is enabled",
      total: demoIndicators.length,
      limit: demoIndicators.length,
      offset: 0,
    };
  }
  try {
    const provenanceQuery =
      provenance === "all" ? "" : `&provenance=${provenance}`;
    const payload = await request<any>(`/iocs?limit=500${provenanceQuery}`);
    const data = listPayload(payload).map(normalizeIndicator);
    hasLiveResponse = true;
    markResource("indicators", false);
    return {
      data,
      mode: "live",
      total: safeNumber(payload?.total, data.length),
      limit: safeNumber(payload?.limit, 500),
      offset: safeNumber(payload?.offset),
    };
  } catch (error) {
    const gatewayUnavailable =
      error instanceof ApiRequestError &&
      [502, 503, 504].includes(error.status);
    const canUseOfflineDemo =
      !hasLiveResponse && (error instanceof TypeError || gatewayUnavailable);
    if (!canUseOfflineDemo) {
      markError("indicators");
      throw error;
    }
    markResource("indicators", true);
    return {
      data: demoIndicators,
      mode: "demo",
      reason:
        error instanceof Error ? error.message : "API transport unavailable",
      total: demoIndicators.length,
      limit: demoIndicators.length,
      offset: 0,
    };
  }
}

const parseSummary = (payload: any): SummaryStats => {
  const raw = payload?.data ?? payload ?? {};
  return {
    totalObservations: safeNumber(
      get(raw, "totalObservations", "total_observations", "total_iocs"),
    ),
    highConfidence: safeNumber(
      get(raw, "highConfidence", "high_confidence", "high_confidence_iocs"),
    ),
    activeCampaigns: safeNumber(
      get(raw, "activeCampaigns", "active_campaigns"),
    ),
    affectedCountries: safeNumber(
      get(raw, "affectedCountries", "affected_countries", "countries"),
    ),
    ingestionLastHour: safeNumber(
      get(raw, "ingestionLastHour", "ingestion_last_hour"),
    ),
    feedHealth: safeNumber(get(raw, "feedHealth", "feed_health")),
    demoIocs: safeNumber(get(raw, "demoIocs", "demo_iocs")),
    liveIocs: safeNumber(get(raw, "liveIocs", "live_iocs")),
    corpusMode: safeString(
      get(raw, "corpusMode", "corpus_mode"),
      "unknown",
    ) as SummaryStats["corpusMode"],
    analysisScope: safeString(
      get(raw, "analysisScope", "analysis_scope"),
      "unknown",
    ) as SummaryStats["analysisScope"],
    trend: {
      indicators: safeNumber(raw?.trend?.indicators),
      confidence: safeNumber(raw?.trend?.confidence),
      campaigns: safeNumber(raw?.trend?.campaigns),
      countries: safeNumber(raw?.trend?.countries),
    },
  };
};

export const threatApi = {
  indicators: loadIndicators,
  indicator: (id: string) =>
    withFallback<Indicator | null>(
      `indicator-${id}`,
      demoIndicators.find((item) => item.id === id) ?? null,
      async () =>
        normalizeIndicator(
          await request<any>(`/iocs/${encodeURIComponent(id)}`),
          0,
        ),
    ),
  campaigns: () =>
    withFallback("campaigns", demoCampaigns, async () =>
      listPayload(await request<any>("/campaigns")).map(normalizeCampaign),
    ),
  campaign: (id: string) =>
    withFallback<Campaign | null>(
      `campaign-${id}`,
      demoCampaigns.find((campaign) => campaign.id === id) ?? null,
      async () =>
        normalizeCampaign(
          await request<any>(`/campaigns/${encodeURIComponent(id)}`),
          0,
        ),
    ),
  techniques: () =>
    withFallback("techniques", demoTechniques, async () => {
      const [catalogPayload, trendingPayload] = await Promise.all([
        request<any>("/techniques?limit=1000"),
        request<any>("/stats/techniques/trending?days=7&limit=100"),
      ]);
      const trends = new Map(
        listPayload(trendingPayload).map((item: any) => [
          safeString(get(item, "technique_id", "techniqueId", "id")),
          safeNumber(get(item, "count", "observations")),
        ]),
      );
      return listPayload(catalogPayload).map((item: any, index) =>
        normalizeTechnique(
          {
            ...item,
            observations:
              trends.get(
                safeString(get(item, "technique_id", "techniqueId", "id")),
              ) ?? 0,
          },
          index,
        ),
      );
    }),
  reports: () =>
    withFallback("reports", demoReports, async () =>
      listPayload(await request<any>("/reports")).map(normalizeReport),
    ),
  report: (id: string) =>
    withFallback<ThreatReport | null>(
      `report-${id}`,
      demoReports.find((report) => report.id === id) ?? null,
      async () =>
        normalizeReport(
          await request<any>(`/reports/${encodeURIComponent(id)}`),
          0,
        ),
    ),
  reportSchedule: async (): Promise<ApiResult<ReportSchedule>> => {
    if (FORCE_DEMO) {
      return {
        data: {
          cadence: "weekly",
          schedulerRunning: false,
          providerConfigured: false,
          adminAuthRequired: false,
          nextRunAt: null,
          timezone: "UTC",
          hourUtc: 6,
          weeklyDay: "mon",
          monthlyDay: 1,
          updatedAt: "",
        },
        mode: "demo",
        reason: "Automatic scheduling is unavailable in demo mode",
      };
    }
    return {
      data: normalizeReportSchedule(await request<any>("/reports/schedule")),
      mode: "live",
    };
  },
  updateReportSchedule: async (
    cadence: ReportCadence,
    adminApiKey: string,
  ): Promise<ApiResult<ReportSchedule>> => {
    if (FORCE_DEMO) {
      throw new ApiRequestError(
        409,
        "Automatic scheduling is unavailable in demo mode",
      );
    }
    return {
      data: normalizeReportSchedule(
        await request<any>("/reports/schedule", {
          method: "PUT",
          ...(adminApiKey ? { headers: { "X-API-Key": adminApiKey } } : {}),
          body: JSON.stringify({ cadence }),
        }),
      ),
      mode: "live",
    };
  },
  rules: () =>
    withFallback("rules", demoRules, async () =>
      listPayload(await request<any>("/rules")).map(normalizeRule),
    ),
  feedStatus: () =>
    withFallback<FeedRun[]>("feed-status", [], async () =>
      listPayload(await request<any>("/feeds/status")).map(normalizeFeedRun),
    ),
  summary: () =>
    withFallback("summary", demoSummary, async () => {
      const [summaryPayload, countryPayload] = await Promise.all([
        request<any>("/stats/summary"),
        request<any>("/stats/by-country?limit=250"),
      ]);
      const summary = parseSummary(summaryPayload);
      summary.affectedCountries = listPayload(countryPayload).length;
      return summary;
    }),
  ask: async (question: string): Promise<ApiResult<AssistantAnswer>> => {
    if (FORCE_DEMO) {
      return {
        data: demoAssistantAnswer(question),
        mode: "demo",
        reason: "Demo mode is enabled",
      };
    }
    try {
      const started = performance.now();
      const payload = await request<any>(
        "/assistant/ask",
        {
          method: "POST",
          body: JSON.stringify({ question }),
        },
        105_000,
      );
      const facts = payload?.grounded_facts ?? {};
      const retrievedIndicators = safeArray(facts.indicators);
      const campaignFacts = safeArray(facts.campaigns);
      const reportFacts = safeArray(facts.recent_reports);
      const citationKinds = new Set([
        "indicator",
        "campaign",
        "technique",
        "report",
        "aggregate",
      ]);
      const citations = safeArray(payload?.citations)
        .map((item: any) => {
          const recordId = safeString(get(item, "recordId", "record_id"));
          const kind = safeString(item?.kind);
          if (!recordId || !citationKinds.has(kind)) return null;
          return {
            recordId,
            id: recordId.includes(":")
              ? recordId.slice(recordId.indexOf(":") + 1)
              : recordId,
            label: safeString(item?.label, recordId),
            kind: kind as AssistantAnswer["citations"][number]["kind"],
          };
        })
        .filter(
          (item): item is AssistantAnswer["citations"][number] => item !== null,
        );
      const integrity = payload?.citation_integrity;
      const integrityStatus = safeString(get(integrity ?? {}, "status"));
      const data: AssistantAnswer = {
        answer: safeString(payload?.answer),
        citations,
        retrievedCount:
          safeNumber(
            facts.retrieved_observation_count,
            retrievedIndicators.length,
          ) +
          campaignFacts.length +
          reportFacts.length,
        queryTimeMs: Math.round(performance.now() - started),
        includedProvenance: ["none", "demo", "live"].includes(
          safeString(facts.included_provenance),
        )
          ? (safeString(
              facts.included_provenance,
            ) as AssistantAnswer["includedProvenance"])
          : undefined,
        citationIntegrity: ["verified", "partial", "absent"].includes(
          integrityStatus,
        )
          ? {
              status: integrityStatus as NonNullable<
                AssistantAnswer["citationIntegrity"]
              >["status"],
              validatedCount: safeNumber(
                get(integrity, "validatedCount", "validated_count"),
              ),
              rejectedCount: safeNumber(
                get(integrity, "rejectedCount", "rejected_count"),
              ),
            }
          : undefined,
      };
      markResource("assistant", false);
      return { data, mode: "live" };
    } catch (error) {
      const wasLive = dataMode === "live";
      if (
        error instanceof ApiRequestError ||
        (error instanceof DOMException && error.name === "AbortError") ||
        wasLive
      ) {
        markError("assistant");
        throw error;
      }
      markResource("assistant", true);
      return {
        data: demoAssistantAnswer(question),
        mode: "demo",
        reason: error instanceof Error ? error.message : "API unavailable",
      };
    }
  },
};

function demoAssistantAnswer(question: string): AssistantAnswer {
  const normalized = question.toLowerCase();
  if (
    normalized.includes("country") ||
    normalized.includes("where") ||
    normalized.includes("region")
  ) {
    const countryCounts = demoIndicators.reduce<Record<string, number>>(
      (counts, item) => ({
        ...counts,
        [item.country]: (counts[item.country] ?? 0) + 1,
      }),
      {},
    );
    const top = Object.entries(countryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4);
    return {
      answer: `Across the retrieved records, ${top.map(([country, count]) => `${country} (${count})`).join(", ")} are the most represented approximate locations. These are IP geolocation estimates—not victim locations or confirmed operator locations.`,
      citations: demoIndicators
        .filter((item) => top.some(([country]) => country === item.country))
        .slice(0, 5)
        .map((item) => ({
          id: item.id,
          recordId: `ioc:${item.id}`,
          label: item.value,
          kind: "indicator" as const,
        })),
      retrievedCount: demoIndicators.length,
      queryTimeMs: 142,
      includedProvenance: "demo",
    };
  }
  if (
    normalized.includes("technique") ||
    normalized.includes("mitre") ||
    normalized.includes("attack")
  ) {
    const top = [...demoTechniques]
      .sort((a, b) => b.observations - a.observations)
      .slice(0, 3);
    return {
      answer: `The strongest observed technique signals are ${top.map((item) => `${item.name} (${item.id}, ${item.observations} observations)`).join("; ")}. Counts reflect mappings in the retrieved OSINT dataset and do not prove execution in any specific environment.`,
      citations: top.map((item) => ({
        id: item.id,
        recordId: `technique:${item.id}`,
        label: `${item.id} ${item.name}`,
        kind: "technique" as const,
      })),
      retrievedCount: top.length,
      queryTimeMs: 118,
      includedProvenance: "demo",
    };
  }
  if (normalized.includes("campaign") || normalized.includes("cluster")) {
    const top = [...demoCampaigns]
      .sort((a, b) => b.averageIocConfidence - a.averageIocConfidence)
      .slice(0, 3);
    return {
      answer: `${top[0]?.label} has the highest average member-IOC confidence at ${top[0]?.averageIocConfidence}%, followed by ${top[1]?.label} at ${top[1]?.averageIocConfidence}%. This metric does not measure cluster or attribution confidence; campaign labels remain correlation hypotheses.`,
      citations: top.map((item) => ({
        id: item.id,
        recordId: `campaign:${item.id}`,
        label: item.label,
        kind: "campaign" as const,
      })),
      retrievedCount: top.length,
      queryTimeMs: 126,
      includedProvenance: "demo",
    };
  }
  const topFamilies = Object.entries(
    demoIndicators.reduce<Record<string, number>>(
      (counts, item) => ({
        ...counts,
        [item.malwareFamily]: (counts[item.malwareFamily] ?? 0) + 1,
      }),
      {},
    ),
  )
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);
  return {
    answer: `The retrieved sample is led by ${topFamilies.map(([name, count]) => `${name} (${count} indicators)`).join(", ")}. High-confidence records should be prioritized for review, but no indicator should be deployed to blocking controls without analyst validation.`,
    citations: demoIndicators
      .filter((item) =>
        topFamilies.some(([family]) => family === item.malwareFamily),
      )
      .slice(0, 5)
      .map((item) => ({
        id: item.id,
        recordId: `ioc:${item.id}`,
        label: item.value,
        kind: "indicator" as const,
      })),
    retrievedCount: demoIndicators.length,
    queryTimeMs: 134,
    includedProvenance: "demo",
  };
}

export { API_BASE_URL };
