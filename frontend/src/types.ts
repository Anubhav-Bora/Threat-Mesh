export type IndicatorType = "ip" | "domain" | "url" | "hash";
export type ConfidenceBand = "high" | "medium" | "low";
export type ThreatStatus = "active" | "monitoring" | "decayed";
export type Severity = "critical" | "high" | "medium" | "low";
export type RuleType = "sigma" | "suricata";
export type CorpusMode = "empty" | "demo" | "live" | "mixed" | "unknown";
export type AnalysisScope = "none" | "demo" | "live" | "unknown";

export interface Indicator {
  id: string;
  value: string;
  type: IndicatorType;
  malwareFamily: string;
  firstSeen: string;
  lastSeen: string;
  sourceFeed: string;
  confidence: number;
  confidenceAvailable?: boolean;
  isDemo?: boolean;
  country: string;
  countryCode: string;
  city: string;
  asn: string;
  asnOrg: string;
  latitude: number | null;
  longitude: number | null;
  locationPrecisionKm: number | null;
  techniqueIds: string[];
  campaignId?: string;
  status: ThreatStatus | null;
  corroboratingFeeds: number | null;
  tags: string[];
}

export interface InvestigationMatch {
  query: string;
  normalizedQuery: string;
  indicator: Indicator;
  blocklistEligible: boolean;
  warnings: string[];
}

export interface InvestigationResult {
  queried: number;
  matched: number;
  matches: InvestigationMatch[];
  unmatched: string[];
  invalid: string[];
}

export interface StixBundle {
  type: "bundle";
  id: string;
  objects: Array<Record<string, unknown>>;
}

export type LineageConfidenceStatus = "available" | "pending";
export type LineageEnrichmentStatus =
  "available" | "not_applicable" | "unavailable";

export interface ConfidenceComponent {
  key: string;
  label: string;
  score: number;
  maxScore: number;
  evidence: string;
}

export interface IndicatorLineage {
  indicatorId: string;
  recordId: string;
  identity: {
    value: string;
    type: IndicatorType;
    port: number | null;
    isDemo: boolean;
  };
  provenance: {
    selectedSource: string;
    observations: Array<{
      recordId: string;
      sourceFeed: string;
      firstSeen: string;
      lastSeen: string;
      sourceConfidenceHint: number | null;
      isSelected: boolean;
    }>;
    rawPayload: {
      retained: boolean;
      sha256: string | null;
      fieldNames: string[];
    };
  };
  confidence: {
    status: LineageConfidenceStatus;
    total: number | null;
    formulaVersion: string | null;
    calculatedAt: string | null;
    components: ConfidenceComponent[];
  };
  enrichment: {
    status: LineageEnrichmentStatus;
    provider: string | null;
    method: string;
    country: string | null;
    countryCode: string | null;
    city: string | null;
    asn: string | null;
    asnOrg: string | null;
    approximate: boolean;
  };
  attackMappings: Array<{
    recordId: string;
    techniqueId: string;
    name: string;
    tactic: string;
    method: string;
    basis: string;
    inference: boolean;
  }>;
  campaignMembership: {
    recordId: string;
    label: string;
    snapshot: "current";
    reasons: string[];
  } | null;
  derivedArtifacts: {
    rules: Array<{
      recordId: string;
      ruleType: RuleType;
      requiresReview: boolean;
      generatedAt: string;
    }>;
    reportMentions: Array<{
      recordId: string;
      title: string;
      periodStart: string;
      periodEnd: string;
    }>;
  };
  limitations: string[];
}

export interface Campaign {
  id: string;
  label: string;
  actor: string;
  isDemo: boolean;
  firstSeen: string;
  lastSeen: string;
  uniqueIndicatorCount: number;
  observationCount: number;
  averageIocConfidence: number;
  averageIocConfidenceAvailable?: boolean;
  volumeTier: "large" | "medium" | "small";
  malwareFamilies: string[];
  countries: string[];
  techniqueIds: string[];
  observedAsns: string[];
  observedSources: string[];
  relationshipEvidence: {
    repeatedIndicators: Array<{
      iocType: string;
      indicatorKey: string;
      observationCount: number;
    }>;
    malwareFamilies: Array<{ value: string; uniqueIndicatorCount: number }>;
    asns: Array<{ value: string; uniqueIndicatorCount: number }>;
  };
  summary: string;
}

export interface AttackTechnique {
  id: string;
  tactic: string;
  tactics?: string[];
  name: string;
  description: string;
  observations: number;
  previousObservations: number;
  hasBaseline?: boolean;
  severity: Severity;
  malwareFamilies: string[];
}

export interface ThreatReport {
  id: string;
  cadence: ReportCadence;
  title: string;
  periodStart: string;
  periodEnd: string;
  createdAt: string;
  status: "generated";
  isDemo: boolean;
  executiveSummary: string;
  /** Original generated Markdown when the detail endpoint has been loaded. */
  content?: string;
  keyFindings: string[];
  recommendations: string[];
  topFamilies: Array<{ name: string; count: number }>;
  relatedCampaignIds: string[];
  generatedBy: "gemini" | "openrouter" | "ollama" | "analyst" | "demo";
}

export type ReportCadence = "weekly" | "monthly";

export interface ReportSchedule {
  cadence: ReportCadence;
  schedulerRunning: boolean;
  schedulerMode: "embedded" | "external" | "disabled";
  providerConfigured: boolean;
  adminAuthRequired: boolean;
  nextRunAt: string | null;
  timezone: string;
  hourUtc: number;
  weeklyDay: string;
  monthlyDay: number;
  updatedAt: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  type: RuleType;
  severity: "high" | "medium" | "low";
  requiresReview: boolean;
  isDemo: boolean;
  malwareFamily: string;
  updatedAt: string;
  indicatorCount: number;
  corroboratingSources: string[];
  falsePositiveRisk: "low" | "medium" | "high" | null;
  content: string;
  tags: string[];
}

export interface SummaryStats {
  totalObservations: number;
  highConfidence: number;
  activeCampaigns: number;
  affectedCountries: number;
  ingestionLastHour: number;
  feedHealth: number;
  demoIocs: number;
  liveIocs: number;
  corpusMode: CorpusMode;
  analysisScope: AnalysisScope;
  trend: {
    indicators: number;
    confidence: number;
    campaigns: number;
    countries: number;
  };
}

export interface ActivityEvent {
  id: string;
  timestamp: string;
  kind: "ingested" | "campaign" | "rule" | "report";
  title: string;
  detail: string;
  severity: Severity;
}

export interface FeedRun {
  id: string;
  feed: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  received: number;
  inserted: number;
  updated: number;
  rejected: number;
  duplicatesCollapsed: number;
  error?: string;
}

export interface MapFilters {
  malwareFamily: string;
  country: string;
  source: string;
  minConfidence: number;
  range: "24h" | "7d" | "30d" | "90d" | "all";
}

export interface AssistantCitation {
  id: string;
  recordId: string;
  label: string;
  kind: "indicator" | "campaign" | "technique" | "report" | "aggregate";
}

export interface CitationIntegrity {
  status: "verified" | "partial" | "absent";
  validatedCount: number;
  rejectedCount: number;
}

export type AssistantMode = "auto" | "threatmesh" | "general";

export interface AssistantHistoryItem {
  role: "user" | "assistant";
  content: string;
}

export interface AssistantAnswer {
  answer: string;
  answerMode: "threatmesh" | "general";
  citations: AssistantCitation[];
  retrievedCount: number;
  queryTimeMs: number;
  includedProvenance?: "none" | "demo" | "live";
  citationIntegrity?: CitationIntegrity;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
  answerMode?: "threatmesh" | "general";
  citations?: AssistantCitation[];
  retrievedCount?: number;
  queryTimeMs?: number;
  includedProvenance?: "none" | "demo" | "live";
  citationIntegrity?: CitationIntegrity;
}
