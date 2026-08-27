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
  generatedBy: "gemini" | "ollama" | "analyst" | "demo";
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
  label: string;
  kind: "indicator" | "campaign" | "technique" | "report";
}

export interface AssistantAnswer {
  answer: string;
  citations: AssistantCitation[];
  retrievedCount: number;
  queryTimeMs: number;
  includedProvenance?: "none" | "demo" | "live";
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
  citations?: AssistantCitation[];
  retrievedCount?: number;
  queryTimeMs?: number;
  includedProvenance?: "none" | "demo" | "live";
}
