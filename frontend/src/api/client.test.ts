import { beforeEach, describe, expect, it, vi } from "vitest";
import { threatApi } from "./client";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("FastAPI client contract", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("normalizes GeoJSON IOC properties from /iocs", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        type: "FeatureCollection",
        total: 1,
        limit: 500,
        offset: 0,
        features: [
          {
            id: 41,
            type: "Feature",
            geometry: { type: "Point", coordinates: [8.68, 50.11] },
            properties: {
              id: 41,
              ioc_value: "198.51.100.3",
              ioc_type: "ip",
              port: 443,
              malware_family: "Example",
              first_seen: "2026-08-01T00:00:00Z",
              last_seen: "2026-08-02T00:00:00Z",
              source_feed: "ThreatFox",
              confidence_score: 91,
              is_demo: true,
              location_precision_km: 25,
              country: "Germany",
              country_code: "DE",
              city: "Frankfurt",
              asn: "AS64500",
              asn_org: "Example Network",
              attack_technique_ids: ["T1071.001"],
              cluster_id: 3,
            },
          },
        ],
      }),
    );
    const result = await threatApi.indicators();
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/iocs?limit=500");
    expect(result.mode).toBe("live");
    expect(result.data[0]).toMatchObject({
      id: "41",
      value: "198.51.100.3",
      latitude: 50.11,
      longitude: 8.68,
      campaignId: "3",
      confidence: 91,
      isDemo: true,
      locationPrecisionKm: 25,
    });
    expect(result).toMatchObject({ total: 1, limit: 500, offset: 0 });
  });

  it("keeps ungeolocated records out of Null Island", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        type: "FeatureCollection",
        total: 1,
        limit: 500,
        offset: 0,
        features: [
          {
            id: 42,
            type: "Feature",
            geometry: null,
            properties: {
              id: 42,
              ioc_value: "unresolved.example",
              ioc_type: "domain",
              malware_family: null,
              first_seen: "2026-08-01T00:00:00Z",
              last_seen: "2026-08-02T00:00:00Z",
              source_feed: "URLhaus",
              confidence_score: 60,
              country: null,
              city: null,
              attack_technique_ids: [],
            },
          },
        ],
      }),
    );
    const result = await threatApi.indicators();
    expect(result.data[0]).toMatchObject({
      latitude: null,
      longitude: null,
      locationPrecisionKm: null,
      corroboratingFeeds: null,
      status: null,
    });
  });

  it("requests a live-only IOC page for mixed-corpus operational views", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        type: "FeatureCollection",
        total: 0,
        limit: 500,
        offset: 0,
        features: [],
      }),
    );
    await threatApi.indicators("live");
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      "/api/v1/iocs?limit=500&provenance=live",
    );
  });

  it("separates campaign relationship evidence from observed context", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([
        {
          id: 7,
          label: "Example infrastructure",
          first_seen: "2026-08-01T00:00:00Z",
          last_seen: "2026-08-03T00:00:00Z",
          observation_count: 31,
          unique_indicator_count: 24,
          average_ioc_confidence: 82,
          is_demo: true,
          summary_text: "Correlation hypothesis from repeated evidence.",
          relationship_evidence: {
            repeated_indicators: [
              {
                ioc_type: "domain",
                indicator_key: "example.test",
                observation_count: 3,
              },
            ],
            malware_families: [{ value: "QakBot", unique_indicator_count: 7 }],
            asns: [{ value: "AS9009", unique_indicator_count: 4 }],
          },
          observed_context: {
            malware_families: ["QakBot"],
            asns: ["AS9009"],
            countries: ["Netherlands"],
            sources: ["ThreatFox"],
            technique_ids: ["T1105"],
            average_ioc_confidence: 82,
            unique_indicator_count: 24,
            observation_count: 31,
          },
        },
      ]),
    );
    const result = await threatApi.campaigns();
    expect(result.data[0]).toMatchObject({
      malwareFamilies: ["QakBot"],
      countries: ["Netherlands"],
      observedAsns: ["AS9009"],
      observedSources: ["ThreatFox"],
      techniqueIds: ["T1105"],
      uniqueIndicatorCount: 24,
      observationCount: 31,
      averageIocConfidence: 82,
      isDemo: true,
      relationshipEvidence: {
        repeatedIndicators: [
          {
            iocType: "domain",
            indicatorKey: "example.test",
            observationCount: 3,
          },
        ],
        malwareFamilies: [{ value: "QakBot", uniqueIndicatorCount: 7 }],
        asns: [{ value: "AS9009", uniqueIndicatorCount: 4 }],
      },
    });
  });

  it("joins /techniques with seven-day trend counts", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const url = String(input);
        if (url.includes("/stats/techniques/trending"))
          return jsonResponse([
            {
              technique_id: "T1071.001",
              name: "Web Protocols",
              tactic: "Command and Control",
              count: 17,
            },
          ]);
        return jsonResponse([
          {
            technique_id: "T1071.001",
            tactic: "execution, command-and-control",
            name: "Web Protocols",
            description: "Uses web protocols.",
          },
        ]);
      });
    const result = await threatApi.techniques();
    expect(fetchMock.mock.calls.map((call) => call[0])).toEqual(
      expect.arrayContaining([
        "/api/v1/techniques?limit=1000",
        "/api/v1/stats/techniques/trending?days=7&limit=100",
      ]),
    );
    expect(result.data[0]).toMatchObject({
      id: "T1071.001",
      tactic: "Execution",
      tactics: ["Execution", "Command and Control"],
      observations: 17,
      hasBaseline: false,
    });
  });

  it("maps grounded assistant facts from /assistant/ask into inspectable citations", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        answer: "One matching record.",
        provider: "stub",
        model: "test",
        grounded_facts: {
          matching_ioc_count: 120,
          retrieved_observation_count: 1,
          included_provenance: "live",
          indicators: [{ value: "203.0.113.9", type: "ip" }],
          attack_techniques: [["T1105", 1]],
          campaigns: [{ id: 4, label: "Cluster 4" }],
          recent_reports: [{ id: 8, title: "Weekly report" }],
        },
        citations: [
          {
            record_id: "campaign:4",
            kind: "campaign",
            label: "Cluster 4",
          },
          {
            record_id: "report:8",
            kind: "report",
            label: "Weekly report",
          },
        ],
        citation_integrity: {
          status: "verified",
          validated_count: 2,
          rejected_count: 0,
        },
        disclaimer: "Grounded facts only.",
      }),
    );
    const result = await threatApi.ask("What was retrieved?");
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/assistant/ask");
    expect(result.data).toMatchObject({
      answer: "One matching record.",
      retrievedCount: 3,
      includedProvenance: "live",
      citationIntegrity: {
        status: "verified",
        validatedCount: 2,
        rejectedCount: 0,
      },
    });
    expect(result.data.citations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          recordId: "campaign:4",
          kind: "campaign",
          label: "Cluster 4",
        }),
        expect.objectContaining({
          recordId: "report:8",
          kind: "report",
          label: "Weekly report",
        }),
      ]),
    );
    expect(result.data.citations).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ label: "203.0.113.9" }),
      ]),
    );
  });

  it("parses report sections while retaining original generated Markdown", async () => {
    const reportText =
      "## Executive Summary\n\nObserved facts only.\n\n## Key Findings\n\n- Finding one\n- Finding two\n\n## Detection Priorities\n\n1. Validate the candidate.";
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        id: 12,
        title: "Weekly CTI report",
        period_start: "2026-08-01T00:00:00Z",
        period_end: "2026-08-08T00:00:00Z",
        created_at: "2026-08-08T01:00:00Z",
        provider: "ollama",
        is_demo: false,
        model: "local",
        report_text: reportText,
        facts_json: {
          top_malware_families_by_observation: [["Example", 3]],
          notable_campaigns: [{ id: 9, label: "Cluster 9" }],
        },
      }),
    );
    const result = await threatApi.report("12");
    expect(result.data).toMatchObject({
      content: reportText,
      executiveSummary: "Observed facts only.",
      keyFindings: ["Finding one", "Finding two"],
      recommendations: ["Validate the candidate."],
      relatedCampaignIds: ["9"],
      topFamilies: [{ name: "Example", count: 3 }],
      generatedBy: "ollama",
      status: "generated",
      isDemo: false,
    });
  });

  it("uses rule corroboration and leaves unsupported risk unassessed", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([
        {
          id: 31,
          ioc_id: 4,
          rule_type: "sigma",
          rule_text: "title: Example",
          corroborating_sources: ["urlhaus", "threatfox"],
          generated_at: "2026-08-08T01:00:00Z",
          requires_review: true,
          is_demo: false,
          malware_family: "Example",
          severity: "high",
          tags: ["T1105"],
        },
      ]),
    );
    const result = await threatApi.rules();
    expect(result.data[0]).toMatchObject({
      corroboratingSources: ["urlhaus", "threatfox"],
      falsePositiveRisk: null,
      requiresReview: true,
      isDemo: false,
    });
  });

  it("surfaces endpoint HTTP failures without mixing in demo records", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ detail: "database unavailable" }, 503),
    );
    await expect(threatApi.campaigns()).rejects.toThrow(
      "API request failed (503)",
    );
  });

  it("surfaces a provider failure instead of fabricating a demo answer", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({ detail: "LLM provider unavailable" }, 503),
    );
    await expect(threatApi.ask("Summarize this week")).rejects.toThrow(
      "API request failed (503)",
    );
  });

  it("joins country buckets into summary instead of inventing a count", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) =>
      String(input).includes("/by-country")
        ? jsonResponse([
            { country: "DE", count: 3 },
            { country: "NL", count: 2 },
          ])
        : jsonResponse({
            total_iocs: 5,
            geolocated_iocs: 5,
            high_confidence_iocs: 3,
            active_campaigns: 1,
            demo_iocs: 2,
            live_iocs: 3,
            corpus_mode: "mixed",
            analysis_scope: "live",
            generated_at: "2026-08-01T00:00:00Z",
          }),
    );
    const result = await threatApi.summary();
    expect(result.data).toMatchObject({
      totalObservations: 5,
      highConfidence: 3,
      activeCampaigns: 1,
      affectedCountries: 2,
      demoIocs: 2,
      liveIocs: 3,
      corpusMode: "mixed",
      analysisScope: "live",
    });
  });

  it("uses live feed runs for operational status without inventing health", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse([
        {
          id: 9,
          feed: "urlhaus",
          status: "partial",
          started_at: "2026-08-26T08:00:00Z",
          completed_at: "2026-08-26T08:01:00Z",
          received: 120,
          inserted: 12,
          updated: 44,
          rejected: 2,
          duplicates_collapsed: 62,
          error: "One page timed out",
        },
      ]),
    );
    const result = await threatApi.feedStatus();
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/v1/feeds/status");
    expect(result.data[0]).toMatchObject({
      feed: "urlhaus",
      status: "partial",
      inserted: 12,
      duplicatesCollapsed: 62,
      error: "One page timed out",
    });
  });
});
