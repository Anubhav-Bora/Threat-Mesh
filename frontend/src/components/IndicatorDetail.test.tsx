import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Indicator, IndicatorLineage } from "../types";
import { IndicatorDetail } from "./IndicatorDetail";

const useIndicatorLineageMock = vi.hoisted(() => vi.fn());

vi.mock("../hooks/useThreatData", () => ({
  useIndicatorLineage: (id?: string) => useIndicatorLineageMock(id),
}));

const indicator: Indicator = {
  id: "41",
  value: "198.51.100.3",
  type: "ip",
  malwareFamily: "Example",
  firstSeen: "2026-08-01T00:00:00Z",
  lastSeen: "2026-08-02T00:00:00Z",
  sourceFeed: "ThreatFox",
  confidence: 87,
  isDemo: false,
  country: "Germany",
  countryCode: "DE",
  city: "Frankfurt",
  asn: "AS64500",
  asnOrg: "Example Network",
  latitude: 50.11,
  longitude: 8.68,
  locationPrecisionKm: 25,
  techniqueIds: ["T1071.001"],
  campaignId: "7",
  status: "active",
  corroboratingFeeds: 2,
  tags: ["c2"],
};

const lineage: IndicatorLineage = {
  indicatorId: "41",
  recordId: "ioc:41",
  identity: {
    value: indicator.value,
    type: "ip",
    port: 443,
    isDemo: false,
  },
  provenance: {
    selectedSource: "ThreatFox",
    observations: [
      {
        recordId: "ioc:41",
        sourceFeed: "ThreatFox",
        firstSeen: indicator.firstSeen,
        lastSeen: indicator.lastSeen,
        sourceConfidenceHint: 90,
        isSelected: true,
      },
    ],
    rawPayload: {
      retained: true,
      sha256: "4a44dc15364204a80fe80e9039455cc1608281820fe2b24e39b8b12d7",
      fieldNames: ["ioc", "malware"],
    },
  },
  confidence: {
    status: "available",
    total: 87,
    formulaVersion: "v1",
    calculatedAt: "2026-08-02T01:00:00Z",
    components: [
      {
        key: "source",
        label: "Source reputation",
        score: 36,
        maxScore: 40,
        evidence: "ThreatFox source prior",
      },
      {
        key: "corroboration",
        label: "Cross-feed corroboration",
        score: 10,
        maxScore: 20,
        evidence: "Observed by two distinct feeds",
      },
    ],
  },
  enrichment: {
    status: "available",
    provider: "ip-api",
    method: "cached passive lookup",
    country: "Germany",
    countryCode: "DE",
    city: "Frankfurt",
    asn: "AS64500",
    asnOrg: "Example Network",
    approximate: true,
  },
  attackMappings: [
    {
      recordId: "technique:T1071.001",
      techniqueId: "T1071.001",
      name: "Web Protocols",
      tactic: "Command and Control",
      method: "curated family mapping",
      basis: "Example family",
      inference: true,
    },
  ],
  campaignMembership: {
    recordId: "campaign:7",
    label: "Cluster 7",
    snapshot: "current",
    reasons: ["shared family"],
  },
  derivedArtifacts: {
    rules: [
      {
        recordId: "rule:9",
        ruleType: "suricata",
        requiresReview: true,
        generatedAt: "2026-08-02T02:00:00Z",
      },
    ],
    reportMentions: [
      {
        recordId: "report:12",
        title: "Weekly CTI report",
        periodStart: "2026-07-27T00:00:00Z",
        periodEnd: "2026-08-03T00:00:00Z",
      },
    ],
  },
  limitations: ["IP geolocation is approximate."],
};

describe("IndicatorDetail evidence lineage", () => {
  afterEach(cleanup);

  beforeEach(() => {
    useIndicatorLineageMock.mockReset();
    useIndicatorLineageMock.mockReturnValue({
      data: { data: lineage, mode: "live" },
      isLoading: false,
      isError: false,
    });
  });

  it("loads and renders inspectable confidence evidence and derivation stages", () => {
    render(<IndicatorDetail indicator={indicator} variant="panel" />);

    expect(useIndicatorLineageMock).toHaveBeenCalledWith("41");
    expect(
      screen.getByRole("heading", { name: "Why this score" }),
    ).toBeInTheDocument();
    expect(screen.getByText("87 / 100")).toBeInTheDocument();
    expect(
      screen.getByRole("progressbar", {
        name: "Source reputation contribution",
      }),
    ).toHaveAttribute("aria-valuenow", "36");
    expect(
      screen.getByRole("heading", { name: "Evidence path" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Source observation")).toBeInTheDocument();
    expect(screen.getByText("Canonical identity")).toBeInTheDocument();
    expect(screen.getByText("Analytic derivation")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Generated detections require analyst review before deployment",
      ),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByText("Inspect evidence records"));
    expect(screen.getByText(/source hint 90%/i)).toBeInTheDocument();
    expect(screen.getByText(/inferred context/i)).toBeInTheDocument();
    expect(screen.getByText(/shared family/i)).toBeInTheDocument();
    expect(screen.getByText("rule:9")).toBeInTheDocument();
    expect(screen.getByText("report:12")).toBeInTheDocument();
    expect(screen.queryByText(/raw_json/i)).not.toBeInTheDocument();
  });

  it("keeps the drawer usable while lineage is loading", () => {
    useIndicatorLineageMock.mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
    });

    render(<IndicatorDetail indicator={indicator} />);

    expect(screen.getByText(indicator.value)).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading evidence lineage",
    );
  });
});
