import { describe, expect, it } from "vitest";
import {
  demoCampaigns,
  demoIndicators,
  demoReports,
  demoRules,
  demoSummary,
  demoTechniques,
} from "./mockData";

const isDocumentationAddress = (value: string) =>
  value.startsWith("192.0.2.") ||
  value.startsWith("198.51.100.") ||
  value.startsWith("203.0.113.") ||
  value.toLowerCase().startsWith("2001:db8:");

describe("bundled synthetic corpus", () => {
  it("uses only documentation network identifiers and fictional private ASNs", () => {
    for (const indicator of demoIndicators) {
      expect(indicator.isDemo).toBe(true);
      if (indicator.type === "ip") {
        expect(isDocumentationAddress(indicator.value)).toBe(true);
      }
      if (indicator.type === "domain") {
        expect(indicator.value.endsWith(".test")).toBe(true);
      }
      if (indicator.type === "url") {
        expect(new URL(indicator.value).hostname.endsWith(".test")).toBe(true);
      }
      const asn = Number(indicator.asn.replace(/^AS/, ""));
      expect(asn).toBeGreaterThanOrEqual(64_500);
      expect(asn).toBeLessThanOrEqual(65_534);
      expect(indicator.asnOrg).toMatch(/^Example /);
    }
  });

  it("derives the summary from the same observation rows", () => {
    expect(demoSummary.totalObservations).toBe(demoIndicators.length);
    expect(demoSummary.demoIocs).toBe(demoIndicators.length);
    expect(demoSummary.liveIocs).toBe(0);
    expect(demoSummary.highConfidence).toBe(
      demoIndicators.filter((item) => item.confidence >= 70).length,
    );
    expect(demoSummary.affectedCountries).toBe(
      new Set(demoIndicators.map((item) => item.country)).size,
    );
    expect(demoSummary.activeCampaigns).toBe(demoCampaigns.length);
    expect(demoSummary.analysisScope).toBe("demo");
  });

  it("reconciles campaign and technique counts to member observations", () => {
    for (const campaign of demoCampaigns) {
      const members = demoIndicators.filter(
        (item) => item.campaignId === campaign.id,
      );
      expect(campaign.isDemo).toBe(true);
      expect(campaign.observationCount).toBe(members.length);
      expect(campaign.uniqueIndicatorCount).toBe(
        new Set(members.map((item) => `${item.type}:${item.value}`)).size,
      );
      const average =
        members.reduce((total, item) => total + item.confidence, 0) /
        members.length;
      expect(campaign.averageIocConfidence).toBeCloseTo(average, 1);
    }
    for (const technique of demoTechniques) {
      expect(technique.observations).toBe(
        demoIndicators.filter(
          (item) =>
            item.techniqueIds.includes(technique.id) &&
            Date.now() - new Date(item.lastSeen).getTime() <=
              7 * 86_400_000 + 60_000,
        ).length,
      );
      expect(technique.hasBaseline).toBe(false);
    }
  });

  it("keeps demo rule candidates scoped to one synthetic IOC", () => {
    for (const rule of demoRules) {
      expect(rule.isDemo).toBe(true);
      expect(rule.indicatorCount).toBe(1);
      expect(rule.requiresReview).toBe(true);
      expect(rule.severity).not.toBe("critical");
      for (const address of rule.content.match(
        /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
      ) ?? []) {
        expect(isDocumentationAddress(address)).toBe(true);
      }
    }
    expect(demoReports).toHaveLength(1);
    expect(demoReports[0]?.isDemo).toBe(true);
  });
});
