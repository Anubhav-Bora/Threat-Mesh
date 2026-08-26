import { describe, expect, it } from "vitest";
import {
  confidenceBand,
  formatDelta,
  formatIsoUtc,
  formatUtcDateTime,
  rangeToDays,
} from "./format";

describe("threat presentation helpers", () => {
  it("uses explicit confidence thresholds", () => {
    expect(confidenceBand(70)).toBe("high");
    expect(confidenceBand(69)).toBe("medium");
    expect(confidenceBand(40)).toBe("medium");
    expect(confidenceBand(39)).toBe("low");
  });

  it("formats positive and negative change without hiding direction", () => {
    expect(formatDelta(12)).toBe("+12%");
    expect(formatDelta(-3)).toBe("-3%");
  });

  it("maps analyst time windows to days", () => {
    expect(rangeToDays("24h")).toBe(1);
    expect(rangeToDays("90d")).toBe(90);
    expect(rangeToDays("all")).toBe(Infinity);
  });

  it("formats evidence timestamps as actual UTC independent of browser locale", () => {
    expect(formatUtcDateTime("2026-08-01T00:00:00Z")).toBe(
      "Aug 1, 2026, 00:00 UTC",
    );
    expect(formatIsoUtc("2026-08-01T00:00:00+05:30")).toBe(
      "2026-07-31T18:30:00.000Z",
    );
  });
});
