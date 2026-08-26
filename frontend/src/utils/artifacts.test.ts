import { describe, expect, it } from "vitest";
import { markSyntheticArtifact } from "./artifacts";

describe("download artifact provenance", () => {
  it("prepends format-safe synthetic warnings", () => {
    expect(markSyntheticArtifact("title: Demo", "sigma", true)).toMatch(
      /^# SYNTHETIC DEMO/,
    );
    expect(markSyntheticArtifact("alert ip any any", "suricata", true)).toMatch(
      /^\/\* SYNTHETIC DEMO/,
    );
    expect(markSyntheticArtifact("# Report", "markdown", true)).toMatch(
      /^> \*\*SYNTHETIC DEMO/,
    );
  });

  it("does not alter live-feed artifacts", () => {
    expect(markSyntheticArtifact("title: Live", "sigma", false)).toBe(
      "title: Live",
    );
  });
});
