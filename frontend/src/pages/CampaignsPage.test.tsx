import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Campaign } from "../types";
import CampaignsPage from "./CampaignsPage";

const listedCampaign = vi.hoisted(
  () =>
    ({
      id: "listed",
      label: "Listed campaign",
      actor: "Unattributed",
      isDemo: false,
      firstSeen: "2026-08-20T00:00:00Z",
      lastSeen: "2026-08-27T00:00:00Z",
      uniqueIndicatorCount: 2,
      observationCount: 3,
      averageIocConfidence: 70,
      volumeTier: "small",
      malwareFamilies: ["Example"],
      countries: ["US"],
      techniqueIds: ["T1105"],
      observedAsns: ["AS64500"],
      observedSources: ["Example feed"],
      relationshipEvidence: {
        repeatedIndicators: [],
        malwareFamilies: [],
        asns: [],
      },
      summary: "Listed campaign summary.",
    }) satisfies Campaign,
);

const exactCampaign = vi.hoisted(
  () =>
    ({
      ...listedCampaign,
      id: "outside-list",
      label: "Exact cited campaign",
      summary: "Loaded through the direct campaign endpoint.",
    }) satisfies Campaign,
);

const useCampaignMock = vi.hoisted(() => vi.fn());

vi.mock("../hooks/useThreatData", () => ({
  useCampaigns: () => ({
    data: { mode: "live", data: [listedCampaign] },
    isLoading: false,
    isError: false,
  }),
  useCampaign: (id?: string) => useCampaignMock(id),
}));

vi.mock("../components/CampaignGraph", () => ({
  CampaignGraph: () => <div>Evidence graph</div>,
}));

describe("CampaignsPage evidence pivots", () => {
  beforeEach(() => {
    useCampaignMock.mockReset();
    useCampaignMock.mockImplementation((id?: string) => ({
      data: {
        mode: "live",
        data: id === exactCampaign.id ? exactCampaign : null,
      },
      isLoading: false,
      isError: false,
    }));
  });

  it("fetches a cited campaign even when it is outside the loaded list", () => {
    render(
      <MemoryRouter initialEntries={["/campaigns?campaign=outside-list"]}>
        <CampaignsPage />
      </MemoryRouter>,
    );

    expect(useCampaignMock).toHaveBeenCalledWith("outside-list");
    expect(
      screen.getByRole("heading", { name: "Exact cited campaign" }),
    ).toBeInTheDocument();
  });
});
