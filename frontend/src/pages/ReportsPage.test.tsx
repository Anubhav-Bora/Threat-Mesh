import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { threatApi } from "../api/client";
import type { ThreatReport } from "../types";
import ReportsPage from "./ReportsPage";

const report = vi.hoisted(
  () =>
    ({
      id: "report-1",
      cadence: "weekly",
      title: "Live threat intelligence report",
      periodStart: "2026-08-20T00:00:00Z",
      periodEnd: "2026-08-27T00:00:00Z",
      createdAt: "2026-08-27T12:00:00Z",
      status: "generated",
      isDemo: false,
      executiveSummary: "Grounded summary.",
      content: "# Grounded report",
      keyFindings: [],
      recommendations: [],
      topFamilies: [],
      relatedCampaignIds: [],
      generatedBy: "gemini",
    }) satisfies ThreatReport,
);

const directReport = vi.hoisted(
  () =>
    ({
      ...report,
      id: "archived-report",
      title: "Archived exact report",
    }) satisfies ThreatReport,
);

const useReportMock = vi.hoisted(() => vi.fn());
const reportsRefetchMock = vi.hoisted(() => vi.fn());

vi.mock("../hooks/useThreatData", () => ({
  useReports: () => ({
    data: { mode: "live", data: [report] },
    isLoading: false,
    isError: false,
    refetch: reportsRefetchMock,
  }),
  useReport: (id?: string) => useReportMock(id),
}));

describe("ReportsPage manual reporting", () => {
  afterEach(() => cleanup());

  beforeEach(() => {
    vi.restoreAllMocks();
    reportsRefetchMock.mockReset();
    reportsRefetchMock.mockResolvedValue(undefined);
    useReportMock.mockReset();
    useReportMock.mockImplementation((id?: string) => ({
      data: {
        mode: "live",
        data: id === directReport.id ? directReport : report,
      },
      isLoading: false,
      isError: false,
    }));
    vi.spyOn(threatApi, "generateWeeklyReport").mockResolvedValue({
      mode: "live",
      data: {
        ...report,
        id: "generated-report-id",
        title: "Generated weekly report",
      },
    });
  });

  it("shows an on-demand weekly report action without scheduler controls", () => {
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(screen.getByText("Weekly report")).toBeInTheDocument();
    expect(screen.getByText("Manual")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Generate weekly report" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Generation schedule")).not.toBeInTheDocument();
    expect(screen.queryByText("Save schedule")).not.toBeInTheDocument();
  });

  it("generates a weekly report directly without an administrator key", async () => {
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Generate weekly report" }),
    );

    await waitFor(() =>
      expect(threatApi.generateWeeklyReport).toHaveBeenCalledWith(),
    );
    await waitFor(() => expect(reportsRefetchMock).toHaveBeenCalled());
    expect(
      screen.queryByLabelText("Administrator key"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("Generated Generated weekly report."),
    ).toBeInTheDocument();
  });

  it("shows report generation errors without requesting a key", async () => {
    vi.mocked(threatApi.generateWeeklyReport).mockRejectedValueOnce(
      new Error("Report generation is temporarily unavailable"),
    );
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Generate weekly report" }),
    );

    await waitFor(() =>
      expect(
        screen.getByText("Report generation is temporarily unavailable"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByLabelText("Administrator key"),
    ).not.toBeInTheDocument();
  });

  it("fetches a cited report even when it is outside the loaded index", () => {
    render(
      <MemoryRouter initialEntries={["/reports?report=archived-report"]}>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(useReportMock).toHaveBeenCalledWith("archived-report");
    expect(screen.getByText("Archived exact report")).toBeInTheDocument();
  });
});
