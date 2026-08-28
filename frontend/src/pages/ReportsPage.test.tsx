import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ThreatReport } from "../types";
import ReportsPage from "./ReportsPage";

const report = vi.hoisted(
  () =>
    ({
      id: "report-1",
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

vi.mock("../hooks/useThreatData", () => ({
  useReports: () => ({
    data: { mode: "live", data: [report] },
    isLoading: false,
    isError: false,
  }),
  useReport: (id?: string) => useReportMock(id),
}));

describe("ReportsPage report generation", () => {
  beforeEach(() => {
    useReportMock.mockReset();
    useReportMock.mockImplementation((id?: string) => ({
      data: {
        mode: "live",
        data: id === directReport.id ? directReport : report,
      },
      isLoading: false,
      isError: false,
    }));
  });

  it("opens a clearly labelled secure generation dialog", () => {
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(screen.queryByText("Operator guide")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Generate report" }));

    const dialog = screen.getByRole("dialog", {
      name: "Generate a report securely",
    });
    expect(
      within(dialog).getByRole("heading", {
        name: "Generate a report securely",
      }),
    ).toBeInTheDocument();
    expect(within(dialog).getByText("PowerShell command")).toBeInTheDocument();
    expect(screen.queryByText("Operator guide")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/authenticated operator request/i),
    ).not.toBeInTheDocument();
  });

  it("fetches a cited report even when it is outside the loaded index", () => {
    render(
      <MemoryRouter initialEntries={["/reports?report=archived-report"]}>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(useReportMock).toHaveBeenCalledWith("archived-report");
    expect(
      screen.getByRole("heading", { name: "Archived exact report" }),
    ).toBeInTheDocument();
  });
});
