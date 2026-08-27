import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
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

vi.mock("../hooks/useThreatData", () => ({
  useReports: () => ({
    data: { mode: "live", data: [report] },
    isLoading: false,
    isError: false,
  }),
  useReport: () => ({
    data: { mode: "live", data: report },
    isLoading: false,
    isError: false,
  }),
}));

describe("ReportsPage report generation", () => {
  it("opens a clearly labelled secure generation dialog", () => {
    render(<ReportsPage />);

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
});
