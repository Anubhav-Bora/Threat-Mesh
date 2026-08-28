import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiRequestError, threatApi } from "../api/client";
import type { ReportSchedule, ThreatReport } from "../types";
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
const scheduleRefetchMock = vi.hoisted(() => vi.fn());

const schedule: ReportSchedule = {
  cadence: "weekly",
  schedulerRunning: true,
  providerConfigured: true,
  adminAuthRequired: true,
  nextRunAt: "2026-08-31T06:00:00Z",
  timezone: "UTC",
  hourUtc: 6,
  weeklyDay: "mon",
  monthlyDay: 1,
  updatedAt: "2026-08-28T09:00:00Z",
};

vi.mock("../hooks/useThreatData", () => ({
  useReports: () => ({
    data: { mode: "live", data: [report] },
    isLoading: false,
    isError: false,
  }),
  useReport: (id?: string) => useReportMock(id),
  useReportSchedule: () => ({
    data: { mode: "live", data: schedule },
    isLoading: false,
    isError: false,
    refetch: scheduleRefetchMock,
  }),
}));

describe("ReportsPage automatic reporting", () => {
  afterEach(() => cleanup());

  beforeEach(() => {
    vi.restoreAllMocks();
    schedule.adminAuthRequired = true;
    schedule.providerConfigured = true;
    scheduleRefetchMock.mockReset();
    scheduleRefetchMock.mockResolvedValue(undefined);
    useReportMock.mockReset();
    useReportMock.mockImplementation((id?: string) => ({
      data: {
        mode: "live",
        data: id === directReport.id ? directReport : report,
      },
      isLoading: false,
      isError: false,
    }));
    vi.spyOn(threatApi, "updateReportSchedule").mockResolvedValue({
      mode: "live",
      data: {
        ...schedule,
        cadence: "monthly",
        nextRunAt: "2026-09-01T06:00:00Z",
      },
    });
  });

  it("shows the automatic schedule without any manual generation path", () => {
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    expect(screen.getByText("Generation schedule")).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
    expect(screen.getByText("AI provider")).toBeInTheDocument();
    expect(screen.getByText("Ready")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Weekly Monday/i }),
    ).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Next draft")).toBeInTheDocument();
    expect(screen.queryByText(/Generate report/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/PowerShell command/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/ADMIN_API_KEY/i)).not.toBeInTheDocument();
  });

  it("authorizes a cadence change once and sends the key only in the request", async () => {
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByRole("button", { name: /Monthly First day/i }));
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));

    const dialog = screen.getByRole("dialog", {
      name: "Authorize schedule change",
    });
    expect(
      within(dialog).getByRole("heading", {
        name: "Authorize schedule change",
      }),
    ).toBeInTheDocument();
    fireEvent.change(within(dialog).getByLabelText("Administrator key"), {
      target: { value: "one-time-key" },
    });
    fireEvent.click(
      within(dialog).getByRole("button", { name: "Apply schedule" }),
    );

    await waitFor(() =>
      expect(threatApi.updateReportSchedule).toHaveBeenCalledWith(
        "monthly",
        "one-time-key",
      ),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: "Authorize schedule change" }),
      ).not.toBeInTheDocument(),
    );
    expect(scheduleRefetchMock).toHaveBeenCalled();
    expect(
      screen.getByText(/Monthly automatic reporting is now active/i),
    ).toBeInTheDocument();
  });

  it("applies a development schedule directly when admin auth is not required", async () => {
    schedule.adminAuthRequired = false;
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByRole("button", { name: /Monthly First day/i }));
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));

    await waitFor(() =>
      expect(threatApi.updateReportSchedule).toHaveBeenCalledWith(
        "monthly",
        "",
      ),
    );
    expect(
      screen.queryByRole("dialog", { name: "Authorize schedule change" }),
    ).not.toBeInTheDocument();
  });

  it("clears a rejected administrator key after the failed attempt", async () => {
    vi.mocked(threatApi.updateReportSchedule).mockRejectedValueOnce(
      new ApiRequestError(401),
    );
    render(
      <MemoryRouter>
        <ReportsPage />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByRole("button", { name: /Monthly First day/i }));
    fireEvent.click(screen.getByRole("button", { name: "Save schedule" }));
    const keyInput = screen.getByLabelText("Administrator key");
    fireEvent.change(keyInput, { target: { value: "wrong-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply schedule" }));

    expect(
      await screen.findByText(/administrator key was not accepted/i),
    ).toBeInTheDocument();
    expect(keyInput).toHaveValue("");
    expect(
      screen.queryByText(/PowerShell|ADMIN_API_KEY/i),
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
