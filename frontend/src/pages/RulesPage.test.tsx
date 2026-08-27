import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import RulesPage from "./RulesPage";

const useRulesMock = vi.hoisted(() => vi.fn());

vi.mock("../hooks/useThreatData", () => ({
  useRules: useRulesMock,
}));

describe("RulesPage", () => {
  beforeEach(() => useRulesMock.mockReset());

  it("presents an empty live rules response as a plain operator command", () => {
    useRulesMock.mockReturnValue({
      data: { data: [], mode: "live" },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    });

    const { container } = render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>,
    );

    expect(
      screen.getByRole("heading", {
        name: "No detection candidates generated",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("PowerShell command")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy command" }),
    ).toBeInTheDocument();
    expect(container).not.toHaveTextContent("authenticated operator request");
    expect(container).not.toHaveTextContent("**PowerShell");
    expect(container).not.toHaveTextContent("&#x20;");
  });

  it("renders generated rule content without transforming it", () => {
    const content = [
      "title: Preserve exact rule content",
      "description: 'Literal **markers** and &#x20; stay in the artifact'",
      "detection:",
      "  condition: selection",
    ].join("\n");
    useRulesMock.mockReturnValue({
      data: {
        mode: "live",
        data: [
          {
            id: "rule-1",
            name: "Exact-content rule",
            type: "sigma",
            severity: "high",
            requiresReview: true,
            isDemo: false,
            malwareFamily: "Example",
            updatedAt: "2026-08-27T00:00:00Z",
            indicatorCount: 1,
            corroboratingSources: ["threatfox"],
            falsePositiveRisk: null,
            content,
            tags: ["T1059.001"],
          },
        ],
      },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    });

    const { container } = render(
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>,
    );

    expect(container.querySelector(".code-window pre code")?.textContent).toBe(
      content,
    );
    fireEvent.change(
      screen.getByRole("textbox", { name: "Search detection rules" }),
      {
        target: { value: "no match" },
      },
    );
    expect(screen.queryByText("Exact-content rule")).not.toBeInTheDocument();
  });
});
