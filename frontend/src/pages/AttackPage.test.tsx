import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import AttackPage from "./AttackPage";

vi.mock("../hooks/useThreatData", () => ({
  useTechniques: () => ({
    data: {
      mode: "live",
      data: [
        {
          id: "T1105",
          tactic: "Command and Control",
          tactics: ["Command and Control"],
          name: "Ingress Tool Transfer",
          description: "Observed transfer behavior.",
          observations: 12,
          previousObservations: 0,
          hasBaseline: false,
          severity: "high",
          malwareFamilies: ["Example"],
        },
        {
          id: "T1001",
          tactic: "Command and Control",
          tactics: ["Command and Control"],
          name: "Data Obfuscation",
          description: "Catalog-only behavior.",
          observations: 0,
          previousObservations: 0,
          hasBaseline: false,
          severity: "low",
          malwareFamilies: [],
        },
        {
          id: "T1071",
          tactic: "Command and Control",
          tactics: ["Command and Control"],
          name: "Application Layer Protocol",
          description: "Observed protocol behavior.",
          observations: 4,
          previousObservations: 0,
          hasBaseline: false,
          severity: "medium",
          malwareFamilies: ["Example"],
        },
      ],
    },
    isLoading: false,
    isError: false,
  }),
}));

describe("AttackPage", () => {
  afterEach(() => vi.restoreAllMocks());

  it("defaults to observed evidence and keeps the full catalog available", () => {
    render(
      <MemoryRouter>
        <AttackPage />
      </MemoryRouter>,
    );

    expect(screen.getAllByText("Ingress Tool Transfer")).toHaveLength(2);
    expect(screen.queryByText("Data Obfuscation")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "2 observed" }));
    expect(screen.getByText("Data Obfuscation")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Full catalog/ }),
    ).toHaveAttribute("aria-pressed", "false");

    fireEvent.change(
      screen.getByRole("textbox", { name: "Search ATT&CK techniques" }),
      { target: { value: "no such technique" } },
    );
    expect(
      screen.getByText("No observed techniques match"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
    expect(screen.getByText("Data Obfuscation")).toBeInTheDocument();
  });

  it("does not count a zero-observation deep link as observed", () => {
    render(
      <MemoryRouter initialEntries={["/attack?technique=T1001"]}>
        <AttackPage />
      </MemoryRouter>,
    );

    expect(screen.getByRole("button", { name: "2 observed" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.getAllByText("Data Obfuscation").length).toBeGreaterThan(0);
  });
});
