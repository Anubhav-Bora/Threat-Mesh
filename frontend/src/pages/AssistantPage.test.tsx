import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import AssistantPage from "./AssistantPage";

const { askMock } = vi.hoisted(() => ({
  askMock: vi.fn(),
}));

vi.mock("../api/client", () => ({
  threatApi: {
    ask: askMock,
  },
}));

vi.mock("../hooks/useThreatData", () => ({
  useApiMode: () => "live",
  useSummary: () => ({
    data: {
      data: {
        corpusMode: "live",
        analysisScope: "live",
      },
    },
  }),
}));

const originalScrollIntoView = Object.getOwnPropertyDescriptor(
  Element.prototype,
  "scrollIntoView",
);

describe("AssistantPage", () => {
  beforeEach(() => {
    askMock.mockResolvedValue({
      data: {
        answer: "One grounded observation was retrieved.",
        citations: [],
        retrievedCount: 1,
        queryTimeMs: 12,
        includedProvenance: "live",
      },
      mode: "live",
    });
    Object.defineProperty(Element.prototype, "scrollIntoView", {
      configurable: true,
      writable: true,
      value: vi.fn(() => Promise.resolve()),
    });
  });

  afterEach(() => {
    askMock.mockReset();
    if (originalScrollIntoView) {
      Object.defineProperty(
        Element.prototype,
        "scrollIntoView",
        originalScrollIntoView,
      );
    } else {
      delete (Element.prototype as Partial<Element>).scrollIntoView;
    }
  });

  it("stays mounted after Enter when scrollIntoView returns a Promise", async () => {
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });

    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/assistant"]}>
          <AssistantPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    const input = screen.getByRole("textbox", {
      name: "Question for ThreatMesh",
    });
    fireEvent.change(input, {
      target: { value: "Summarize recent threats" },
    });
    fireEvent.keyDown(input, { key: "Enter", code: "Enter" });

    await waitFor(() => expect(askMock).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByText("One grounded observation was retrieved."),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("textbox", { name: "Question for ThreatMesh" }),
    ).toBeInTheDocument();
  });
});
