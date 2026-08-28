import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
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

function LocationProbe() {
  const location = useLocation();
  return (
    <output data-testid="location">{`${location.pathname}${location.search}`}</output>
  );
}

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
    cleanup();
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

  it("renders only server citations and opens the exact evidence record", async () => {
    askMock.mockResolvedValueOnce({
      data: {
        answer: "One observation matched [ioc:41].",
        citations: [
          {
            id: "41",
            recordId: "ioc:41",
            label: "198.51.100.41",
            kind: "indicator",
          },
        ],
        retrievedCount: 4,
        queryTimeMs: 18,
        includedProvenance: "live",
        citationIntegrity: {
          status: "verified",
          validatedCount: 1,
          rejectedCount: 0,
        },
      },
      mode: "live",
    });
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
          <LocationProbe />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    fireEvent.change(
      screen.getByRole("textbox", { name: "Question for ThreatMesh" }),
      { target: { value: "Show the evidence" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Send question" }));

    const inlineCitation = await screen.findByRole("button", {
      name: "Open evidence 198.51.100.41",
    });
    expect(screen.queryByText("[ioc:41]")).not.toBeInTheDocument();
    expect(screen.getByText("1 citation ID verified")).toBeInTheDocument();
    fireEvent.click(inlineCitation);
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent(
        "/indicators?ioc=41",
      ),
    );
  });

  it("makes rejected citation IDs visible without rendering evidence links", async () => {
    askMock.mockResolvedValueOnce({
      data: {
        answer: "The provider returned unsupported wording.",
        citations: [],
        retrievedCount: 4,
        queryTimeMs: 18,
        includedProvenance: "live",
        citationIntegrity: {
          status: "absent",
          validatedCount: 0,
          rejectedCount: 2,
        },
      },
      mode: "live",
    });
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter>
          <AssistantPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    fireEvent.change(
      screen.getByRole("textbox", { name: "Question for ThreatMesh" }),
      { target: { value: "Show unsupported citations" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Send question" }));

    expect(await screen.findByText("0 valid · 2 rejected")).toBeInTheDocument();
    expect(
      screen.queryByText("Server-validated evidence"),
    ).not.toBeInTheDocument();
  });
});
