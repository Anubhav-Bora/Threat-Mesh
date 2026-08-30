import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { createRef } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Indicator } from "../types";
import {
  ARCGIS_BASE_TILE_SERVICE,
  ARCGIS_RASTER_ATTRIBUTION,
  ARCGIS_REFERENCE_TILE_SERVICE,
  ArcGisRasterMap,
} from "./ArcGisRasterMap";
import type { ArcGisRasterMapHandle } from "./ArcGisRasterMap";

const indicator: Indicator = {
  id: "indicator-1",
  value: "203.0.113.42",
  type: "ip",
  malwareFamily: "ExampleLoader",
  firstSeen: "2026-08-27T00:00:00Z",
  lastSeen: "2026-08-28T00:00:00Z",
  sourceFeed: "ThreatFox",
  confidence: 92,
  country: "India",
  countryCode: "IN",
  city: "New Delhi",
  asn: "AS64500",
  asnOrg: "Example Network",
  latitude: 26,
  longitude: 18,
  locationPrecisionKm: 25,
  techniqueIds: ["T1059.001"],
  status: "active",
  corroboratingFeeds: 2,
  tags: ["test"],
};

const tileSources = (container: HTMLElement) =>
  Array.from(container.querySelectorAll<HTMLImageElement>("img")).map(
    (image) => image.src,
  );

const tileCoverage = (container: HTMLElement) => {
  const tiles = Array.from(
    container.querySelectorAll<HTMLElement>(".arcgis-raster-map__tile"),
  );
  const left = tiles.map((tile) => Number.parseFloat(tile.style.left));
  const top = tiles.map((tile) => Number.parseFloat(tile.style.top));
  return {
    left: Math.min(...left),
    right: Math.max(...left) + 256,
    top: Math.min(...top),
    bottom: Math.max(...top) + 256,
  };
};

let viewportWidth: number;
let viewportHeight: number;
let resizeObserverCallbacks: ResizeObserverCallback[];

describe("ArcGisRasterMap", () => {
  beforeEach(() => {
    viewportWidth = 1000;
    viewportHeight = 500;
    resizeObserverCallbacks = [];
    vi.stubGlobal(
      "ResizeObserver",
      class {
        constructor(callback: ResizeObserverCallback) {
          resizeObserverCallbacks.push(callback);
        }

        observe = vi.fn();
        disconnect = vi.fn();
        unobserve = vi.fn();
      },
    );
    vi.spyOn(HTMLElement.prototype, "clientWidth", "get").mockImplementation(
      function (this: HTMLElement) {
        return this.classList.contains("arcgis-raster-map") ? viewportWidth : 0;
      },
    );
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockImplementation(
      function (this: HTMLElement) {
        return this.classList.contains("arcgis-raster-map")
          ? viewportHeight
          : 0;
      },
    );
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("renders genuine ArcGIS base and reference tiles without fetching them", () => {
    const { container } = render(
      <ArcGisRasterMap
        indicators={[indicator]}
        mode="clusters"
        onSelect={vi.fn()}
      />,
    );

    const map = screen.getByRole("region", {
      name: "Interactive ArcGIS raster map of approximate threat infrastructure locations",
    });
    expect(map).toHaveAttribute(
      "data-arcgis-base-service",
      ARCGIS_BASE_TILE_SERVICE,
    );

    const sources = tileSources(container);
    expect(
      container.querySelector(
        `img[src="${ARCGIS_BASE_TILE_SERVICE}/tile/2/1/2"]`,
      ),
    ).toBeInTheDocument();
    expect(
      container.querySelector(
        `img[src="${ARCGIS_REFERENCE_TILE_SERVICE}/tile/2/1/2"]`,
      ),
    ).toBeInTheDocument();
    expect(
      sources.some((source) =>
        source.startsWith(`${ARCGIS_BASE_TILE_SERVICE}/tile/2/`),
      ),
    ).toBe(true);
    expect(
      sources.some((source) =>
        source.startsWith(`${ARCGIS_REFERENCE_TILE_SERVICE}/tile/2/`),
      ),
    ).toBe(true);
    expect(ARCGIS_RASTER_ATTRIBUTION).toMatch(/Esri/);
    expect(container.querySelector(".arcgis-raster-map__markers")).toHaveClass(
      "mode-clusters",
    );
  });

  it("selects an indicator through its keyboard-accessible marker", () => {
    const onSelect = vi.fn();
    render(
      <ArcGisRasterMap
        indicators={[indicator]}
        mode="clusters"
        onSelect={onSelect}
      />,
    );

    const marker = screen.getByRole("button", {
      name: "Open 203.0.113.42, 92% confidence",
    });
    marker.focus();
    expect(marker).toHaveFocus();
    fireEvent.click(marker);

    expect(onSelect).toHaveBeenCalledOnce();
    expect(onSelect).toHaveBeenCalledWith(indicator);
  });

  it("changes ArcGIS tile levels with the mouse wheel and can restore the default view", () => {
    const ref = createRef<ArcGisRasterMapHandle>();
    const { container } = render(
      <ArcGisRasterMap
        ref={ref}
        indicators={[indicator]}
        mode="clusters"
        onSelect={vi.fn()}
      />,
    );

    expect(
      tileSources(container).every((source) => source.includes("/tile/2/")),
    ).toBe(true);

    fireEvent.wheel(
      screen.getByRole("region", {
        name: "Interactive ArcGIS raster map of approximate threat infrastructure locations",
      }),
      { deltaY: -100 },
    );
    expect(
      tileSources(container).every((source) => source.includes("/tile/3/")),
    ).toBe(true);

    act(() => ref.current?.recenter());
    expect(
      tileSources(container).every((source) => source.includes("/tile/2/")),
    ).toBe(true);
  });

  it("raises and enforces the raster zoom floor for a wide fullscreen viewport", async () => {
    viewportWidth = 2635;
    viewportHeight = 1484;
    const ref = createRef<ArcGisRasterMapHandle>();
    const { container } = render(
      <ArcGisRasterMap
        ref={ref}
        indicators={[indicator]}
        mode="clusters"
        onSelect={vi.fn()}
      />,
    );

    await waitFor(() =>
      expect(
        tileSources(container).every((source) => source.includes("/tile/4/")),
      ).toBe(true),
    );
    expect(tileCoverage(container)).toMatchObject({
      left: expect.any(Number),
      right: expect.any(Number),
      top: expect.any(Number),
      bottom: expect.any(Number),
    });
    const coverage = tileCoverage(container);
    expect(coverage.left).toBeLessThanOrEqual(0);
    expect(coverage.right).toBeGreaterThanOrEqual(viewportWidth);
    expect(coverage.top).toBeLessThanOrEqual(0);
    expect(coverage.bottom).toBeGreaterThanOrEqual(viewportHeight);

    act(() => ref.current?.adjustZoom(-1));
    expect(
      tileSources(container).every((source) => source.includes("/tile/4/")),
    ).toBe(true);
    act(() => ref.current?.recenter());
    expect(
      tileSources(container).every((source) => source.includes("/tile/4/")),
    ).toBe(true);
  });

  it("clamps the projected center so a portrait viewport exposes no polar gap", async () => {
    viewportWidth = 390;
    viewportHeight = 844;
    const { container } = render(
      <ArcGisRasterMap
        indicators={[indicator]}
        mode="clusters"
        onSelect={vi.fn()}
      />,
    );

    await waitFor(() => {
      const coverage = tileCoverage(container);
      expect(coverage.top).toBeLessThanOrEqual(0);
      expect(coverage.bottom).toBeGreaterThanOrEqual(viewportHeight);
    });
    expect(
      tileSources(container).every((source) => source.includes("/tile/2/")),
    ).toBe(true);

    viewportWidth = 2635;
    viewportHeight = 1484;
    act(() => {
      resizeObserverCallbacks[0]?.([], {} as ResizeObserver);
    });
    await waitFor(() =>
      expect(
        tileSources(container).every((source) => source.includes("/tile/4/")),
      ).toBe(true),
    );
  });
});
