import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { createRef } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
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

describe("ArcGisRasterMap", () => {
  afterEach(cleanup);

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
});
