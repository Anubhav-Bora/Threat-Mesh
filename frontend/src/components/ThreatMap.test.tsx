import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Indicator, MapFilters } from "../types";
import { ARCGIS_RASTER_ATTRIBUTION } from "./ArcGisRasterMap";
import { ThreatMap } from "./ThreatMap";

interface MockGraphicRecord {
  attributes?: Record<string, unknown>;
  geometry?: unknown;
  symbol?: unknown;
}

interface MockEdits {
  deleteFeatures?: MockGraphicRecord[];
  addFeatures?: MockGraphicRecord[];
}

interface MockFeatureLayerHarness {
  records: MockGraphicRecord[];
  load: ReturnType<typeof vi.fn>;
  queryObjectIds: ReturnType<typeof vi.fn>;
  applyEdits: ReturnType<typeof vi.fn>;
  featureReduction?: { clusterRadius?: string } | null;
}

interface MockMapViewHarness {
  constraints: {
    minZoom: number;
    maxZoom: number;
    rotationEnabled: boolean;
    snapToZoom: boolean;
  };
  goTo: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  zoom: number;
}

interface MockMapViewOptions {
  spatialReference: { wkid: number };
  center: [number, number];
  zoom: number;
  constraints: {
    geometry: {
      type: string;
      xmin: number;
      ymin: number;
      xmax: number;
      ymax: number;
      spatialReference: { wkid: number };
    };
    minZoom: number;
    maxZoom: number;
    rotationEnabled: boolean;
    snapToZoom: boolean;
  };
  background: { color: number[] };
}

interface MockArcGisState {
  shouldThrowMapView: boolean;
  mapViewConstructed: ReturnType<typeof vi.fn>;
  mapViews: MockMapViewHarness[];
  featureLayers: MockFeatureLayerHarness[];
  editGates: Promise<void>[];
  featureReductionClusterModuleLoaded: boolean;
}

const arcgis = vi.hoisted((): MockArcGisState => ({
  shouldThrowMapView: false,
  mapViewConstructed: vi.fn(),
  mapViews: [],
  featureLayers: [],
  editGates: [],
  featureReductionClusterModuleLoaded: false,
}));

vi.mock("@arcgis/core/config.js", () => ({ default: {} }));
vi.mock("@arcgis/core/Map.js", () => ({
  default: class {
    addMany = vi.fn();

    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/Basemap.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/layers/TileLayer.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/layers/FeatureLayer.js", () => ({
  default: class implements MockFeatureLayerHarness {
    records: MockGraphicRecord[];
    source: { toArray: () => MockGraphicRecord[] };
    featureReduction?: { clusterRadius?: string } | null;
    load = vi.fn(async () => this);
    queryObjectIds = vi.fn(async () =>
      this.records
        .map((graphic) => graphic.attributes?.object_id)
        .filter(
          (objectId): objectId is number | string =>
            typeof objectId === "number" || typeof objectId === "string",
        ),
    );
    applyEdits = vi.fn(async (edits: MockEdits) => {
      const gate = arcgis.editGates.shift();
      if (gate) await gate;

      const deletedObjectIds = new Set(
        (edits.deleteFeatures ?? []).map(
          (graphic) => graphic.attributes?.object_id,
        ),
      );
      this.records = this.records.filter(
        (graphic) => !deletedObjectIds.has(graphic.attributes?.object_id),
      );
      this.records.push(...(edits.addFeatures ?? []));
      return {
        addFeatureResults: (edits.addFeatures ?? []).map(() => ({})),
        deleteFeatureResults: (edits.deleteFeatures ?? []).map(() => ({})),
      };
    });

    constructor(
      options: Record<string, unknown> & { source?: MockGraphicRecord[] },
    ) {
      Object.assign(this, options);
      this.records = [...(options.source ?? [])];
      this.source = { toArray: () => [...this.records] };
      arcgis.featureLayers.push(this);
    }
  },
}));
vi.mock("@arcgis/core/layers/GraphicsLayer.js", () => ({
  default: class {
    graphics: {
      records: MockGraphicRecord[];
      removeAll: () => void;
      addMany: (graphics: MockGraphicRecord[]) => void;
    };

    constructor(
      options: Record<string, unknown> & { graphics?: MockGraphicRecord[] },
    ) {
      Object.assign(this, options);
      const records = [...(options.graphics ?? [])];
      this.graphics = {
        records,
        removeAll: () => records.splice(0, records.length),
        addMany: (graphics) => records.push(...graphics),
      };
    }
  },
}));
vi.mock("@arcgis/core/Graphic.js", () => ({
  default: class {
    constructor(options: MockGraphicRecord) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/geometry/Point.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/geometry/Circle.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/renderers/SimpleRenderer.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/renderers/UniqueValueRenderer.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/renderers/HeatmapRenderer.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/symbols/SimpleMarkerSymbol.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/symbols/SimpleFillSymbol.js", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      Object.assign(this, options);
    }
  },
}));
vi.mock("@arcgis/core/layers/support/FeatureReductionCluster.js", () => ({
  default: (() => {
    arcgis.featureReductionClusterModuleLoaded = true;
    return class {
      constructor(options: Record<string, unknown>) {
        Object.assign(this, options);
      }
    };
  })(),
}));
vi.mock("@arcgis/core/core/reactiveUtils.js", () => ({
  watch: vi.fn(() => ({ remove: vi.fn() })),
  whenOnce: vi.fn(() => Promise.resolve()),
}));
vi.mock("@arcgis/core/views/MapView.js", () => ({
  default: class {
    zoom = 2;
    constraints = {
      minZoom: 1,
      maxZoom: 14,
      rotationEnabled: false,
      snapToZoom: true,
    };
    center: { x: number; y: number } = { x: 0, y: 0 };
    resolution = 1;
    width = 0;
    height = 0;
    container?: HTMLElement;
    ready = true;
    fatalError = null;
    when = vi.fn(async () => this);
    on = vi.fn(() => ({ remove: vi.fn() }));
    destroy = vi.fn();
    goTo = vi.fn(async () => undefined);
    hitTest = vi.fn(async () => ({ results: [] }));
    tryFatalErrorRecovery = vi.fn();
    resize = vi.fn(() => {
      this.width = this.container?.clientWidth ?? 0;
      this.height = this.container?.clientHeight ?? 0;
    });

    constructor(options: Record<string, unknown>) {
      arcgis.mapViewConstructed(options);
      if (arcgis.shouldThrowMapView)
        throw new Error("WebGL failed while constructing MapView");
      Object.assign(this, options);
      this.center = { x: 0, y: 0 };
      this.width = this.container?.clientWidth ?? 0;
      this.height = this.container?.clientHeight ?? 0;
      arcgis.mapViews.push(this);
    }
  },
}));

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

const filters: MapFilters = {
  malwareFamily: "all",
  country: "all",
  source: "all",
  minConfidence: 0,
  range: "all",
};

const originalGetContext = Object.getOwnPropertyDescriptor(
  HTMLCanvasElement.prototype,
  "getContext",
);
let getContextMock: ReturnType<typeof vi.fn>;
let resizeObserverCallbacks: ResizeObserverCallback[];
let viewportWidth: number;
let viewportHeight: number;

const makeIndicator = (id: string): Indicator => ({
  ...indicator,
  id,
  value: `203.0.113.${id.at(-1)}`,
});

const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

describe("ThreatMap", () => {
  beforeEach(() => {
    arcgis.shouldThrowMapView = false;
    arcgis.mapViewConstructed.mockClear();
    arcgis.mapViews.splice(0);
    arcgis.featureLayers.splice(0);
    arcgis.editGates.splice(0);
    arcgis.featureReductionClusterModuleLoaded = false;
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
        return this.classList.contains("threat-map__canvas")
          ? viewportWidth
          : 0;
      },
    );
    vi.spyOn(HTMLElement.prototype, "clientHeight", "get").mockImplementation(
      function (this: HTMLElement) {
        return this.classList.contains("threat-map__canvas")
          ? viewportHeight
          : 0;
      },
    );
    getContextMock = vi.fn((contextId: string) =>
      contextId === "webgl2"
        ? {
            getExtension: vi.fn(() => ({ loseContext: vi.fn() })),
          }
        : null,
    );
    Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
      configurable: true,
      writable: true,
      value: getContextMock,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    if (originalGetContext) {
      Object.defineProperty(
        HTMLCanvasElement.prototype,
        "getContext",
        originalGetContext,
      );
    }
  });

  it("renders a bounded flat MapView with clustering and a viewport-sized zoom floor", async () => {
    const { container } = render(
      <ThreatMap
        indicators={[indicator]}
        filters={filters}
        mode="clusters"
        onModeChange={vi.fn()}
        onSelect={vi.fn()}
      />,
    );

    await waitFor(() => expect(arcgis.mapViews).toHaveLength(1));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Zoom out" })).toBeEnabled(),
    );
    const view = arcgis.mapViews[0];
    if (!view) throw new Error("Expected a WebGL flat map view");
    const options = arcgis.mapViewConstructed.mock.calls[0]?.[0] as
      MockMapViewOptions | undefined;
    if (!options) throw new Error("MapView was not constructed");

    expect(options).toMatchObject({
      spatialReference: { wkid: 3857 },
      center: [18, 22],
      zoom: 2,
      constraints: {
        geometry: {
          type: "extent",
          spatialReference: { wkid: 3857 },
        },
        minZoom: 2,
        maxZoom: 14,
        rotationEnabled: false,
        snapToZoom: true,
      },
      background: { color: [3, 8, 18, 1] },
    });
    expect(arcgis.featureReductionClusterModuleLoaded).toBe(true);
    await waitFor(() =>
      expect(arcgis.featureLayers[0]?.featureReduction?.clusterRadius).toBe(
        "54px",
      ),
    );
    expect(screen.getByRole("button", { name: /clusters/i })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(
      screen.getByLabelText(
        "Interactive flat map of approximate threat infrastructure locations",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/bounded flat view/i)).toBeInTheDocument();

    viewportWidth = 2635;
    viewportHeight = 1484;
    act(() => {
      resizeObserverCallbacks[0]?.([], {} as ResizeObserver);
    });
    expect(view.resize).toHaveBeenCalled();
    expect(view.constraints.minZoom).toBe(4);
    expect(view.zoom).toBe(4);

    view.zoom = 4;
    fireEvent.click(screen.getByRole("button", { name: "Zoom out" }));
    expect(view.goTo).toHaveBeenLastCalledWith({ zoom: 4 }, { duration: 220 });

    fireEvent.click(screen.getByRole("button", { name: "Reset map extent" }));
    expect(view.goTo).toHaveBeenLastCalledWith(
      { center: [18, 22], zoom: 4 },
      { duration: 420 },
    );

    fireEvent.click(screen.getByRole("button", { name: "Expand map" }));
    expect(container.querySelector(".threat-map")).toHaveClass(
      "threat-map--fullscreen",
    );
    expect(
      screen.getByRole("button", { name: "Exit fullscreen map" }),
    ).toBeInTheDocument();
  });

  it("replaces a failed MapView constructor with a real ArcGIS raster map", async () => {
    arcgis.shouldThrowMapView = true;
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { container } = render(
      <ThreatMap
        indicators={[indicator]}
        filters={filters}
        mode="clusters"
        onModeChange={vi.fn()}
        onSelect={vi.fn()}
      />,
    );

    expect(screen.getByRole("button", { name: "Zoom in" })).toBeDisabled();
    expect(
      await screen.findByRole("region", {
        name: "Interactive ArcGIS raster map of approximate threat infrastructure locations",
      }),
    ).toBeInTheDocument();

    expect(getContextMock).toHaveBeenCalledWith("webgl2", {
      failIfMajorPerformanceCaveat: true,
    });
    expect(arcgis.mapViewConstructed).toHaveBeenCalledOnce();
    expect(container).not.toHaveTextContent("Simplified coordinate view");
    expect(container).not.toHaveTextContent(
      "ArcGIS WebGL renderer unavailable",
    );
    expect(screen.getByText(ARCGIS_RASTER_ATTRIBUTION)).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Zoom in" })).toBeEnabled(),
    );
  });

  it("serializes rapid replacements and retains only the latest indicator IDs", async () => {
    const firstUpdateGate = deferred();
    const initial = [makeIndicator("indicator-1")];
    const second = [makeIndicator("indicator-2")];
    const latest = [makeIndicator("indicator-3")];
    const props = {
      filters,
      mode: "clusters" as const,
      onModeChange: vi.fn(),
      onSelect: vi.fn(),
    };
    const { rerender } = render(<ThreatMap indicators={initial} {...props} />);

    await waitFor(() => expect(arcgis.featureLayers).toHaveLength(1));
    const layer = arcgis.featureLayers[0];
    if (!layer) throw new Error("FeatureLayer mock was not constructed");
    await waitFor(() =>
      expect(layer.featureReduction?.clusterRadius).toBe("54px"),
    );

    arcgis.editGates.push(firstUpdateGate.promise);
    rerender(<ThreatMap indicators={second} {...props} />);
    await waitFor(() => expect(layer.applyEdits).toHaveBeenCalledTimes(1));

    rerender(<ThreatMap indicators={latest} {...props} />);
    expect(layer.applyEdits).toHaveBeenCalledTimes(1);

    await act(async () => firstUpdateGate.resolve());
    await waitFor(() => expect(layer.applyEdits).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(
        layer.records.map((graphic) => graphic.attributes?.ioc_id),
      ).toEqual(["indicator-3"]),
    );

    expect(layer.queryObjectIds).toHaveBeenNthCalledWith(1, {
      where: "1=1",
      timeExtent: null,
    });
    expect(layer.queryObjectIds).toHaveBeenNthCalledWith(2, {
      where: "1=1",
      timeExtent: null,
    });

    const firstCall = layer.applyEdits.mock.calls[0];
    const latestCall = layer.applyEdits.mock.calls[1];
    if (!firstCall || !latestCall)
      throw new Error("Expected two serialized edit calls");
    const firstEdits = firstCall[0] as MockEdits;
    const latestEdits = latestCall[0] as MockEdits;
    expect(firstEdits.deleteFeatures?.[0]?.attributes?.object_id).toBe(1);
    expect(firstEdits.addFeatures?.[0]?.attributes).toMatchObject({
      object_id: 2,
      ioc_id: "indicator-2",
    });
    expect(latestEdits.deleteFeatures?.[0]?.attributes?.object_id).toBe(2);
    expect(latestEdits.addFeatures?.[0]?.attributes).toMatchObject({
      object_id: 3,
      ioc_id: "indicator-3",
    });
  });
});
