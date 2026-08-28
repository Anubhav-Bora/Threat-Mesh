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

interface MockCamera {
  position: {
    longitude: number;
    latitude: number;
    z: number;
    spatialReference?: { wkid: number };
  };
  heading: number;
  tilt: number;
  clone: ReturnType<typeof vi.fn>;
}

interface MockSceneViewHarness {
  camera: MockCamera;
  constraints: { altitude: { min: number; max: number } };
  goTo: ReturnType<typeof vi.fn>;
  resize: ReturnType<typeof vi.fn>;
  zoom: number;
}

interface MockSceneViewOptions {
  viewingMode: string;
  camera: {
    position: {
      longitude: number;
      latitude: number;
      z: number;
      spatialReference: { wkid: number };
    };
    heading: number;
    tilt: number;
  };
  constraints: { altitude: { min: number; max: number } };
  environment: {
    starsEnabled: boolean;
    atmosphereEnabled: boolean;
    background: { type: string; color: number[] };
    lighting: { type: string; directShadowsEnabled: boolean };
  };
}

interface MockArcGisState {
  shouldThrowSceneView: boolean;
  sceneViewConstructed: ReturnType<typeof vi.fn>;
  sceneViews: MockSceneViewHarness[];
  featureLayers: MockFeatureLayerHarness[];
  editGates: Promise<void>[];
  featureReductionClusterModuleLoaded: boolean;
}

const arcgis = vi.hoisted((): MockArcGisState => ({
  shouldThrowSceneView: false,
  sceneViewConstructed: vi.fn(),
  sceneViews: [],
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
    return class {};
  })(),
}));
vi.mock("@arcgis/core/core/reactiveUtils.js", () => ({
  watch: vi.fn(() => ({ remove: vi.fn() })),
  whenOnce: vi.fn(() => Promise.resolve()),
}));
vi.mock("@arcgis/core/views/SceneView.js", () => ({
  default: class {
    zoom = 2.2;
    constraints = { altitude: { min: 75_000, max: 30_000_000 } };
    camera!: MockCamera;
    ready = true;
    fatalError = null;
    when = vi.fn(async () => this);
    on = vi.fn(() => ({ remove: vi.fn() }));
    destroy = vi.fn();
    goTo = vi.fn(async () => undefined);
    hitTest = vi.fn(async () => ({ results: [] }));
    tryFatalErrorRecovery = vi.fn();
    resize = vi.fn();

    constructor(options: Record<string, unknown>) {
      arcgis.sceneViewConstructed(options);
      if (arcgis.shouldThrowSceneView)
        throw new Error("WebGL failed while constructing SceneView");
      Object.assign(this, options);
      const camera = options.camera as Omit<MockCamera, "clone">;
      this.camera = {
        ...camera,
        position: { ...camera.position },
        clone: vi.fn(() => ({
          ...camera,
          position: { ...camera.position },
        })),
      };
      arcgis.sceneViews.push(this);
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
    arcgis.shouldThrowSceneView = false;
    arcgis.sceneViewConstructed.mockClear();
    arcgis.sceneViews.splice(0);
    arcgis.featureLayers.splice(0);
    arcgis.editGates.splice(0);
    arcgis.featureReductionClusterModuleLoaded = false;
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

  it("renders the WebGL map as a constrained global scene", async () => {
    const { container } = render(
      <ThreatMap
        indicators={[indicator]}
        filters={filters}
        mode="clusters"
        onModeChange={vi.fn()}
        onSelect={vi.fn()}
      />,
    );

    await waitFor(() => expect(arcgis.sceneViews).toHaveLength(1));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Zoom out" })).toBeEnabled(),
    );
    const view = arcgis.sceneViews[0];
    if (!view) throw new Error("Expected a WebGL global scene view");
    const options = arcgis.sceneViewConstructed.mock.calls[0]?.[0] as
      MockSceneViewOptions | undefined;
    if (!options) throw new Error("SceneView was not constructed");

    expect(options).toMatchObject({
      viewingMode: "global",
      camera: {
        position: {
          longitude: 18,
          latitude: 22,
          z: 18_000_000,
          spatialReference: { wkid: 4326 },
        },
        heading: 0,
        tilt: 0,
      },
      constraints: {
        altitude: {
          min: 75_000,
          max: 19_500_000,
        },
      },
      environment: {
        starsEnabled: true,
        atmosphereEnabled: true,
        background: {
          type: "color",
          color: [2, 7, 18, 1],
        },
        lighting: { type: "virtual", directShadowsEnabled: false },
      },
    });
    expect(arcgis.featureReductionClusterModuleLoaded).toBe(false);
    await waitFor(() =>
      expect(arcgis.featureLayers[0]?.featureReduction).toBeNull(),
    );
    expect(
      screen.getByRole("button", { name: "Observations" }),
    ).toHaveAttribute("aria-pressed", "true");

    act(() => {
      resizeObserverCallbacks[0]?.([], {} as ResizeObserver);
    });
    expect(view.resize).toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    expect(view.goTo).toHaveBeenLastCalledWith(
      expect.objectContaining({
        position: expect.objectContaining({ z: 10_440_000 }),
      }),
      { duration: 320 },
    );
    fireEvent.click(screen.getByRole("button", { name: "Zoom out" }));
    expect(view.goTo).toHaveBeenCalledTimes(2);
    expect(view.goTo).toHaveBeenLastCalledWith(
      expect.objectContaining({
        position: expect.objectContaining({ z: 19_500_000 }),
      }),
      { duration: 320 },
    );

    fireEvent.click(screen.getByRole("button", { name: "Reset map extent" }));
    expect(view.goTo).toHaveBeenCalledTimes(3);
    const resetTarget = view.goTo.mock.calls.at(-1)?.[0] as
      MockCamera | undefined;
    expect(resetTarget).toMatchObject({
      position: { longitude: 18, latitude: 22, z: 18_000_000 },
      heading: 0,
      tilt: 0,
    });
    expect(view.goTo).toHaveBeenLastCalledWith(resetTarget, { duration: 520 });

    fireEvent.click(screen.getByRole("button", { name: "Expand map" }));
    expect(container.querySelector(".threat-map")).toHaveClass(
      "threat-map--fullscreen",
    );
    expect(
      screen.getByRole("button", { name: "Exit fullscreen map" }),
    ).toBeInTheDocument();
  });

  it("replaces a failed SceneView constructor with a real ArcGIS raster map", async () => {
    arcgis.shouldThrowSceneView = true;
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
    expect(arcgis.sceneViewConstructed).toHaveBeenCalledOnce();
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
    await waitFor(() => expect(layer.featureReduction).toBeNull());

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
