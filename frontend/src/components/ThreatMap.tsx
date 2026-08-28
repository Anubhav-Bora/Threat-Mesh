import {
  Globe2,
  Layers3,
  LocateFixed,
  Maximize2,
  Minimize2,
  Minus,
  Plus,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Indicator, MapFilters } from "../types";
import { rangeToDays } from "../utils/format";
import {
  ARCGIS_BASE_TILE_SERVICE,
  ARCGIS_RASTER_ATTRIBUTION,
  ARCGIS_REFERENCE_TILE_SERVICE,
  ArcGisRasterMap,
} from "./ArcGisRasterMap";
import type { ArcGisRasterMapHandle } from "./ArcGisRasterMap";
import {
  THREAT_FAMILY_COLORS,
  threatFamilyColor,
  threatFamilyColorIndex,
} from "./mapVisuals";

export type MapMode = "clusters" | "heatmap" | "uncertainty";

interface ThreatMapProps {
  indicators: Indicator[];
  filters: MapFilters;
  mode: MapMode;
  onModeChange: (mode: MapMode) => void;
  onSelect: (indicator: Indicator) => void;
}

const hasWebGl2 = () => {
  try {
    const canvas = document.createElement("canvas");
    canvas.width = 1;
    canvas.height = 1;
    const context = canvas.getContext("webgl2", {
      failIfMajorPerformanceCaveat: true,
    });
    return context !== null;
  } catch {
    return false;
  }
};

const MIN_GLOBE_ALTITUDE = 75_000;
const RESET_GLOBE_ALTITUDE = 18_000_000;
const MAX_GLOBE_ALTITUDE = 19_500_000;
const GLOBE_CENTER = { longitude: 18, latitude: 22 };

export function ThreatMap({
  indicators,
  filters,
  mode,
  onModeChange,
  onSelect,
}: ThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const rasterMapRef = useRef<ArcGisRasterMapHandle>(null);
  const viewRef = useRef<any>(null);
  const layerRef = useRef<any>(null);
  const precisionLayerRef = useRef<any>(null);
  const createGraphicsRef = useRef<((items: Indicator[]) => any[]) | null>(
    null,
  );
  const createDeleteGraphicsRef = useRef<
    ((objectIds: Array<number | string>) => any[]) | null
  >(null);
  const createPointRendererRef = useRef<(() => any) | null>(null);
  const createPrecisionGraphicsRef = useRef<
    ((items: Indicator[]) => any[]) | null
  >(null);
  const onSelectRef = useRef(onSelect);
  const indicatorsRef = useRef(indicators);
  const lastQueuedIndicatorsRef = useRef<Indicator[] | null>(null);
  const activeObjectIdsRef = useRef<Array<number | string>>([]);
  const editQueueRef = useRef<Promise<void>>(Promise.resolve());
  const editVersionRef = useRef(0);
  const disposedRef = useRef(false);
  const [mapState, setMapState] = useState<"loading" | "ready" | "fallback">(
    "loading",
  );
  const [isFullscreen, setIsFullscreen] = useState(false);

  onSelectRef.current = onSelect;
  indicatorsRef.current = indicators;

  const fallbackIndicators = useMemo(() => {
    const days = rangeToDays(filters.range);
    const cutoff = Date.now() - days * 86_400_000;
    return indicators.filter(
      (item) =>
        item.latitude !== null &&
        item.longitude !== null &&
        item.confidence >= filters.minConfidence &&
        (filters.malwareFamily === "all" ||
          item.malwareFamily === filters.malwareFamily) &&
        (filters.country === "all" || item.country === filters.country) &&
        (filters.source === "all" || item.sourceFeed === filters.source) &&
        (!Number.isFinite(days) || new Date(item.lastSeen).getTime() >= cutoff),
    );
  }, [filters, indicators]);

  const familyLegend = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of fallbackIndicators)
      counts.set(item.malwareFamily, (counts.get(item.malwareFamily) ?? 0) + 1);
    const families = Array.from(counts, ([family, count]) => ({
      family,
      count,
    })).sort((left, right) => right.count - left.count);
    return {
      items: families.slice(0, 3),
      remaining: Math.max(0, families.length - 3),
    };
  }, [fallbackIndicators]);

  useEffect(() => {
    if (!containerRef.current) return;
    let cancelled = false;
    let view: any;
    let fatalErrorHandle: { remove: () => void } | undefined;
    let recoveryController: AbortController | undefined;
    let viewportObserver: ResizeObserver | undefined;
    let removeWindowResizeListener: (() => void) | undefined;
    disposedRef.current = false;

    const initialize = async () => {
      if (!hasWebGl2()) {
        setMapState("fallback");
        return;
      }

      try {
        const [
          { default: config },
          { default: ArcGISMap },
          { default: SceneView },
          { default: Basemap },
          { default: TileLayer },
          { default: FeatureLayer },
          { default: GraphicsLayer },
          { default: Graphic },
          { default: Point },
          { default: Circle },
          { default: UniqueValueRenderer },
          { default: SimpleMarkerSymbol },
          { default: SimpleFillSymbol },
          reactiveUtils,
        ] = await Promise.all([
          import("@arcgis/core/config.js"),
          import("@arcgis/core/Map.js"),
          import("@arcgis/core/views/SceneView.js"),
          import("@arcgis/core/Basemap.js"),
          import("@arcgis/core/layers/TileLayer.js"),
          import("@arcgis/core/layers/FeatureLayer.js"),
          import("@arcgis/core/layers/GraphicsLayer.js"),
          import("@arcgis/core/Graphic.js"),
          import("@arcgis/core/geometry/Point.js"),
          import("@arcgis/core/geometry/Circle.js"),
          import("@arcgis/core/renderers/UniqueValueRenderer.js"),
          import("@arcgis/core/symbols/SimpleMarkerSymbol.js"),
          import("@arcgis/core/symbols/SimpleFillSymbol.js"),
          import("@arcgis/core/core/reactiveUtils.js"),
        ]);
        if (cancelled || !containerRef.current) return;

        const apiKey = import.meta.env.VITE_ARCGIS_API_KEY?.trim();
        if (apiKey) config.apiKey = apiKey;

        const basemap = new Basemap({
          baseLayers: [
            new TileLayer({
              url: ARCGIS_BASE_TILE_SERVICE,
              title: "ArcGIS World Imagery",
            }),
          ],
          referenceLayers: [
            new TileLayer({
              url: ARCGIS_REFERENCE_TILE_SERVICE,
              title: "ArcGIS Boundaries and Places",
              opacity: 0.88,
            }),
          ],
        });

        const map = new ArcGISMap({ basemap });
        let nextObjectId = 1;
        const createGraphics = (items: Indicator[]) =>
          items
            .filter(
              (
                item,
              ): item is Indicator & { latitude: number; longitude: number } =>
                item.latitude !== null &&
                item.longitude !== null &&
                Number.isFinite(item.latitude) &&
                Number.isFinite(item.longitude),
            )
            .map(
              (item) =>
                new Graphic({
                  geometry: new Point({
                    longitude: item.longitude,
                    latitude: item.latitude,
                    spatialReference: { wkid: 4326 },
                  }),
                  attributes: {
                    object_id: nextObjectId++,
                    ioc_id: item.id,
                    value: item.value,
                    family: item.malwareFamily,
                    family_color: String(
                      threatFamilyColorIndex(item.malwareFamily),
                    ),
                    confidence: item.confidence,
                    country: item.country,
                    source: item.sourceFeed,
                    provenance: item.isDemo
                      ? "Synthetic demo"
                      : "Live-feed observation",
                    last_seen: new Date(item.lastSeen).getTime(),
                    type: item.type,
                  },
                }),
            );
        createGraphicsRef.current = createGraphics;
        const createDeleteGraphics = (objectIds: Array<number | string>) =>
          objectIds.map(
            (objectId) => new Graphic({ attributes: { object_id: objectId } }),
          );
        createDeleteGraphicsRef.current = createDeleteGraphics;
        const initialItems = indicatorsRef.current;
        const graphics = createGraphics(initialItems);
        activeObjectIdsRef.current = graphics.map(
          (graphic) => graphic.attributes.object_id,
        );
        lastQueuedIndicatorsRef.current = initialItems;
        const createPrecisionGraphics = (items: Indicator[]) =>
          items
            .filter(
              (
                item,
              ): item is Indicator & { latitude: number; longitude: number } =>
                item.latitude !== null &&
                item.longitude !== null &&
                item.locationPrecisionKm !== null &&
                item.locationPrecisionKm > 0 &&
                Number.isFinite(item.latitude) &&
                Number.isFinite(item.longitude),
            )
            .map(
              (item) =>
                new Graphic({
                  geometry: new Circle({
                    center: new Point({
                      longitude: item.longitude,
                      latitude: item.latitude,
                      spatialReference: { wkid: 4326 },
                    }),
                    geodesic: true,
                    radius: item.locationPrecisionKm!,
                    radiusUnit: "kilometers",
                  }),
                  symbol: new SimpleFillSymbol({
                    color: [139, 92, 246, 0.035],
                    outline: { color: [167, 139, 250, 0.3], width: 0.8 },
                  }),
                  attributes: { ioc_id: item.id },
                }),
            );
        createPrecisionGraphicsRef.current = createPrecisionGraphics;

        const createPointRenderer = () =>
          new UniqueValueRenderer({
            field: "family_color",
            defaultSymbol: new SimpleMarkerSymbol({
              color: "#94a3b8",
              outline: { color: [241, 245, 249, 0.86], width: 1 },
              size: 9,
            }),
            uniqueValueInfos: THREAT_FAMILY_COLORS.map((color, index) => ({
              value: String(index),
              label: `Threat family color ${index + 1}`,
              symbol: new SimpleMarkerSymbol({
                color,
                outline: { color: [248, 250, 252, 0.88], width: 1 },
                size: 9,
              }),
            })),
            visualVariables: [
              {
                type: "opacity",
                field: "confidence",
                stops: [
                  { value: 0, opacity: 0.38 },
                  { value: 60, opacity: 0.72 },
                  { value: 100, opacity: 1 },
                ],
              },
            ],
          });
        createPointRendererRef.current = createPointRenderer;

        const pointRenderer = createPointRenderer();

        const layer = new FeatureLayer({
          title: "ThreatMesh IOC observations",
          source: graphics,
          objectIdField: "object_id",
          fields: [
            { name: "object_id", alias: "Object ID", type: "oid" },
            { name: "ioc_id", alias: "Indicator ID", type: "string" },
            { name: "value", alias: "Indicator", type: "string" },
            { name: "family", alias: "Malware family", type: "string" },
            {
              name: "family_color",
              alias: "Family color index",
              type: "string",
            },
            { name: "confidence", alias: "Confidence", type: "double" },
            { name: "country", alias: "Country", type: "string" },
            { name: "source", alias: "Source", type: "string" },
            { name: "provenance", alias: "Provenance", type: "string" },
            { name: "last_seen", alias: "Last seen", type: "date" },
            { name: "type", alias: "Type", type: "string" },
          ],
          geometryType: "point",
          spatialReference: { wkid: 4326 },
          elevationInfo: { mode: "on-the-ground" },
          renderer: pointRenderer,
          timeInfo: { startField: "last_seen" },
          popupTemplate: {
            title: "{family}",
            content: [
              {
                type: "fields",
                fieldInfos: [
                  { fieldName: "value", label: "Indicator" },
                  { fieldName: "confidence", label: "Confidence" },
                  { fieldName: "country", label: "Approximate location" },
                  { fieldName: "source", label: "Source feed" },
                  { fieldName: "provenance", label: "Provenance" },
                ],
              },
            ],
          },
        });
        const precisionLayer = new GraphicsLayer({
          title: "Illustrative geolocation context",
          visible: false,
          listMode: "hide",
          elevationInfo: { mode: "on-the-ground" },
          graphics: createPrecisionGraphics(indicatorsRef.current),
        });
        map.addMany([precisionLayer, layer]);

        const viewContainer = containerRef.current;
        view = new SceneView({
          container: viewContainer,
          map,
          viewingMode: "global",
          camera: {
            position: {
              ...GLOBE_CENTER,
              z: RESET_GLOBE_ALTITUDE,
              spatialReference: { wkid: 4326 },
            },
            heading: 0,
            tilt: 0,
          },
          constraints: {
            altitude: {
              min: MIN_GLOBE_ALTITUDE,
              max: MAX_GLOBE_ALTITUDE,
            },
          },
          environment: {
            background: { type: "color", color: [2, 7, 18, 1] },
            atmosphereEnabled: true,
            starsEnabled: true,
            lighting: {
              type: "virtual",
              directShadowsEnabled: false,
            },
          },
          attributionVisible: true,
          ui: { components: [] },
          popup: { dockEnabled: false },
        });

        const synchronizeViewport = () => {
          if (cancelled || !view || !containerRef.current) return;
          if (typeof view.resize === "function") view.resize();
        };
        synchronizeViewport();
        if (typeof ResizeObserver !== "undefined") {
          viewportObserver = new ResizeObserver(synchronizeViewport);
          viewportObserver.observe(viewContainer);
        } else {
          window.addEventListener("resize", synchronizeViewport);
          removeWindowResizeListener = () =>
            window.removeEventListener("resize", synchronizeViewport);
        }

        fatalErrorHandle = reactiveUtils.watch(
          () => view.fatalError,
          (fatalError: unknown) => {
            if (!fatalError || cancelled) return;
            setMapState("fallback");
            recoveryController?.abort();
            recoveryController = new AbortController();
            try {
              view.tryFatalErrorRecovery();
              void reactiveUtils
                .whenOnce(() => view.ready && !view.fatalError, {
                  signal: recoveryController.signal,
                })
                .then(() => {
                  if (!cancelled) setMapState("ready");
                })
                .catch(() => undefined);
            } catch {
              // The interactive raster renderer remains active.
            }
          },
        );

        const readiness = view.when().then(() => true);
        const loaded = await Promise.race([
          readiness,
          new Promise<false>((resolve) =>
            window.setTimeout(() => resolve(false), 7000),
          ),
        ]);
        if (cancelled) return;
        viewRef.current = view;
        layerRef.current = layer;
        precisionLayerRef.current = precisionLayer;
        setMapState(loaded ? "ready" : "fallback");
        if (!loaded) {
          void readiness
            .then(() => {
              if (!cancelled) setMapState("ready");
            })
            .catch(() => undefined);
        }

        view.on("click", async (event: any) => {
          const hit = await view.hitTest(event, { include: layer });
          const result = hit.results.find(
            (entry: any) => entry.graphic?.layer === layer,
          );
          const id = result?.graphic?.attributes?.ioc_id;
          const selected = indicatorsRef.current.find((item) => item.id === id);
          if (selected) onSelectRef.current(selected);
        });
        layer.featureReduction = null;
      } catch (error) {
        console.error("ArcGIS globe initialization failed", error);
        viewportObserver?.disconnect();
        viewportObserver = undefined;
        removeWindowResizeListener?.();
        removeWindowResizeListener = undefined;
        fatalErrorHandle?.remove();
        recoveryController?.abort();
        if (view) {
          view.destroy();
          view = undefined;
        }
        if (!cancelled) {
          viewRef.current = null;
          layerRef.current = null;
          precisionLayerRef.current = null;
          setMapState("fallback");
        }
      }
    };

    void initialize();
    return () => {
      cancelled = true;
      disposedRef.current = true;
      editVersionRef.current += 1;
      recoveryController?.abort();
      fatalErrorHandle?.remove();
      viewportObserver?.disconnect();
      removeWindowResizeListener?.();
      if (view) view.destroy();
      viewRef.current = null;
      layerRef.current = null;
      precisionLayerRef.current = null;
      createGraphicsRef.current = null;
      createDeleteGraphicsRef.current = null;
      createPointRendererRef.current = null;
      createPrecisionGraphicsRef.current = null;
      lastQueuedIndicatorsRef.current = null;
      activeObjectIdsRef.current = [];
      editQueueRef.current = Promise.resolve();
    };
  }, []);

  useEffect(() => {
    const layer = layerRef.current;
    const createGraphics = createGraphicsRef.current;
    const createDeleteGraphics = createDeleteGraphicsRef.current;
    if (
      !layer ||
      !createGraphics ||
      !createDeleteGraphics ||
      indicators === lastQueuedIndicatorsRef.current
    )
      return;

    const nextIndicators = indicators;
    const version = ++editVersionRef.current;
    lastQueuedIndicatorsRef.current = nextIndicators;
    editQueueRef.current = editQueueRef.current
      .catch(() => undefined)
      .then(async () => {
        if (disposedRef.current || layerRef.current !== layer) return;
        await layer.load();
        const queriedObjectIds: Array<number | string> =
          await layer.queryObjectIds({
            where: "1=1",
            timeExtent: null,
          });
        if (
          disposedRef.current ||
          layerRef.current !== layer ||
          version !== editVersionRef.current
        )
          return;

        const objectIds = Array.from(
          new Set([...activeObjectIdsRef.current, ...(queriedObjectIds ?? [])]),
        );
        const nextGraphics = createGraphics(nextIndicators);
        const result = await layer.applyEdits({
          deleteFeatures: createDeleteGraphics(objectIds),
          addFeatures: nextGraphics,
        });
        const failures = [
          ...(result.addFeatureResults ?? []),
          ...(result.deleteFeatureResults ?? []),
        ].flatMap((edit: { error?: { message?: string } }) =>
          edit.error ? [edit.error.message ?? "unknown edit failure"] : [],
        );
        if (failures.length > 0) {
          activeObjectIdsRef.current = Array.from(
            new Set([
              ...objectIds,
              ...nextGraphics.map((graphic) => graphic.attributes.object_id),
            ]),
          );
          throw new Error(`Feature edits rejected: ${failures.join("; ")}`);
        }
        activeObjectIdsRef.current = nextGraphics.map(
          (graphic) => graphic.attributes.object_id,
        );
      })
      .catch((error: unknown) => {
        if (version === editVersionRef.current)
          lastQueuedIndicatorsRef.current = null;
        console.error("ArcGIS indicator update failed", error);
      });
  }, [indicators, mapState]);

  useEffect(() => {
    const precisionLayer = precisionLayerRef.current;
    const createPrecisionGraphics = createPrecisionGraphicsRef.current;
    if (!precisionLayer || !createPrecisionGraphics) return;
    precisionLayer.graphics.removeAll();
    precisionLayer.graphics.addMany(
      createPrecisionGraphics(fallbackIndicators),
    );
  }, [fallbackIndicators, mapState]);

  useEffect(() => {
    const layer = layerRef.current;
    const precisionLayer = precisionLayerRef.current;
    const view = viewRef.current;
    const createPointRenderer = createPointRendererRef.current;
    if (!layer || !precisionLayer || !view || !createPointRenderer) return;
    let cancelled = false;
    const setMode = async () => {
      const { default: HeatmapRenderer } =
        await import("@arcgis/core/renderers/HeatmapRenderer.js");
      if (cancelled) return;
      precisionLayer.visible = mode === "uncertainty";
      if (mode === "heatmap") {
        layer.featureReduction = null;
        layer.renderer = new HeatmapRenderer({
          field: "confidence",
          radius: 27,
          minDensity: 0,
          maxDensity: 0.08,
          colorStops: [
            { ratio: 0, color: [3, 8, 24, 0] },
            { ratio: 0.12, color: [49, 46, 129, 0.18] },
            { ratio: 0.34, color: [124, 58, 237, 0.48] },
            { ratio: 0.56, color: [236, 72, 153, 0.7] },
            { ratio: 0.78, color: [249, 115, 22, 0.86] },
            { ratio: 1, color: [253, 224, 71, 0.98] },
          ],
        });
      } else {
        layer.renderer = createPointRenderer();
        layer.featureReduction = null;
      }
    };
    void setMode();
    return () => {
      cancelled = true;
    };
  }, [mapState, mode]);

  useEffect(() => {
    const layer = layerRef.current;
    const view = viewRef.current;
    if (!layer || !view) return;
    const quote = (value: string) => value.replaceAll("'", "''");
    const clauses = [`confidence >= ${filters.minConfidence}`];
    if (filters.malwareFamily !== "all")
      clauses.push(`family = '${quote(filters.malwareFamily)}'`);
    if (filters.country !== "all")
      clauses.push(`country = '${quote(filters.country)}'`);
    if (filters.source !== "all")
      clauses.push(`source = '${quote(filters.source)}'`);
    layer.definitionExpression = clauses.join(" AND ");
    const days = rangeToDays(filters.range);
    view.timeExtent = Number.isFinite(days)
      ? { start: new Date(Date.now() - days * 86_400_000), end: new Date() }
      : null;
  }, [filters, mapState]);

  const adjustZoom = (delta: number) => {
    if (mapState === "fallback") {
      rasterMapRef.current?.adjustZoom(delta);
      return;
    }
    const view = viewRef.current;
    const camera = view?.camera?.clone?.();
    if (!view || !camera?.position) return;
    const currentAltitude = Number(camera.position.z);
    const nextAltitude =
      (Number.isFinite(currentAltitude)
        ? currentAltitude
        : RESET_GLOBE_ALTITUDE) * (delta > 0 ? 0.58 : 1.72);
    camera.position.z = Math.min(
      MAX_GLOBE_ALTITUDE,
      Math.max(MIN_GLOBE_ALTITUDE, nextAltitude),
    );
    view.goTo(camera, { duration: 320 }).catch(() => undefined);
  };

  const recenter = () => {
    if (mapState === "fallback") {
      rasterMapRef.current?.recenter();
      return;
    }
    const view = viewRef.current;
    const camera = view?.camera?.clone?.();
    if (!view || !camera?.position) return;
    camera.position.longitude = GLOBE_CENTER.longitude;
    camera.position.latitude = GLOBE_CENTER.latitude;
    camera.position.z = RESET_GLOBE_ALTITUDE;
    camera.heading = 0;
    camera.tilt = 0;
    view.goTo(camera, { duration: 520 }).catch(() => undefined);
  };

  useEffect(() => {
    if (!isFullscreen) return;
    const previousOverflow = document.body.style.overflow;
    const exitOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setIsFullscreen(false);
    };
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", exitOnEscape);
    const frame = window.requestAnimationFrame(() =>
      viewRef.current?.resize?.(),
    );
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("keydown", exitOnEscape);
      document.body.style.overflow = previousOverflow;
      window.requestAnimationFrame(() => viewRef.current?.resize?.());
    };
  }, [isFullscreen]);

  return (
    <div
      className={`threat-map ${isFullscreen ? "threat-map--fullscreen" : ""}`}
    >
      <div
        ref={containerRef}
        className="threat-map__canvas"
        aria-label="Interactive 3D globe of approximate threat infrastructure locations"
        aria-hidden={mapState === "fallback"}
        inert={mapState === "fallback"}
      />
      {mapState === "loading" && (
        <div className="map-loading">
          <span className="logo-loader">
            <span />
            <span />
            <span />
          </span>
          <span>Initializing ArcGIS globe</span>
        </div>
      )}
      {mapState === "fallback" && (
        <div className="map-fallback">
          <ArcGisRasterMap
            ref={rasterMapRef}
            indicators={fallbackIndicators}
            mode={mode}
            onSelect={(indicator) => onSelectRef.current(indicator)}
          />
        </div>
      )}
      <div className="map-atmosphere" aria-hidden="true" />
      <div className="map-mode" aria-label="Map display mode">
        <Layers3 size={15} />
        {(["clusters", "heatmap", "uncertainty"] as MapMode[]).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => onModeChange(value)}
            className={mode === value ? "is-active" : ""}
            aria-pressed={mode === value}
          >
            {value === "clusters"
              ? "Observations"
              : value === "uncertainty"
                ? "Location context"
                : value}
          </button>
        ))}
      </div>
      <div className="map-basemap-badge">
        <Globe2 size={12} />
        <span>ArcGIS World Imagery · 3D globe</span>
        <i aria-hidden="true" />
      </div>
      <div className="map-controls">
        <button
          type="button"
          onClick={() => adjustZoom(1)}
          aria-label="Zoom in"
          disabled={mapState === "loading"}
        >
          <Plus size={17} />
        </button>
        <button
          type="button"
          onClick={() => adjustZoom(-1)}
          aria-label="Zoom out"
          disabled={mapState === "loading"}
        >
          <Minus size={17} />
        </button>
        <button
          type="button"
          onClick={recenter}
          aria-label="Reset map extent"
          disabled={mapState === "loading"}
        >
          <LocateFixed size={17} />
        </button>
        <button
          type="button"
          onClick={() => setIsFullscreen((value) => !value)}
          aria-label={isFullscreen ? "Exit fullscreen map" : "Expand map"}
        >
          {isFullscreen ? <Minimize2 size={17} /> : <Maximize2 size={17} />}
        </button>
      </div>
      <div className="map-legend">
        <strong>
          {mode === "heatmap" ? "Threat density" : "Top families"}
        </strong>
        {mode === "heatmap" ? (
          <span className="map-legend__heat-scale">
            <small>Low</small>
            <i />
            <small>High</small>
          </span>
        ) : (
          <>
            {familyLegend.items.map(({ family, count }) => (
              <span key={family} title={`${family} · ${count} mapped`}>
                <i
                  className="map-legend__dot"
                  style={{
                    backgroundColor: threatFamilyColor(family),
                    color: threatFamilyColor(family),
                  }}
                />
                {family}
              </span>
            ))}
            {familyLegend.remaining > 0 && (
              <span className="map-legend__more">
                +{familyLegend.remaining} more
              </span>
            )}
          </>
        )}
        <span className="map-legend__note">
          {mode === "uncertainty"
            ? "Ring = approximate location context"
            : mode === "heatmap"
              ? "Brighter areas = more observations"
              : "Color = family · opacity = confidence"}
        </span>
      </div>
      {mapState === "fallback" && (
        <div className="map-attribution">{ARCGIS_RASTER_ATTRIBUTION}</div>
      )}
    </div>
  );
}
