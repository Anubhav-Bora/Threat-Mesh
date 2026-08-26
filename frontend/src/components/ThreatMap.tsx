import {
  AlertTriangle,
  Layers3,
  LocateFixed,
  Maximize2,
  Minus,
  Plus,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { Indicator, MapFilters } from "../types";
import { rangeToDays } from "../utils/format";

export type MapMode = "clusters" | "heatmap" | "uncertainty";

interface ThreatMapProps {
  indicators: Indicator[];
  filters: MapFilters;
  mode: MapMode;
  onModeChange: (mode: MapMode) => void;
  onSelect: (indicator: Indicator) => void;
}

export function ThreatMap({
  indicators,
  filters,
  mode,
  onModeChange,
  onSelect,
}: ThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<any>(null);
  const layerRef = useRef<any>(null);
  const precisionLayerRef = useRef<any>(null);
  const createGraphicsRef = useRef<((items: Indicator[]) => any[]) | null>(
    null,
  );
  const createPrecisionGraphicsRef = useRef<
    ((items: Indicator[]) => any[]) | null
  >(null);
  const onSelectRef = useRef(onSelect);
  const indicatorsRef = useRef(indicators);
  const [mapState, setMapState] = useState<
    "loading" | "ready" | "fallback" | "error"
  >("loading");
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

  useEffect(() => {
    if (!containerRef.current) return;
    let cancelled = false;
    let view: any;

    const initialize = async () => {
      try {
        const [
          { default: config },
          { default: ArcGISMap },
          { default: MapView },
          { default: Basemap },
          { default: WebTileLayer },
          { default: FeatureLayer },
          { default: GraphicsLayer },
          { default: Graphic },
          { default: Point },
          { default: Circle },
          { default: SimpleRenderer },
          { default: SimpleMarkerSymbol },
          { default: SimpleFillSymbol },
          { default: FeatureReductionCluster },
        ] = await Promise.all([
          import("@arcgis/core/config.js"),
          import("@arcgis/core/Map.js"),
          import("@arcgis/core/views/MapView.js"),
          import("@arcgis/core/Basemap.js"),
          import("@arcgis/core/layers/WebTileLayer.js"),
          import("@arcgis/core/layers/FeatureLayer.js"),
          import("@arcgis/core/layers/GraphicsLayer.js"),
          import("@arcgis/core/Graphic.js"),
          import("@arcgis/core/geometry/Point.js"),
          import("@arcgis/core/geometry/Circle.js"),
          import("@arcgis/core/renderers/SimpleRenderer.js"),
          import("@arcgis/core/symbols/SimpleMarkerSymbol.js"),
          import("@arcgis/core/symbols/SimpleFillSymbol.js"),
          import("@arcgis/core/layers/support/FeatureReductionCluster.js"),
        ]);
        if (cancelled || !containerRef.current) return;

        const apiKey = import.meta.env.VITE_ARCGIS_API_KEY?.trim();
        if (apiKey) config.apiKey = apiKey;

        const basemap = apiKey
          ? "arcgis/navigation-night"
          : new Basemap({
              baseLayers: [
                new WebTileLayer({
                  urlTemplate:
                    "https://{subDomain}.basemaps.cartocdn.com/dark_all/{level}/{col}/{row}.png",
                  subDomains: ["a", "b", "c", "d"],
                  copyright: "OpenStreetMap contributors, CARTO",
                }),
              ],
            });

        const map = new ArcGISMap({ basemap });
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
              (item, index) =>
                new Graphic({
                  geometry: new Point({
                    longitude: item.longitude,
                    latitude: item.latitude,
                    spatialReference: { wkid: 4326 },
                  }),
                  attributes: {
                    object_id: index + 1,
                    ioc_id: item.id,
                    value: item.value,
                    family: item.malwareFamily,
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
        const graphics = createGraphics(indicatorsRef.current);
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
                    color: [110, 231, 216, 0.08],
                    outline: { color: [110, 231, 216, 0.48], width: 1 },
                  }),
                  attributes: { ioc_id: item.id },
                }),
            );
        createPrecisionGraphicsRef.current = createPrecisionGraphics;

        const pointRenderer = new SimpleRenderer({
          symbol: new SimpleMarkerSymbol({
            color: [110, 231, 216, 0.3],
            outline: { color: [154, 245, 232, 0.92], width: 1.2 },
            size: 17,
          }),
          visualVariables: [
            {
              type: "color",
              field: "confidence",
              stops: [
                { value: 0, color: "#8393a7" },
                { value: 39, color: "#8393a7" },
                { value: 40, color: "#f4b860" },
                { value: 69, color: "#f4b860" },
                { value: 70, color: "#6ee7d8" },
                { value: 100, color: "#6ee7d8" },
              ],
            },
            {
              type: "size",
              field: "confidence",
              minDataValue: 50,
              maxDataValue: 100,
              minSize: 11,
              maxSize: 27,
            },
          ],
        });

        const layer = new FeatureLayer({
          title: "ThreatMesh IOC observations",
          source: graphics,
          objectIdField: "object_id",
          fields: [
            { name: "object_id", alias: "Object ID", type: "oid" },
            { name: "ioc_id", alias: "Indicator ID", type: "string" },
            { name: "value", alias: "Indicator", type: "string" },
            { name: "family", alias: "Malware family", type: "string" },
            { name: "confidence", alias: "Confidence", type: "integer" },
            { name: "country", alias: "Country", type: "string" },
            { name: "source", alias: "Source", type: "string" },
            { name: "provenance", alias: "Provenance", type: "string" },
            { name: "last_seen", alias: "Last seen", type: "date" },
            { name: "type", alias: "Type", type: "string" },
          ],
          geometryType: "point",
          spatialReference: { wkid: 4326 },
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
          graphics: createPrecisionGraphics(indicatorsRef.current),
        });
        map.addMany([precisionLayer, layer]);

        view = new MapView({
          container: containerRef.current,
          map,
          center: [18, 26],
          zoom: 2.2,
          constraints: { minZoom: 1.5, maxZoom: 14, snapToZoom: false },
          ui: { components: [] },
          popup: { dockEnabled: false },
          background: { color: [8, 11, 18, 1] },
        });

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

        const cluster = new FeatureReductionCluster({
          clusterRadius: "64px",
          popupTemplate: {
            title: "Indicator cluster",
            content:
              "This area contains <b>{cluster_count}</b> IOC observations.",
          },
          labelingInfo: [
            {
              deconflictionStrategy: "none",
              labelExpressionInfo: {
                expression: "Text($feature.cluster_count, '#,###')",
              },
              symbol: {
                type: "text",
                color: "#f7fafc",
                font: { family: "Inter", size: 11, weight: "bold" },
                haloColor: "#172029",
                haloSize: 1,
              },
              labelPlacement: "center-center",
            },
          ],
        });
        layer.featureReduction = cluster;
      } catch (error) {
        console.error("ArcGIS map initialization failed", error);
        if (!cancelled) setMapState("fallback");
      }
    };

    void initialize();
    return () => {
      cancelled = true;
      if (view) view.destroy();
      viewRef.current = null;
      layerRef.current = null;
      precisionLayerRef.current = null;
      createGraphicsRef.current = null;
      createPrecisionGraphicsRef.current = null;
    };
  }, []);

  useEffect(() => {
    const layer = layerRef.current;
    const createGraphics = createGraphicsRef.current;
    if (!layer || !createGraphics) return;
    layer.source.removeAll();
    layer.source.addMany(createGraphics(indicators));
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
    if (!layer || !precisionLayer || !view) return;
    let cancelled = false;
    const setMode = async () => {
      const [
        { default: SimpleRenderer },
        { default: SimpleMarkerSymbol },
        { default: HeatmapRenderer },
        { default: FeatureReductionCluster },
      ] = await Promise.all([
        import("@arcgis/core/renderers/SimpleRenderer.js"),
        import("@arcgis/core/symbols/SimpleMarkerSymbol.js"),
        import("@arcgis/core/renderers/HeatmapRenderer.js"),
        import("@arcgis/core/layers/support/FeatureReductionCluster.js"),
      ]);
      if (cancelled) return;
      precisionLayer.visible = mode === "uncertainty";
      if (mode === "heatmap") {
        layer.featureReduction = null;
        layer.renderer = new HeatmapRenderer({
          field: "confidence",
          radius: 34,
          minDensity: 0,
          maxDensity: 0.08,
          colorStops: [
            { ratio: 0, color: [8, 11, 18, 0] },
            { ratio: 0.2, color: [72, 68, 177, 0.35] },
            { ratio: 0.45, color: [63, 143, 176, 0.62] },
            { ratio: 0.7, color: [64, 211, 178, 0.8] },
            { ratio: 1, color: [255, 191, 99, 0.95] },
          ],
        });
      } else {
        layer.renderer = new SimpleRenderer({
          symbol: new SimpleMarkerSymbol({
            color: [110, 231, 216, 0.3],
            outline: { color: [154, 245, 232, 0.9], width: 1.2 },
            size: 17,
          }),
          visualVariables: [
            {
              type: "color",
              field: "confidence",
              stops: [
                { value: 0, color: "#8393a7" },
                { value: 39, color: "#8393a7" },
                { value: 40, color: "#f4b860" },
                { value: 69, color: "#f4b860" },
                { value: 70, color: "#6ee7d8" },
                { value: 100, color: "#6ee7d8" },
              ],
            },
            {
              type: "size",
              field: "confidence",
              minDataValue: 50,
              maxDataValue: 100,
              minSize: 11,
              maxSize: 27,
            },
          ],
        });
        layer.featureReduction =
          mode === "clusters"
            ? new FeatureReductionCluster({ clusterRadius: "64px" })
            : null;
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
    const view = viewRef.current;
    if (view)
      view
        .goTo({ zoom: view.zoom + delta }, { duration: 220 })
        .catch(() => undefined);
  };

  const recenter = () =>
    viewRef.current
      ?.goTo({ center: [18, 26], zoom: 2.2 }, { duration: 420 })
      .catch(() => undefined);

  return (
    <div
      className={`threat-map ${isFullscreen ? "threat-map--fullscreen" : ""}`}
    >
      <div
        ref={containerRef}
        className="threat-map__canvas"
        aria-label="Interactive map of approximate threat infrastructure locations"
      />
      {mapState === "loading" && (
        <div className="map-loading">
          <span className="logo-loader">
            <span />
            <span />
            <span />
          </span>
          <span>Initializing GIS layer</span>
        </div>
      )}
      {mapState === "fallback" && (
        <div
          className="map-fallback"
          aria-label="Simplified coordinate view of threat infrastructure"
        >
          <svg
            viewBox="0 0 1000 500"
            role="img"
            aria-label={`${fallbackIndicators.length} geolocated threat indicators`}
          >
            <defs>
              <pattern
                id="fallback-grid"
                width="50"
                height="50"
                patternUnits="userSpaceOnUse"
              >
                <path
                  d="M50 0H0V50"
                  fill="none"
                  stroke="#1b2934"
                  strokeWidth="1"
                />
              </pattern>
              <filter id="point-glow">
                <feGaussianBlur stdDeviation="5" />
              </filter>
            </defs>
            <rect width="1000" height="500" fill="url(#fallback-grid)" />
            <g className="fallback-land">
              <path d="M70 120 118 76l93-30 85 28 47 54-17 49-57 21-33 62-55-8-28-54-61-18Z" />
              <path d="m262 277 52 24 29 61-20 91-41 31-24-91-26-59Z" />
              <path d="m460 100 73-49 85 17 49 35 95 7 109 60-51 41-89-9-44 37-55-11-29 48-61-18-19-51-68-27-31-43Z" />
              <path d="m524 267 80 6 42 57-27 100-47 24-49-81-26-61Z" />
              <path d="m810 348 63-26 61 45-13 55-73 5-44-37Z" />
            </g>
            {fallbackIndicators.map((item) => {
              const x = ((item.longitude! + 180) / 360) * 1000;
              const y = ((90 - item.latitude!) / 180) * 500;
              const color =
                item.confidence >= 70
                  ? "#6ee7d8"
                  : item.confidence >= 40
                    ? "#f4b860"
                    : "#8393a7";
              return (
                <g
                  key={item.id}
                  className="fallback-point"
                  onClick={() => onSelectRef.current(item)}
                >
                  <circle
                    cx={x}
                    cy={y}
                    r="13"
                    fill={color}
                    opacity=".15"
                    filter="url(#point-glow)"
                  />
                  <circle
                    cx={x}
                    cy={y}
                    r={item.confidence >= 70 ? 5 : 4}
                    fill={color}
                    opacity=".92"
                  />
                  <circle
                    cx={x}
                    cy={y}
                    r="9"
                    fill="none"
                    stroke={color}
                    strokeWidth="1"
                    opacity=".28"
                  />
                </g>
              );
            })}
          </svg>
          <div className="map-fallback__notice">
            <AlertTriangle size={13} />
            <span>
              {mode === "uncertainty"
                ? "Illustrative context halos require ArcGIS WebGL · points only in fallback"
                : "Simplified coordinate view · ArcGIS WebGL renderer unavailable"}
            </span>
          </div>
        </div>
      )}
      {mapState === "error" && (
        <div className="map-error">
          <AlertTriangle size={24} />
          <strong>Map rendering unavailable</strong>
          <span>
            The indicator list remains available. Check browser WebGL support or
            the tile connection.
          </span>
        </div>
      )}
      <div className="map-mode" aria-label="Map display mode">
        <Layers3 size={15} />
        {(["clusters", "heatmap", "uncertainty"] as MapMode[]).map((value) => (
          <button
            key={value}
            type="button"
            onClick={() => onModeChange(value)}
            className={mode === value ? "is-active" : ""}
          >
            {value === "uncertainty" ? "Context halo" : value}
          </button>
        ))}
      </div>
      <div className="map-controls">
        <button
          type="button"
          onClick={() => adjustZoom(1)}
          aria-label="Zoom in"
        >
          <Plus size={17} />
        </button>
        <button
          type="button"
          onClick={() => adjustZoom(-1)}
          aria-label="Zoom out"
        >
          <Minus size={17} />
        </button>
        <button type="button" onClick={recenter} aria-label="Reset map extent">
          <LocateFixed size={17} />
        </button>
        <button
          type="button"
          onClick={() => setIsFullscreen((value) => !value)}
          aria-label={isFullscreen ? "Exit fullscreen map" : "Expand map"}
        >
          <Maximize2 size={17} />
        </button>
      </div>
      <div className="map-legend">
        <span>
          <i className="map-legend__dot map-legend__dot--high" />
          High confidence
        </span>
        <span>
          <i className="map-legend__dot map-legend__dot--medium" />
          Medium
        </span>
        <span>
          <i className="map-legend__dot map-legend__dot--low" />
          Low
        </span>
        <span className="map-legend__note">
          {mode === "uncertainty"
            ? "Illustrative geodesic context radius · not an accuracy or confidence bound"
            : "Observed-host geolocation · approximate"}
        </span>
      </div>
      <div className="map-attribution">
        ArcGIS Maps SDK · Basemap © Esri or © OpenStreetMap contributors, CARTO
      </div>
    </div>
  );
}
