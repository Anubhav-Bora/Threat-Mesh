import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";
import type {
  CSSProperties,
  KeyboardEvent as ReactKeyboardEvent,
  PointerEvent as ReactPointerEvent,
} from "react";
import type { Indicator } from "../types";
import { threatFamilyColor } from "./mapVisuals";
import type { MapMode } from "./ThreatMap";

const TILE_SIZE = 256;
const MIN_ZOOM = 1;
const MAX_ZOOM = 16;
const MAX_MERCATOR_LATITUDE = 85.05112878;
const DEFAULT_CENTER = { longitude: 18, latitude: 26 };

export const ARCGIS_BASE_TILE_SERVICE =
  "https://services.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer";
export const ARCGIS_REFERENCE_TILE_SERVICE =
  "https://services.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer";
export const ARCGIS_RASTER_ATTRIBUTION =
  "Powered by Esri · Imagery: Esri, Vantor, Earthstar Geographics, GIS User Community · Labels: Esri, HERE, Garmin, © OpenStreetMap contributors";

interface ArcGisRasterMapProps {
  indicators: Indicator[];
  mode: MapMode;
  onSelect: (indicator: Indicator) => void;
}

export interface ArcGisRasterMapHandle {
  adjustZoom: (delta: number) => void;
  recenter: () => void;
}

interface ViewportSize {
  width: number;
  height: number;
}

interface ProjectedMarker {
  item: Indicator & { latitude: number; longitude: number };
  left: number;
  top: number;
  precisionRadius: number;
}

interface DisplayMarker extends ProjectedMarker {
  key: string;
  members: ProjectedMarker[];
}

const clamp = (value: number, minimum: number, maximum: number) =>
  Math.min(maximum, Math.max(minimum, value));

const wrap = (value: number, modulus: number) =>
  ((value % modulus) + modulus) % modulus;

const worldSizeAt = (zoom: number) => TILE_SIZE * 2 ** zoom;

const longitudeToWorldX = (longitude: number, worldSize: number) =>
  ((longitude + 180) / 360) * worldSize;

const latitudeToWorldY = (latitude: number, worldSize: number) => {
  const clamped = clamp(
    latitude,
    -MAX_MERCATOR_LATITUDE,
    MAX_MERCATOR_LATITUDE,
  );
  const sine = Math.sin((clamped * Math.PI) / 180);
  return (0.5 - Math.log((1 + sine) / (1 - sine)) / (4 * Math.PI)) * worldSize;
};

const worldXToLongitude = (x: number, worldSize: number) =>
  (wrap(x, worldSize) / worldSize) * 360 - 180;

const worldYToLatitude = (y: number, worldSize: number) => {
  const normalized = 0.5 - clamp(y, 0, worldSize) / worldSize;
  return 90 - (360 * Math.atan(Math.exp(-normalized * 2 * Math.PI))) / Math.PI;
};

export const ArcGisRasterMap = forwardRef<
  ArcGisRasterMapHandle,
  ArcGisRasterMapProps
>(function ArcGisRasterMap({ indicators, mode, onSelect }, ref) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const lastWheelZoomRef = useRef(Number.NEGATIVE_INFINITY);
  const minimumZoomRef = useRef(MIN_ZOOM);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    startY: number;
    centerX: number;
    centerY: number;
  } | null>(null);
  const [size, setSize] = useState<ViewportSize>({
    width: 1000,
    height: 500,
  });
  const [center, setCenter] = useState(DEFAULT_CENTER);
  const [zoom, setZoom] = useState(2);
  const [dragging, setDragging] = useState(false);
  const minimumZoom = clamp(
    Math.ceil(
      Math.log2(Math.max(size.width, size.height, TILE_SIZE) / TILE_SIZE),
    ),
    MIN_ZOOM,
    MAX_ZOOM,
  );
  minimumZoomRef.current = minimumZoom;

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;

    const updateSize = () => {
      const width = viewport.clientWidth;
      const height = viewport.clientHeight;
      if (width > 0 && height > 0) setSize({ width, height });
    };

    updateSize();
    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(updateSize);
      observer.observe(viewport);
      return () => observer.disconnect();
    }

    window.addEventListener("resize", updateSize);
    return () => window.removeEventListener("resize", updateSize);
  }, []);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;

    const handleWheel = (event: globalThis.WheelEvent) => {
      if (event.ctrlKey || event.metaKey) return;
      event.preventDefault();
      const now = performance.now();
      if (now - lastWheelZoomRef.current < 160) return;
      lastWheelZoomRef.current = now;
      setZoom((value) =>
        clamp(
          value + (event.deltaY < 0 ? 1 : -1),
          minimumZoomRef.current,
          MAX_ZOOM,
        ),
      );
    };

    viewport.addEventListener("wheel", handleWheel, { passive: false });
    return () => viewport.removeEventListener("wheel", handleWheel);
  }, []);

  useEffect(() => {
    setZoom((value) => Math.max(value, minimumZoom));
  }, [minimumZoom]);

  const adjustZoom = (delta: number) =>
    setZoom((value) => clamp(value + delta, minimumZoom, MAX_ZOOM));
  const recenter = () => {
    setCenter(DEFAULT_CENTER);
    setZoom(Math.max(2, minimumZoom));
  };

  useImperativeHandle(ref, () => ({ adjustZoom, recenter }));

  const projection = useMemo(() => {
    const worldSize = worldSizeAt(zoom);
    return {
      worldSize,
      centerX: longitudeToWorldX(center.longitude, worldSize),
      centerY: latitudeToWorldY(center.latitude, worldSize),
    };
  }, [center, zoom]);

  const tiles = useMemo(() => {
    const { centerX, centerY } = projection;
    const tileCount = 2 ** zoom;
    const left = centerX - size.width / 2;
    const top = centerY - size.height / 2;
    const firstColumn = Math.floor(left / TILE_SIZE) - 1;
    const lastColumn = Math.floor((left + size.width) / TILE_SIZE) + 1;
    const firstRow = Math.max(0, Math.floor(top / TILE_SIZE) - 1);
    const lastRow = Math.min(
      tileCount - 1,
      Math.floor((top + size.height) / TILE_SIZE) + 1,
    );
    const visible = [];

    for (let row = firstRow; row <= lastRow; row += 1) {
      for (let column = firstColumn; column <= lastColumn; column += 1) {
        const wrappedColumn = wrap(column, tileCount);
        visible.push({
          key: `${zoom}-${column}-${row}`,
          left: column * TILE_SIZE - left,
          top: row * TILE_SIZE - top,
          baseUrl: `${ARCGIS_BASE_TILE_SERVICE}/tile/${zoom}/${row}/${wrappedColumn}`,
          referenceUrl: `${ARCGIS_REFERENCE_TILE_SERVICE}/tile/${zoom}/${row}/${wrappedColumn}`,
        });
      }
    }
    return visible;
  }, [projection, size, zoom]);

  const markers = useMemo(() => {
    const { centerX, centerY, worldSize } = projection;
    return indicators
      .filter(
        (item): item is Indicator & { latitude: number; longitude: number } =>
          item.latitude !== null &&
          item.longitude !== null &&
          Number.isFinite(item.latitude) &&
          Number.isFinite(item.longitude),
      )
      .map((item) => {
        let deltaX = longitudeToWorldX(item.longitude, worldSize) - centerX;
        if (deltaX > worldSize / 2) deltaX -= worldSize;
        if (deltaX < -worldSize / 2) deltaX += worldSize;
        const left = size.width / 2 + deltaX;
        const top =
          size.height / 2 +
          latitudeToWorldY(item.latitude, worldSize) -
          centerY;
        const metersPerPixel =
          (156543.03392 * Math.cos((item.latitude * Math.PI) / 180)) /
          2 ** zoom;
        const precisionRadius =
          item.locationPrecisionKm && item.locationPrecisionKm > 0
            ? clamp(
                (item.locationPrecisionKm * 1000) / Math.max(metersPerPixel, 1),
                9,
                28,
              )
            : 0;
        return { item, left, top, precisionRadius };
      })
      .filter(
        ({ left, top }) =>
          left >= -130 &&
          left <= size.width + 130 &&
          top >= -130 &&
          top <= size.height + 130,
      );
  }, [indicators, projection, size, zoom]);

  const displayMarkers = useMemo<DisplayMarker[]>(() => {
    if (mode !== "clusters") {
      return markers.map((marker) => ({
        ...marker,
        key: marker.item.id,
        members: [marker],
      }));
    }

    const cells = new Map<string, ProjectedMarker[]>();
    for (const marker of markers) {
      const key = `${Math.floor(marker.left / 54)}:${Math.floor(marker.top / 54)}`;
      const members = cells.get(key);
      if (members) members.push(marker);
      else cells.set(key, [marker]);
    }

    return Array.from(cells, ([key, members]) => {
      const primary = members.reduce((highest, candidate) =>
        candidate.item.confidence > highest.item.confidence
          ? candidate
          : highest,
      );
      return {
        ...primary,
        key,
        members,
        left:
          members.reduce((total, marker) => total + marker.left, 0) /
          members.length,
        top:
          members.reduce((total, marker) => total + marker.top, 0) /
          members.length,
      };
    });
  }, [markers, mode]);

  const panBy = (deltaX: number, deltaY: number) => {
    const verticalLimit = Math.min(size.height / 2, projection.worldSize / 2);
    setCenter({
      longitude: worldXToLongitude(
        projection.centerX + deltaX,
        projection.worldSize,
      ),
      latitude: worldYToLatitude(
        clamp(
          projection.centerY + deltaY,
          verticalLimit,
          projection.worldSize - verticalLimit,
        ),
        projection.worldSize,
      ),
    });
  };

  const handleKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    const movement = 96;
    const offsets: Partial<Record<string, [number, number]>> = {
      ArrowLeft: [-movement, 0],
      ArrowRight: [movement, 0],
      ArrowUp: [0, -movement],
      ArrowDown: [0, movement],
    };
    const offset = offsets[event.key];
    if (!offset) return;
    event.preventDefault();
    panBy(...offset);
  };

  const startDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    dragRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      centerX: projection.centerX,
      centerY: projection.centerY,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
    setDragging(true);
  };

  const moveDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== event.pointerId) return;
    const nextX = drag.centerX - (event.clientX - drag.startX);
    const nextY = drag.centerY - (event.clientY - drag.startY);
    const verticalLimit = Math.min(size.height / 2, projection.worldSize / 2);
    setCenter({
      longitude: worldXToLongitude(nextX, projection.worldSize),
      latitude: worldYToLatitude(
        clamp(nextY, verticalLimit, projection.worldSize - verticalLimit),
        projection.worldSize,
      ),
    });
  };

  const stopDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (dragRef.current?.pointerId !== event.pointerId) return;
    dragRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
    setDragging(false);
  };

  return (
    <div
      ref={viewportRef}
      className={`arcgis-raster-map ${dragging ? "is-dragging" : ""}`}
      role="region"
      tabIndex={0}
      aria-label="Interactive ArcGIS raster map of approximate threat infrastructure locations"
      aria-description="Use the arrow keys to pan. Use the external map controls to zoom or reset the view."
      data-arcgis-base-service={ARCGIS_BASE_TILE_SERVICE}
      onPointerDown={startDrag}
      onPointerMove={moveDrag}
      onPointerUp={stopDrag}
      onPointerCancel={stopDrag}
      onKeyDown={handleKeyDown}
    >
      <div className="arcgis-raster-map__tiles" aria-hidden="true">
        {tiles.map((tile) => (
          <div
            key={tile.key}
            className="arcgis-raster-map__tile"
            style={{ left: tile.left, top: tile.top }}
          >
            <img src={tile.baseUrl} alt="" draggable={false} />
            <img
              className="arcgis-raster-map__reference"
              src={tile.referenceUrl}
              alt=""
              draggable={false}
            />
          </div>
        ))}
      </div>
      <div className={`arcgis-raster-map__markers mode-${mode}`}>
        {displayMarkers.map(
          ({ key, item, left, top, precisionRadius, members }) => {
            const isCluster = members.length > 1;
            const confidence =
              item.confidence >= 70
                ? "high"
                : item.confidence >= 40
                  ? "medium"
                  : "low";
            return (
              <button
                key={key}
                className={`arcgis-raster-marker confidence-${confidence} ${isCluster ? "is-cluster" : ""}`}
                type="button"
                style={
                  {
                    left,
                    top,
                    "--marker-color": threatFamilyColor(item.malwareFamily),
                  } as CSSProperties
                }
                aria-label={
                  isCluster
                    ? `Zoom into cluster of ${members.length} indicators`
                    : `Open ${item.value}, ${item.confidence}% confidence`
                }
                title={
                  isCluster
                    ? `${members.length} indicators · zoom in`
                    : `${item.malwareFamily} · ${item.confidence}% confidence`
                }
                onPointerDown={(event) => event.stopPropagation()}
                onClick={() => {
                  if (!isCluster || zoom === MAX_ZOOM) {
                    onSelect(item);
                    return;
                  }
                  setCenter({
                    longitude: item.longitude,
                    latitude: item.latitude,
                  });
                  adjustZoom(1);
                }}
              >
                {mode === "uncertainty" && precisionRadius > 0 && (
                  <span
                    className="arcgis-raster-marker__precision"
                    style={{
                      width: precisionRadius * 2,
                      height: precisionRadius * 2,
                    }}
                  />
                )}
                <span className="arcgis-raster-marker__glow" />
                <span className="arcgis-raster-marker__dot" />
                {isCluster && (
                  <span className="arcgis-raster-marker__count">
                    {members.length}
                  </span>
                )}
              </button>
            );
          },
        )}
      </div>
    </div>
  );
});
