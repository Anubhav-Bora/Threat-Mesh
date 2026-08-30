const ARCGIS_TILE_SIZE = 256;
const MIN_FLAT_MAP_ZOOM = 1;
export const MAX_FLAT_MAP_ZOOM = 14;
export const WEB_MERCATOR_HALF_WORLD = 20_037_508.342789244;
const MINIMUM_SAFE_EXTENT_SPAN_METERS = 1;

const finitePositive = (value: number, fallback: number) =>
  Number.isFinite(value) && value > 0 ? value : fallback;

export const minimumFlatMapZoom = (width: number, height: number) => {
  const safeWidth = finitePositive(width, ARCGIS_TILE_SIZE);
  const safeHeight = finitePositive(height, ARCGIS_TILE_SIZE);
  return Math.min(
    MAX_FLAT_MAP_ZOOM,
    Math.max(
      MIN_FLAT_MAP_ZOOM,
      Math.ceil(Math.log2(Math.max(safeWidth, safeHeight) / ARCGIS_TILE_SIZE)),
    ),
  );
};

export const minimumRasterMapZoom = (width: number, height: number) => {
  const safeWidth = finitePositive(width, ARCGIS_TILE_SIZE);
  const safeHeight = finitePositive(height, ARCGIS_TILE_SIZE);
  return Math.min(
    16,
    Math.max(
      MIN_FLAT_MAP_ZOOM,
      Math.ceil(Math.log2(Math.max(safeWidth, safeHeight) / ARCGIS_TILE_SIZE)),
    ),
  );
};

const clamp = (value: number, minimum: number, maximum: number) =>
  Math.min(maximum, Math.max(minimum, value));

const normalizeWorldX = (x: number) => {
  const worldWidth = WEB_MERCATOR_HALF_WORLD * 2;
  return (
    ((((x + WEB_MERCATOR_HALF_WORLD) % worldWidth) + worldWidth) % worldWidth) -
    WEB_MERCATOR_HALF_WORLD
  );
};

interface ConstrainCenterInput {
  x: number;
  y: number;
  resolution: number;
  width: number;
  height: number;
}

interface FlatMapSafeExtentInput {
  resolution: number;
  width: number;
  height: number;
}

export const flatMapSafeExtent = ({
  resolution,
  width,
  height,
}: FlatMapSafeExtentInput) => {
  const safeResolution = finitePositive(resolution, 0);
  const safeWidth = finitePositive(width, 0);
  const safeHeight = finitePositive(height, 0);
  const halfViewportWidth = Math.min(
    WEB_MERCATOR_HALF_WORLD,
    (safeWidth * safeResolution) / 2,
  );
  const halfViewportHeight = Math.min(
    WEB_MERCATOR_HALF_WORLD,
    (safeHeight * safeResolution) / 2,
  );

  let xmin = -WEB_MERCATOR_HALF_WORLD + halfViewportWidth;
  let ymin = -WEB_MERCATOR_HALF_WORLD + halfViewportHeight;
  let xmax = WEB_MERCATOR_HALF_WORLD - halfViewportWidth;
  let ymax = WEB_MERCATOR_HALF_WORLD - halfViewportHeight;

  // ArcGIS cannot navigate against a point extent. A one-metre span remains
  // far below a screen pixel at world-scale zoom while keeping the geometry
  // constraint numerically valid on square, power-of-two viewports.
  if (xmax - xmin < MINIMUM_SAFE_EXTENT_SPAN_METERS) {
    xmin = -MINIMUM_SAFE_EXTENT_SPAN_METERS / 2;
    xmax = MINIMUM_SAFE_EXTENT_SPAN_METERS / 2;
  }
  if (ymax - ymin < MINIMUM_SAFE_EXTENT_SPAN_METERS) {
    ymin = -MINIMUM_SAFE_EXTENT_SPAN_METERS / 2;
    ymax = MINIMUM_SAFE_EXTENT_SPAN_METERS / 2;
  }

  return { xmin, ymin, xmax, ymax };
};

export const constrainFlatMapCenter = ({
  x,
  y,
  resolution,
  width,
  height,
}: ConstrainCenterInput) => {
  if (
    !Number.isFinite(x) ||
    !Number.isFinite(y) ||
    !Number.isFinite(resolution) ||
    resolution <= 0
  )
    return { x: 0, y: 0 };

  const extent = flatMapSafeExtent({ resolution, width, height });

  return {
    x: clamp(normalizeWorldX(x), extent.xmin, extent.xmax),
    y: clamp(y, extent.ymin, extent.ymax),
  };
};
