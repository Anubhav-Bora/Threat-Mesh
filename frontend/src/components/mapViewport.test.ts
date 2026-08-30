import { describe, expect, it } from "vitest";
import {
  constrainFlatMapCenter,
  flatMapSafeExtent,
  MAX_FLAT_MAP_ZOOM,
  minimumFlatMapZoom,
  minimumRasterMapZoom,
  WEB_MERCATOR_HALF_WORLD,
} from "./mapViewport";

describe("map viewport constraints", () => {
  it.each([
    { width: 1000, height: 500, expected: 2, label: "standard" },
    { width: 1366, height: 460, expected: 3, label: "wide dashboard" },
    { width: 2635, height: 1484, expected: 4, label: "wide fullscreen" },
    { width: 390, height: 844, expected: 2, label: "portrait" },
  ])(
    "uses integer zoom $expected for the $label viewport",
    ({ width, height, expected }) => {
      expect(minimumFlatMapZoom(width, height)).toBe(expected);
      expect(minimumRasterMapZoom(width, height)).toBe(expected);
      expect(256 * 2 ** expected).toBeGreaterThanOrEqual(
        Math.max(width, height),
      );
    },
  );

  it("uses safe bounds for invalid and exceptionally large dimensions", () => {
    expect(minimumFlatMapZoom(0, Number.NaN)).toBe(1);
    expect(minimumRasterMapZoom(Number.NEGATIVE_INFINITY, -10)).toBe(1);
    expect(minimumFlatMapZoom(10_000_000, 10_000_000)).toBe(MAX_FLAT_MAP_ZOOM);
    expect(minimumRasterMapZoom(100_000_000, 100_000_000)).toBe(16);
  });

  it("keeps the entire portrait viewport inside the projected world", () => {
    const width = 390;
    const height = 844;
    const worldSize = 256 * 2 ** minimumFlatMapZoom(width, height);
    const resolution = (WEB_MERCATOR_HALF_WORLD * 2) / worldSize;
    const constrained = constrainFlatMapCenter({
      x: WEB_MERCATOR_HALF_WORLD,
      y: WEB_MERCATOR_HALF_WORLD,
      resolution,
      width,
      height,
    });
    const halfWidth = (width * resolution) / 2;
    const halfHeight = (height * resolution) / 2;

    expect(constrained.x - halfWidth).toBeGreaterThanOrEqual(
      -WEB_MERCATOR_HALF_WORLD,
    );
    expect(constrained.x + halfWidth).toBeLessThanOrEqual(
      WEB_MERCATOR_HALF_WORLD,
    );
    expect(constrained.y - halfHeight).toBeGreaterThanOrEqual(
      -WEB_MERCATOR_HALF_WORLD,
    );
    expect(constrained.y + halfHeight).toBeLessThanOrEqual(
      WEB_MERCATOR_HALF_WORLD,
    );
  });

  it("keeps ArcGIS geometry valid when a square viewport exactly fits the world", () => {
    const width = 2048;
    const height = 2048;
    const worldSize = 256 * 2 ** minimumFlatMapZoom(width, height);
    const extent = flatMapSafeExtent({
      resolution: (WEB_MERCATOR_HALF_WORLD * 2) / worldSize,
      width,
      height,
    });

    expect(extent.xmax - extent.xmin).toBe(1);
    expect(extent.ymax - extent.ymin).toBe(1);
  });

  it("falls back to the projected origin for an unusable center", () => {
    expect(
      constrainFlatMapCenter({
        x: Number.NaN,
        y: 1,
        resolution: 0,
        width: 1000,
        height: 500,
      }),
    ).toEqual({ x: 0, y: 0 });
  });
});
