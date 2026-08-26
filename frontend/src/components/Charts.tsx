import { clamp } from "../utils/format";

export function Sparkline({
  values,
  color = "#6ee7d8",
  width = 120,
  height = 36,
}: {
  values: number[];
  color?: string;
  width?: number;
  height?: number;
}) {
  if (values.length < 2) return <div className="sparkline-empty" />;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const points = values
    .map(
      (value, index) =>
        `${(index / (values.length - 1)) * width},${height - 3 - ((value - min) / range) * (height - 7)}`,
    )
    .join(" ");
  const area = `0,${height} ${points} ${width},${height}`;
  return (
    <svg
      className="sparkline"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`Trend from ${values[0]} to ${values[values.length - 1]}`}
    >
      <defs>
        <linearGradient
          id={`spark-${color.replace("#", "")}`}
          x1="0"
          y1="0"
          x2="0"
          y2="1"
        >
          <stop offset="0" stopColor={color} stopOpacity=".24" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#spark-${color.replace("#", "")})`} />
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

interface TrendDatum {
  label: string;
  value: number;
  high: number;
}

export function AreaTrendChart({ data }: { data: TrendDatum[] }) {
  const width = 800;
  const height = 210;
  const padding = { left: 18, right: 12, top: 18, bottom: 30 };
  const max = Math.max(...data.flatMap((item) => [item.value, item.high]), 1);
  const point = (value: number, index: number) => ({
    x:
      padding.left +
      (index / (data.length - 1)) * (width - padding.left - padding.right),
    y:
      padding.top + (1 - value / max) * (height - padding.top - padding.bottom),
  });
  const primary = data.map((item, index) => point(item.value, index));
  const secondary = data.map((item, index) => point(item.high, index));
  const line = (points: Array<{ x: number; y: number }>) =>
    points
      .map((p, index) => `${index === 0 ? "M" : "L"}${p.x},${p.y}`)
      .join(" ");
  const area = `${line(primary)} L${primary.at(-1)?.x},${height - padding.bottom} L${primary[0]?.x},${height - padding.bottom} Z`;
  return (
    <div className="area-chart">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="Indicator ingestion during the last 24 hours"
      >
        <defs>
          <linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#756bf0" stopOpacity=".28" />
            <stop offset="1" stopColor="#756bf0" stopOpacity=".01" />
          </linearGradient>
        </defs>
        {[0, 0.25, 0.5, 0.75, 1].map((level) => (
          <line
            key={level}
            x1={padding.left}
            x2={width - padding.right}
            y1={padding.top + level * (height - padding.top - padding.bottom)}
            y2={padding.top + level * (height - padding.top - padding.bottom)}
            className="area-chart__grid"
          />
        ))}
        <path d={area} fill="url(#trend-fill)" />
        <path d={line(primary)} className="area-chart__primary" />
        <path d={line(secondary)} className="area-chart__secondary" />
        {data.map(
          (item, index) =>
            index % 2 === 0 && (
              <text
                key={item.label}
                x={point(item.value, index).x}
                y={height - 8}
                textAnchor="middle"
              >
                {item.label}
              </text>
            ),
        )}
      </svg>
    </div>
  );
}

export function Donut({
  value,
  size = 82,
  label,
}: {
  value: number;
  size?: number;
  label?: string;
}) {
  const normalized = clamp(value, 0, 100);
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  return (
    <div className="donut" style={{ width: size, height: size }}>
      <svg
        viewBox="0 0 68 68"
        aria-label={`${label ?? "Score"} ${normalized}%`}
      >
        <circle cx="34" cy="34" r={radius} className="donut__track" />
        <circle
          cx="34"
          cy="34"
          r={radius}
          className="donut__value"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - normalized / 100)}
        />
      </svg>
      <strong>
        {normalized}
        <small>%</small>
      </strong>
    </div>
  );
}
