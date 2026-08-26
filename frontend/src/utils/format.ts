import { format, formatDistanceToNowStrict } from "date-fns";
import type { ConfidenceBand } from "../types";

export const formatNumber = (value: number) =>
  new Intl.NumberFormat("en-US", {
    notation: value >= 10_000 ? "compact" : "standard",
    maximumFractionDigits: 1,
  }).format(value);

export const formatDate = (value: string, pattern = "MMM d, yyyy") => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : format(date, pattern);
};

export const formatUtcDateTime = (value: string) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return `${new Intl.DateTimeFormat("en-US", {
    timeZone: "UTC",
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(date)} UTC`;
};

export const formatIsoUtc = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toISOString();
};

export const formatRelative = (value: string) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Unknown"
    : `${formatDistanceToNowStrict(date)} ago`;
};

export const confidenceBand = (score: number): ConfidenceBand =>
  score >= 70 ? "high" : score >= 40 ? "medium" : "low";

export const formatDelta = (value: number) =>
  `${value > 0 ? "+" : ""}${value}%`;

export const clamp = (value: number, min: number, max: number) =>
  Math.max(min, Math.min(max, value));

export const downloadText = (
  content: string,
  filename: string,
  type = "text/plain",
) => {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
};

export const rangeToDays = (range: string) =>
  ({ "24h": 1, "7d": 7, "30d": 30, "90d": 90, all: Infinity })[range] ?? 30;
