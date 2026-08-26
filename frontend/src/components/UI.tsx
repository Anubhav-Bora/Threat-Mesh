import type { LucideIcon } from "lucide-react";
import {
  Check,
  Copy,
  DatabaseZap,
  Terminal,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import { useState } from "react";
import type { ConfidenceBand, Severity } from "../types";
import { confidenceBand, formatDelta, formatNumber } from "../utils/format";

export function PageLoader({ label = "Loading" }: { label?: string }) {
  return (
    <div className="page-loader" role="status">
      <LogoLoader />
      <span>{label}</span>
    </div>
  );
}

export function LogoLoader() {
  return (
    <span className="logo-loader" aria-hidden="true">
      <span />
      <span />
      <span />
    </span>
  );
}

export function Badge({
  children,
  tone = "neutral",
  dot = false,
}: {
  children: React.ReactNode;
  tone?:
    | Severity
    | ConfidenceBand
    | "neutral"
    | "info"
    | "success"
    | "warning"
    | "purple";
  dot?: boolean;
}) {
  return (
    <span className={`badge badge--${tone}`}>
      {dot && <span className="badge__dot" />}
      {children}
    </span>
  );
}

export function Confidence({
  score,
  compact = false,
}: {
  score: number;
  compact?: boolean;
}) {
  const band = confidenceBand(score);
  return (
    <span className={`confidence confidence--${band}`}>
      <span
        className="confidence__ring"
        style={{ "--score": score } as React.CSSProperties}
      />
      <span>{compact ? score : `${score}% · ${band}`}</span>
    </span>
  );
}

export function KpiCard({
  label,
  value,
  trend,
  icon: Icon,
  helper,
  accent = "teal",
}: {
  label: string;
  value: number;
  trend: number | null;
  icon: LucideIcon;
  helper: string;
  accent?: "teal" | "violet" | "amber" | "blue";
}) {
  const up = (trend ?? 0) >= 0;
  return (
    <article className={`kpi-card kpi-card--${accent}`}>
      <div className="kpi-card__top">
        <span>{label}</span>
        <span className="kpi-card__icon">
          <Icon size={19} />
        </span>
      </div>
      <div className="kpi-card__value">{formatNumber(value)}</div>
      <div className="kpi-card__meta">
        {trend === null ? (
          <span className="muted">Current snapshot</span>
        ) : (
          <span className={up ? "positive" : "negative"}>
            {up ? <TrendingUp size={13} /> : <TrendingDown size={13} />}
            {formatDelta(trend)}
          </span>
        )}
        <span>{helper}</span>
      </div>
    </article>
  );
}

export function PanelHeader({
  eyebrow,
  title,
  action,
}: {
  eyebrow?: string;
  title: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="panel-header">
      <div>
        {eyebrow && <span>{eyebrow}</span>}
        <h2>{title}</h2>
      </div>
      {action}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  allowSync = false,
}: {
  title: string;
  description: string;
  allowSync?: boolean;
}) {
  const [showOperatorAction, setShowOperatorAction] = useState(false);
  const syncCommand = `$env:ADMIN_API_KEY = Read-Host 'Enter the same ADMIN_API_KEY value from .env'
$headers = @{'X-API-Key' = $env:ADMIN_API_KEY}
Invoke-RestMethod -Method Post -Uri 'http://localhost:8000/api/v1/feeds/sync' -Headers $headers`;
  return (
    <div className="empty-state">
      <span className="empty-state__icon">
        <DatabaseZap size={28} />
      </span>
      <h2>{title}</h2>
      <p>{description}</p>
      {allowSync && (
        <button
          className="button button--primary"
          type="button"
          onClick={() => setShowOperatorAction((value) => !value)}
        >
          <Terminal size={16} />
          Operator sync instructions
        </button>
      )}
      {showOperatorAction && (
        <div className="operator-instruction">
          <strong>PowerShell · trusted operator shell</strong>
          <code>{syncCommand}</code>
          <CopyButton text={syncCommand} label="Copy command" />
          <span>
            Paste the root <code>ADMIN_API_KEY</code> value at the prompt.
            PowerShell does not load Compose <code>.env</code> automatically;
            the key is intentionally never stored in browser code.
          </span>
        </div>
      )}
    </div>
  );
}

export function CopyButton({
  text,
  label = "Copy",
}: {
  text: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };
  return (
    <button
      className="button button--ghost button--small"
      type="button"
      onClick={copy}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
      {copied ? "Copied" : label}
    </button>
  );
}

export function SkeletonRows({ count = 5 }: { count?: number }) {
  return (
    <div className="skeleton-list" aria-label="Loading data">
      {Array.from({ length: count }, (_, index) => (
        <span
          key={index}
          style={{ "--delay": `${index * 80}ms` } as React.CSSProperties}
        />
      ))}
    </div>
  );
}
