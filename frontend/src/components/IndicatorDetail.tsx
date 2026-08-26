import {
  Building2,
  CalendarClock,
  Fingerprint,
  Globe2,
  Network,
  ShieldCheck,
  X,
} from "lucide-react";
import type { Indicator } from "../types";
import { formatRelative, formatUtcDateTime } from "../utils/format";
import { Badge, Confidence, CopyButton } from "./UI";

export function IndicatorDetail({
  indicator,
  onClose,
  variant = "drawer",
}: {
  indicator: Indicator;
  onClose?: () => void;
  variant?: "drawer" | "panel";
}) {
  return (
    <aside
      className={`indicator-detail indicator-detail--${variant}`}
      aria-label={`Indicator details for ${indicator.value}`}
    >
      <div className="indicator-detail__head">
        <div>
          <span className="eyebrow">Indicator evidence</span>
          <h2>{indicator.malwareFamily}</h2>
        </div>
        {onClose && (
          <button
            className="icon-button"
            type="button"
            onClick={onClose}
            aria-label="Close details"
          >
            <X size={18} />
          </button>
        )}
      </div>
      <div className="indicator-value">
        <Fingerprint size={18} />
        <code>{indicator.value}</code>
        <CopyButton text={indicator.value} label="" />
      </div>
      <div className="indicator-detail__badges">
        <Badge tone="purple">{indicator.type.toUpperCase()}</Badge>
        {indicator.isDemo && <Badge tone="info">Synthetic demo</Badge>}
        {indicator.status && (
          <Badge
            tone={
              indicator.status === "active"
                ? "critical"
                : indicator.status === "monitoring"
                  ? "warning"
                  : "neutral"
            }
            dot
          >
            {indicator.status}
          </Badge>
        )}
        <Confidence score={indicator.confidence} />
      </div>
      <section className="detail-section">
        <h3>Context</h3>
        <dl className="detail-grid">
          <div>
            <dt>
              <Globe2 size={14} />
              Approximate location
            </dt>
            <dd>
              {indicator.city}, {indicator.country}
            </dd>
          </div>
          <div>
            <dt>
              <Network size={14} />
              Network
            </dt>
            <dd>{indicator.asn}</dd>
          </div>
          <div>
            <dt>
              <Building2 size={14} />
              Organization
            </dt>
            <dd>{indicator.asnOrg}</dd>
          </div>
          <div>
            <dt>
              <ShieldCheck size={14} />
              Corroboration
            </dt>
            <dd>
              {indicator.corroboratingFeeds === null
                ? "Not supplied by source"
                : `${indicator.corroboratingFeeds} feed${indicator.corroboratingFeeds === 1 ? "" : "s"}`}
            </dd>
          </div>
          <div>
            <dt>
              <CalendarClock size={14} />
              First seen
            </dt>
            <dd>{formatUtcDateTime(indicator.firstSeen)}</dd>
          </div>
          <div>
            <dt>
              <CalendarClock size={14} />
              Last seen
            </dt>
            <dd>{formatRelative(indicator.lastSeen)}</dd>
          </div>
        </dl>
      </section>
      <section className="detail-section">
        <h3>MITRE ATT&CK</h3>
        <div className="tag-list">
          {indicator.techniqueIds.length ? (
            indicator.techniqueIds.map((id) => (
              <Badge key={id} tone="purple">
                {id}
              </Badge>
            ))
          ) : (
            <span className="muted">No technique mapping</span>
          )}
        </div>
      </section>
      <section className="detail-section">
        <h3>Provenance</h3>
        <div className="provenance-row">
          <span className="source-logo">
            {indicator.sourceFeed.slice(0, 2).toUpperCase()}
          </span>
          <div>
            <strong>{indicator.sourceFeed}</strong>
            <span>Public OSINT · normalized by ThreatMesh</span>
          </div>
        </div>
        <p className="method-note">
          Geolocation describes observed infrastructure, not an operator or
          victim location.{" "}
          {indicator.locationPrecisionKm === null
            ? "No illustrative location context radius is available for this observation."
            : `Context-halo mode renders a configured ${indicator.locationPrecisionKm} km geodesic visual buffer. It is not provider-measured accuracy or a confidence bound.`}
        </p>
      </section>
    </aside>
  );
}
