import {
  AlertTriangle,
  Building2,
  CalendarClock,
  CheckCircle2,
  CircleDashed,
  Database,
  Fingerprint,
  Globe2,
  GitBranch,
  Network,
  ShieldCheck,
  X,
} from "lucide-react";
import { useIndicatorLineage } from "../hooks/useThreatData";
import type { Indicator, IndicatorLineage } from "../types";
import { formatRelative, formatUtcDateTime } from "../utils/format";
import { Badge, Confidence, CopyButton } from "./UI";

type EvidenceStageStatus = "complete" | "pending" | "unavailable";

interface EvidenceStage {
  label: string;
  summary: string;
  detail: string;
  status: EvidenceStageStatus;
}

function evidenceStages(lineage: IndicatorLineage): EvidenceStage[] {
  const observations = lineage.provenance.observations;
  const distinctSources = new Set(
    observations.map((item) => item.sourceFeed).filter(Boolean),
  ).size;
  const rawEvidence = lineage.provenance.rawPayload;
  const location = [lineage.enrichment.city, lineage.enrichment.country]
    .filter(Boolean)
    .join(", ");
  const artifactCount =
    lineage.derivedArtifacts.rules.length +
    lineage.derivedArtifacts.reportMentions.length;

  return [
    {
      label: "Source observation",
      summary: observations.length
        ? `${observations.length} retained observation${observations.length === 1 ? "" : "s"} across ${distinctSources} source${distinctSources === 1 ? "" : "s"}`
        : "No source observation records returned",
      detail: rawEvidence.retained
        ? `Original payload retained with ${rawEvidence.fieldNames.length} indexed field${rawEvidence.fieldNames.length === 1 ? "" : "s"}${rawEvidence.sha256 ? ` · SHA-256 ${rawEvidence.sha256.slice(0, 12)}…` : ""}`
        : "Original source payload is not retained for this observation",
      status: observations.length ? "complete" : "unavailable",
    },
    {
      label: "Canonical identity",
      summary: `${lineage.identity.type.toUpperCase()} normalized for correlation${lineage.identity.port === null ? "" : ` on port ${lineage.identity.port}`}`,
      detail: lineage.identity.isDemo
        ? "Synthetic demonstration record isolated from live analysis"
        : "Live-source record normalized by the ingestion pipeline",
      status: "complete",
    },
    {
      label: "Infrastructure enrichment",
      summary:
        lineage.enrichment.status === "available"
          ? location || lineage.enrichment.asn || "Network context attached"
          : lineage.enrichment.status === "not_applicable"
            ? "Not applicable to this indicator type"
            : "No enrichment evidence available",
      detail:
        lineage.enrichment.status === "available"
          ? `${lineage.enrichment.method}${lineage.enrichment.provider ? ` · ${lineage.enrichment.provider}` : ""}${lineage.enrichment.approximate ? " · approximate" : ""}`
          : lineage.enrichment.method,
      status:
        lineage.enrichment.status === "available" ? "complete" : "unavailable",
    },
    {
      label: "Analytic derivation",
      summary:
        lineage.confidence.status === "available" &&
        lineage.confidence.total !== null
          ? `${lineage.confidence.total}/100 confidence · ${lineage.attackMappings.length} ATT&CK mapping${lineage.attackMappings.length === 1 ? "" : "s"}`
          : "Confidence calculation pending",
      detail: lineage.campaignMembership
        ? `Current campaign hypothesis: ${lineage.campaignMembership.label}`
        : "No current campaign membership",
      status:
        lineage.confidence.status === "available" ? "complete" : "pending",
    },
    {
      label: "Downstream artifacts",
      summary: artifactCount
        ? `${lineage.derivedArtifacts.rules.length} detection rule${lineage.derivedArtifacts.rules.length === 1 ? "" : "s"} · ${lineage.derivedArtifacts.reportMentions.length} report mention${lineage.derivedArtifacts.reportMentions.length === 1 ? "" : "s"}`
        : "No derived rule or report references",
      detail: artifactCount
        ? lineage.derivedArtifacts.rules.some((rule) => rule.requiresReview)
          ? "Generated detections require analyst review before deployment"
          : "Derived outputs remain traceable to this record"
        : "No downstream artifact references are recorded in this snapshot",
      status: artifactCount ? "complete" : "unavailable",
    },
  ];
}

function ScoreEvidence({ lineage }: { lineage: IndicatorLineage }) {
  const confidence = lineage.confidence;
  return (
    <section className="detail-section lineage-score-section">
      <div className="detail-section__title">
        <h3>Why this score</h3>
        {confidence.status === "available" && confidence.total !== null ? (
          <span className="lineage-score-total">{confidence.total} / 100</span>
        ) : (
          <span className="lineage-status lineage-status--pending">
            Pending
          </span>
        )}
      </div>
      {confidence.components.length ? (
        <div className="score-evidence-list">
          {confidence.components.map((component) => {
            const ratio =
              component.maxScore > 0
                ? Math.min(
                    100,
                    Math.max(0, (component.score / component.maxScore) * 100),
                  )
                : 0;
            return (
              <div className="score-evidence" key={component.key}>
                <div className="score-evidence__head">
                  <strong>{component.label}</strong>
                  <span>
                    {component.score} / {component.maxScore}
                  </span>
                </div>
                <div
                  className="score-evidence__track"
                  role="progressbar"
                  aria-label={`${component.label} contribution`}
                  aria-valuemin={0}
                  aria-valuemax={component.maxScore}
                  aria-valuenow={component.score}
                >
                  <span style={{ width: `${ratio}%` }} />
                </div>
                <p>{component.evidence}</p>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="lineage-empty">
          Component evidence will appear after the next confidence analysis.
        </p>
      )}
      <p className="lineage-method">
        {confidence.formulaVersion
          ? `Formula ${confidence.formulaVersion}`
          : "Formula version pending"}
        {confidence.calculatedAt
          ? ` · calculated ${formatUtcDateTime(confidence.calculatedAt)}`
          : ""}
      </p>
    </section>
  );
}

function formatSourceHint(value: number): string {
  return `${Math.round(value)}%`;
}

function EvidenceRecords({ lineage }: { lineage: IndicatorLineage }) {
  const evidenceCount =
    lineage.provenance.observations.length +
    lineage.attackMappings.length +
    (lineage.campaignMembership ? 1 : 0) +
    lineage.derivedArtifacts.rules.length +
    lineage.derivedArtifacts.reportMentions.length;

  return (
    <details className="lineage-records">
      <summary>
        <span>
          <Database size={13} />
          Inspect evidence records
        </span>
        <b>{evidenceCount}</b>
      </summary>
      <div className="lineage-record-groups">
        {lineage.provenance.observations.length > 0 && (
          <section>
            <h4>Source observations</h4>
            <ul>
              {lineage.provenance.observations.map((observation) => (
                <li key={observation.recordId}>
                  <div>
                    <code>{observation.recordId}</code>
                    {observation.isSelected && <span>Selected</span>}
                  </div>
                  <strong>{observation.sourceFeed}</strong>
                  <small>
                    {formatUtcDateTime(observation.firstSeen)} →{" "}
                    {formatUtcDateTime(observation.lastSeen)}
                    {observation.sourceConfidenceHint === null
                      ? ""
                      : ` · source hint ${formatSourceHint(observation.sourceConfidenceHint)}`}
                  </small>
                </li>
              ))}
            </ul>
          </section>
        )}
        {lineage.attackMappings.length > 0 && (
          <section>
            <h4>ATT&CK mappings</h4>
            <ul>
              {lineage.attackMappings.map((mapping) => (
                <li key={mapping.recordId}>
                  <code>{mapping.recordId}</code>
                  <strong>
                    {mapping.techniqueId} · {mapping.name}
                  </strong>
                  <small>
                    {mapping.method} · basis: {mapping.basis} ·{" "}
                    {mapping.inference ? "inferred context" : "direct evidence"}
                  </small>
                </li>
              ))}
            </ul>
          </section>
        )}
        {lineage.campaignMembership && (
          <section>
            <h4>Campaign membership</h4>
            <ul>
              <li>
                <code>{lineage.campaignMembership.recordId}</code>
                <strong>{lineage.campaignMembership.label}</strong>
                <small>
                  Current snapshot
                  {lineage.campaignMembership.reasons.length
                    ? ` · ${lineage.campaignMembership.reasons.join(" · ")}`
                    : " · no relationship reason supplied"}
                </small>
              </li>
            </ul>
          </section>
        )}
        {(lineage.derivedArtifacts.rules.length > 0 ||
          lineage.derivedArtifacts.reportMentions.length > 0) && (
          <section>
            <h4>Derived artifacts</h4>
            <ul>
              {lineage.derivedArtifacts.rules.map((rule) => (
                <li key={rule.recordId}>
                  <code>{rule.recordId}</code>
                  <strong>{rule.ruleType.toUpperCase()} detection</strong>
                  <small>
                    {rule.requiresReview
                      ? "Analyst review required"
                      : "No review flag"}
                    {rule.generatedAt
                      ? ` · generated ${formatUtcDateTime(rule.generatedAt)}`
                      : ""}
                  </small>
                </li>
              ))}
              {lineage.derivedArtifacts.reportMentions.map((report) => (
                <li key={report.recordId}>
                  <code>{report.recordId}</code>
                  <strong>{report.title}</strong>
                  <small>
                    Coverage {formatUtcDateTime(report.periodStart)} →{" "}
                    {formatUtcDateTime(report.periodEnd)}
                  </small>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </details>
  );
}

function EvidencePath({ lineage }: { lineage: IndicatorLineage }) {
  const stages = evidenceStages(lineage);
  return (
    <section className="detail-section">
      <div className="detail-section__title">
        <h3>Evidence path</h3>
        <span className="lineage-record-id">{lineage.recordId}</span>
      </div>
      <ol className="evidence-path">
        {stages.map((stage) => (
          <li key={stage.label} data-status={stage.status}>
            <span className="evidence-path__marker" aria-hidden="true">
              {stage.status === "complete" ? (
                <CheckCircle2 size={15} />
              ) : stage.status === "pending" ? (
                <CircleDashed size={15} />
              ) : (
                <Database size={14} />
              )}
            </span>
            <div>
              <strong>{stage.label}</strong>
              <span>{stage.summary}</span>
              <small>{stage.detail}</small>
            </div>
          </li>
        ))}
      </ol>
      <EvidenceRecords lineage={lineage} />
      {lineage.limitations.length > 0 && (
        <details className="lineage-limitations">
          <summary>
            <AlertTriangle size={13} />
            Analyst caveats ({lineage.limitations.length})
          </summary>
          <ul>
            {lineage.limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}

export function IndicatorDetail({
  indicator,
  onClose,
  variant = "drawer",
}: {
  indicator: Indicator;
  onClose?: () => void;
  variant?: "drawer" | "panel";
}) {
  const lineageQuery = useIndicatorLineage(indicator.id);
  const lineage = lineageQuery.data?.data ?? null;

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
        {indicator.confidenceAvailable === false ? (
          <Badge tone="neutral">Analysis pending</Badge>
        ) : (
          <Confidence score={indicator.confidence} />
        )}
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
      {lineageQuery.isLoading ? (
        <section className="detail-section">
          <div className="lineage-loading" role="status">
            <GitBranch size={15} />
            Loading evidence lineage…
          </div>
        </section>
      ) : lineage ? (
        <>
          <ScoreEvidence lineage={lineage} />
          <EvidencePath lineage={lineage} />
        </>
      ) : (
        <section className="detail-section">
          <div className="lineage-loading lineage-loading--error" role="status">
            <AlertTriangle size={15} />
            Evidence lineage is unavailable for this observation.
          </div>
        </section>
      )}
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
