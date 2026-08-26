import { useMemo, useState } from "react";
import {
  Boxes,
  CalendarDays,
  ChevronRight,
  Filter,
  Network,
  Search,
  ShieldAlert,
} from "lucide-react";
import { CampaignGraph } from "../components/CampaignGraph";
import { Donut } from "../components/Charts";
import { Badge, EmptyState, PanelHeader, SkeletonRows } from "../components/UI";
import { useCampaigns } from "../hooks/useThreatData";
import type { Campaign } from "../types";
import { formatDate, formatRelative } from "../utils/format";

export default function CampaignsPage() {
  const query = useCampaigns();
  const campaigns = useMemo(() => query.data?.data ?? [], [query.data]);
  const [search, setSearch] = useState("");
  const [volume, setVolume] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const filtered = useMemo(
    () =>
      campaigns.filter(
        (campaign) =>
          (volume === "all" || campaign.volumeTier === volume) &&
          `${campaign.label} ${campaign.malwareFamilies.join(" ")} ${campaign.countries.join(" ")}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [campaigns, search, volume],
  );
  const selected: Campaign | undefined =
    campaigns.find((campaign) => campaign.id === selectedId) ?? filtered[0];
  const selectedEvidence = selected
    ? [
        ...selected.relationshipEvidence.repeatedIndicators.map((item) => ({
          label: item.indicatorKey,
          detail: `${item.observationCount} repeated ${item.iocType} observations`,
        })),
        ...selected.relationshipEvidence.malwareFamilies.map((item) => ({
          label: item.value,
          detail: `${item.uniqueIndicatorCount} unique indicators share this family`,
        })),
        ...selected.relationshipEvidence.asns.map((item) => ({
          label: item.value,
          detail: `${item.uniqueIndicatorCount} unique indicators share this ASN`,
        })),
      ]
    : [];

  if (query.isLoading)
    return (
      <section className="panel">
        <SkeletonRows count={7} />
      </section>
    );
  if (query.isError)
    return (
      <section className="panel">
        <EmptyState
          title="Campaign request failed"
          description="The API returned an error. ThreatMesh has not substituted synthetic campaign records."
        />
      </section>
    );
  if (query.data?.mode === "live" && campaigns.length === 0)
    return (
      <section className="panel">
        <EmptyState
          title="No campaign communities yet"
          description="The API is connected, but clustering has not produced a campaign. Ingest and enrich IOCs, then run the campaign clustering job."
        />
      </section>
    );

  return (
    <div className="campaigns-layout">
      <section className="panel campaign-list-panel">
        <div className="list-toolbar">
          <label className="search-field">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search campaigns"
              aria-label="Search campaigns"
            />
          </label>
          <label className="select-field select-field--compact">
            <Filter size={14} />
            <select
              value={volume}
              onChange={(event) => setVolume(event.target.value)}
              aria-label="Filter by IOC volume"
            >
              <option value="all">All volumes</option>
              <option value="large">Large · 50+ IOCs</option>
              <option value="medium">Medium · 20–49</option>
              <option value="small">Small · &lt;20</option>
            </select>
          </label>
        </div>
        <div className="result-count">
          <span>{filtered.length} campaigns</span>
          <span>Ranked by latest activity</span>
        </div>
        <div className="campaign-list">
          {filtered.map((campaign) => (
            <button
              key={campaign.id}
              type="button"
              className={`campaign-card ${selected?.id === campaign.id ? "campaign-card--selected" : ""}`}
              onClick={() => setSelectedId(campaign.id)}
            >
              <div className="campaign-card__head">
                <span
                  className={`volume-marker volume-marker--${campaign.volumeTier}`}
                />
                <div>
                  <strong>{campaign.label}</strong>
                  <span>{campaign.actor}</span>
                </div>
                {campaign.isDemo && <Badge tone="info">Synthetic demo</Badge>}
                <Badge
                  tone={
                    campaign.volumeTier === "large"
                      ? "purple"
                      : campaign.volumeTier === "medium"
                        ? "info"
                        : "neutral"
                  }
                >
                  {campaign.volumeTier} volume
                </Badge>
              </div>
              <p>{campaign.summary}</p>
              <div className="campaign-card__stats">
                <span>
                  <Boxes size={14} />
                  {campaign.uniqueIndicatorCount} unique IOCs
                </span>
                <span>
                  <Network size={14} />
                  {campaign.countries.length} regions
                </span>
                <span>{formatRelative(campaign.lastSeen)}</span>
              </div>
              <div className="campaign-card__trend">
                <span>Inspect evidence</span>
                <ChevronRight size={17} />
              </div>
            </button>
          ))}
          {filtered.length === 0 && (
            <div className="inline-empty">
              No campaigns match these filters.
            </div>
          )}
        </div>
      </section>

      {selected && (
        <section className="campaign-detail">
          <article className="panel campaign-hero">
            <div className="campaign-hero__head">
              <div>
                <span className="eyebrow">
                  {selected.id} · infrastructure community
                </span>
                <h2>{selected.label}</h2>
                {selected.isDemo && (
                  <Badge tone="info">Synthetic demo community</Badge>
                )}
                <p>{selected.summary}</p>
              </div>
              {selected.averageIocConfidenceAvailable !== false ? (
                <Donut
                  value={selected.averageIocConfidence}
                  label="Average IOC confidence"
                />
              ) : (
                <div className="metric-unavailable">
                  <strong>N/A</strong>
                  <span>
                    Confidence scoring
                    <br />
                    not provided by API
                  </span>
                </div>
              )}
            </div>
            <div className="campaign-metrics">
              <div>
                <span>Unique indicators</span>
                <strong>{selected.uniqueIndicatorCount}</strong>
              </div>
              <div>
                <span>Source observations</span>
                <strong>{selected.observationCount}</strong>
              </div>
              <div>
                <span>First observed</span>
                <strong>{formatDate(selected.firstSeen, "MMM d, yyyy")}</strong>
              </div>
              <div>
                <span>Last observed</span>
                <strong>{formatRelative(selected.lastSeen)}</strong>
              </div>
            </div>
            <div className="attribution-note">
              <ShieldAlert size={17} />
              <p>
                <strong>Analytical boundary:</strong> grouping reflects shared
                normalized indicators, or malware-family and ASN co-occurrence
                within a configured time window—not confirmed common ownership
                or actor attribution. Time, country, and source alone do not
                create a relationship.
              </p>
            </div>
          </article>

          <article className="panel graph-panel">
            <PanelHeader
              eyebrow="Correlation inputs"
              title="Relationship evidence graph"
            />
            <CampaignGraph campaign={selected} />
          </article>

          <div className="campaign-detail-grid">
            <article className="panel compact-panel">
              <PanelHeader
                eyebrow="Correlation inputs"
                title="Relationship evidence"
              />
              <div className="evidence-list">
                {selectedEvidence.map((item, index) => (
                  <div key={`${item.label}-${index}`}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{item.label}</strong>
                      <small>{item.detail}</small>
                    </div>
                  </div>
                ))}
                {selectedEvidence.length === 0 && (
                  <div className="inline-empty">
                    No repeated relationship signal was included in this
                    campaign summary.
                  </div>
                )}
              </div>
            </article>
            <article className="panel compact-panel">
              <PanelHeader
                eyebrow="Observed behavior"
                title="ATT&CK techniques"
              />
              <div className="technique-list">
                {selected.techniqueIds.map((id) => (
                  <div key={id}>
                    <Badge tone="purple">{id}</Badge>
                    <span>Mapped from public malware reporting</span>
                  </div>
                ))}
              </div>
            </article>
            <article className="panel compact-panel">
              <PanelHeader eyebrow="Scope" title="Timeline & regions" />
              <div className="timeline-summary">
                <CalendarDays size={18} />
                <span>
                  {formatDate(selected.firstSeen)} —{" "}
                  {formatDate(selected.lastSeen)}
                </span>
              </div>
              <div className="tag-list">
                {selected.countries.map((country) => (
                  <Badge key={country} tone="neutral">
                    {country}
                  </Badge>
                ))}
                {selected.observedSources.map((source) => (
                  <Badge key={source} tone="info">
                    Source: {source}
                  </Badge>
                ))}
              </div>
            </article>
          </div>
        </section>
      )}
    </div>
  );
}
