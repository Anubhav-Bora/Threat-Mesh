import { useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  BookOpen,
  ExternalLink,
  Search,
  ShieldCheck,
} from "lucide-react";
import { Badge, EmptyState, PanelHeader, SkeletonRows } from "../components/UI";
import { useTechniques } from "../hooks/useThreatData";
import type { AttackTechnique } from "../types";

const tacticOrder = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export default function AttackPage() {
  const query = useTechniques();
  const techniques = useMemo(() => query.data?.data ?? [], [query.data]);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<AttackTechnique | null>(null);
  const filtered = useMemo(
    () =>
      techniques.filter((item) =>
        `${item.id} ${item.name} ${(item.tactics ?? [item.tactic]).join(" ")} ${item.malwareFamilies.join(" ")}`
          .toLowerCase()
          .includes(search.toLowerCase()),
      ),
    [techniques, search],
  );
  const groups = tacticOrder
    .map((tactic) => ({
      tactic,
      items: filtered.filter((item) =>
        (item.tactics ?? [item.tactic]).includes(tactic),
      ),
    }))
    .filter((group) => group.items.length);
  const max = Math.max(...techniques.map((item) => item.observations), 1);
  const hasBaseline = techniques.some((item) => item.hasBaseline !== false);
  const trending = [...techniques]
    .sort((a, b) =>
      hasBaseline
        ? b.observations -
          b.previousObservations -
          (a.observations - a.previousObservations)
        : b.observations - a.observations,
    )
    .slice(0, 5);

  if (query.isLoading)
    return (
      <section className="panel">
        <SkeletonRows count={8} />
      </section>
    );
  if (query.isError)
    return (
      <section className="panel">
        <EmptyState
          title="ATT&CK catalog request failed"
          description="The API returned an error. ThreatMesh has not substituted illustrative technique data."
        />
      </section>
    );
  if (query.data?.mode === "live" && techniques.length === 0)
    return (
      <section className="panel">
        <EmptyState
          title="No ATT&CK mappings available"
          description="Load the official Enterprise ATT&CK STIX bundle and run malware-family mapping to populate this view."
        />
      </section>
    );

  return (
    <div className="attack-page">
      <section className="panel attack-matrix-panel">
        <div className="matrix-toolbar">
          <div>
            <PanelHeader
              eyebrow="Enterprise matrix"
              title="Observed technique intensity"
            />
            <p>
              Color reflects observation volume in the selected period, not
              inherent technique severity.
            </p>
          </div>
          <label className="search-field">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search ID, technique, family"
              aria-label="Search ATT&CK techniques"
            />
          </label>
        </div>
        <div
          className="attack-matrix"
          role="list"
          aria-label="MITRE ATT&CK technique matrix"
        >
          {groups.map((group) => (
            <section className="tactic-column" key={group.tactic}>
              <header>
                <span>{group.tactic}</span>
                <small>
                  {group.items.length} technique
                  {group.items.length === 1 ? "" : "s"}
                </small>
              </header>
              <div>
                {group.items.map((technique) => {
                  const intensity = Math.max(
                    0.12,
                    technique.observations / max,
                  );
                  const delta =
                    technique.observations - technique.previousObservations;
                  return (
                    <button
                      key={technique.id}
                      type="button"
                      onClick={() => setSelected(technique)}
                      className={`technique-tile ${selected?.id === technique.id ? "technique-tile--selected" : ""}`}
                      style={
                        { "--intensity": intensity } as React.CSSProperties
                      }
                    >
                      <span>{technique.id}</span>
                      <strong>{technique.name}</strong>
                      <small>
                        {technique.observations} observations{" "}
                        {technique.hasBaseline !== false && (
                          <i className={delta >= 0 ? "positive" : "negative"}>
                            {delta >= 0 ? "+" : ""}
                            {delta}
                          </i>
                        )}
                      </small>
                    </button>
                  );
                })}
              </div>
            </section>
          ))}
        </div>
        <div className="matrix-legend">
          <span>Observation intensity</span>
          <i />
          <i />
          <i />
          <i />
          <i />
          <small>Low</small>
          <small>High</small>
        </div>
      </section>

      <aside className="attack-sidebar">
        <section className="panel trending-panel">
          <PanelHeader
            eyebrow={
              hasBaseline
                ? "Compared with prior period"
                : "Current seven-day window"
            }
            title={
              hasBaseline ? "Technique momentum" : "Top observed techniques"
            }
          />
          <div className="trend-rank-list">
            {trending.map((technique, index) => {
              const delta =
                technique.observations - technique.previousObservations;
              return (
                <button
                  key={technique.id}
                  type="button"
                  onClick={() => setSelected(technique)}
                >
                  <span className="trend-rank">{index + 1}</span>
                  <div>
                    <strong>{technique.name}</strong>
                    <span>
                      {technique.id} ·{" "}
                      {(technique.tactics ?? [technique.tactic]).join(" · ")}
                    </span>
                  </div>
                  <span className={delta >= 0 ? "positive" : "negative"}>
                    {hasBaseline ? (
                      <>
                        {delta >= 0 ? (
                          <ArrowUp size={13} />
                        ) : (
                          <ArrowDown size={13} />
                        )}
                        {Math.abs(delta)}
                      </>
                    ) : (
                      technique.observations
                    )}
                  </span>
                </button>
              );
            })}
          </div>
        </section>
        <section className="panel technique-detail-card">
          {selected ? (
            <>
              <div className="technique-detail-card__head">
                <Badge tone="purple">{selected.id}</Badge>
                <a
                  href={`https://attack.mitre.org/techniques/${selected.id.replace(".", "/")}/`}
                  target="_blank"
                  rel="noreferrer"
                  aria-label="Open technique on MITRE ATT&CK"
                >
                  <ExternalLink size={16} />
                </a>
              </div>
              <span className="eyebrow">
                {(selected.tactics ?? [selected.tactic]).join(" · ")}
              </span>
              <h2>{selected.name}</h2>
              <p>{selected.description}</p>
              <div className="observation-total">
                <strong>{selected.observations}</strong>
                <span>
                  observations
                  <br />
                  this period
                </span>
              </div>
              <h3>Associated malware</h3>
              {selected.malwareFamilies.length > 0 ? (
                <div className="tag-list">
                  {selected.malwareFamilies.map((family) => (
                    <Badge key={family}>{family}</Badge>
                  ))}
                </div>
              ) : (
                <p className="muted">
                  Family associations are not supplied by this catalog view.
                </p>
              )}
              <div className="method-note">
                <ShieldCheck size={15} />
                Mappings originate from known family behavior and public
                reporting; an IOC alone does not prove technique execution.
              </div>
            </>
          ) : (
            <div className="select-prompt">
              <BookOpen size={28} />
              <strong>Select a technique</strong>
              <span>Inspect its description, trend, and evidence context.</span>
            </div>
          )}
        </section>
      </aside>
    </div>
  );
}
