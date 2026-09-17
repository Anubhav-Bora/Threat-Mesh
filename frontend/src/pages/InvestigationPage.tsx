import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Download,
  FileJson2,
  LoaderCircle,
  ScanSearch,
  ShieldQuestion,
} from "lucide-react";
import { type FormEvent, useMemo, useState } from "react";

import { ApiRequestError, threatApi } from "../api/client";
import { Badge, PanelHeader } from "../components/UI";
import type { InvestigationResult } from "../types";
import { downloadText, formatUtcDateTime } from "../utils/format";
import "./InvestigationPage.css";

const MAX_OBSERVABLES = 100;

function parseObservables(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\n,\r]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ).slice(0, MAX_OBSERVABLES);
}

function csvCell(value: string | number): string {
  return `"${String(value).replaceAll('"', '""')}"`;
}

export default function InvestigationPage() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const observables = useMemo(() => parseObservables(input), [input]);

  const investigate = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!observables.length) return;
    setIsRunning(true);
    setError(null);
    try {
      setResult(await threatApi.investigateIocs(observables));
    } catch (requestError) {
      setResult(null);
      setError(
        requestError instanceof ApiRequestError || requestError instanceof Error
          ? requestError.message
          : "Investigation could not be completed.",
      );
    } finally {
      setIsRunning(false);
    }
  };

  const exportStix = async () => {
    if (!result?.matches.length) return;
    setIsExporting(true);
    setError(null);
    try {
      const bundle = await threatApi.exportStixIocs(
        result.matches.map((match) => match.query),
      );
      downloadText(
        `${JSON.stringify(bundle, null, 2)}\n`,
        "threatmesh-indicators-stix-2.1.json",
        "application/stix+json",
      );
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "STIX export could not be generated.",
      );
    } finally {
      setIsExporting(false);
    }
  };

  const exportCsv = () => {
    if (!result?.matches.length) return;
    const header = [
      "observable",
      "type",
      "confidence",
      "malware_family",
      "source",
      "last_seen_utc",
      "blocklist_eligible",
      "warnings",
    ];
    const rows = result.matches.map(
      ({ indicator, blocklistEligible, warnings }) =>
        [
          indicator.value,
          indicator.type,
          indicator.confidence,
          indicator.malwareFamily,
          indicator.sourceFeed,
          indicator.lastSeen,
          blocklistEligible ? "yes" : "no",
          warnings.join("; "),
        ]
          .map(csvCell)
          .join(","),
    );
    downloadText(
      `${header.join(",")}\n${rows.join("\n")}\n`,
      "threatmesh-investigation.csv",
      "text/csv",
    );
  };

  const exportBlocklist = () => {
    if (!result?.matches.length) return;
    const values = Array.from(
      new Set(
        result.matches
          .filter((match) => match.blocklistEligible)
          .map(({ indicator }) => indicator.value),
      ),
    ).sort();
    const excluded = new Set(
      result.matches
        .filter((match) => !match.blocklistEligible)
        .map(({ indicator }) => indicator.value),
    ).size;
    downloadText(
      `# ThreatMesh matched indicators - analyst review required\n# ${excluded} non-global or reserved value(s) excluded\n${values.join("\n")}\n`,
      "threatmesh-blocklist.txt",
    );
  };

  return (
    <div className="investigation-layout">
      <section className="panel investigation-input">
        <PanelHeader eyebrow="Bulk lookup" title="Alert observables" />
        <div className="investigation-guidance">
          <ScanSearch size={20} />
          <div>
            <strong>Exact evidence matching</strong>
            <span>
              Paste IPs, domains, URLs, or MD5/SHA-1/SHA-256 hashes. Defanged
              forms such as hxxps and [.] are normalized safely.
            </span>
          </div>
        </div>
        <form onSubmit={investigate}>
          <label htmlFor="investigation-observables">Observables</label>
          <textarea
            id="investigation-observables"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder={
              "31.57.51.110\nmalicious.example\nhttps://example.test/payload"
            }
            spellCheck={false}
            rows={12}
          />
          <div className="investigation-form__footer">
            <span>
              {observables.length} / {MAX_OBSERVABLES} unique values
            </span>
            <button
              className="button button--primary"
              type="submit"
              disabled={!observables.length || isRunning}
            >
              {isRunning ? (
                <LoaderCircle className="investigation-spin" size={16} />
              ) : (
                <ClipboardCheck size={16} />
              )}
              Investigate
            </button>
          </div>
        </form>
        <p className="investigation-caveat">
          <ShieldQuestion size={15} /> No match means "not present in the
          current ThreatMesh corpus," not "safe." Matches are observations, not
          automatic blocking decisions.
        </p>
      </section>

      <section className="panel investigation-results">
        <PanelHeader
          eyebrow="Evidence"
          title="Triage results"
          action={
            result ? (
              <Badge tone="success">{result.matched} matched</Badge>
            ) : undefined
          }
        />
        {!result && !error && (
          <div className="investigation-placeholder">
            <ShieldQuestion size={34} />
            <strong>Ready for an observable set</strong>
            <span>
              Results retain source, confidence, family, and recency context.
            </span>
          </div>
        )}
        {error && (
          <div className="investigation-error" role="alert">
            <AlertTriangle size={18} /> {error}
          </div>
        )}
        {result && (
          <>
            <div className="investigation-summary">
              <div>
                <strong>{result.queried}</strong>
                <span>Queried</span>
              </div>
              <div>
                <strong>{result.matched}</strong>
                <span>Matched</span>
              </div>
              <div>
                <strong>{result.unmatched.length}</strong>
                <span>Unknown</span>
              </div>
              <div>
                <strong>{result.invalid.length}</strong>
                <span>Invalid</span>
              </div>
            </div>

            {result.matches.length > 0 && (
              <>
                <div className="investigation-actions">
                  <button
                    className="button button--ghost"
                    type="button"
                    onClick={exportStix}
                    disabled={isExporting}
                  >
                    <FileJson2 size={15} />
                    {isExporting ? "Building STIX..." : "STIX 2.1"}
                  </button>
                  <button
                    className="button button--ghost"
                    type="button"
                    onClick={exportCsv}
                  >
                    <Download size={15} /> CSV
                  </button>
                  <button
                    className="button button--ghost"
                    type="button"
                    onClick={exportBlocklist}
                  >
                    <Download size={15} /> Blocklist
                  </button>
                </div>
                <div className="investigation-table-wrap">
                  <table className="investigation-table">
                    <thead>
                      <tr>
                        <th>Observable</th>
                        <th>Context</th>
                        <th>Confidence</th>
                        <th>Last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.matches.map(
                        ({
                          query,
                          normalizedQuery,
                          indicator,
                          blocklistEligible,
                          warnings,
                        }) => (
                          <tr key={`${query}-${indicator.id}`}>
                            <td>
                              <code>{indicator.value}</code>
                              {query !== normalizedQuery && (
                                <span>Normalized from {query}</span>
                              )}
                              <Badge
                                tone={blocklistEligible ? "neutral" : "warning"}
                              >
                                {blocklistEligible ? indicator.type : "review"}
                              </Badge>
                            </td>
                            <td>
                              <strong>
                                {indicator.malwareFamily || "Unclassified"}
                              </strong>
                              <span>
                                {indicator.sourceFeed} /{" "}
                                {indicator.corroboratingFeeds ?? 1} source(s)
                              </span>
                              {warnings.map((warning) => (
                                <span
                                  className="investigation-warning"
                                  key={warning}
                                >
                                  {warning}
                                </span>
                              ))}
                            </td>
                            <td>
                              <span
                                className={`investigation-score investigation-score--${indicator.confidence >= 70 ? "high" : indicator.confidence >= 40 ? "medium" : "low"}`}
                              >
                                {Math.round(indicator.confidence)}
                              </span>
                            </td>
                            <td>{formatUtcDateTime(indicator.lastSeen)}</td>
                          </tr>
                        ),
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {(result.unmatched.length > 0 || result.invalid.length > 0) && (
              <div className="investigation-exceptions">
                {result.unmatched.length > 0 && (
                  <div>
                    <strong>Valid but not observed</strong>
                    <span>{result.unmatched.join(" / ")}</span>
                  </div>
                )}
                {result.invalid.length > 0 && (
                  <div>
                    <strong>Malformed or unsupported</strong>
                    <span>{result.invalid.join(" / ")}</span>
                  </div>
                )}
              </div>
            )}
            {result.matched > 0 && (
              <div className="investigation-success">
                <CheckCircle2 size={17} /> Exports contain matched evidence
                only; the plain blocklist also excludes local and reserved
                values.
              </div>
            )}
          </>
        )}
      </section>
    </div>
  );
}
