import { useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  BrainCircuit,
  CheckCircle2,
  DatabaseZap,
  KeyRound,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";
import { useState } from "react";

import {
  ApiRequestError,
  type FeedSlug,
  type OperationResponse,
  threatApi,
} from "../api/client";
import { Badge, PanelHeader } from "./UI";
import "./OperationsCenter.css";

type OperationName = FeedSlug | "enrichment" | "analysis" | "refresh";

const feeds: Array<{
  id: FeedSlug;
  label: string;
  description: string;
  speed: string;
}> = [
  {
    id: "feodo",
    label: "Feodo Tracker",
    description: "Botnet command-and-control infrastructure from abuse.ch.",
    speed: "Fast",
  },
  {
    id: "urlhaus",
    label: "URLhaus",
    description: "Active malware delivery URLs and hosting infrastructure.",
    speed: "Medium",
  },
  {
    id: "threatfox",
    label: "ThreatFox",
    description: "Malware indicators shared by the threat research community.",
    speed: "Large import",
  },
];

function summarize(result: OperationResponse, fallback: string): string {
  const numeric = Object.entries(result.details ?? {})
    .filter(([, value]) => typeof value === "number")
    .slice(0, 3)
    .map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`);
  return numeric.length ? `${fallback} ${numeric.join(" | ")}` : fallback;
}

export function OperationsCenter({ enabled }: { enabled: boolean }) {
  const queryClient = useQueryClient();
  const [adminKey, setAdminKey] = useState("");
  const [active, setActive] = useState<OperationName | null>(null);
  const [notice, setNotice] = useState<{
    kind: "success" | "error" | "info";
    text: string;
  } | null>(null);
  const ready = enabled && adminKey.trim().length > 0 && active === null;

  const refreshDashboard = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ["feed-status"] }),
      queryClient.invalidateQueries({ queryKey: ["summary"] }),
      queryClient.invalidateQueries({ queryKey: ["indicators"] }),
      queryClient.invalidateQueries({ queryKey: ["campaigns"] }),
      queryClient.invalidateQueries({ queryKey: ["techniques"] }),
      queryClient.invalidateQueries({ queryKey: ["rules"] }),
    ]);
  };

  const execute = async (
    name: OperationName,
    action: () => Promise<OperationResponse>,
    successMessage: string,
  ) => {
    setActive(name);
    setNotice({ kind: "info", text: "Operation started. Keep this tab open." });
    try {
      const result = await action();
      await refreshDashboard();
      setNotice({ kind: "success", text: summarize(result, successMessage) });
      return true;
    } catch (error) {
      const message =
        error instanceof ApiRequestError || error instanceof Error
          ? error.message
          : "The operation could not be completed.";
      setNotice({ kind: "error", text: message });
      return false;
    } finally {
      setActive(null);
    }
  };

  const runFeed = (feed: FeedSlug) =>
    execute(
      feed,
      () => threatApi.syncFeed(feed, adminKey),
      `${feeds.find((item) => item.id === feed)?.label ?? feed} synchronized.`,
    );

  const runFastRefresh = async () => {
    setActive("refresh");
    setNotice({
      kind: "info",
      text: "Refreshing Feodo and URLhaus, then rebuilding intelligence.",
    });
    try {
      await threatApi.syncFeed("feodo", adminKey);
      await threatApi.syncFeed("urlhaus", adminKey);
      await threatApi.runEnrichment(adminKey);
      await threatApi.runAnalysis(adminKey);
      await refreshDashboard();
      setNotice({
        kind: "success",
        text: "Fast refresh completed. Dashboards now use the latest intelligence.",
      });
    } catch (error) {
      setNotice({
        kind: "error",
        text:
          error instanceof Error
            ? error.message
            : "Fast refresh could not be completed.",
      });
    } finally {
      setActive(null);
    }
  };

  return (
    <section className="panel operations-center" id="operations">
      <PanelHeader
        eyebrow="Administration"
        title="Operations center"
        action={
          <Badge tone={enabled ? "success" : "warning"}>
            {enabled ? "API online" : "API unavailable"}
          </Badge>
        }
      />

      <div className="operations-primary">
        <div>
          <span className="operations-kicker">
            <ShieldAlert size={15} /> Live intelligence controls
          </span>
          <h3>Refresh threat data without a server or cron job</h3>
          <p>
            Keys remain only in this tab's memory and are never saved to local
            storage. Every feed sync also removes records older than 30 days.
          </p>
        </div>
        <button
          className="button button--primary"
          type="button"
          disabled={!ready}
          onClick={runFastRefresh}
        >
          {active === "refresh" ? (
            <LoaderCircle className="operations-spin" size={16} />
          ) : (
            <RefreshCw size={16} />
          )}
          Run fast refresh
        </button>
      </div>

      <label className="operations-auth">
        <span>
          <KeyRound size={16} /> Administrator API key
        </span>
        <input
          type="password"
          value={adminKey}
          onChange={(event) => setAdminKey(event.target.value)}
          placeholder="Enter ADMIN_API_KEY for this session"
          autoComplete="off"
          spellCheck={false}
        />
      </label>

      <div className="operations-grid">
        {feeds.map((feed) => (
          <article className="operation-card" key={feed.id}>
            <div className="operation-card__head">
              <DatabaseZap size={19} />
              <Badge>{feed.speed}</Badge>
            </div>
            <h3>{feed.label}</h3>
            <p>{feed.description}</p>
            <button
              className="button button--ghost"
              type="button"
              disabled={!ready}
              onClick={() => runFeed(feed.id)}
            >
              {active === feed.id ? (
                <LoaderCircle className="operations-spin" size={15} />
              ) : (
                <Play size={15} />
              )}
              Sync source
            </button>
          </article>
        ))}

        <article className="operation-card operation-card--workflow">
          <div className="operation-card__head">
            <Activity size={19} />
            <Badge tone="success">Workflow</Badge>
          </div>
          <h3>Enrich indicators</h3>
          <p>
            Add geographic and contextual metadata to newly ingested indicators.
          </p>
          <button
            className="button button--ghost"
            type="button"
            disabled={!ready}
            onClick={() =>
              execute(
                "enrichment",
                () => threatApi.runEnrichment(adminKey),
                "Enrichment completed.",
              )
            }
          >
            {active === "enrichment" ? (
              <LoaderCircle className="operations-spin" size={15} />
            ) : (
              <Play size={15} />
            )}
            Run enrichment
          </button>
        </article>

        <article className="operation-card operation-card--workflow">
          <div className="operation-card__head">
            <BrainCircuit size={19} />
            <Badge tone="success">Workflow</Badge>
          </div>
          <h3>Analyze intelligence</h3>
          <p>
            Recalculate risk, campaigns, ATT&amp;CK mappings, clusters, and
            detection rules.
          </p>
          <button
            className="button button--ghost"
            type="button"
            disabled={!ready}
            onClick={() =>
              execute(
                "analysis",
                () => threatApi.runAnalysis(adminKey),
                "Analysis completed.",
              )
            }
          >
            {active === "analysis" ? (
              <LoaderCircle className="operations-spin" size={15} />
            ) : (
              <Play size={15} />
            )}
            Run analysis
          </button>
        </article>
      </div>

      {notice && (
        <div
          className={`operations-notice operations-notice--${notice.kind}`}
          role="status"
        >
          {notice.kind === "success" ? (
            <CheckCircle2 size={17} />
          ) : notice.kind === "error" ? (
            <ShieldAlert size={17} />
          ) : (
            <LoaderCircle className="operations-spin" size={17} />
          )}
          <span>{notice.text}</span>
        </div>
      )}
    </section>
  );
}
