import { useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Download,
  Filter,
  Search,
} from "lucide-react";
import { IndicatorDetail } from "../components/IndicatorDetail";
import { Badge, Confidence, EmptyState, SkeletonRows } from "../components/UI";
import { useIndicators } from "../hooks/useThreatData";
import type { Indicator } from "../types";
import { rowsToCsv } from "../utils/csv";
import { downloadText, formatDate, formatRelative } from "../utils/format";

type SortKey = "lastSeen" | "confidence" | "malwareFamily" | "country";
const pageSize = 10;

export default function IndicatorsPage() {
  const query = useIndicators();
  const indicators = useMemo(() => query.data?.data ?? [], [query.data]);
  const sourceTotal = query.data?.total ?? indicators.length;
  const isSampled =
    query.data?.mode === "live" && sourceTotal > indicators.length;
  const [search, setSearch] = useState("");
  const [type, setType] = useState("all");
  const [confidence, setConfidence] = useState("all");
  const [source, setSource] = useState("all");
  const [sort, setSort] = useState<SortKey>("lastSeen");
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Indicator | null>(null);

  const sources = useMemo(
    () => [...new Set(indicators.map((item) => item.sourceFeed))].sort(),
    [indicators],
  );
  const filtered = useMemo(() => {
    const scoreFloor =
      confidence === "high"
        ? 70
        : confidence === "medium"
          ? 40
          : confidence === "low"
            ? 0
            : -1;
    const scoreCeiling =
      confidence === "medium" ? 69 : confidence === "low" ? 39 : 101;
    return indicators
      .filter((item) => {
        const haystack =
          `${item.value} ${item.malwareFamily} ${item.country} ${item.city} ${item.asn} ${item.asnOrg} ${item.tags.join(" ")}`.toLowerCase();
        return (
          haystack.includes(search.toLowerCase()) &&
          (type === "all" || item.type === type) &&
          (source === "all" || item.sourceFeed === source) &&
          item.confidence >= scoreFloor &&
          item.confidence <= scoreCeiling
        );
      })
      .sort((a, b) => {
        const left =
          sort === "lastSeen" ? new Date(a.lastSeen).getTime() : a[sort];
        const right =
          sort === "lastSeen" ? new Date(b.lastSeen).getTime() : b[sort];
        const result =
          typeof left === "number" && typeof right === "number"
            ? left - right
            : String(left).localeCompare(String(right));
        return direction === "asc" ? result : -result;
      });
  }, [confidence, direction, indicators, search, sort, source, type]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice(
    (Math.min(page, totalPages) - 1) * pageSize,
    Math.min(page, totalPages) * pageSize,
  );
  const activeFilters = [type, confidence, source].filter(
    (item) => item !== "all",
  ).length;

  const changeSort = (key: SortKey) => {
    if (sort === key)
      setDirection((value) => (value === "asc" ? "desc" : "asc"));
    else {
      setSort(key);
      setDirection("desc");
    }
  };

  const exportCsv = () => {
    const containsDemo = filtered.some((item) => item.isDemo === true);
    const containsLive = filtered.some((item) => item.isDemo === false);
    const rows = [
      [
        "value",
        "type",
        "malware_family",
        "confidence",
        "country",
        "city",
        "asn",
        "source",
        "provenance",
        "first_seen",
        "last_seen",
      ],
      ...filtered.map((item) => [
        item.value,
        item.type,
        item.malwareFamily,
        item.confidence,
        item.country,
        item.city,
        item.asn,
        item.sourceFeed,
        item.isDemo === true
          ? "synthetic_demo"
          : item.isDemo === false
            ? "live_feed"
            : "unknown",
        item.firstSeen,
        item.lastSeen,
      ]),
    ];
    downloadText(
      rowsToCsv(rows),
      `threatmesh-${containsDemo && containsLive ? "mixed-" : containsDemo ? "synthetic-demo-" : ""}ioc-observations${isSampled ? "-loaded-sample" : ""}-${formatDate(new Date().toISOString(), "yyyy-MM-dd")}.csv`,
      "text/csv",
    );
  };

  if (query.isLoading)
    return (
      <section className="panel">
        <SkeletonRows count={10} />
      </section>
    );
  if (query.isError)
    return (
      <section className="panel">
        <EmptyState
          title="Indicator request failed"
          description="The API returned an error. No demo indicators were mixed into this API-backed view."
        />
      </section>
    );
  if (query.data?.mode === "live" && indicators.length === 0)
    return (
      <section className="panel">
        <EmptyState
          allowSync
          title="No indicators available"
          description="The API is connected but has no normalized indicators. Start the initial OSINT synchronization to populate the explorer."
        />
      </section>
    );

  return (
    <div className="indicators-page">
      <section className="panel indicators-panel">
        <div className="indicator-toolbar">
          <label className="search-field search-field--wide">
            <Search size={17} />
            <input
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                setPage(1);
              }}
              placeholder="Search IOC, family, location, ASN, or tag…"
              aria-label="Search indicators"
            />
          </label>
          <button
            className="button button--primary"
            type="button"
            onClick={exportCsv}
          >
            <Download size={16} />
            {isSampled ? "Export loaded sample" : "Export CSV"}
          </button>
        </div>
        <div className="filter-row">
          <span>
            <Filter size={14} />
            Filters {activeFilters > 0 && <b>{activeFilters}</b>}
          </span>
          <label>
            Type
            <select
              value={type}
              onChange={(event) => {
                setType(event.target.value);
                setPage(1);
              }}
            >
              <option value="all">All types</option>
              <option value="ip">IP address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">Hash</option>
            </select>
          </label>
          <label>
            Confidence
            <select
              value={confidence}
              onChange={(event) => {
                setConfidence(event.target.value);
                setPage(1);
              }}
            >
              <option value="all">All scores</option>
              <option value="high">High · 70+</option>
              <option value="medium">Medium · 40–69</option>
              <option value="low">Low · &lt;40</option>
            </select>
          </label>
          <label>
            Source
            <select
              value={source}
              onChange={(event) => {
                setSource(event.target.value);
                setPage(1);
              }}
            >
              <option value="all">All feeds</option>
              {sources.map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
          </label>
          {activeFilters > 0 && (
            <button
              className="text-button"
              type="button"
              onClick={() => {
                setType("all");
                setConfidence("all");
                setSource("all");
              }}
            >
              Clear all
            </button>
          )}
          <span className="filter-row__result">
            {filtered.length} loaded result{filtered.length === 1 ? "" : "s"}
            {isSampled && ` · latest ${indicators.length} of ${sourceTotal}`}
          </span>
        </div>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Indicator</th>
                <th>Type</th>
                <SortableHeader
                  label="Malware family"
                  value="malwareFamily"
                  current={sort}
                  direction={direction}
                  onSort={changeSort}
                />
                <SortableHeader
                  label="Confidence"
                  value="confidence"
                  current={sort}
                  direction={direction}
                  onSort={changeSort}
                />
                <SortableHeader
                  label="Location"
                  value="country"
                  current={sort}
                  direction={direction}
                  onSort={changeSort}
                />
                <th>Source</th>
                <SortableHeader
                  label="Last observed"
                  value="lastSeen"
                  current={sort}
                  direction={direction}
                  onSort={changeSort}
                />
              </tr>
            </thead>
            <tbody>
              {visible.map((item) => (
                <tr
                  key={item.id}
                  className={selected?.id === item.id ? "is-selected" : ""}
                  onClick={() => setSelected(item)}
                >
                  <td>
                    <button
                      className="ioc-cell"
                      type="button"
                      onClick={() => setSelected(item)}
                    >
                      <span
                        className={`ioc-type-icon ioc-type-icon--${item.type}`}
                      >
                        {item.type === "ip"
                          ? "IP"
                          : item.type === "domain"
                            ? "D"
                            : item.type === "url"
                              ? "U"
                              : "#"}
                      </span>
                      <div>
                        <code>{item.value}</code>
                        <span>{item.tags.slice(0, 2).join(" · ")}</span>
                        {item.isDemo && (
                          <span className="demo-record-label">
                            Synthetic demo
                          </span>
                        )}
                      </div>
                    </button>
                  </td>
                  <td>
                    <Badge tone="neutral">{item.type}</Badge>
                  </td>
                  <td>
                    <strong className="table-primary">
                      {item.malwareFamily}
                    </strong>
                  </td>
                  <td>
                    <Confidence score={item.confidence} compact />
                  </td>
                  <td>
                    <span className="location-cell">
                      <i>{item.countryCode}</i>
                      <span>
                        {item.city}
                        <small>{item.country}</small>
                      </span>
                    </span>
                  </td>
                  <td>
                    <span className="source-cell">
                      <i>{item.sourceFeed.slice(0, 1)}</i>
                      {item.sourceFeed}
                    </span>
                  </td>
                  <td>
                    <time title={formatDate(item.lastSeen, "PPpp")}>
                      {formatRelative(item.lastSeen)}
                    </time>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {visible.length === 0 && (
            <div className="inline-empty">
              No indicators match the current query.
            </div>
          )}
        </div>
        <footer className="table-footer">
          <span>
            Showing{" "}
            {visible.length
              ? (Math.min(page, totalPages) - 1) * pageSize + 1
              : 0}
            –{Math.min(Math.min(page, totalPages) * pageSize, filtered.length)}{" "}
            of {filtered.length}
          </span>
          <div>
            <button
              type="button"
              disabled={page <= 1}
              onClick={() => setPage((value) => value - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft size={16} />
            </button>
            <span>
              Page {Math.min(page, totalPages)} of {totalPages}
            </span>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((value) => value + 1)}
              aria-label="Next page"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </footer>
      </section>
      {selected && (
        <>
          <button
            className="drawer-scrim"
            type="button"
            aria-label="Close indicator details"
            onClick={() => setSelected(null)}
          />
          <IndicatorDetail
            indicator={selected}
            onClose={() => setSelected(null)}
          />
        </>
      )}
    </div>
  );
}

function SortableHeader({
  label,
  value,
  current,
  direction,
  onSort,
}: {
  label: string;
  value: SortKey;
  current: SortKey;
  direction: "asc" | "desc";
  onSort: (value: SortKey) => void;
}) {
  return (
    <th>
      <button
        className="sort-button"
        type="button"
        onClick={() => onSort(value)}
      >
        {label}
        {current === value ? (
          direction === "asc" ? (
            <ArrowUp size={13} />
          ) : (
            <ArrowDown size={13} />
          )
        ) : (
          <ArrowUpDown size={13} />
        )}
      </button>
    </th>
  );
}
