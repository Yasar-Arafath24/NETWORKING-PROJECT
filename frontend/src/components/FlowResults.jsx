
import { useMemo, useState } from "react";
import {
  Activity,
  Search,
  ShieldAlert,
  ShieldCheck,
  ArrowDownUp,
  Filter,
  Network,
  Info,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

function formatNumber(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString() : String(value);
}

function formatDuration(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  return Number.isFinite(number) ? `${number.toFixed(3)} s` : String(value);
}

function getProtocol(flow) {
  return String(flow.protocol ?? flow.protocol_name ?? "Unknown").toUpperCase();
}

function getClassification(flow) {
  const label = String(
    flow.label ?? flow.classification ?? flow.anomaly_prediction ?? ""
  ).toUpperCase();

  if (
    flow.anomaly === true ||
    flow.is_anomaly === true ||
    flow.is_suspicious === true ||
    flow.suspicious === true ||
    label.includes("SUSPICIOUS") ||
    label.includes("ANOMAL")
  ) {
    return "SUSPICIOUS";
  }

  if (
    flow.anomaly === false ||
    label === "NORMAL" ||
    label === "BENIGN"
  ) {
    return "NORMAL";
  }

  return "UNAVAILABLE";
}

function getExplanation(flow) {
  if (flow.explanation) return String(flow.explanation);

  const classification = getClassification(flow);
  const score = Number(flow.anomaly_score);

  if (classification === "SUSPICIOUS") {
    return Number.isFinite(score)
      ? `The model marked this flow as unusual. Its anomaly score is ${score.toFixed(6)}. Investigate the endpoints, protocol, packet volume, and timing.`
      : "The model marked this flow as unusual. Review its endpoints, protocol, packet volume, and timing.";
  }

  if (classification === "NORMAL") {
    return Number.isFinite(score)
      ? `The model classified this flow as normal relative to its learned patterns. Anomaly score: ${score.toFixed(6)}. This does not guarantee the traffic is safe.`
      : "The model classified this flow as normal relative to its learned patterns. This does not guarantee the traffic is safe.";
  }

  return "No usable anomaly classification was returned for this flow.";
}

function getScore(flow) {
  if (flow.anomaly_score === null || flow.anomaly_score === undefined || flow.anomaly_score === "") {
    return null;
  }

  const score = Number(flow.anomaly_score);
  return Number.isFinite(score) ? score : null;
}

function getEndpoints(flow) {
  return [
    flow.src_ip ?? flow.source_ip ?? flow.source ?? "",
    flow.dst_ip ?? flow.destination_ip ?? flow.destination ?? "",
  ];
}

export default function FlowResults({ flows = [] }) {
  const safeFlows = Array.isArray(flows) ? flows : [];

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [securityFilter, setSecurityFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("packets");
  const [sortDescending, setSortDescending] = useState(true);
  const [expandedFlow, setExpandedFlow] = useState(null);

  const protocols = useMemo(
    () => ["ALL", ...new Set(safeFlows.map(getProtocol))],
    [safeFlows]
  );

  const counts = useMemo(() => {
    const suspicious = safeFlows.filter(
      (flow) => getClassification(flow) === "SUSPICIOUS"
    ).length;
    const normal = safeFlows.filter(
      (flow) => getClassification(flow) === "NORMAL"
    ).length;
    const unavailable = safeFlows.length - suspicious - normal;

    return { suspicious, normal, unavailable };
  }, [safeFlows]);

  const filteredFlows = useMemo(() => {
    const query = search.trim().toLowerCase();

    const result = safeFlows.filter((flow) => {
      const protocol = getProtocol(flow);
      const [source, destination] = getEndpoints(flow);
      const classification = getClassification(flow);

      const searchable = [
        protocol,
        source,
        destination,
        flow.src_port,
        flow.dst_port,
        flow.label,
        flow.explanation,
      ]
        .filter((value) => value !== null && value !== undefined)
        .join(" ")
        .toLowerCase();

      const matchesSearch = !query || searchable.includes(query);
      const matchesProtocol =
        protocolFilter === "ALL" || protocol === protocolFilter;
      const matchesSecurity =
        securityFilter === "ALL" || classification === securityFilter;

      return matchesSearch && matchesProtocol && matchesSecurity;
    });

    const sortValues = {
      packets: (flow) => Number(flow.packet_count ?? flow.packets ?? 0),
      bytes: (flow) =>
        Number(flow.total_bytes ?? flow.bytes ?? flow.byte_count ?? 0),
      duration: (flow) => Number(flow.duration ?? 0),
      score: (flow) => getScore(flow) ?? -Infinity,
    };

    result.sort((a, b) => {
      const aValue = sortValues[sortBy](a);
      const bValue = sortValues[sortBy](b);
      return sortDescending ? bValue - aValue : aValue - bValue;
    });

    return result;
  }, [
    safeFlows,
    search,
    protocolFilter,
    securityFilter,
    sortBy,
    sortDescending,
  ]);

  function changeSort(field) {
    if (sortBy === field) {
      setSortDescending((current) => !current);
    } else {
      setSortBy(field);
      setSortDescending(true);
    }
  }

  function renderSortButton(field, label) {
    return (
      <button
        type="button"
        className="flow-sort-button"
        onClick={() => changeSort(field)}
      >
        {label} <ArrowDownUp size={13} />
      </button>
    );
  }

  if (safeFlows.length === 0) {
    return (
      <section className="panel flow-results-panel">
        <div className="panel-heading">
          <div>
            <h2>Extracted Network Flows</h2>
            <p>Connection details and AI anomaly analysis</p>
          </div>
          <span className="flow-heading-icon">
            <Network size={20} />
          </span>
        </div>

        <div className="flow-empty-state">
          <span className="flow-empty-icon">
            <Activity size={25} />
          </span>
          <strong>No flow records available</strong>
          <p>
            Upload a PCAP or PCAPNG file, run the analysis, and return here
            to inspect the extracted flows and anomaly classifications.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="panel flow-results-panel">
      <div className="panel-heading flow-results-heading">
        <div>
          <h2>Extracted Network Flows</h2>
          <p>
            Showing {filteredFlows.length} of {safeFlows.length} flows
          </p>
        </div>
        <span className="flow-heading-icon">
          <Network size={20} />
        </span>
      </div>

      <div className="flow-summary">
        <div className="flow-summary-card">
          <span>Total flows</span>
          <strong>{formatNumber(safeFlows.length)}</strong>
        </div>
        <div className="flow-summary-card">
          <span>Normal</span>
          <strong className="flow-normal-value">{formatNumber(counts.normal)}</strong>
        </div>
        <div className="flow-summary-card">
          <span>Suspicious</span>
          <strong className={counts.suspicious ? "flow-alert-value" : ""}>
            {formatNumber(counts.suspicious)}
          </strong>
        </div>
        <div className="flow-summary-card">
          <span>Unavailable</span>
          <strong>{formatNumber(counts.unavailable)}</strong>
        </div>
      </div>

      <div className="flow-detection-explanation">
        <Info size={18} />
        <div>
          <strong>How to read these results</strong>
          <p>
            <b>Suspicious</b> means the model identified a flow as unusual
            compared with learned traffic patterns. It is a warning for
            investigation, not proof of an attack. <b>Normal</b> does not
            guarantee that a flow is safe.
          </p>
        </div>
      </div>

      <div className="flow-toolbar">
        <label className="flow-search">
          <Search size={16} />
          <input
            type="search"
            placeholder="Search IP address, protocol, or label..."
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            aria-label="Search network flows"
          />
        </label>

        <label className="flow-select-label">
          <Filter size={15} />
          <select
            value={protocolFilter}
            onChange={(event) => setProtocolFilter(event.target.value)}
            aria-label="Filter by protocol"
          >
            {protocols.map((protocol) => (
              <option key={protocol} value={protocol}>
                {protocol === "ALL" ? "All protocols" : protocol}
              </option>
            ))}
          </select>
        </label>

        <label className="flow-select-label">
          <select
            value={securityFilter}
            onChange={(event) => setSecurityFilter(event.target.value)}
            aria-label="Filter by classification"
          >
            <option value="ALL">All classifications</option>
            <option value="SUSPICIOUS">Suspicious only</option>
            <option value="NORMAL">Normal only</option>
            <option value="UNAVAILABLE">Unavailable only</option>
          </select>
        </label>
      </div>

      <div className="table-scroll">
        <table className="flows-table">
          <thead>
            <tr>
              <th>Protocol</th>
              <th>Source IP</th>
              <th>Destination IP</th>
              <th>{renderSortButton("packets", "Packets")}</th>
              <th>{renderSortButton("bytes", "Bytes")}</th>
              <th>{renderSortButton("duration", "Duration")}</th>
              <th>{renderSortButton("score", "Anomaly score")}</th>
              <th>AI result</th>
              <th>Details</th>
            </tr>
          </thead>

          <tbody>
            {filteredFlows.map((flow, index) => {
              const classification = getClassification(flow);
              const protocol = getProtocol(flow);
              const [source, destination] = getEndpoints(flow);
              const score = getScore(flow);
              const rowKey =
                flow.id ?? flow.flow_id ?? flow.flow_index ?? index;
              const expanded = expandedFlow === rowKey;

              return (
                <>
                  <tr key={rowKey}>
                    <td>
                      <span className="protocol-badge">{protocol}</span>
                    </td>
                    <td className="flow-ip">
                      {source || "—"}
                      {flow.src_port != null && `:${flow.src_port}`}
                    </td>
                    <td className="flow-ip">
                      {destination || "—"}
                      {flow.dst_port != null && `:${flow.dst_port}`}
                    </td>
                    <td>{formatNumber(flow.packet_count ?? flow.packets)}</td>
                    <td>
                      {formatNumber(
                        flow.total_bytes ?? flow.bytes ?? flow.byte_count
                      )}
                    </td>
                    <td>{formatDuration(flow.duration)}</td>
                    <td>{score === null ? "—" : score.toFixed(6)}</td>
                    <td>
                      {classification === "SUSPICIOUS" ? (
                        <span className="flow-classification suspicious">
                          <ShieldAlert size={14} />
                          Suspicious
                        </span>
                      ) : classification === "NORMAL" ? (
                        <span className="flow-classification normal">
                          <ShieldCheck size={14} />
                          Normal
                        </span>
                      ) : (
                        <span className="flow-classification unavailable">
                          Unavailable
                        </span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="flow-sort-button"
                        aria-expanded={expanded}
                        onClick={() => setExpandedFlow(expanded ? null : rowKey)}
                      >
                        Explain {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    </td>
                  </tr>

                  {expanded && (
                    <tr key={`${rowKey}-details`} className="flow-detail-row">
                      <td colSpan={9}>
                        <div className="flow-detail-content">
                          <strong>AI anomaly explanation</strong>
                          <p>{getExplanation(flow)}</p>
                          <div className="flow-detail-meta">
                            <span>
                              Classification: <b>{classification}</b>
                            </span>
                            <span>
                              Score: <b>{score === null ? "Unavailable" : score.toFixed(6)}</b>
                            </span>
                            <span>
                              Flow index: <b>{flow.flow_index ?? "—"}</b>
                            </span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
          </tbody>
        </table>

        {filteredFlows.length === 0 && (
          <div className="flow-no-matches">
            No flows match the current search and filters.
          </div>
        )}
      </div>

      <div className="flow-table-footer">
        <span>
          AI classifications are experimental and should be investigated
          alongside other security evidence.
        </span>
        <span>
          Sort: {sortBy} ({sortDescending ? "descending" : "ascending"})
        </span>
      </div>
    </section>
  );
}
