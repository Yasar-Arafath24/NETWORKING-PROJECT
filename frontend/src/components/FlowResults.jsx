
import { useMemo, useState } from "react";
import {
  Activity,
  Search,
  ShieldAlert,
  ArrowDownUp,
  Filter,
  Network,
} from "lucide-react";

function formatNumber(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  const number = Number(value);
  return Number.isFinite(number) ? number.toLocaleString() : String(value);
}

function formatDuration(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return `${value.toFixed(3)} s`;
  }

  return String(value);
}

function getProtocol(flow) {
  const protocol = flow.protocol ?? flow.protocol_name ?? "Unknown";
  return String(protocol).toUpperCase();
}

function isSuspicious(flow) {
  return (
    flow.is_suspicious === true ||
    flow.suspicious === true ||
    flow.is_anomaly === true ||
    flow.anomaly === true ||
    String(flow.label ?? flow.classification ?? "")
      .toLowerCase()
      .includes("suspicious") ||
    String(flow.label ?? flow.classification ?? "")
      .toLowerCase()
      .includes("anomal")
  );
}

export default function FlowResults({ flows = [] }) {
  const safeFlows = Array.isArray(flows) ? flows : [];

  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("ALL");
  const [securityFilter, setSecurityFilter] = useState("ALL");
  const [sortBy, setSortBy] = useState("packets");
  const [sortDescending, setSortDescending] = useState(true);

  const protocols = useMemo(() => {
    return [
      "ALL",
      ...new Set(safeFlows.map(getProtocol).filter(Boolean)),
    ];
  }, [safeFlows]);

  const filteredFlows = useMemo(() => {
    const query = search.trim().toLowerCase();

    const result = safeFlows.filter((flow) => {
      const protocol = getProtocol(flow);
      const source = String(
        flow.src_ip ?? flow.source_ip ?? ""
      ).toLowerCase();
      const destination = String(
        flow.dst_ip ?? flow.destination_ip ?? ""
      ).toLowerCase();

      const matchesSearch =
        !query ||
        protocol.toLowerCase().includes(query) ||
        source.includes(query) ||
        destination.includes(query);

      const matchesProtocol =
        protocolFilter === "ALL" || protocol === protocolFilter;

      const suspicious = isSuspicious(flow);
      const matchesSecurity =
        securityFilter === "ALL" ||
        (securityFilter === "SUSPICIOUS" && suspicious) ||
        (securityFilter === "NORMAL" && !suspicious);

      return matchesSearch && matchesProtocol && matchesSecurity;
    });

    result.sort((a, b) => {
      const fields = {
        packets: (flow) => Number(flow.packet_count ?? flow.packets ?? 0),
        bytes: (flow) =>
          Number(flow.total_bytes ?? flow.bytes ?? flow.byte_count ?? 0),
        duration: (flow) => Number(flow.duration ?? 0),
      };

      const getValue = fields[sortBy];
      const aValue = getValue ? getValue(a) : 0;
      const bValue = getValue ? getValue(b) : 0;

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

  const suspiciousCount = safeFlows.filter(isSuspicious).length;

  function changeSort(field) {
    if (sortBy === field) {
      setSortDescending((current) => !current);
    } else {
      setSortBy(field);
      setSortDescending(true);
    }
  }

  if (safeFlows.length === 0) {
    return (
      <section className="panel flow-results-panel">
        <div className="panel-heading">
          <div>
            <h2>Extracted Network Flows</h2>
            <p>Connection summaries extracted from packet captures</p>
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
            Upload a PCAP file and complete an analysis to display extracted
            network flows here.
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
            {filteredFlows.length} of {safeFlows.length} flow records
          </p>
        </div>

        <span className="flow-heading-icon">
          <Network size={20} />
        </span>
      </div>

      <div className="flow-summary">
        <div className="flow-summary-card">
          <span>Total flows</span>
          <strong>{safeFlows.length.toLocaleString()}</strong>
        </div>

        <div className="flow-summary-card">
          <span>Protocols</span>
          <strong>
            {new Set(safeFlows.map(getProtocol)).size}
          </strong>
        </div>

        <div className="flow-summary-card">
          <span>Flagged flows</span>
          <strong className={suspiciousCount > 0 ? "flow-alert-value" : ""}>
            {suspiciousCount.toLocaleString()}
          </strong>
        </div>
      </div>

      <div className="flow-toolbar">
        <label className="flow-search">
          <Search size={16} />
          <input
            type="search"
            placeholder="Search IP address or protocol..."
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
            aria-label="Filter by security classification"
          >
            <option value="ALL">All classifications</option>
            <option value="SUSPICIOUS">Flagged only</option>
            <option value="NORMAL">Not flagged</option>
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
              <th>
                <button
                  type="button"
                  className="flow-sort-button"
                  onClick={() => changeSort("packets")}
                >
                  Packets <ArrowDownUp size={13} />
                </button>
              </th>
              <th>
                <button
                  type="button"
                  className="flow-sort-button"
                  onClick={() => changeSort("bytes")}
                >
                  Bytes <ArrowDownUp size={13} />
                </button>
              </th>
              <th>
                <button
                  type="button"
                  className="flow-sort-button"
                  onClick={() => changeSort("duration")}
                >
                  Duration <ArrowDownUp size={13} />
                </button>
              </th>
              <th>Classification</th>
            </tr>
          </thead>

          <tbody>
            {filteredFlows.map((flow, index) => {
              const suspicious = isSuspicious(flow);
              const protocol = getProtocol(flow);

              return (
                <tr key={flow.id ?? flow.flow_id ?? index}>
                  <td>
                    <span className="protocol-badge">{protocol}</span>
                  </td>

                  <td className="flow-ip">
                    {flow.src_ip ?? flow.source_ip ?? "—"}
                  </td>

                  <td className="flow-ip">
                    {flow.dst_ip ?? flow.destination_ip ?? "—"}
                  </td>

                  <td>
                    {formatNumber(flow.packet_count ?? flow.packets)}
                  </td>

                  <td>
                    {formatNumber(
                      flow.total_bytes ?? flow.bytes ?? flow.byte_count
                    )}
                  </td>

                  <td>{formatDuration(flow.duration)}</td>

                  <td>
                    {suspicious ? (
                      <span className="flow-classification suspicious">
                        <ShieldAlert size={13} />
                        Flagged
                      </span>
                    ) : (
                      <span className="flow-classification normal">
                        Not flagged
                      </span>
                    )}
                  </td>
                </tr>
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
          Classification is based on flags supplied by the backend.
        </span>

        <span>
          Sort: {sortBy} ({sortDescending ? "descending" : "ascending"})
        </span>
      </div>
    </section>
  );
}
