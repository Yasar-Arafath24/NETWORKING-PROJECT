
import { useMemo, useState } from "react";
import {
  Activity,
  Download,
  Filter,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Wifi,
  X,
} from "lucide-react";

function getSourceIp(flow) {
  return (
    flow?.src_ip ??
    flow?.source_ip ??
    flow?.src ??
    flow?.source ??
    "Unknown"
  );
}

function getDestinationIp(flow) {
  return (
    flow?.dst_ip ??
    flow?.destination_ip ??
    flow?.dst ??
    flow?.destination ??
    "Unknown"
  );
}

function getClassification(flow) {
  return String(
    flow?.classification ??
      flow?.label ??
      flow?.prediction_label ??
      flow?.prediction ??
      flow?.status ??
      ""
  ).toLowerCase();
}

function isSuspicious(flow) {
  const label = getClassification(flow);

  return (
    flow?.is_suspicious === true ||
    flow?.is_anomaly === true ||
    flow?.suspicious === true ||
    flow?.anomaly === true ||
    flow?.anomaly_prediction === -1 ||
    label.includes("suspicious") ||
    label.includes("anomal") ||
    label === "attack" ||
    label === "malicious" ||
    label === "intrusion"
  );
}

function getBytes(flow) {
  const bytes = Number(
    flow?.total_bytes ?? flow?.bytes ?? flow?.byte_count ?? 0
  );

  return Number.isFinite(bytes) && bytes > 0 ? bytes : 0;
}

function formatBytes(value) {
  if (!value) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  );

  return `${(value / 1024 ** index).toFixed(
    index === 0 ? 0 : 2
  )} ${units[index]}`;
}

function formatNumber(value) {
  const number = Number(value);

  return Number.isFinite(number)
    ? number.toLocaleString()
    : "—";
}

function escapeCsv(value) {
  const text = String(value ?? "");
  return `"${text.replace(/"/g, '""')}"`;
}

function exportFlowsToCsv(flows) {
  const headers = [
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packets",
    "Bytes",
    "Classification",
    "Suspicious",
  ];

  const rows = flows.map((flow) => [
    getSourceIp(flow),
    getDestinationIp(flow),
    flow?.protocol ?? "Unknown",
    flow?.src_port ?? flow?.source_port ?? "",
    flow?.dst_port ?? flow?.destination_port ?? "",
    flow?.packet_count ?? "",
    getBytes(flow),
    getClassification(flow) || "Unclassified",
    isSuspicious(flow) ? "Yes" : "No",
  ]);

  const csv = [
    headers.map(escapeCsv).join(","),
    ...rows.map((row) => row.map(escapeCsv).join(",")),
  ].join("\r\n");

  const blob = new Blob(["\uFEFF", csv], {
    type: "text/csv;charset=utf-8;",
  });

  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = "netsentry-traffic-monitor.csv";

  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(url);
}

export default function TrafficMonitor({
  flows = [],
  loading = false,
  onRefresh,
}) {
  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [classificationFilter, setClassificationFilter] =
    useState("all");
  const [page, setPage] = useState(1);

  const pageSize = 10;

  const safeFlows = useMemo(() => Array.isArray(flows) ? flows : [], [flows]);

  const protocols = useMemo(() => {
    return [
      ...new Set(
        safeFlows
          .map((flow) =>
            String(flow?.protocol ?? "").trim().toUpperCase()
          )
          .filter(Boolean)
      ),
    ].sort();
  }, [safeFlows]);

  const suspiciousCount = safeFlows.filter(isSuspicious).length;

  const totalBytes = safeFlows.reduce(
    (sum, flow) => sum + getBytes(flow),
    0
  );

  const filteredFlows = useMemo(() => {
    const query = search.trim().toLowerCase();

    return safeFlows.filter((flow) => {
      const protocol = String(
        flow?.protocol ?? ""
      ).toUpperCase();

      const suspicious = isSuspicious(flow);

      const matchesSearch =
        !query ||
        [
          getSourceIp(flow),
          getDestinationIp(flow),
          flow?.protocol,
          flow?.src_port,
          flow?.source_port,
          flow?.dst_port,
          flow?.destination_port,
          getClassification(flow),
        ].some((value) =>
          String(value ?? "").toLowerCase().includes(query)
        );

      const matchesProtocol =
        protocolFilter === "all" ||
        protocol === protocolFilter;

      const matchesClassification =
        classificationFilter === "all" ||
        (classificationFilter === "suspicious" && suspicious) ||
        (classificationFilter === "normal" &&
          !suspicious &&
          (flow?.is_suspicious === false ||
            flow?.is_anomaly === false ||
            flow?.anomaly === false ||
            ["normal", "benign", "safe"].includes(
              getClassification(flow)
            ))) ||
        (classificationFilter === "unclassified" &&
          !suspicious &&
          flow?.is_suspicious !== false &&
          flow?.is_anomaly !== false &&
          flow?.anomaly !== false &&
          !["normal", "benign", "safe"].includes(
            getClassification(flow)
          ));

      return (
        matchesSearch &&
        matchesProtocol &&
        matchesClassification
      );
    });
  }, [
    safeFlows,
    search,
    protocolFilter,
    classificationFilter,
  ]);

  const totalPages = Math.max(
    1,
    Math.ceil(filteredFlows.length / pageSize)
  );

  const currentPage = Math.min(page, totalPages);

  const visibleFlows = filteredFlows.slice(
    (currentPage - 1) * pageSize,
    currentPage * pageSize
  );

  function updateSearch(value) {
    setSearch(value);
    setPage(1);
  }

  function clearFilters() {
    setSearch("");
    setProtocolFilter("all");
    setClassificationFilter("all");
    setPage(1);
  }

  return (
    <section className="tm-root">
      <div className="tm-header">
        <div>
          <p className="tm-eyebrow">NETWORK VISIBILITY</p>
          <h2>Traffic Monitor</h2>
          <p className="tm-muted">
            Search and inspect network flows from your PCAP analysis.
          </p>
        </div>

        <div className="tm-actions">
          <button
            type="button"
            className="tm-button tm-secondary"
            onClick={onRefresh}
            disabled={loading || !onRefresh}
          >
            <RefreshCw
              size={16}
              className={loading ? "tm-spinning" : ""}
            />
            Refresh
          </button>

          <button
            type="button"
            className="tm-button tm-primary"
            onClick={() => exportFlowsToCsv(filteredFlows)}
            disabled={filteredFlows.length === 0}
          >
            <Download size={16} />
            Export CSV
          </button>
        </div>
      </div>

      <div className="tm-metrics">
        <article className="tm-metric">
          <span className="tm-metric-icon">
            <Activity size={20} />
          </span>
          <span className="tm-metric-label">Total flows</span>
          <strong>{formatNumber(safeFlows.length)}</strong>
          <small>Records received</small>
        </article>

        <article className="tm-metric">
          <span className="tm-metric-icon tm-warning-icon">
            <ShieldAlert size={20} />
          </span>
          <span className="tm-metric-label">Suspicious flows</span>
          <strong>{formatNumber(suspiciousCount)}</strong>
          <small>Flagged for investigation</small>
        </article>

        <article className="tm-metric">
          <span className="tm-metric-icon">
            <Wifi size={20} />
          </span>
          <span className="tm-metric-label">Protocols</span>
          <strong>{formatNumber(protocols.length)}</strong>
          <small>Distinct protocol values</small>
        </article>

        <article className="tm-metric">
          <span className="tm-metric-icon">
            <Download size={20} />
          </span>
          <span className="tm-metric-label">Traffic volume</span>
          <strong>{formatBytes(totalBytes)}</strong>
          <small>Sum of reported flow bytes</small>
        </article>
      </div>

      <div className="tm-panel">
        <div className="tm-panel-heading">
          <div>
            <h3>Network flow records</h3>
            <p className="tm-muted">
              {filteredFlows.length.toLocaleString()} matching records
            </p>
          </div>

          <Filter size={19} />
        </div>

        <div className="tm-filters">
          <label className="tm-search">
            <Search size={17} />
            <input
              type="search"
              value={search}
              onChange={(event) => updateSearch(event.target.value)}
              placeholder="Search IP, port, protocol..."
              aria-label="Search network flows"
            />

            {search && (
              <button
                type="button"
                aria-label="Clear search"
                onClick={() => updateSearch("")}
              >
                <X size={15} />
              </button>
            )}
          </label>

          <select
            value={protocolFilter}
            onChange={(event) => {
              setProtocolFilter(event.target.value);
              setPage(1);
            }}
            aria-label="Filter by protocol"
          >
            <option value="all">All protocols</option>
            {protocols.map((protocol) => (
              <option key={protocol} value={protocol}>
                {protocol}
              </option>
            ))}
          </select>

          <select
            value={classificationFilter}
            onChange={(event) => {
              setClassificationFilter(event.target.value);
              setPage(1);
            }}
            aria-label="Filter by classification"
          >
            <option value="all">All classifications</option>
            <option value="suspicious">Suspicious</option>
            <option value="normal">Normal</option>
            <option value="unclassified">Unclassified</option>
          </select>

          <button
            type="button"
            className="tm-button tm-clear"
            onClick={clearFilters}
            disabled={
              !search &&
              protocolFilter === "all" &&
              classificationFilter === "all"
            }
          >
            Clear
          </button>
        </div>

        {loading ? (
          <div className="tm-empty">
            <RefreshCw size={26} className="tm-spinning" />
            <h3>Loading traffic records</h3>
            <p>Please wait while the records are refreshed.</p>
          </div>
        ) : safeFlows.length === 0 ? (
          <div className="tm-empty">
            <Activity size={30} />
            <h3>No traffic records available</h3>
            <p>
              Upload and analyze a PCAP file before inspecting network flows.
            </p>
          </div>
        ) : filteredFlows.length === 0 ? (
          <div className="tm-empty">
            <Search size={28} />
            <h3>No matching flows</h3>
            <p>Try another search term or clear your filters.</p>
            <button
              type="button"
              className="tm-button tm-secondary"
              onClick={clearFilters}
            >
              Clear filters
            </button>
          </div>
        ) : (
          <>
            <div className="tm-table-wrapper">
              <table className="tm-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Source port</th>
                    <th>Destination port</th>
                    <th>Packets</th>
                    <th>Bytes</th>
                    <th>Classification</th>
                  </tr>
                </thead>

                <tbody>
                  {visibleFlows.map((flow, index) => {
                    const suspicious = isSuspicious(flow);
                    const classification =
                      getClassification(flow) || "unclassified";

                    return (
                      <tr key={flow.id ?? flow.flow_id ?? index}>
                        <td>{getSourceIp(flow)}</td>
                        <td>{getDestinationIp(flow)}</td>
                        <td>
                          <span className="tm-protocol">
                            {String(flow?.protocol ?? "Unknown").toUpperCase()}
                          </span>
                        </td>
                        <td>
                          {flow?.src_port ??
                            flow?.source_port ??
                            "—"}
                        </td>
                        <td>
                          {flow?.dst_port ??
                            flow?.destination_port ??
                            "—"}
                        </td>
                        <td>{formatNumber(flow?.packet_count)}</td>
                        <td>
                          {formatBytes(getBytes(flow))}
                        </td>
                        <td>
                          <span
                            className={`tm-classification ${
                              suspicious ? "tm-suspicious" : "tm-normal"
                            }`}
                          >
                            {suspicious ? (
                              <ShieldAlert size={13} />
                            ) : (
                              <ShieldCheck size={13} />
                            )}
                            {suspicious
                              ? "Suspicious"
                              : classification === "unclassified"
                                ? "Unclassified"
                                : classification.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="tm-pagination">
              <span>
                Showing{" "}
                {((currentPage - 1) * pageSize + 1).toLocaleString()}–
                {Math.min(
                  currentPage * pageSize,
                  filteredFlows.length
                ).toLocaleString()}{" "}
                of {filteredFlows.length.toLocaleString()}
              </span>

              <div className="tm-pagination-actions">
                <button
                  type="button"
                  className="tm-button tm-secondary"
                  onClick={() =>
                    setPage((previous) => Math.max(1, previous - 1))
                  }
                  disabled={currentPage === 1}
                >
                  Previous
                </button>

                <span>
                  Page {currentPage} of {totalPages}
                </span>

                <button
                  type="button"
                  className="tm-button tm-secondary"
                  onClick={() =>
                    setPage((previous) =>
                      Math.min(totalPages, previous + 1)
                    )
                  }
                  disabled={currentPage >= totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      <style>{`
        .tm-root {
          display: flex;
          flex-direction: column;
          gap: 22px;
          width: 100%;
          color: #0f172a;
        }

        .tm-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 18px;
          flex-wrap: wrap;
        }

        .tm-eyebrow {
          margin: 0 0 7px;
          color: #2563eb;
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 1.4px;
        }

        .tm-header h2 {
          margin: 0;
          font-size: 25px;
          font-weight: 750;
        }

        .tm-muted {
          color: #64748b;
          font-size: 13px;
          line-height: 1.6;
        }

        .tm-header .tm-muted {
          margin: 8px 0 0;
        }

        .tm-actions {
          display: flex;
          gap: 9px;
          flex-wrap: wrap;
        }

        .tm-button {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          min-height: 38px;
          padding: 9px 13px;
          border: 1px solid #e2e8f0;
          border-radius: 9px;
          font: inherit;
          font-size: 13px;
          font-weight: 600;
          cursor: pointer;
          transition: background 150ms ease;
        }

        .tm-button:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .tm-primary {
          border-color: #2563eb;
          color: #fff;
          background: #2563eb;
        }

        .tm-primary:hover:not(:disabled) {
          background: #1d4ed8;
        }

        .tm-secondary,
        .tm-clear {
          color: #334155;
          background: #fff;
        }

        .tm-secondary:hover:not(:disabled),
        .tm-clear:hover:not(:disabled) {
          background: #f1f5f9;
        }

        .tm-metrics {
          display: grid;
          grid-template-columns: repeat(4, minmax(0, 1fr));
          gap: 15px;
        }

        .tm-metric {
          display: grid;
          grid-template-columns: 1fr auto;
          align-items: center;
          gap: 7px 10px;
          min-width: 0;
          padding: 17px;
          border: 1px solid #e2e8f0;
          border-radius: 13px;
          background: #fff;
        }

        .tm-metric-icon {
          display: flex;
          align-items: center;
          justify-content: center;
          grid-column: 2;
          grid-row: 1 / span 2;
          width: 39px;
          height: 39px;
          border-radius: 10px;
          color: #2563eb;
          background: #eff6ff;
        }

        .tm-warning-icon {
          color: #c2410c;
          background: #ffedd5;
        }

        .tm-metric-label {
          color: #64748b;
          font-size: 12px;
        }

        .tm-metric strong {
          grid-column: 1;
          font-size: 25px;
          overflow-wrap: anywhere;
        }

        .tm-metric small {
          grid-column: 1 / -1;
          color: #64748b;
          font-size: 11px;
        }

        .tm-panel {
          min-width: 0;
          overflow: hidden;
          border: 1px solid #e2e8f0;
          border-radius: 14px;
          background: #fff;
        }

        .tm-panel-heading {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 14px;
          padding: 20px 20px 16px;
        }

        .tm-panel-heading h3 {
          margin: 0;
          font-size: 16px;
          font-weight: 700;
        }

        .tm-panel-heading p {
          margin: 6px 0 0;
        }

        .tm-filters {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 0 20px 18px;
          flex-wrap: wrap;
        }

        .tm-search {
          display: flex;
          align-items: center;
          gap: 8px;
          flex: 1;
          min-width: 180px;
          min-height: 39px;
          padding: 0 11px;
          border: 1px solid #e2e8f0;
          border-radius: 9px;
          color: #94a3b8;
        }

        .tm-search input {
          width: 100%;
          min-width: 0;
          border: 0;
          outline: none;
          color: #0f172a;
          background: transparent;
          font: inherit;
          font-size: 13px;
        }

        .tm-search button {
          display: flex;
          padding: 3px;
          border: 0;
          color: #64748b;
          background: transparent;
          cursor: pointer;
        }

        .tm-filters select {
          min-height: 39px;
          max-width: 190px;
          padding: 0 10px;
          border: 1px solid #e2e8f0;
          border-radius: 9px;
          color: #334155;
          background: #fff;
          font: inherit;
          font-size: 13px;
        }

        .tm-table-wrapper {
          width: 100%;
          overflow-x: auto;
          border-top: 1px solid #e2e8f0;
        }

        .tm-table {
          width: 100%;
          min-width: 940px;
          border-collapse: collapse;
          text-align: left;
          font-size: 12px;
        }

        .tm-table th {
          padding: 13px 15px;
          color: #64748b;
          background: #f8fafc;
          font-weight: 600;
          white-space: nowrap;
        }

        .tm-table td {
          padding: 14px 15px;
          border-top: 1px solid #f1f5f9;
          color: #334155;
          white-space: nowrap;
        }

        .tm-table tbody tr:hover {
          background: #f8fafc;
        }

        .tm-protocol {
          display: inline-block;
          padding: 4px 7px;
          border-radius: 5px;
          color: #1d4ed8;
          background: #eff6ff;
          font-size: 10px;
          font-weight: 800;
        }

        .tm-classification {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 5px 8px;
          border-radius: 999px;
          font-size: 10px;
          font-weight: 700;
        }

        .tm-suspicious {
          color: #b91c1c;
          background: #fee2e2;
        }

        .tm-normal {
          color: #475569;
          background: #f1f5f9;
        }

        .tm-empty {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 10px;
          min-height: 220px;
          padding: 30px 20px;
          color: #64748b;
          text-align: center;
        }

        .tm-empty h3 {
          margin: 0;
          color: #0f172a;
          font-size: 16px;
        }

        .tm-empty p {
          max-width: 440px;
          margin: 0;
          font-size: 13px;
          line-height: 1.7;
        }

        .tm-pagination {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 14px;
          padding: 15px 20px;
          border-top: 1px solid #e2e8f0;
          color: #64748b;
          font-size: 12px;
          flex-wrap: wrap;
        }

        .tm-pagination-actions {
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
        }

        .tm-pagination .tm-button {
          min-height: 32px;
          padding: 6px 10px;
          font-size: 12px;
        }

        .tm-spinning {
          animation: tm-spin 1s linear infinite;
        }

        @keyframes tm-spin {
          to {
            transform: rotate(360deg);
          }
        }

        @media (max-width: 1000px) {
          .tm-metrics {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }
        }

        @media (max-width: 600px) {
          .tm-header h2 {
            font-size: 22px;
          }

          .tm-metrics {
            grid-template-columns: 1fr 1fr;
            gap: 9px;
          }

          .tm-metric {
            padding: 12px;
          }

          .tm-metric strong {
            font-size: 21px;
          }

          .tm-filters {
            padding-right: 12px;
            padding-left: 12px;
          }

          .tm-search {
            flex-basis: 100%;
          }

          .tm-filters select {
            flex: 1;
            max-width: none;
          }

          .tm-panel-heading {
            padding-right: 14px;
            padding-left: 14px;
          }

          .tm-pagination {
            padding-right: 12px;
            padding-left: 12px;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .tm-spinning {
            animation: none;
          }
        }
      `}</style>
    </section>
  );
}
