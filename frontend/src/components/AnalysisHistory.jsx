
import { useCallback, useEffect, useState } from "react";
import { FileText, RefreshCw, Search, AlertCircle } from "lucide-react";
import { getAnalysisHistory } from "../services/api";

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) return String(value);

  return date.toLocaleString();
}

function getReportId(report, index) {
  return report.id ?? report.report_id ?? `report-${index}`;
}

export default function AnalysisHistory() {
  const [reports, setReports] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const data = await getAnalysisHistory({ skip: 0, limit: 50 });

      const items = Array.isArray(data)
        ? data
        : data?.reports ?? data?.items ?? data?.results ?? [];

      setReports(Array.isArray(items) ? items : []);
    } catch (err) {
      setError(err.message || "Unable to load analysis history.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const filteredReports = reports.filter((report) => {
    const query = search.trim().toLowerCase();

    if (!query) return true;

    return [
      report.id,
      report.report_id,
      report.filename,
      report.file_name,
      report.status,
      report.created_at,
    ].some((value) =>
      String(value ?? "").toLowerCase().includes(query)
    );
  });

  return (
    <section className="panel analysis-history-panel">
      <div className="panel-heading">
        <div>
          <h2>Analysis History</h2>
          <p>Review previous PCAP analysis reports.</p>
        </div>

        <button
          type="button"
          className="history-refresh-button"
          onClick={loadHistory}
          disabled={loading}
          aria-label="Refresh analysis history"
        >
          <RefreshCw size={16} className={loading ? "history-spinning" : ""} />
          Refresh
        </button>
      </div>

      <label className="history-search">
        <Search size={16} />
        <input
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Search reports..."
          aria-label="Search analysis history"
        />
      </label>

      {error && (
        <div className="history-error" role="alert">
          <AlertCircle size={18} />
          <span>{error}</span>
          <button type="button" onClick={loadHistory}>
            Retry
          </button>
        </div>
      )}

      {loading && reports.length === 0 ? (
        <p className="history-state">Loading analysis history...</p>
      ) : !error && filteredReports.length === 0 ? (
        <div className="history-empty">
          <FileText size={28} />
          <strong>No analysis reports found</strong>
          <p>Analyze a PCAP file to create your first report.</p>
        </div>
      ) : (
        <div className="history-table-wrap">
          <table className="flows-table">
            <thead>
              <tr>
                <th>Report ID</th>
                <th>Created</th>
                <th>Packets</th>
                <th>Flows</th>
              </tr>
            </thead>

            <tbody>
              {filteredReports.map((report, index) => (
                <tr key={getReportId(report, index)}>
                  <td className="history-report-id">
                    {getReportId(report, index)}
                  </td>
                  <td>{formatDate(report.created_at)}</td>
                  <td>
                    {report.total_packets == null
                      ? "—"
                      : Number(report.total_packets).toLocaleString()}
                  </td>
                  <td>
                    {report.total_flows == null
                      ? "—"
                      : Number(report.total_flows).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="history-footer">
        Showing {filteredReports.length} of {reports.length} loaded reports
      </div>
    </section>
  );
}
