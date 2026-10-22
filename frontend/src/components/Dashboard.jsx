
import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  ChevronDown,
  CircleHelp,
  FileSearch,
  FileText,
  Gauge,
  LayoutDashboard,
  Network,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Upload,
  Wifi,
} from "lucide-react";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import BackendStatus from "./BackendStatus";
import FlowResults from "./FlowResults";
import PcapUpload from "./PcapUpload";
import {
  uploadPcap,
  getAnalysisHistory,
  API_BASE_URL,
} from "../services/api";

const navigation = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "PCAP Analysis", icon: FileSearch },
  { label: "Traffic Monitoring", icon: Activity },
  { label: "AI Detection", icon: ShieldAlert },
  { label: "Security Alerts", icon: Bell },
  { label: "Analysis History", icon: FileText },
];

function formatNumber(value) {
  if (
    value === null ||
    value === undefined ||
    value === "" ||
    !Number.isFinite(Number(value))
  ) {
    return "—";
  }

  return Number(value).toLocaleString();
}

function MetricCard({
  title,
  value,
  description,
  icon: Icon,
  trend,
  trendDirection = "up",
}) {
  return (
    <article className="metric-card">
      <div className="metric-top">
        <span className="metric-title">{title}</span>
        <span className="metric-icon">
          <Icon size={19} strokeWidth={1.8} />
        </span>
      </div>

      <div className="metric-value">{value}</div>

      <div className="metric-footer">
        {trend && (
          <span
            className={`metric-trend ${
              trendDirection === "down" ? "trend-down" : ""
            }`}
          >
            {trendDirection === "down" ? (
              <ArrowDownRight size={14} />
            ) : (
              <ArrowUpRight size={14} />
            )}
            {trend}
          </span>
        )}
        <span className="metric-description">{description}</span>
      </div>
    </article>
  );
}

function PageHeading({ eyebrow, title, description, action }) {
  return (
    <section className="welcome-row">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {action}
    </section>
  );
}

function EmptyState({ title, description }) {
  return (
    <div className="chart-empty">
      <p>{title}</p>
      <span>{description}</span>
    </div>
  );
}

function getFlows(result) {
  if (Array.isArray(result?.flows)) return result.flows;
  if (Array.isArray(result?.results)) return result.results;
  if (Array.isArray(result?.data?.flows)) return result.data.flows;
  if (Array.isArray(result?.analysis?.flows)) return result.analysis.flows;
  return [];
}

function getSuspiciousFlows(flows) {
  return flows.filter((flow) => {
    const label = String(
      flow?.classification ?? flow?.label ?? flow?.prediction ?? ""
    ).toLowerCase();

    return (
      flow?.is_suspicious === true ||
      flow?.is_anomaly === true ||
      flow?.suspicious === true ||
      flow?.anomaly === true ||
      label.includes("suspicious") ||
      label.includes("anomal")
    );
  });
}

export default function Dashboard() {
  const [uploadingPcap, setUploadingPcap] = useState(false);
  const [analysis, setAnalysis] = useState(null);

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState("");
  const [uploadError, setUploadError] = useState("");

  const [backendStatus, setBackendStatus] = useState("Checking");
  const [activePage, setActivePage] = useState("Overview");

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);

    try {
      const result = await getAnalysisHistory({ skip: 0, limit: 20 });

      setHistory(
        Array.isArray(result?.reports)
          ? result.reports
          : Array.isArray(result)
            ? result
            : []
      );

      setHistoryError("");
      setBackendStatus("Connected");
    } catch (error) {
      setHistoryError(
        error instanceof Error
          ? error.message
          : "Unable to load analysis history."
      );
      setBackendStatus("Unavailable");
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    // Defer the initial load so the effect does not set state synchronously.
    const timeoutId = setTimeout(loadHistory, 0);

    return () => clearTimeout(timeoutId);
  }, [loadHistory]);

  async function handlePcapUpload(file) {
    setUploadingPcap(true);
    setUploadError("");

    try {
      const result = await uploadPcap(file);
      setAnalysis(result);
      await loadHistory();
      return result;
    } catch (error) {
      setUploadError(
        error instanceof Error ? error.message : "PCAP analysis failed."
      );
      throw error;
    } finally {
      setUploadingPcap(false);
    }
  }

  function navigateTo(label) {
    setActivePage(label);
  }

  const packetTotal =
    analysis?.total_packets ??
    analysis?.packet_count ??
    analysis?.summary?.total_packets ??
    (history.length
      ? history.reduce(
          (sum, report) => sum + (Number(report.total_packets) || 0),
          0
        )
      : null);

  const flowTotal =
    analysis?.total_flows ??
    analysis?.flow_count ??
    analysis?.summary?.total_flows ??
    (history.length
      ? history.reduce(
          (sum, report) => sum + (Number(report.total_flows) || 0),
          0
        )
      : null);

  const reportTotal = historyLoading ? "…" : history.length;

  const trafficData = Array.isArray(analysis?.traffic_data)
    ? analysis.traffic_data
    : [];

  const flows = getFlows(analysis);
  const suspiciousFlows = getSuspiciousFlows(flows);

  const suspiciousCount =
    analysis?.suspicious_flows ??
    analysis?.anomalies_detected ??
    analysis?.anomaly_count ??
    analysis?.summary?.suspicious_flows ??
    suspiciousFlows.length;

  const hasAnomalyResult =
    analysis !== null &&
    (analysis?.suspicious_flows !== undefined ||
      analysis?.anomalies_detected !== undefined ||
      analysis?.anomaly_count !== undefined ||
      analysis?.summary?.suspicious_flows !== undefined ||
      flows.length > 0);

  const alerts = Array.isArray(analysis?.alerts) ? analysis.alerts : [];

  const primaryAction = (
    <button
      type="button"
      className="primary-button"
      onClick={() => navigateTo("PCAP Analysis")}
    >
      <Upload size={17} />
      Analyze PCAP
    </button>
  );

  function renderOverview() {
    return (
      <>
        <PageHeading
          eyebrow="NETWORK OPERATIONS"
          title="Security overview"
          description="Monitor network activity and review your traffic analysis."
          action={primaryAction}
        />

        <section className="monitor-banner">
          <div className="monitor-icon">
            <Wifi size={21} />
          </div>

          <div className="monitor-copy">
            <strong>Network monitoring workspace</strong>
            <span>
              {backendStatus === "Connected"
                ? "The analysis history endpoint is responding."
                : backendStatus === "Unavailable"
                  ? "Backend unavailable. Check that FastAPI is running."
                  : "Checking the backend connection..."}
            </span>
          </div>

          <span className="preview-badge">
            {backendStatus.toUpperCase()}
          </span>
        </section>

        <section className="metrics-grid">
          <MetricCard
            title="Total packets"
            value={formatNumber(packetTotal)}
            description={
              analysis
                ? "Latest PCAP analysis"
                : "Sum of reports currently loaded"
            }
            icon={Network}
          />

          <MetricCard
            title="Network flows"
            value={formatNumber(flowTotal)}
            description={
              analysis
                ? "Latest PCAP analysis"
                : "Sum of reports currently loaded"
            }
            icon={Activity}
          />

          <MetricCard
            title="Anomalies detected"
            value={
              hasAnomalyResult ? formatNumber(suspiciousCount) : "—"
            }
            description={
              hasAnomalyResult
                ? "Reported or inferred from returned flow flags"
                : "No anomaly result returned"
            }
            icon={ShieldAlert}
          />

          <MetricCard
            title="Analysis reports"
            value={reportTotal}
            description="Reports returned by the history API"
            icon={FileText}
          />
        </section>

        {historyError && (
          <div className="panel" role="alert">
            <strong>Unable to load analysis history</strong>
            <p>{historyError}</p>
            <button
              type="button"
              className="secondary-button"
              onClick={loadHistory}
            >
              Retry
            </button>
          </div>
        )}

        <section className="content-grid">
          <article className="panel traffic-panel">
            <div className="panel-heading">
              <div>
                <h2>Network traffic</h2>
                <p>
                  {trafficData.length > 0
                    ? "Traffic data from the latest analysis"
                    : "No time-series data returned"}
                </p>
              </div>

              <button
                type="button"
                className="select-button"
                onClick={loadHistory}
                disabled={historyLoading}
              >
                Refresh data <Activity size={15} />
              </button>
            </div>

            <div className="chart-legend">
              <span>
                <i className="legend-blue" /> Packets
              </span>
            </div>

            <div className="chart-container">
              {trafficData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={trafficData}
                    margin={{ top: 12, right: 8, left: -16, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient
                        id="packetGradient"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                      >
                        <stop
                          offset="0%"
                          stopColor="#2563eb"
                          stopOpacity={0.15}
                        />
                        <stop
                          offset="95%"
                          stopColor="#2563eb"
                          stopOpacity={0}
                        />
                      </linearGradient>
                    </defs>

                    <CartesianGrid
                      stroke="#e2e8f0"
                      strokeDasharray="3 3"
                      vertical={false}
                    />

                    <XAxis
                      dataKey="time"
                      tick={{ fill: "#64748b", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      tick={{ fill: "#64748b", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip />

                    <Area
                      type="monotone"
                      dataKey="packets"
                      name="Packets"
                      stroke="#2563eb"
                      strokeWidth={2}
                      fill="url(#packetGradient)"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState
                  title="No traffic time series available."
                  description="The chart appears when the analysis API returns compatible time-series data."
                />
              )}
            </div>
          </article>

          <article className="panel system-panel">
            <div className="panel-heading">
              <div>
                <h2>System status</h2>
                <p>Application connection information</p>
              </div>
              <Gauge size={20} />
            </div>

            <div className="system-list">
              <div className="system-row">
                <span className="system-row-icon">
                  <Wifi size={18} />
                </span>
                <div className="system-row-copy">
                  <strong>FastAPI backend</strong>
                  <small>History endpoint connectivity</small>
                </div>
                <span className="status-neutral">{backendStatus}</span>
              </div>

              <div className="system-row">
                <span className="system-row-icon">
                  <Network size={18} />
                </span>
                <div className="system-row-copy">
                  <strong>Packet analysis</strong>
                  <small>
                    {analysis
                      ? "Analysis response received"
                      : "Awaiting PCAP upload"}
                  </small>
                </div>
              </div>

              <div className="system-row">
                <span className="system-row-icon">
                  <ShieldAlert size={18} />
                </span>
                <div className="system-row-copy">
                  <strong>AI detection</strong>
                  <small>
                    {hasAnomalyResult
                      ? "Detection information returned"
                      : "No anomaly result available"}
                  </small>
                </div>
              </div>
            </div>

            <div className="system-note">
              The backend status reflects the history endpoint request. It
              does not independently verify every backend service or model.
            </div>
          </article>
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Recent analysis</h2>
              <p>Your latest reports from the history API</p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={() => navigateTo("Analysis History")}
            >
              View history
            </button>
          </div>

          {historyLoading ? (
            <p>Loading reports...</p>
          ) : history.length === 0 ? (
            <p>No reports found. Upload a PCAP file to begin.</p>
          ) : (
            <div className="table-scroll">
              <table className="flows-table">
                <thead>
                  <tr>
                    <th>Report ID</th>
                    <th>Packets</th>
                    <th>Flows</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {history.slice(0, 5).map((report, index) => (
                    <tr key={report.id ?? index}>
                      <td>{report.id ?? "—"}</td>
                      <td>{formatNumber(report.total_packets)}</td>
                      <td>{formatNumber(report.total_flows)}</td>
                      <td>
                        {report.created_at
                          ? new Date(report.created_at).toLocaleString()
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </>
    );
  }

  function renderPcapAnalysis() {
    return (
      <>
        <PageHeading
          eyebrow="PACKET INSPECTION"
          title="PCAP Analysis"
          description="Upload a packet capture and inspect the response from the analysis API."
        />

        {uploadError && (
          <div className="panel" role="alert">
            <strong>PCAP analysis failed</strong>
            <p>{uploadError}</p>
          </div>
        )}

        <PcapUpload
          onUpload={handlePcapUpload}
          uploading={uploadingPcap}
        />

        {analysis && (
          <section className="panel">
            <div className="panel-heading">
              <div>
                <h2>Latest analysis result</h2>
                <p>The response from your most recent PCAP upload</p>
              </div>
              <span className="status-neutral">Response received</span>
            </div>

            <section className="metrics-grid">
              <MetricCard
                title="Packets"
                value={formatNumber(
                  analysis.total_packets ??
                    analysis.packet_count ??
                    analysis.summary?.total_packets
                )}
                description="Reported by the API"
                icon={Network}
              />

              <MetricCard
                title="Flows"
                value={formatNumber(
                  analysis.total_flows ??
                    analysis.flow_count ??
                    analysis.summary?.total_flows
                )}
                description="Reported by the API"
                icon={Activity}
              />

              <MetricCard
                title="Anomalies"
                value={
                  hasAnomalyResult ? formatNumber(suspiciousCount) : "—"
                }
                description={
                  hasAnomalyResult
                    ? "Reported by the API or flow flags"
                    : "No anomaly count returned"
                }
                icon={ShieldAlert}
              />
            </section>

            {flows.length > 0 ? (
              <FlowResults flows={flows} />
            ) : (
              <EmptyState
                title="No flow records returned."
                description="The upload succeeded, but the response did not contain a recognized flows array."
              />
            )}

            <details className="response-details">
              <summary>View raw API response</summary>
              <pre>{JSON.stringify(analysis, null, 2)}</pre>
            </details>
          </section>
        )}
      </>
    );
  }

  function renderTrafficMonitoring() {
    return (
      <>
        <PageHeading
          eyebrow="NETWORK VISIBILITY"
          title="Traffic Monitoring"
          description="Inspect the flows extracted from your latest PCAP analysis."
          action={primaryAction}
        />

        {trafficData.length > 0 && (
          <section className="panel traffic-panel">
            <div className="panel-heading">
              <div>
                <h2>Packet activity</h2>
                <p>Time-series data returned by the latest analysis</p>
              </div>
            </div>

            <div className="chart-container">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficData}>
                  <CartesianGrid
                    stroke="#e2e8f0"
                    strokeDasharray="3 3"
                    vertical={false}
                  />
                  <XAxis dataKey="time" />
                  <YAxis />
                  <Tooltip />
                  <Area
                    type="monotone"
                    dataKey="packets"
                    name="Packets"
                    stroke="#2563eb"
                    fill="#dbeafe"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </section>
        )}

        {analysis ? (
          flows.length > 0 ? (
            <FlowResults flows={flows} />
          ) : (
            <section className="panel">
              <EmptyState
                title="No flow data available."
                description="The latest analysis did not return a recognized flow list."
              />
            </section>
          )
        ) : (
          <section className="panel">
            <EmptyState
              title="No traffic analysis yet."
              description="Upload a PCAP file to view extracted network flows."
            />
          </section>
        )}
      </>
    );
  }

  function renderAiDetection() {
    return (
      <>
        <PageHeading
          eyebrow="THREAT DETECTION"
          title="AI Detection"
          description="Review anomaly information returned by the analysis API."
          action={primaryAction}
        />

        <section className="metrics-grid">
          <MetricCard
            title="Reported anomalies"
            value={
              hasAnomalyResult ? formatNumber(suspiciousCount) : "—"
            }
            description={
              hasAnomalyResult
                ? "Value returned or inferred from flow flags"
                : "No recognized anomaly result"
            }
            icon={ShieldAlert}
          />

          <MetricCard
            title="Analyzed flows"
            value={formatNumber(
              analysis?.total_flows ?? analysis?.flow_count ?? flows.length
            )}
            description="Flows in the latest analysis response"
            icon={Network}
          />
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Detection status</h2>
              <p>Information available from the latest API response</p>
            </div>
          </div>

          {!analysis ? (
            <EmptyState
              title="No analysis has been run."
              description="Upload a PCAP file to inspect detection information returned by the backend."
            />
          ) : (
            <div className="system-note">
              {hasAnomalyResult
                ? `The analysis returned an anomaly count of ${formatNumber(
                    suspiciousCount
                  )}. This display does not independently validate AI model accuracy.`
                : "The response contains no recognized anomaly-count field or flow flags."}
            </div>
          )}

          {flows.length > 0 && <FlowResults flows={flows} />}
        </section>
      </>
    );
  }

  function renderSecurityAlerts() {
    return (
      <>
        <PageHeading
          eyebrow="SECURITY OPERATIONS"
          title="Security Alerts"
          description="Review alert records and suspicious flows from the latest analysis."
          action={primaryAction}
        />

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Analysis alerts</h2>
              <p>Alert information from the current analysis response</p>
            </div>
            <Bell size={20} />
          </div>

          {!analysis ? (
            <EmptyState
              title="No analysis available."
              description="Upload a PCAP file before reviewing alerts."
            />
          ) : alerts.length === 0 && suspiciousFlows.length === 0 ? (
            <EmptyState
              title="No alert records returned."
              description="No recognized alert entries or suspicious flow flags were found. This does not prove that the traffic is safe."
            />
          ) : (
            <>
              {alerts.length > 0 && (
                <div className="table-scroll">
                  <table className="flows-table">
                    <thead>
                      <tr>
                        <th>Alert</th>
                        <th>Severity</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.map((alert, index) => (
                        <tr key={alert.id ?? index}>
                          <td>
                            {alert.title ?? alert.name ?? alert.type ?? "Alert"}
                          </td>
                          <td>{alert.severity ?? "Unspecified"}</td>
                          <td>
                            {alert.description ?? alert.message ?? "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {suspiciousFlows.length > 0 && (
                <>
                  <h3>Flagged flows</h3>
                  <FlowResults flows={suspiciousFlows} />
                </>
              )}
            </>
          )}
        </section>
      </>
    );
  }

  function renderAnalysisHistory() {
    return (
      <>
        <PageHeading
          eyebrow="REPORTS"
          title="Analysis History"
          description="Browse reports returned by the backend."
          action={
            <button
              type="button"
              className="secondary-button"
              onClick={loadHistory}
              disabled={historyLoading}
            >
              {historyLoading ? "Loading..." : "Refresh history"}
            </button>
          }
        />

        {historyError && (
          <div className="panel" role="alert">
            <strong>Unable to load history</strong>
            <p>{historyError}</p>
          </div>
        )}

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Recent reports</h2>
              <p>{history.length} reports currently loaded</p>
            </div>
            <FileText size={20} />
          </div>

          {historyLoading ? (
            <p>Loading analysis history...</p>
          ) : history.length === 0 ? (
            <EmptyState
              title="No analysis reports found."
              description="Run a PCAP analysis and refresh the history."
            />
          ) : (
            <div className="table-scroll">
              <table className="flows-table">
                <thead>
                  <tr>
                    <th>Report ID</th>
                    <th>Packets</th>
                    <th>Flows</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((report, index) => (
                    <tr key={report.id ?? index}>
                      <td>{report.id ?? "—"}</td>
                      <td>{formatNumber(report.total_packets)}</td>
                      <td>{formatNumber(report.total_flows)}</td>
                      <td>
                        {report.created_at
                          ? new Date(report.created_at).toLocaleString()
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </>
    );
  }

  function renderSettings() {
    return (
      <>
        <PageHeading
          eyebrow="PREFERENCES"
          title="Settings"
          description="Configuration information for your development workspace."
        />

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Connection configuration</h2>
              <p>Current frontend API settings</p>
            </div>
            <Settings size={20} />
          </div>

          <div className="system-row">
            <div className="system-row-copy">
              <strong>Backend URL</strong>
              <small>{API_BASE_URL}</small>
            </div>
            <span className="status-neutral">{backendStatus}</span>
          </div>

          <div className="system-note">
            This screen displays configuration only. It does not persist
            changes to the backend URL.
          </div>
        </section>
      </>
    );
  }

  function renderHelp() {
    return (
      <>
        <PageHeading
          eyebrow="DOCUMENTATION"
          title="Help & documentation"
          description="Quick guidance for using the NetSentry AI dashboard."
        />

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Getting started</h2>
              <p>Basic workflow</p>
            </div>
            <CircleHelp size={20} />
          </div>

          <ol>
            <li>Start the FastAPI backend.</li>
            <li>Open PCAP Analysis and select a .pcap or .pcapng file.</li>
            <li>Run the analysis and review the returned results.</li>
            <li>Use Traffic Monitoring to inspect extracted flows.</li>
            <li>Use Analysis History to review saved reports.</li>
          </ol>

          <div className="system-note">
            Confirm that file-size limits and packet validation are also
            enforced by the backend.
          </div>
        </section>
      </>
    );
  }

  function renderPage() {
    switch (activePage) {
      case "PCAP Analysis":
        return renderPcapAnalysis();
      case "Traffic Monitoring":
        return renderTrafficMonitoring();
      case "AI Detection":
        return renderAiDetection();
      case "Security Alerts":
        return renderSecurityAlerts();
      case "Analysis History":
        return renderAnalysisHistory();
      case "Settings":
        return renderSettings();
      case "Help":
        return renderHelp();
      default:
        return renderOverview();
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button
          type="button"
          className="brand"
          onClick={() => navigateTo("Overview")}
          aria-label="Go to NetSentry overview"
        >
          <span className="brand-icon">
            <Shield size={23} />
          </span>
          <span>
            <strong>NetSentry</strong>
            <small>NETWORK INTELLIGENCE</small>
          </span>
        </button>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="navigation" aria-label="Main navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              type="button"
              key={label}
              className={`nav-item ${
                activePage === label ? "nav-active" : ""
              }`}
              aria-current={activePage === label ? "page" : undefined}
              onClick={() => navigateTo(label)}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-label tools-label">PREFERENCES</div>

        <nav className="navigation" aria-label="Preferences">
          <button
            type="button"
            className={`nav-item ${
              activePage === "Settings" ? "nav-active" : ""
            }`}
            aria-current={activePage === "Settings" ? "page" : undefined}
            onClick={() => navigateTo("Settings")}
          >
            <Settings size={18} strokeWidth={1.8} />
            <span>Settings</span>
          </button>

          <button
            type="button"
            className={`nav-item ${
              activePage === "Help" ? "nav-active" : ""
            }`}
            aria-current={activePage === "Help" ? "page" : undefined}
            onClick={() => navigateTo("Help")}
          >
            <CircleHelp size={18} strokeWidth={1.8} />
            <span>Help &amp; documentation</span>
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-indicator">
            <span
              className="status-dot"
              style={{
                background:
                  backendStatus === "Connected"
                    ? "#16a34a"
                    : backendStatus === "Unavailable"
                      ? "#dc2626"
                      : "#94a3b8",
              }}
            />

            <div>
              <strong>API connection</strong>
              <small>{backendStatus}</small>
            </div>
          </div>

          <p>NetSentry AI · Development</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{activePage}</strong>
          </div>

          <div className="topbar-actions">
            <BackendStatus />

            <label className="search-box">
              <Search size={17} />
              <input
                placeholder="Search dashboard..."
                aria-label="Search dashboard"
              />
              <kbd>Ctrl K</kbd>
            </label>

            <button
              type="button"
              className="icon-button"
              aria-label="Open security alerts"
              onClick={() => navigateTo("Security Alerts")}
            >
              <Bell size={19} />
            </button>

            <div className="profile">
              <div className="avatar">NS</div>
              <div className="profile-info">
                <strong>Network Admin</strong>
                <small>Administrator</small>
              </div>
              <ChevronDown size={15} />
            </div>
          </div>
        </header>

        <div className="dashboard-content" key={activePage}>
          {renderPage()}

          <footer className="dashboard-footer">
            <span>NetSentry AI · Network traffic analysis</span>
            <span>Development environment</span>
          </footer>
        </div>
      </main>
    </div>
  );
}
