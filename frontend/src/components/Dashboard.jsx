
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  ChevronDown,
  CircleHelp,
  Clock,
  FileSearch,
  FileText,
  Gauge,
  Globe2,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Upload,
  Wifi,
  X,
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
import RealtimeTrafficMonitor from "./RealtimeTrafficMonitor";
import WebsiteMonitoring from "./WebsiteMonitoring";
import WebsiteAnomalyAnalytics from "./WebsiteAnomalyAnalytics";
import WebsiteIntegrations from "./WebsiteIntegrations";
import HistoricalTrafficAnalytics from "./HistoricalTrafficAnalytics";

import {
  uploadPcap,
  getAnalysisHistory,
  getLatestAnalysis,
  getSecurityAlerts,
  setWebsiteAlertStatus,
  checkBackendConnection,
  API_BASE_URL,
} from "../services/api";

const navigation = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "PCAP Analysis", icon: FileSearch },
  { label: "Traffic Monitoring", icon: Activity },
  { label: "Website Integrations", icon: Globe2 },
  { label: "Real-Time Monitoring", icon: Wifi },
  { label: "Website Traffic", icon: Globe2 },
  { label: "AI Detection", icon: ShieldAlert },
  { label: "Security Alerts", icon: Bell },
  { label: "Analysis History", icon: FileText },
];

const preferenceNavigation = [
  { label: "Settings", icon: Settings },
  { label: "Help", icon: CircleHelp },
];

function GithubIcon() {
  return (
    <svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor" aria-hidden="true">
      <path d="M12 .7A11.5 11.5 0 0 0 8.36 23.1c.58.1.79-.25.79-.56v-2.23c-3.22.7-3.9-1.37-3.9-1.37-.52-1.34-1.29-1.7-1.29-1.7-1.05-.72.08-.71.08-.71 1.17.08 1.78 1.2 1.78 1.2 1.04 1.78 2.72 1.27 3.38.97.1-.75.41-1.27.74-1.56-2.57-.29-5.28-1.29-5.28-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.16 1.18A11 11 0 0 1 12 6.11c.98 0 1.96.13 2.88.39 2.2-1.49 3.16-1.18 3.16-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.71 5.38-5.29 5.67.42.36.79 1.06.79 2.14v3.27c0 .31.21.67.79.56A11.5 11.5 0 0 0 12 .7Z" />
    </svg>
  );
}

function LinkedInIcon() {
  return (
    <svg viewBox="0 0 24 24" width="17" height="17" fill="currentColor" aria-hidden="true">
      <path d="M5.2 7.8H1.7V22h3.5V7.8ZM3.45 1A2.06 2.06 0 1 0 3.45 5.12 2.06 2.06 0 0 0 3.45 1ZM22.3 13.62c0-4.26-2.27-6.24-5.31-6.24a4.58 4.58 0 0 0-4.15 2.28V7.8H9.33V22h3.51v-7.03c0-1.86.35-3.66 2.65-3.66 2.27 0 2.3 2.12 2.3 3.78V22h3.51v-8.38Z" />
    </svg>
  );
}

const developers = [
  {
    name: "Yasar Arafath",
    linkedin: "https://www.linkedin.com/in/yasar-arafath-365490333/",
    github: "https://github.com/Yasar-Arafath24",
  },
  {
    name: "Moohamed Thavubik",
    linkedin: "https://www.linkedin.com/in/moohamed-thavubik-444554308/",
    github: "https://github.com/mohamedthoufik003",
  },
  {
    name: "Mohamed Imran",
    linkedin: "https://www.linkedin.com/in/-techie-imran",
    github: "https://github.com/Techie-Imran",
  },
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

function formatBytes(value) {
  const bytes = Number(value);

  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";

  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );

  return `${(bytes / 1024 ** index).toFixed(
    index === 0 ? 0 : 2
  )} ${units[index]}`;
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
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

function EmptyState({ title, description, action }) {
  return (
    <div className="chart-empty">
      <Shield size={30} />
      <p>{title}</p>
      <span>{description}</span>
      {action}
    </div>
  );
}

function getFlows(result) {
  if (Array.isArray(result?.flows)) return result.flows;
  if (Array.isArray(result?.results)) return result.results;
  if (Array.isArray(result?.data?.flows)) return result.data.flows;
  if (Array.isArray(result?.data?.results)) return result.data.results;
  if (Array.isArray(result?.analysis?.flows)) return result.analysis.flows;
  if (Array.isArray(result?.analysis?.results)) return result.analysis.results;
  if (Array.isArray(result?.report_data?.flows)) return result.report_data.flows;
  if (Array.isArray(result?.data?.report_data?.flows)) return result.data.report_data.flows;
  if (Array.isArray(result?.analysis?.report_data?.flows)) return result.analysis.report_data.flows;

  return [];
}

function getFlowLabel(flow) {
  return String(
    flow?.classification ??
      flow?.label ??
      flow?.anomaly_prediction ??
      flow?.prediction ??
      flow?.prediction_label ??
      flow?.status ??
      ""
  )
    .trim()
    .toLowerCase();
}

function isSuspiciousFlow(flow) {
  const label = getFlowLabel(flow);

  return (
    flow?.is_suspicious === true ||
    flow?.is_anomaly === true ||
    flow?.suspicious === true ||
    flow?.anomaly === true ||
    Number(flow?.anomaly_prediction) === -1 ||
    label.includes("suspicious") ||
    label.includes("anomal") ||
    label === "attack" ||
    label === "malicious" ||
    label === "intrusion"
  );
}

function isNormalFlow(flow) {
  const label = getFlowLabel(flow);

  return (
    flow?.is_suspicious === false ||
    flow?.is_anomaly === false ||
    flow?.anomaly === false ||
    Number(flow?.anomaly_prediction) === 1 ||
    label === "normal" ||
    label === "benign" ||
    label === "safe"
  );
}

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

function getSeverity(alert) {
  const severity = String(
    alert?.severity ?? alert?.level ?? alert?.risk ?? "medium"
  ).toLowerCase();

  if (severity.includes("critical")) return "critical";
  if (severity.includes("high")) return "high";
  if (severity.includes("low") || severity.includes("info")) return "low";

  return "medium";
}

function getAlertTitle(alert) {
  return (
    alert?.title ??
    alert?.name ??
    alert?.type ??
    alert?.rule_name ??
    alert?.message ??
    "Suspicious network activity"
  );
}

function getAlertDescription(alert) {
  return (
    alert?.description ??
    alert?.message ??
    alert?.details ??
    "Review this event and investigate the associated network traffic."
  );
}

function getAlerts(result) {
  if (Array.isArray(result?.alerts)) return result.alerts;
  if (Array.isArray(result?.data?.alerts)) return result.data.alerts;
  if (Array.isArray(result?.analysis?.alerts)) return result.analysis.alerts;

  return [];
}

function getHistoryReports(result) {
  if (Array.isArray(result?.reports)) return result.reports;
  if (Array.isArray(result?.history)) return result.history;
  if (Array.isArray(result?.data?.reports)) return result.data.reports;
  if (Array.isArray(result)) return result;

  return [];
}

function getPacketTotal(result) {
  return (
    result?.total_packets ??
    result?.packet_count ??
    result?.summary?.total_packets ??
    result?.data?.total_packets ??
    null
  );
}

function getFlowTotal(result) {
  return (
    result?.total_flows ??
    result?.flow_count ??
    result?.traffic_summary?.total_flows_analyzed ??
    result?.summary?.total_flows ??
    result?.data?.total_flows ??
    null
  );
}

function SeverityBadge({ severity = "medium", children }) {
  return (
    <span className={`severity-badge ${severity}`}>
      {children ?? severity.toUpperCase()}
    </span>
  );
}

export default function Dashboard({ user = null, onSignOut }) {
  const [uploadingPcap, setUploadingPcap] = useState(false);
  const [analysis, setAnalysis] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(true);
  const [analysisError, setAnalysisError] = useState("");

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState("");
  const [persistedAlerts, setPersistedAlerts] = useState([]);
  const [securityAlertsError, setSecurityAlertsError] = useState("");
  const [uploadError, setUploadError] = useState("");

  const [backendStatus, setBackendStatus] = useState("Checking");
  const [activePage, setActivePage] = useState("Overview");

  const [searchQuery, setSearchQuery] = useState("");
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [profileMenuOpen, setProfileMenuOpen] = useState(false);

  const loadHistory = useCallback(async () => {
    setHistoryLoading(true);

    try {
      const result = await getAnalysisHistory({
        skip: 0,
        limit: 20,
      });

      setHistory(getHistoryReports(result));
      setHistoryError("");
    } catch (error) {
      setHistoryError(
        error instanceof Error
          ? error.message
          : "Unable to load analysis history."
      );

    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadLatestAnalysis = useCallback(async () => {
    setAnalysisLoading(true);
    try {
      const result = await getLatestAnalysis();
      setAnalysis(result?.report_data ?? result?.analysis ?? result);
      setAnalysisError("");
    } catch (error) {
      if (error?.status === 404) {
        setAnalysis(null);
        setAnalysisError("");
      } else {
        setAnalysisError(error instanceof Error ? error.message : "Unable to load the latest PCAP analysis.");
      }
    } finally {
      setAnalysisLoading(false);
    }
  }, []);

  const loadPersistedAlerts = useCallback(async () => {
    try {
      const result = await getSecurityAlerts({ limit: 100 });
      setPersistedAlerts(Array.isArray(result?.alerts) ? result.alerts : []);
      setSecurityAlertsError("");
    } catch (error) {
      setSecurityAlertsError(error instanceof Error ? error.message : "Unable to load security alerts.");
    }
  }, []);

  async function changeWebsiteAlertStatus(alert, status) {
    const alertId = Number(String(alert.id).replace(/^website-/, ""));
    if (!alert.site_id || !Number.isInteger(alertId)) return;
    try {
      await setWebsiteAlertStatus(alert.site_id, alertId, status);
      await loadPersistedAlerts();
    } catch (error) {
      setSecurityAlertsError(error instanceof Error ? error.message : "Unable to update alert status.");
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(loadHistory, 0);
    return () => window.clearTimeout(timer);
  }, [loadHistory]);

  useEffect(() => {
    const timer = window.setTimeout(loadLatestAnalysis, 0);
    return () => window.clearTimeout(timer);
  }, [loadLatestAnalysis]);

  useEffect(() => {
    const initial = window.setTimeout(loadPersistedAlerts, 0);
    const timer = window.setInterval(loadPersistedAlerts, 15000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [loadPersistedAlerts]);

  useEffect(() => {
    let active = true;
    const checkBackend = async () => {
      try {
        await checkBackendConnection();
        if (active) setBackendStatus("Connected");
      } catch {
        if (active) setBackendStatus("Unavailable");
      }
    };
    checkBackend();
    const timer = window.setInterval(checkBackend, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    function handleShortcut(event) {
      if (
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === "k"
      ) {
        event.preventDefault();
        document.getElementById("dashboard-search")?.focus();
      }

      if (event.key === "Escape") {
        setMobileMenuOpen(false);
        setProfileMenuOpen(false);
        setSearchQuery("");
      }
    }

    window.addEventListener("keydown", handleShortcut);

    return () => {
      window.removeEventListener("keydown", handleShortcut);
    };
  }, []);

  async function handlePcapUpload(file) {
    setUploadingPcap(true);
    setUploadError("");

    try {
      const result = await uploadPcap(file);

      setAnalysis(result);
      setAnalysisError("");
      setAnalysisLoading(false);
      setActivePage("PCAP Analysis");

      await loadHistory();

      return result;
    } catch (error) {
      setUploadError(
        error instanceof Error
          ? error.message
          : "PCAP analysis failed."
      );

      throw error;
    } finally {
      setUploadingPcap(false);
    }
  }

  function navigateTo(label) {
    setActivePage(label);
    setMobileMenuOpen(false);
    setProfileMenuOpen(false);
    setSearchQuery("");
  }

  const flows = useMemo(() => getFlows(analysis), [analysis]);

  const suspiciousFlows = useMemo(
    () => flows.filter(isSuspiciousFlow),
    [flows]
  );

  const normalFlows = useMemo(
    () => flows.filter(isNormalFlow),
    [flows]
  );

  const unclassifiedFlows = useMemo(
    () =>
      flows.filter(
        (flow) => !isSuspiciousFlow(flow) && !isNormalFlow(flow)
      ),
    [flows]
  );

  const alerts = useMemo(() => {
    const combined = [...getAlerts(analysis), ...persistedAlerts];
    return combined.sort((left, right) => new Date(right.created_at || 0) - new Date(left.created_at || 0));
  }, [analysis, persistedAlerts]);

  const criticalAlerts = alerts.filter(
    (alert) => getSeverity(alert) === "critical"
  );

  const highAlerts = alerts.filter(
    (alert) => getSeverity(alert) === "high"
  );
  const mediumAlerts = alerts.filter((alert) => getSeverity(alert) === "medium");
  const lowAlerts = alerts.filter((alert) => getSeverity(alert) === "low");
  const openAlerts = alerts.filter((alert) => !["RESOLVED", "FALSE_POSITIVE"].includes(String(alert.status || "OPEN").toUpperCase()));
  const resolvedAlerts = alerts.filter((alert) => ["RESOLVED", "FALSE_POSITIVE"].includes(String(alert.status || "").toUpperCase()));

  const packetTotal =
    getPacketTotal(analysis) ??
    (history.length
      ? history.reduce(
          (sum, report) =>
            sum + (Number(report.total_packets) || 0),
          0
        )
      : null);

  const flowTotal =
    getFlowTotal(analysis) ??
    (history.length
      ? history.reduce(
          (sum, report) =>
            sum + (Number(report.total_flows) || 0),
          0
        )
      : null);

  const reportTotal = historyLoading ? "…" : history.length;

  const trafficData = Array.isArray(analysis?.traffic_data)
    ? analysis.traffic_data
    : Array.isArray(analysis?.data?.traffic_data)
      ? analysis.data.traffic_data
      : [];

  const hasAnomalyResult =
    analysis !== null &&
    (
      analysis?.suspicious_flows !== undefined ||
      analysis?.anomalies_detected !== undefined ||
      analysis?.anomaly_count !== undefined ||
      analysis?.summary?.suspicious_flows !== undefined ||
      suspiciousFlows.length > 0 ||
      flows.length > 0
    );

  const suspiciousCount =
    analysis?.suspicious_flows ??
    analysis?.anomalies_detected ??
    analysis?.anomaly_count ??
    analysis?.summary?.suspicious_flows ??
    suspiciousFlows.length;
  const normalCount = analysis?.traffic_summary?.normal_flows ?? normalFlows.length;
  const unclassifiedCount = analysis?.traffic_summary?.unavailable_predictions ?? unclassifiedFlows.length;
  const analyzedFlowCount = getFlowTotal(analysis) ?? flows.length;

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
                : "Sum of loaded report values"
            }
            icon={Network}
          />

          <MetricCard
            title="Network flows"
            value={formatNumber(flowTotal)}
            description={
              analysis
                ? "Latest PCAP analysis"
                : "Sum of loaded report values"
            }
            icon={Activity}
          />

          <MetricCard
            title="Anomalies detected"
            value={
              hasAnomalyResult
                ? formatNumber(suspiciousCount)
                : "—"
            }
            description={
              hasAnomalyResult
                ? "Reported or inferred from flow flags"
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
                    margin={{
                      top: 12,
                      right: 8,
                      left: -16,
                      bottom: 0,
                    }}
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
              Backend status reflects the history endpoint request. It does
              not independently verify every backend service or model.
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
                      <td>{formatDate(report.created_at)}</td>
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
                value={formatNumber(getPacketTotal(analysis))}
                description="Reported by the API"
                icon={Network}
              />

              <MetricCard
                title="Flows"
                value={formatNumber(getFlowTotal(analysis))}
                description="Reported by the API"
                icon={Activity}
              />

              <MetricCard
                title="Anomalies"
                value={
                  hasAnomalyResult
                    ? formatNumber(suspiciousCount)
                    : "—"
                }
                description={
                  hasAnomalyResult
                    ? "Reported by API or inferred from flow flags"
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
          eyebrow="HISTORICAL NETWORK ANALYTICS"
          title="Traffic Monitoring"
          description="Analyze saved PCAP traffic, compare historical flow patterns, and investigate protocols, addresses, and ports."
          action={primaryAction}
        />
        <HistoricalTrafficAnalytics />
      </>
    );
  }

  function renderRealtimeMonitoring() {
    return (
      <>
        <PageHeading
          eyebrow="LIVE NETWORK OPERATIONS"
          title="Real-Time Monitoring"
          description="Capture current packets from an available interface or replay a local PCAP. Live counters and detections update only from observed traffic."
          action={primaryAction}
        />
        <RealtimeTrafficMonitor />
      </>
    );
  }

  function renderWebsiteTraffic() {
    return (
      <>
        <PageHeading
          eyebrow="AUTHORIZED WEBSITE TELEMETRY"
          title="Website Traffic"
          description="View access-log events sent by collectors installed on websites you own or are authorized to monitor."
          action={primaryAction}
        />
        <WebsiteMonitoring embedded />
      </>
    );
  }

  function renderAiDetection() {
    return (
      <>
        <PageHeading
          eyebrow="MACHINE LEARNING"
          title="AI Detection"
          description="Review network-flow model results and rule-based anomaly analytics from your website access logs."
          action={primaryAction}
        />

        <section className="metrics-grid">
          <MetricCard
            title="Suspicious flows"
            value={analysis ? formatNumber(suspiciousCount) : "—"}
            description="Flows flagged by recognized anomaly indicators"
            icon={ShieldAlert}
          />

          <MetricCard
            title="Normal flows"
            value={analysis ? formatNumber(normalCount) : "—"}
            description="Flows classified as normal or benign"
            icon={ShieldCheck}
          />

          <MetricCard
            title="Unclassified flows"
            value={analysis ? formatNumber(unclassifiedCount) : "—"}
            description="Flows without a recognized classification"
            icon={Activity}
          />

          <MetricCard
            title="Total analyzed flows"
            value={analysis ? formatNumber(analyzedFlowCount) : "—"}
            description="Flow records in the latest response"
            icon={Network}
          />
        </section>

        <WebsiteAnomalyAnalytics />

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Detection summary</h2>
              <p>Classification breakdown for the latest analysis</p>
            </div>

            <ShieldAlert size={20} />
          </div>

          {analysisLoading ? (
            <EmptyState
              title="Loading your latest analysis"
              description="Retrieving your most recent PCAP analysis from your account history."
            />
          ) : analysisError ? (
            <div className="website-error" role="alert">
              <strong>Unable to load AI detection results</strong>
              <p>{analysisError}</p>
              <button type="button" className="secondary-button" onClick={loadLatestAnalysis}>Retry</button>
            </div>
          ) : !analysis ? (
            <EmptyState
              title="No analysis available"
              description="Upload a PCAP file and run an analysis to view AI detection results."
              action={primaryAction}
            />
          ) : flows.length === 0 ? (
            <EmptyState
              title="No flow records returned"
              description="The response contains no recognized flow array. Inspect the raw API response on the PCAP Analysis page."
            />
          ) : (
            <>
              <div className="system-list">
                <div className="system-row">
                  <span className="system-row-icon">
                    <ShieldAlert size={18} />
                  </span>

                  <div className="system-row-copy">
                    <strong>Suspicious flows</strong>
                    <small>Potentially unusual traffic requiring review</small>
                  </div>

                  <strong>{formatNumber(suspiciousFlows.length)}</strong>
                </div>

                <div className="system-row">
                  <span className="system-row-icon">
                    <ShieldCheck size={18} />
                  </span>

                  <div className="system-row-copy">
                    <strong>Normal flows</strong>
                    <small>Classified as normal or benign</small>
                  </div>

                  <strong>{formatNumber(normalFlows.length)}</strong>
                </div>

                <div className="system-row">
                  <span className="system-row-icon">
                    <Activity size={18} />
                  </span>

                  <div className="system-row-copy">
                    <strong>Unclassified flows</strong>
                    <small>No recognized classification field</small>
                  </div>

                  <strong>{formatNumber(unclassifiedFlows.length)}</strong>
                </div>
              </div>

              <div className="system-note">
                These counts are derived from returned fields. A normal
                classification does not guarantee that traffic is safe and
                does not independently validate model accuracy.
              </div>

              <FlowResults flows={flows} />
            </>
          )}
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
          description="Review website traffic heuristics, live network alerts, and suspicious flows."
          action={primaryAction}
        />

        <section className="metrics-grid">
          <MetricCard
            title="Total alerts"
            value={formatNumber(alerts.length)}
            description="Alert records returned by the API"
            icon={Bell}
          />

          <MetricCard
            title="Critical alerts"
            value={formatNumber(criticalAlerts.length)}
            description="Alerts marked critical"
            icon={ShieldAlert}
          />

          <MetricCard
            title="High alerts"
            value={formatNumber(highAlerts.length)}
            description="Alerts marked high severity"
            icon={ShieldAlert}
          />

          <MetricCard title="Medium alerts" value={formatNumber(mediumAlerts.length)} description="Medium severity findings" icon={ShieldAlert} />
          <MetricCard title="Low alerts" value={formatNumber(lowAlerts.length)} description="Low severity findings" icon={ShieldCheck} />
          <MetricCard title="Open alerts" value={formatNumber(openAlerts.length)} description="Open or under investigation" icon={Bell} />
          <MetricCard title="Resolved alerts" value={formatNumber(resolvedAlerts.length)} description="Resolved or marked false positive" icon={ShieldCheck} />

          <MetricCard
            title="Suspicious flows"
            value={formatNumber(suspiciousFlows.length)}
            description="Flagged flows requiring review"
            icon={Activity}
          />
        </section>

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Analysis alerts</h2>
              <p>Alerts refresh automatically and include website collector heuristics.</p>
            </div>

            <Bell size={20} />
          </div>

          {securityAlertsError && <div className="website-error" role="alert">{securityAlertsError}</div>}
          {alerts.length === 0 && suspiciousFlows.length === 0 ? (
            <EmptyState
              title="No alerts yet"
              description="Website traffic heuristics appear here after your authorized collector sends flagged request events. HTTP error codes alone are not treated as attacks."
            />
          ) : (
            <>
              {alerts.length > 0 && (
                <div className="security-alert-list">
                  {alerts.map((alert, index) => {
                    const severity = getSeverity(alert);

                    return (
                      <article
                        className="security-alert-item"
                        key={alert.id ?? alert.alert_id ?? index}
                      >
                        <div className={`alert-severity-icon ${severity}`}>
                          <ShieldAlert size={20} />
                        </div>

                        <div className="security-alert-content">
                          <div className="security-alert-title-row">
                            <h3>{getAlertTitle(alert)}</h3>
                            <SeverityBadge severity={severity} />
                          </div>

                          <p>{getAlertDescription(alert)}</p>

                          {(alert.source_ip || alert.src_ip) && (
                            <span className="alert-detail">
                              Source: {alert.source_ip ?? alert.src_ip}
                            </span>
                          )}

                          {alert.event_type === "website_traffic" && (
                            <>
                              <span className="alert-detail">Website: {alert.site_name} · {alert.category || "website traffic"} · {alert.endpoint || alert.request_path} · Risk {alert.risk_score ?? "—"}/100 · {alert.related_event_count || 1} related event(s)</span>
                              <span className="alert-detail">Status: {alert.status || "OPEN"} · First seen {formatDate(alert.first_seen || alert.created_at)} · Last seen {formatDate(alert.last_seen || alert.created_at)}</span>
                              {alert.status !== "RESOLVED" && alert.status !== "FALSE_POSITIVE" && <div className="website-alert-controls"><button className="secondary-button" onClick={() => changeWebsiteAlertStatus(alert, "INVESTIGATING")}>Investigate</button><button className="secondary-button" onClick={() => changeWebsiteAlertStatus(alert, "RESOLVED")}>Resolve</button><button className="secondary-button" onClick={() => changeWebsiteAlertStatus(alert, "FALSE_POSITIVE")}>False positive</button></div>}
                            </>
                          )}

                          {(alert.destination_ip || alert.dst_ip) && (
                            <span className="alert-detail">
                              Destination:{" "}
                              {alert.destination_ip ?? alert.dst_ip}
                            </span>
                          )}

                          {alert.protocol && (
                            <span className="alert-detail">
                              Protocol: {alert.protocol}
                            </span>
                          )}

                          {(alert.timestamp || alert.created_at) && (
                            <span className="alert-detail">
                              <Clock size={12} />{" "}
                              {formatDate(alert.timestamp ?? alert.created_at)}
                            </span>
                          )}
                        </div>
                      </article>
                    );
                  })}
                </div>
              )}

              {suspiciousFlows.length > 0 && (
                <div className="security-suspicious-section">
                  <div className="panel-heading">
                    <div>
                      <h2>Flagged network flows</h2>
                      <p>
                        {suspiciousFlows.length} suspicious flow records
                        identified by recognized flags or labels
                      </p>
                    </div>
                  </div>

                  <div className="table-scroll">
                    <table className="flows-table">
                      <thead>
                        <tr>
                          <th>Source IP</th>
                          <th>Destination IP</th>
                          <th>Protocol</th>
                          <th>Packets</th>
                          <th>Bytes</th>
                          <th>Classification</th>
                        </tr>
                      </thead>

                      <tbody>
                        {suspiciousFlows.map((flow, index) => (
                          <tr key={flow.id ?? flow.flow_id ?? index}>
                            <td>{getSourceIp(flow)}</td>
                            <td>{getDestinationIp(flow)}</td>
                            <td>{flow.protocol ?? "Unknown"}</td>
                            <td>{formatNumber(flow.packet_count)}</td>
                            <td>
                              {formatBytes(
                                flow.total_bytes ??
                                  flow.bytes ??
                                  flow.byte_count
                              )}
                            </td>
                            <td>
                              <SeverityBadge severity="high">
                                Suspicious
                              </SeverityBadge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
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
              title="No analysis reports found"
              description="Run a PCAP analysis and refresh the history."
              action={primaryAction}
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
                    <tr key={report.id ?? report.report_id ?? index}>
                      <td>{report.id ?? report.report_id ?? "—"}</td>
                      <td>{formatNumber(report.total_packets)}</td>
                      <td>{formatNumber(report.total_flows)}</td>
                      <td>{formatDate(report.created_at)}</td>
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

          <ol className="help-steps">
            <li>Start the FastAPI backend.</li>
            <li>
              Open PCAP Analysis and select a .pcap or .pcapng file.
            </li>
            <li>Run the analysis and review the returned results.</li>
            <li>Use Traffic Monitoring to inspect extracted flows.</li>
            <li>Review Security Alerts and AI Detection.</li>
            <li>Use Analysis History to review saved reports.</li>
          </ol>

          <div className="system-note">
            Keep file-size limits, packet validation, and upload security
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

      case "Website Integrations":
        return <WebsiteIntegrations />;

      case "Real-Time Monitoring":
        return renderRealtimeMonitoring();

      case "Website Traffic":
        return renderWebsiteTraffic();

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

  const searchablePages = [...navigation, ...preferenceNavigation];

  const searchResults = searchQuery.trim()
    ? searchablePages.filter((item) =>
        item.label.toLowerCase().includes(searchQuery.trim().toLowerCase())
      )
    : [];

  return (
    <div className="app-shell">
      {mobileMenuOpen && (
        <button
          type="button"
          className="mobile-sidebar-backdrop"
          aria-label="Close navigation menu"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <aside className={`sidebar ${mobileMenuOpen ? "sidebar-open" : ""}`}>
        <button
          type="button"
          className="brand"
          onClick={() => navigateTo("Overview")}
          aria-label="Go to NetSentry overview"
        >
          <span className="brand-icon" aria-hidden="true">
            <span className="brand-icon-orbit" />
            <Shield size={21} strokeWidth={1.8} />
            <span className="brand-icon-signal" />
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

              {label === "Security Alerts" && alerts.length > 0 && (
                <span className="nav-count">{alerts.length}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-label tools-label">PREFERENCES</div>

        <nav className="navigation" aria-label="Preferences">
          {preferenceNavigation.map(({ label, icon: Icon }) => (
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
              <span>
                {label === "Help" ? "Help & documentation" : label}
              </span>
            </button>
          ))}
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
          <button
            type="button"
            className="mobile-menu-button"
            aria-label="Toggle navigation"
            onClick={() => setMobileMenuOpen((open) => !open)}
          >
            {mobileMenuOpen ? <X size={21} /> : <Menu size={21} />}
          </button>

          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{activePage}</strong>
          </div>

          <div className="topbar-actions">
            <BackendStatus />

            <div className="dashboard-search-wrapper">
              <label className="search-box" htmlFor="dashboard-search">
                <Search size={17} />

                <input
                  id="dashboard-search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Search dashboard..."
                  aria-label="Search dashboard pages"
                  autoComplete="off"
                />

                {searchQuery ? (
                  <button
                    type="button"
                    className="search-clear"
                    aria-label="Clear search"
                    onClick={() => setSearchQuery("")}
                  >
                    <X size={15} />
                  </button>
                ) : (
                  <kbd>Ctrl K</kbd>
                )}
              </label>

              {searchQuery.trim() && (
                <div className="search-results">
                  {searchResults.length > 0 ? (
                    searchResults.map(({ label, icon: Icon }) => (
                      <button
                        type="button"
                        key={label}
                        onClick={() => navigateTo(label)}
                      >
                        <Icon size={17} />
                        <span>{label}</span>
                      </button>
                    ))
                  ) : (
                    <p>No dashboard pages found.</p>
                  )}
                </div>
              )}
            </div>

            <button
              type="button"
              className="icon-button"
              aria-label="Open security alerts"
              onClick={() => navigateTo("Security Alerts")}
            >
              <Bell size={19} />

              {alerts.length > 0 && (
                <span className="notification-dot" />
              )}
            </button>

            <div className="profile-wrapper">
              <button
                type="button"
                className="profile profile-trigger"
                aria-expanded={profileMenuOpen}
                onClick={() => setProfileMenuOpen((open) => !open)}
              >
                <span className="avatar">{(user?.name || "NS").split(" ").map((part) => part[0]).join("").slice(0, 2).toUpperCase()}</span>

                <span className="profile-info">
                  <strong>{user?.name || "NetSentry user"}</strong>
                  <small>{user?.email || "User account"}</small>
                </span>

                <ChevronDown size={15} />
              </button>

              {profileMenuOpen && (
                <div className="profile-menu">
                  <button
                    type="button"
                    onClick={() => navigateTo("Settings")}
                  >
                    <Settings size={16} />
                    Settings
                  </button>

                  <button
                    type="button"
                    onClick={() => navigateTo("Help")}
                  >
                    <CircleHelp size={16} />
                    Help & documentation
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await onSignOut?.();
                      } catch (error) {
                        setHistoryError(error.message || "Unable to sign out.");
                      }
                    }}
                  >
                    <LogOut size={16} />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <div className="dashboard-content" key={activePage}>
          {renderPage()}

          <footer className="developers-footer">
            <div className="developers-footer-heading">
              <span>NETSENTRY TEAM</span>
              <h2>Meet the developers</h2>
              <p>The Team behind NetSentry AI.</p>
            </div>
            <div className="developer-grid">
              {developers.map((developer, index) => (
                <article className="developer-card" key={developer.name}>
                  <div className="developer-avatar" aria-hidden="true">
                    {developer.name.split(" ").map((part) => part[0]).join("").slice(0, 2)}
                  </div>
                  <div className="developer-info">
                    <span>Developer {index + 1}</span>
                    <strong>{developer.name}</strong>
                  </div>
                  <div className="developer-links">
                    <a href={developer.linkedin} target="_blank" rel="noreferrer" aria-label={`${developer.name} on LinkedIn`}>
                      <LinkedInIcon />
                    </a>
                    <a href={developer.github} target="_blank" rel="noreferrer" aria-label={`${developer.name} on GitHub`}>
                      <GithubIcon />
                    </a>
                  </div>
                </article>
              ))}
            </div>
            <div className="developers-footer-bottom">
              <span>NetSentry AI · Network traffic analysis</span>
              <span>Built for clearer network visibility</span>
            </div>
          </footer>
        </div>
      </main>

      <style>{`
        .topbar {
          position: relative;
          isolation: isolate;
        }
        .topbar::after {
          content: "";
          position: absolute;
          right: 0;
          bottom: -1px;
          left: 0;
          height: 1px;
          transform: scaleX(.18);
          transform-origin: left;
          background: linear-gradient(90deg, #172033, #64748b, transparent);
          animation: topbar-signal 4s ease-in-out infinite alternate;
        }
        @keyframes topbar-signal {
          from { transform: scaleX(.18); opacity: .45; }
          to { transform: scaleX(1); opacity: .85; }
        }
        .developers-footer {
          margin-top: 44px;
          padding-top: 28px;
          border-top: 1px solid #e2e8f0;
        }
        .developers-footer-heading > span {
          color: #64748b;
          font-size: 10px;
          font-weight: 800;
          letter-spacing: 1.5px;
        }
        .developers-footer-heading h2 {
          margin: 7px 0 3px;
          color: #0f172a;
          font-size: 20px;
          letter-spacing: -.6px;
        }
        .developers-footer-heading p {
          margin: 0;
          color: #64748b;
          font-size: 12px;
        }
        .developer-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 10px;
          margin-top: 18px;
        }
        .developer-card {
          position: relative;
          display: grid;
          grid-template-columns: 42px minmax(0, 1fr) auto;
          align-items: center;
          gap: 11px;
          min-width: 0;
          padding: 13px;
          overflow: hidden;
          border: 1px solid #e5e7eb;
          border-radius: 9px;
          background: #fff;
          transition: transform .2s ease, border-color .2s ease, box-shadow .2s ease;
        }
        .developer-card::before {
          content: "";
          position: absolute;
          inset: 0 auto 0 0;
          width: 2px;
          background: #172033;
          transform: scaleY(0);
          transition: transform .2s ease;
        }
        .developer-card:hover {
          transform: translateY(-2px);
          border-color: #cbd5e1;
          box-shadow: 0 10px 24px rgba(15, 23, 42, .07);
        }
        .developer-card:hover::before { transform: scaleY(1); }
        .developer-avatar {
          display: grid;
          place-items: center;
          width: 42px;
          height: 42px;
          border-radius: 50%;
          color: #fff;
          background: #172033;
          font-size: 11px;
          font-weight: 800;
          letter-spacing: .5px;
        }
        .developer-info { min-width: 0; }
        .developer-info span {
          display: block;
          margin-bottom: 3px;
          color: #94a3b8;
          font-size: 9px;
          font-weight: 700;
          letter-spacing: .7px;
          text-transform: uppercase;
        }
        .developer-info strong {
          display: block;
          overflow: hidden;
          color: #1e293b;
          font-size: 12px;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .developer-links { display: flex; gap: 5px; }
        .developer-links a {
          display: grid;
          place-items: center;
          width: 32px;
          height: 32px;
          border: 1px solid #e2e8f0;
          border-radius: 7px;
          color: #475569;
          background: #fff;
          transition: color .2s ease, border-color .2s ease, transform .2s ease;
        }
        .developer-links a:hover {
          color: #172033;
          border-color: #94a3b8;
          transform: translateY(-2px);
        }
        .developers-footer-bottom {
          display: flex;
          justify-content: space-between;
          gap: 15px;
          padding: 18px 0 3px;
          margin-top: 22px;
          border-top: 1px solid #edf0f4;
          color: #94a3b8;
          font-size: 10px;
        }
        @media (max-width: 1050px) {
          .developer-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 600px) {
          .developers-footer { margin-top: 30px; }
          .developer-card { grid-template-columns: 38px minmax(0, 1fr) auto; padding: 11px; }
          .developer-avatar { width: 38px; height: 38px; }
          .developers-footer-bottom { flex-direction: column; gap: 5px; }
        }
        @media (prefers-reduced-motion: reduce) {
          .topbar::after { animation: none; transform: scaleX(1); }
        }
        .security-alert-list {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .security-alert-item {
          display: flex;
          align-items: flex-start;
          gap: 14px;
          padding: 16px;
          border: 1px solid var(--border-color, #e2e8f0);
          border-radius: 12px;
          background: var(--panel-background, #fff);
        }

        .alert-severity-icon {
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
          width: 42px;
          height: 42px;
          border-radius: 10px;
        }

        .alert-severity-icon.critical,
        .severity-badge.critical {
          color: #b91c1c;
          background: #fee2e2;
        }

        .alert-severity-icon.high,
        .severity-badge.high {
          color: #c2410c;
          background: #ffedd5;
        }

        .alert-severity-icon.medium,
        .severity-badge.medium {
          color: #a16207;
          background: #fef3c7;
        }

        .alert-severity-icon.low,
        .severity-badge.low {
          color: #166534;
          background: #dcfce7;
        }

        .security-alert-content {
          flex: 1;
          min-width: 0;
        }

        .security-alert-title-row {
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
          flex-wrap: wrap;
        }

        .security-alert-title-row h3 {
          margin: 0;
          font-size: 15px;
          font-weight: 600;
        }

        .security-alert-content p {
          margin: 8px 0;
          color: var(--muted-text, #64748b);
          font-size: 14px;
        }

        .severity-badge {
          display: inline-flex;
          align-items: center;
          padding: 4px 9px;
          border-radius: 999px;
          font-size: 11px;
          font-weight: 700;
          white-space: nowrap;
        }

        .alert-detail {
          display: inline-flex;
          align-items: center;
          gap: 4px;
          margin: 4px 12px 0 0;
          color: var(--muted-text, #64748b);
          font-size: 12px;
          overflow-wrap: anywhere;
        }

        .security-suspicious-section {
          margin-top: 28px;
        }

        .security-suspicious-section .panel-heading {
          margin-top: 8px;
        }

        .nav-count {
          margin-left: auto;
          padding: 2px 7px;
          border-radius: 999px;
          color: #1d4ed8;
          background: #dbeafe;
          font-size: 11px;
          font-weight: 700;
        }

        .dashboard-search-wrapper,
        .profile-wrapper {
          position: relative;
        }

        .search-results,
        .profile-menu {
          position: absolute;
          top: calc(100% + 8px);
          right: 0;
          z-index: 100;
          width: 240px;
          padding: 6px;
          border: 1px solid #e2e8f0;
          border-radius: 12px;
          background: #fff;
          box-shadow: 0 12px 28px rgba(15, 23, 42, 0.12);
        }

        .search-results button,
        .profile-menu button {
          display: flex;
          align-items: center;
          gap: 10px;
          width: 100%;
          padding: 10px;
          border: 0;
          border-radius: 8px;
          color: #334155;
          background: transparent;
          text-align: left;
          cursor: pointer;
        }

        .search-results button:hover,
        .profile-menu button:hover {
          background: #eff6ff;
        }

        .search-results p {
          margin: 10px;
          color: #64748b;
          font-size: 13px;
        }

        .search-clear {
          display: inline-flex;
          align-items: center;
          justify-content: center;
          border: 0;
          color: #64748b;
          background: transparent;
          cursor: pointer;
        }

        .profile-trigger {
          border: 0;
          background: transparent;
          cursor: pointer;
          text-align: left;
        }

        .notification-dot {
          position: absolute;
          top: 5px;
          right: 5px;
          width: 8px;
          height: 8px;
          border: 2px solid #fff;
          border-radius: 50%;
          background: #dc2626;
        }

        .icon-button {
          position: relative;
        }

        .mobile-menu-button,
        .mobile-sidebar-backdrop {
          display: none;
        }

        .help-steps li {
          margin-bottom: 10px;
          line-height: 1.6;
        }

        .response-details {
          margin-top: 20px;
          border-top: 1px solid #e2e8f0;
          padding-top: 14px;
        }

        .response-details summary {
          cursor: pointer;
          font-weight: 600;
        }

        .response-details pre {
          max-height: 420px;
          overflow: auto;
          padding: 14px;
          border-radius: 10px;
          background: #0f172a;
          color: #e2e8f0;
          font-size: 12px;
          white-space: pre-wrap;
          overflow-wrap: anywhere;
        }

        .traffic-chart-section {
          margin-top: 24px;
        }

        @media (max-width: 900px) {
          .mobile-menu-button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 38px;
            height: 38px;
            border: 1px solid #e2e8f0;
            border-radius: 10px;
            color: #334155;
            background: #fff;
            cursor: pointer;
          }

          .sidebar {
            position: fixed;
            top: 0;
            bottom: 0;
            left: 0;
            z-index: 200;
            width: min(290px, 85vw);
            transform: translateX(-105%);
            transition: transform 180ms ease;
            overflow-y: auto;
          }

          .sidebar.sidebar-open {
            transform: translateX(0);
          }

          .mobile-sidebar-backdrop {
            display: block;
            position: fixed;
            inset: 0;
            z-index: 190;
            border: 0;
            background: rgba(15, 23, 42, 0.42);
          }

          .main-content {
            width: 100%;
            margin-left: 0;
          }

          .topbar {
            gap: 12px;
          }

          .topbar-actions {
            min-width: 0;
            gap: 10px;
          }

          .profile-info,
          .profile-trigger > svg {
            display: none;
          }

          .breadcrumb {
            white-space: nowrap;
          }
        }

        @media (max-width: 640px) {
          .topbar {
            flex-wrap: wrap;
            padding: 12px;
          }

          .breadcrumb {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
          }

          .topbar-actions {
            display: flex;
            width: 100%;
            justify-content: space-between;
          }

          .dashboard-search-wrapper {
            flex: 1;
            min-width: 0;
          }

          .search-box {
            width: 100%;
          }

          .search-box kbd {
            display: none;
          }

          .welcome-row {
            align-items: flex-start;
            flex-direction: column;
            gap: 16px;
          }

          .security-alert-item {
            padding: 12px;
          }

          .security-alert-title-row {
            align-items: flex-start;
          }

          .metrics-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .table-scroll {
            overflow-x: auto;
          }

          .flows-table {
            min-width: 600px;
          }
        }

        @media (prefers-reduced-motion: reduce) {
          .sidebar {
            transition: none;
          }
        }
      `}</style>
    </div>
  );
}
