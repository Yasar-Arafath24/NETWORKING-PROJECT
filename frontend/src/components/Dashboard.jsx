import { useState } from "react";
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
import FlowResults from "./FlowResults";
import PcapUpload from "./PcapUpload";
import { uploadPcap } from "../services/api";


const trafficData = [
  { time: "09:00", packets: 120, suspicious: 12 },
  { time: "09:10", packets: 180, suspicious: 18 },
  { time: "09:20", packets: 150, suspicious: 9 },
  { time: "09:30", packets: 240, suspicious: 28 },
  { time: "09:40", packets: 210, suspicious: 16 },
  { time: "09:50", packets: 310, suspicious: 35 },
  { time: "10:00", packets: 260, suspicious: 21 },
  { time: "10:10", packets: 350, suspicious: 42 },
];

const navigation = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "PCAP Analysis", icon: FileSearch },
  { label: "Traffic Monitoring", icon: Activity },
  { label: "AI Detection", icon: ShieldAlert },
  { label: "Security Alerts", icon: Bell },
  { label: "Analysis History", icon: FileText },
];

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

export default function Dashboard() {
  const [uploadingPcap, setUploadingPcap] = useState(false);
  const [analysis, setAnalysis] = useState(null);

  async function handlePcapUpload(file) {
    setUploadingPcap(true);

    try {
      const result = await uploadPcap(file);
      setAnalysis(result);
      return result;
    } finally {
      setUploadingPcap(false);
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#overview">
          <span className="brand-icon">
            <Shield size={23} />
          </span>
          <span>
            <strong>NetSentry</strong>
            <small>NETWORK INTELLIGENCE</small>
          </span>
        </a>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="navigation">
          {navigation.map(({ label, icon: Icon }, index) => (
            <a
              href={`#${label.toLowerCase().replaceAll(" ", "-")}`}
              key={label}
              className={`nav-item ${index === 0 ? "nav-active" : ""}`}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
            </a>
          ))}
        </nav>

        <div className="sidebar-label tools-label">PREFERENCES</div>

        <nav className="navigation">
          <a href="#settings" className="nav-item">
            <Settings size={18} strokeWidth={1.8} />
            <span>Settings</span>
          </a>
          <a href="#help" className="nav-item">
            <CircleHelp size={18} strokeWidth={1.8} />
            <span>Help & documentation</span>
          </a>
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-indicator">
            <span className="status-dot" />
            <div>
              <strong>API connection</strong>
              <small>Not verified</small>
            </div>
          </div>
          <p>NetSentry AI · Development</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>Overview</strong>
          </div>

          <div className="topbar-actions">
            <label className="search-box">
              <Search size={17} />
              <input placeholder="Search dashboard..." aria-label="Search dashboard" />
              <kbd>⌘ K</kbd>
            </label>

            <button className="icon-button" aria-label="Notifications">
              <Bell size={19} />
              <span className="notification-dot" />
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

        <div className="dashboard-content" id="overview">
          <section className="welcome-row">
            <div>
              <div className="eyebrow">NETWORK OPERATIONS</div>
              <h1>Security overview</h1>
              <p className="page-description">
                Monitor network activity and review your traffic analysis.
              </p>
            </div>

            <button
              type="button"
              className="primary-button"
              onClick={() =>
                document
                  .getElementById("pcap-analysis")
                  ?.scrollIntoView({ behavior: "smooth" })
              }
            >
              <Upload size={17} />
              Analyze PCAP
            </button>
          </section>

          <section className="monitor-banner">
            <div className="monitor-icon">
              <Wifi size={21} />
            </div>
            <div className="monitor-copy">
              <strong>Network monitoring workspace</strong>
              <span>
                Dashboard preview · Connect the backend to display live results.
              </span>
            </div>
            <span className="preview-badge">UI PREVIEW</span>
          </section>

          <section id="pcap-analysis" className="mt-6">
            <PcapUpload
              onUpload={handlePcapUpload}
              uploading={uploadingPcap}
            />
          </section>

          <section className="metrics-grid">
            <MetricCard
              title="Total packets"
              value="—"
              description="Awaiting backend data"
              icon={Network}
            />
            <MetricCard
              title="Network flows"
              value="—"
              description="Awaiting backend data"
              icon={Activity}
            />
            <MetricCard
              title="Anomalies detected"
              value="—"
              description="AI results not connected"
              icon={ShieldAlert}
            />
            <MetricCard
              title="Analysis reports"
              value="—"
              description="Awaiting backend data"
              icon={FileText}
            />
          </section>

          <section className="content-grid">
            <article className="panel traffic-panel">
              <div className="panel-heading">
                <div>
                  <h2>Network traffic</h2>
                  <p>Sample visualization · Not live traffic</p>
                </div>
                <button className="select-button">
                  Last 60 minutes <ChevronDown size={15} />
                </button>
              </div>

              <div className="chart-legend">
                <span>
                  <i className="legend-blue" /> Packets
                </span>
                <span>
                  <i className="legend-light" /> Suspicious activity
                </span>
              </div>

              <div className="chart-container">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart
                    data={trafficData}
                    margin={{ top: 12, right: 8, left: -16, bottom: 0 }}
                  >
                    <defs>
                      <linearGradient id="packetGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#2563EB" stopOpacity={0.15} />
                        <stop offset="95%" stopColor="#2563EB" stopOpacity={0} />
                      </linearGradient>
                    </defs>

                    <CartesianGrid
                      stroke="#E2E8F0"
                      strokeDasharray="3 3"
                      vertical={false}
                    />

                    <XAxis
                      dataKey="time"
                      tick={{ fill: "#64748B", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                      tickMargin={12}
                    />

                    <YAxis
                      tick={{ fill: "#64748B", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={{
                        borderRadius: 8,
                        border: "1px solid #E2E8F0",
                        fontSize: 12,
                      }}
                    />

                    <Area
                      type="monotone"
                      dataKey="packets"
                      stroke="#2563EB"
                      strokeWidth={2}
                      fill="url(#packetGradient)"
                    />

                    <Area
                      type="monotone"
                      dataKey="suspicious"
                      stroke="#94A3B8"
                      strokeWidth={2}
                      fill="transparent"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </article>

            <article className="panel system-panel">
              <div className="panel-heading">
                <div>
                  <h2>System status</h2>
                  <p>Service availability</p>
                </div>
                <span className="status-neutral">Unverified</span>
              </div>

              <div className="system-list">
                <div className="system-row">
                  <span className="system-row-icon">
                    <Gauge size={18} />
                  </span>
                  <div className="system-row-copy">
                    <strong>FastAPI backend</strong>
                    <small>Connection not checked</small>
                  </div>
                  <span className="status-neutral">Unknown</span>
                </div>

                <div className="system-row">
                  <span className="system-row-icon">
                    <Network size={18} />
                  </span>
                  <div className="system-row-copy">
                    <strong>Packet analysis</strong>
                    <small>Awaiting verification</small>
                  </div>
                  <span className="status-neutral">Unknown</span>
                </div>

                <div className="system-row">
                  <span className="system-row-icon">
                    <ShieldAlert size={18} />
                  </span>
                  <div className="system-row-copy">
                    <strong>AI detection</strong>
                    <small>Integration not checked</small>
                  </div>
                  <span className="status-neutral">Unknown</span>
                </div>
              </div>

              <div className="system-note">
                Service status will be displayed after API integration.
              </div>
            </article>
          </section>

          <FlowResults flows={analysis?.flows ?? []} />

          <footer className="dashboard-footer">
            <span>NetSentry AI · Network traffic analysis</span>
            <span>Development preview · Not a live security console</span>
          </footer>
        </div>
      </main>
    </div>
  );
}