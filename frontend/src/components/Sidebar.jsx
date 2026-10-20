
import {
  Activity,
  LayoutDashboard,
  Network,
  FileSearch,
  ShieldCheck,
  History,
} from "lucide-react";

const navigation = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "PCAP Analysis", icon: FileSearch },
  { label: "Network Flows", icon: Network },
  { label: "Threat Monitoring", icon: ShieldCheck },
  { label: "Analysis History", icon: History },
];

export default function Sidebar({
  activePage = "Overview",
  onNavigate,
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">
          <Activity size={22} />
        </div>

        <div>
          <h2>NetSentry</h2>
          <span>AI NETWORK SECURITY</span>
        </div>
      </div>

      <p className="sidebar-section-label">WORKSPACE</p>

      <nav className="sidebar-nav" aria-label="Main navigation">
        {navigation.map(({ label, icon: Icon }) => (
          <button
            key={label}
            type="button"
            className={`nav-item ${
              activePage === label ? "active" : ""
            }`}
            aria-current={activePage === label ? "page" : undefined}
            onClick={() => onNavigate?.(label)}
          >
            <Icon size={19} />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-footer">
        <span className="status-dot" />

        <div>
          <strong>NetSentry Engine</strong>
          <p>Interface ready</p>
        </div>
      </div>
    </aside>
  );
}
