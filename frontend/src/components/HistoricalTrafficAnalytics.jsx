import { useEffect, useMemo, useState } from "react";
import { Activity, BarChart3, Filter, RefreshCw, Search, TrendingUp } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getHistoricalTrafficAnalytics } from "../services/api";

const PAGE_SIZE = 20;
const EMPTY = {
  total_flows: 0, total_packets: 0, total_bytes: 0, average_packet_size: 0,
  flows: [], protocol_distribution: {}, transport_distribution: {},
  traffic_volume_over_time: [], top_sources: [], top_destinations: [], top_ports: [], protocols: [],
  total_matching_records: 0, flow_records_truncated: false, truncated: false,
};

function formatNumber(value) { return Number(value || 0).toLocaleString(); }
function formatBytes(value) {
  let size = Number(value || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
}
function dateLabel(value) { return value ? new Date(value).toLocaleString() : "—"; }

export default function HistoricalTrafficAnalytics() {
  const [data, setData] = useState(EMPTY);
  const [draft, setDraft] = useState({ since: "", until: "", protocol: "", search: "" });
  const [filters, setFilters] = useState({ since: "", until: "", protocol: "", search: "" });
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  const query = useMemo(() => ({
    skip: page * PAGE_SIZE,
    limit: PAGE_SIZE,
    ...(filters.since ? { since: new Date(`${filters.since}T00:00:00`).toISOString() } : {}),
    ...(filters.until ? { until: new Date(`${filters.until}T23:59:59.999`).toISOString() } : {}),
    protocol: filters.protocol,
    search: filters.search.trim(),
  }), [filters, page]);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      try {
        const result = await getHistoricalTrafficAnalytics(query);
        if (active) { setData(result); setError(""); }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Unable to load historical traffic analytics.");
      } finally { if (active) setLoading(false); }
    }, 0);
    return () => { active = false; window.clearTimeout(timer); };
  }, [query, refreshKey]);

  function applyFilters(event) {
    event.preventDefault();
    setPage(0);
    setFilters(draft);
  }

  const chartData = useMemo(() => (data.traffic_volume_over_time || []).map((item) => ({
    time: item.time,
    bytes: Number(item.bytes || 0),
    flows: Number(item.flows || 0),
    packets: Number(item.packets || 0),
  })), [data.traffic_volume_over_time]);
  const totalPages = Math.max(1, Math.ceil(Number(data.total_matching_records || 0) / PAGE_SIZE));
  const packetsPerMinute = Number(data.average_packets_per_minute || 0);
  const protocols = Object.entries(data.protocol_distribution || {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="historical-traffic-page">
      <form className="panel historical-filters" onSubmit={applyFilters}>
        <div className="historical-filter-heading"><div><Filter size={17} /><div><strong>Filter saved traffic</strong><small>PCAP analysis reports only · choose a date range or protocol</small></div></div><button type="button" className="secondary-button" onClick={() => setRefreshKey((value) => value + 1)} disabled={loading}><RefreshCw size={14} /> Refresh</button></div>
        <label>From<input type="date" value={draft.since} onChange={(event) => setDraft({ ...draft, since: event.target.value })} /></label>
        <label>Through<input type="date" value={draft.until} onChange={(event) => setDraft({ ...draft, until: event.target.value })} /></label>
        <label>Protocol<select value={draft.protocol} onChange={(event) => setDraft({ ...draft, protocol: event.target.value })}><option value="">All protocols</option>{(data.protocols || []).map((protocol) => <option key={protocol}>{protocol}</option>)}</select></label>
        <label className="historical-search"><Search size={16} /><input type="search" value={draft.search} onChange={(event) => setDraft({ ...draft, search: event.target.value })} placeholder="Search address, port, protocol, report…" /></label>
        <button className="primary-button historical-apply" type="submit">Apply filters</button>
      </form>

      {error && <div className="website-error" role="alert">{error}</div>}
      {(data.truncated || data.flow_records_truncated) && <div className="website-status-note">{data.truncated && "Analytics summarize the most recent 250 saved PCAP reports. "}{data.flow_records_truncated && "Some saved PCAP reports retain only the first 100 flow records, so protocol breakdowns, byte totals, and the visible history table cover those returned records; total packet and flow counts use the saved report totals."}</div>}

      <section className="historical-metrics">
        <article><span><Activity size={17} /> Total packets</span><strong>{loading ? "…" : formatNumber(data.total_packets)}</strong><small>From matching saved PCAP flows</small></article>
        <article><span><BarChart3 size={17} /> Total flows</span><strong>{loading ? "…" : formatNumber(data.total_flows)}</strong><small>Historical flow records</small></article>
        <article><span><TrendingUp size={17} /> Bytes transferred</span><strong>{loading ? "…" : formatBytes(data.total_bytes)}</strong><small>Sum from flow records retained in saved reports</small></article>
        <article><span><Activity size={17} /> Average packet size</span><strong>{loading ? "…" : formatBytes(data.average_packet_size)}</strong><small>{formatNumber(packetsPerMinute)} packets/min from retained flow durations</small></article>
      </section>

      <div className="historical-charts-grid">
        <section className="panel historical-chart-card"><div className="panel-heading"><div><h2>Traffic volume over time</h2><p>Saved report time · bytes in analyzed flows</p></div></div>{chartData.length ? <div className="historical-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={chartData}><CartesianGrid strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" tick={{ fontSize: 10 }} minTickGap={28} /><YAxis tick={{ fontSize: 10 }} /><Tooltip formatter={(value) => formatBytes(value)} /><Line type="monotone" dataKey="bytes" name="Bytes" stroke="#2563eb" strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer></div> : <p className="historical-empty">No saved traffic for this filter.</p>}</section>
        <section className="panel historical-chart-card"><div className="panel-heading"><div><h2>Flows over time</h2><p>Actual flow records grouped by analysis report timestamp</p></div></div>{chartData.length ? <div className="historical-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={chartData}><CartesianGrid strokeDasharray="3 3" vertical={false} /><XAxis dataKey="time" tick={{ fontSize: 10 }} minTickGap={28} /><YAxis tick={{ fontSize: 10 }} allowDecimals={false} /><Tooltip /><Line type="monotone" dataKey="flows" name="Flows" stroke="#0f766e" strokeWidth={2} dot={false} /></LineChart></ResponsiveContainer></div> : <p className="historical-empty">No saved traffic for this filter.</p>}</section>
      </div>

      <section className="historical-breakdowns-grid">
        <section className="panel historical-breakdown"><h2>Protocol distribution</h2>{protocols.length ? protocols.map(([protocol, count]) => <div key={protocol}><span>{protocol}</span><b>{formatNumber(count)}</b></div>) : <p>No protocol records.</p>}<h3>TCP versus UDP</h3><div><span>TCP</span><b>{formatNumber(data.transport_distribution?.TCP)}</b></div><div><span>UDP</span><b>{formatNumber(data.transport_distribution?.UDP)}</b></div></section>
        <section className="panel historical-breakdown"><h2>Top source IP addresses</h2>{data.top_sources?.length ? data.top_sources.slice(0, 5).map((item) => <div key={item.ip}><code>{item.ip}</code><b>{formatNumber(item.packets)} pkts</b></div>) : <p>No source records.</p>}<h3>Top destination IP addresses</h3>{data.top_destinations?.length ? data.top_destinations.slice(0, 5).map((item) => <div key={item.ip}><code>{item.ip}</code><b>{formatNumber(item.packets)} pkts</b></div>) : <p>No destination records.</p>}</section>
        <section className="panel historical-breakdown"><h2>Most-used ports</h2>{data.top_ports?.length ? data.top_ports.slice(0, 10).map((item) => <div key={item.port}><code>{item.port}</code><b>{formatNumber(item.packets)} pkts</b></div>) : <p>No port records.</p>}</section>
      </section>

      <section className="panel historical-flow-table">
        <div className="panel-heading"><div><h2>Historical traffic flows</h2><p>{formatNumber(data.total_matching_records)} matching stored flow rows · {formatNumber(data.total_flows)} total flows reported by selected PCAPs</p></div></div>
        {loading && !data.flows?.length ? <p className="historical-empty">Loading saved flow records…</p> : data.flows?.length ? <div className="table-scroll"><table><thead><tr><th>Analysis time</th><th>Report</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Ports</th><th>Packets</th><th>Bytes</th><th>Classification</th></tr></thead><tbody>{data.flows.map((flow, index) => <tr key={`${flow.report_id}-${index}`}><td>{dateLabel(flow.timestamp)}</td><td>#{flow.report_id}</td><td>{flow.src_ip}</td><td>{flow.dst_ip}</td><td>{flow.protocol}</td><td>{flow.src_port} → {flow.dst_port}</td><td>{formatNumber(flow.packet_count)}</td><td>{formatBytes(flow.total_bytes)}</td><td>{flow.classification || "UNASSESSED"}</td></tr>)}</tbody></table></div> : <p className="historical-empty">No saved flows match the filters. Analyze a PCAP from the PCAP Analysis page to add historical data.</p>}
        <div className="historical-pagination"><span>Page {page + 1} of {totalPages}</span><div><button className="secondary-button" disabled={page === 0 || loading} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</button><button className="secondary-button" disabled={page + 1 >= totalPages || loading} onClick={() => setPage((value) => value + 1)}>Next</button></div></div>
      </section>
      <p className="historical-data-note">Historical charts group retained flow records by the time their PCAP analysis was saved because existing reports do not retain packet-by-packet timestamps. Packets/minute is derived from retained flow packet counts and durations.</p>
    </div>
  );
}
