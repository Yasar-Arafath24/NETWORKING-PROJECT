import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, Pause, Play, RefreshCw, ShieldAlert } from "lucide-react";
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getWebsiteConnectionStatus, getWebsiteEvents, getWebsites, websiteLiveUrl } from "../services/api";

const PAGE_SIZE = 50;
const RANGE_MS = { "1h": 60 * 60 * 1000, "24h": 24 * 60 * 60 * 1000, "7d": 7 * 24 * 60 * 60 * 1000 };
const HTTP_STATUSES = Array.from({ length: 500 }, (_, index) => index + 100);
const EMPTY_METRICS = {
  total_requests: 0,
  requests_per_minute: 0,
  successful_requests: 0,
  client_errors: 0,
  server_errors: 0,
  average_duration_ms: 0,
  duration_sample_count: 0,
  response_bytes: 0,
  anomaly_count: 0,
  status_distribution: {},
  requests_per_minute_timeline: [],
};

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes.toLocaleString()} B`;
  const units = ["KB", "MB", "GB", "TB"];
  const unit = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)) - 1, units.length - 1);
  return `${(bytes / 1024 ** (unit + 1)).toFixed(2)} ${units[unit]}`;
}

function statusClass(value) {
  return String(value || "DISCONNECTED").toLowerCase();
}

export default function WebsiteTrafficMonitoring({ initialSiteId, onOpenIntegrations }) {
  const [websites, setWebsites] = useState([]);
  const [selectedId, setSelectedId] = useState(initialSiteId ?? null);
  const [events, setEvents] = useState([]);
  const [filteredTotal, setFilteredTotal] = useState(0);
  const [metrics, setMetrics] = useState(EMPTY_METRICS);
  const [connection, setConnection] = useState(null);
  const [loadingSites, setLoadingSites] = useState(true);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [error, setError] = useState("");
  const [paused, setPaused] = useState(false);
  const [socketState, setSocketState] = useState("Disconnected");
  const [clock, setClock] = useState(0);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({
    search: "",
    method: "",
    status_code: "",
    classification: "all",
    range: "24h",
  });
  const requestSequence = useRef(0);
  const seenMessages = useRef(new Set());
  const queryRef = useRef(null);
  const loadEventsRef = useRef(null);

  const selected = websites.find((website) => website.id === selectedId) || null;
  const query = useMemo(() => ({
    skip: page * PAGE_SIZE,
    limit: PAGE_SIZE,
    search: filters.search.trim(),
    method: filters.method,
    status_code: filters.status_code,
    classification: filters.classification,
    since: new Date(clock - RANGE_MS[filters.range]).toISOString(),
  }), [clock, filters, page]);

  const loadSites = useCallback(async () => {
    try {
      const result = await getWebsites();
      const sites = result.websites || [];
      setWebsites(sites);
      setSelectedId((current) => {
        if (initialSiteId && sites.some((site) => site.id === initialSiteId)) return initialSiteId;
        if (current && sites.some((site) => site.id === current)) return current;
        return sites[0]?.id ?? null;
      });
      setError("");
    } catch (requestError) {
      setError(requestError.message || "Unable to load your websites.");
    } finally {
      setLoadingSites(false);
    }
  }, [initialSiteId]);

  const loadEvents = useCallback(async (siteId, options = query) => {
    if (!siteId) {
      setEvents([]);
      setFilteredTotal(0);
      setMetrics(EMPTY_METRICS);
      return;
    }
    const requestId = ++requestSequence.current;
    setLoadingEvents(true);
    try {
      const result = await getWebsiteEvents(siteId, options);
      if (requestId !== requestSequence.current) return;
      setEvents(result.events || []);
      setFilteredTotal(Number(result.total || 0));
      setMetrics({ ...EMPTY_METRICS, ...(result.summary || {}) });
      setError("");
    } catch (requestError) {
      if (requestId === requestSequence.current) {
        setError(requestError.message || "Unable to load website traffic.");
      }
    } finally {
      if (requestId === requestSequence.current) setLoadingEvents(false);
    }
  }, [query]);
  useEffect(() => {
    queryRef.current = query;
    loadEventsRef.current = loadEvents;
  }, [loadEvents, query]);

  useEffect(() => {
    const timer = window.setTimeout(loadSites, 0);
    return () => window.clearTimeout(timer);
  }, [loadSites]);

  useEffect(() => {
    if (!selectedId) return undefined;
    const timer = window.setTimeout(() => {
      loadEventsRef.current?.(selectedId, queryRef.current);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      requestSequence.current += 1;
    };
  }, [filters, page, selectedId]);

  useEffect(() => {
    if (!clock || paused || !selectedId) return undefined;
    const timer = window.setTimeout(() => {
      loadEventsRef.current?.(selectedId, queryRef.current);
    }, 0);
    return () => {
      window.clearTimeout(timer);
      requestSequence.current += 1;
    };
  }, [clock, paused, selectedId]);

  useEffect(() => {
    if (!selectedId) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const result = await getWebsiteConnectionStatus(selectedId);
        if (active) setConnection(result);
      } catch (requestError) {
        if (active) setConnection({ site_id: selectedId, status: "ERROR", message: requestError.message });
      }
    };
    refresh();
    const timer = window.setInterval(refresh, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [selectedId]);

  useEffect(() => {
    const initial = window.setTimeout(() => setClock(Date.now()), 0);
    const timer = window.setInterval(() => setClock(Date.now()), 60000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!selectedId || paused || !selected?.enabled) {
      return undefined;
    }

    let socket;
    let retryTimer;
    let retryCount = 0;
    let disposed = false;
    seenMessages.current = new Set();

    const connect = () => {
      if (disposed) return;
      setSocketState(retryCount ? "Reconnecting" : "Connecting");
      try {
        socket = new WebSocket(websiteLiveUrl(selectedId));
      } catch {
        scheduleReconnect();
        return;
      }
      socket.onopen = () => {
        retryCount = 0;
        setSocketState("Connected");
      };
      socket.onmessage = (message) => {
        let payload;
        try {
          payload = JSON.parse(message.data);
        } catch {
          return;
        }
        if (payload.type !== "traffic_event") return;
        const identity = payload.event_id || payload.id;
        if (identity && seenMessages.current.has(identity)) return;
        if (identity) {
          seenMessages.current.add(identity);
          if (seenMessages.current.size > 2000) {
            seenMessages.current = new Set(Array.from(seenMessages.current).slice(-1000));
          }
        }
        loadEventsRef.current?.(selectedId, queryRef.current);
        loadSites();
      };
      socket.onerror = () => socket.close();
      socket.onclose = (event) => {
        if (disposed) return;
        if (event.code === 1008) {
          setSocketState("Disconnected");
          return;
        }
        if (event.code === 1000) {
          getWebsiteConnectionStatus(selectedId).then((status) => {
            if (disposed) return;
            if (status.enabled) scheduleReconnect();
            else setSocketState("Disconnected");
          }).catch(() => {
            if (!disposed) scheduleReconnect();
          });
          return;
        }
        scheduleReconnect();
      };
    };

    const scheduleReconnect = () => {
      if (disposed) return;
      setSocketState("Reconnecting");
      const delay = Math.min(1000 * (2 ** retryCount), 30000);
      retryCount += 1;
      retryTimer = window.setTimeout(connect, delay);
    };

    const initialTimer = window.setTimeout(connect, 0);
    return () => {
      disposed = true;
      window.clearTimeout(initialTimer);
      window.clearTimeout(retryTimer);
      if (socket) {
        socket.onclose = null;
        socket.close();
      }
    };
  }, [loadSites, paused, selected?.enabled, selectedId]);

  const chartData = useMemo(() => {
    const raw = metrics.requests_per_minute_timeline || [];
    if (!raw.length) return [];
    const counts = new Map(raw.map((item) => [
      Math.floor(new Date(item.minute).getTime() / 60000) * 60000,
      Number(item.count || 0),
    ]));
    const lastMinute = Math.floor(clock / 60000) * 60000;
    const minuteCount = RANGE_MS[filters.range] / 60000;
    return Array.from({ length: minuteCount }, (_, index) => {
      const timestamp = lastMinute - (minuteCount - index - 1) * 60000;
      return { minute: new Date(timestamp).toISOString(), requests: counts.get(timestamp) || 0 };
    });
  }, [clock, filters.range, metrics.requests_per_minute_timeline]);
  const anomalies = events.filter((event) => event.severity === "HEURISTIC" || ["SUSPICIOUS", "ANOMALOUS"].includes(event.classification));
  const totalPages = Math.max(1, Math.ceil(filteredTotal / PAGE_SIZE));
  const connectionState = (connection && connection.site_id === selected?.id ? connection.status : selected?.integration_status) || "WAITING_FOR_EVENTS";
  const liveState = paused ? "Paused" : !selected?.enabled ? "Disconnected" : socketState;

  function changeFilter(name, value) {
    setPage(0);
    setFilters((current) => ({ ...current, [name]: value }));
  }

  return (
    <div className="website-monitor-page traffic-monitoring-page">
      <section className="welcome-row">
        <div>
          <div className="eyebrow">AUTHENTICATED WEBSITE TELEMETRY</div>
          <h1>Traffic Monitoring</h1>
          <p className="page-description">Live HTTP requests received from your registered website collector. PCAP and network-flow analytics remain separate under PCAP Analysis.</p>
        </div>
        <div className="traffic-page-actions">
          {selected && <button type="button" className="secondary-button" onClick={() => setPaused((value) => !value)}>{paused ? <Play size={15} /> : <Pause size={15} />}{paused ? "Resume live updates" : "Pause live updates"}</button>}
          <button type="button" className="secondary-button" onClick={() => selectedId && loadEvents(selectedId)} disabled={loadingEvents}><RefreshCw size={14} /> Refresh</button>
        </div>
      </section>

      {error && <div className="website-error" role="alert">{error}</div>}

      {loadingSites ? (
        <section className="panel website-empty">Loading your registered websites…</section>
      ) : websites.length === 0 ? (
        <section className="panel website-empty">
          <h2>No websites registered</h2>
          <p>Register a website and install its server-side collector to start receiving real request events.</p>
          <button type="button" className="primary-button" onClick={onOpenIntegrations}>Open Website Integrations</button>
        </section>
      ) : (
        <>
          <section className="panel traffic-website-selector">
            <label htmlFor="traffic-website">Website</label>
            <select id="traffic-website" value={selectedId || ""} onChange={(event) => { setPage(0); setSelectedId(Number(event.target.value)); }}>
              {websites.map((website) => <option key={website.id} value={website.id}>{website.name} · {website.url}</option>)}
            </select>
            {selected && <div className="traffic-selected-website"><strong>{selected.name}</strong><span>{selected.url}</span></div>}
            <span className={`integration-status status-${statusClass(connectionState)}`}>{connectionState}</span>
            <span className={`traffic-socket-state traffic-socket-${statusClass(liveState)}`}>{liveState}</span>
          </section>

          <section className="website-metrics traffic-metrics">
            <article><span>Total requests</span><strong>{Number(metrics.total_requests || 0).toLocaleString()}</strong><small>{filters.range} window</small></article>
            <article><span>Requests / minute</span><strong>{Number(metrics.requests_per_minute || 0).toLocaleString()}</strong><small>Last 60 seconds</small></article>
            <article><span>Successful requests (2xx)</span><strong>{Number(metrics.successful_requests || 0).toLocaleString()}</strong></article>
            <article><span>Client errors (4xx)</span><strong>{Number(metrics.client_errors || 0).toLocaleString()}</strong></article>
            <article><span>Server errors (5xx)</span><strong>{Number(metrics.server_errors || 0).toLocaleString()}</strong></article>
            <article><span>Average response time</span><strong>{Number(metrics.duration_sample_count || 0) ? `${Number(metrics.average_duration_ms || 0).toFixed(1)} ms` : "—"}</strong><small>{Number(metrics.duration_sample_count || 0) ? `${Number(metrics.duration_sample_count).toLocaleString()} measured requests` : Number(metrics.total_requests || 0) ? "No duration values reported by the access log" : "No received requests"}</small></article>
            <article><span>Total response bytes</span><strong>{formatBytes(metrics.response_bytes)}</strong></article>
            <article><span>Anomaly count</span><strong>{Number(metrics.anomaly_count || 0).toLocaleString()}</strong></article>
          </section>

          <section className="panel website-chart traffic-chart">
            <div className="panel-heading"><div><h2>Requests per minute</h2><p>Accepted access-log events · {filters.range} window{paused ? " · live updates paused; history remains visible" : ""}</p></div><Activity size={18} /></div>
            {chartData.length ? (
              <div className="traffic-chart-content">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="minute" tick={{ fontSize: 10 }} minTickGap={30} tickFormatter={(value) => new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 10 }} />
                    <Tooltip labelFormatter={(value) => formatTime(value)} />
                    <Line type="stepAfter" dataKey="requests" name="Requests" stroke="#2563eb" strokeWidth={2} dot={false} isAnimationActive={false} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            ) : <p className="historical-empty">No accepted website events in this time range.</p>}
          </section>

          {anomalies.length > 0 && <section className="panel traffic-anomaly-panel">
            <div className="panel-heading"><div><h2><ShieldAlert size={17} /> Anomaly findings</h2><p>Findings returned by the website detection service for actual events</p></div><strong>{Number(metrics.anomaly_count || 0).toLocaleString()} total</strong></div>
            <div className="traffic-anomaly-list">{anomalies.slice(0, 5).map((event) => <article key={event.id}><span className={`traffic-classification ${statusClass(event.classification)}`}>{event.classification}</span><code>{event.method} {event.path}</code><span>{event.detection_categories?.join(", ") || event.reason || "Rule-based finding"}</span><small>{formatTime(event.request_timestamp || event.received_at)}</small></article>)}</div>
          </section>}

          <section className="panel">
            <div className="panel-heading"><div><h2>Live website requests</h2><p>{selected?.name} · {Number(metrics.total_requests || 0).toLocaleString()} requests in the selected time range</p></div></div>
            <div className="website-event-filters traffic-event-filters">
              <input aria-label="Search path or source IP" placeholder="Search path or source IP" value={filters.search} onChange={(event) => changeFilter("search", event.target.value)} />
              <select aria-label="Filter HTTP method" value={filters.method} onChange={(event) => changeFilter("method", event.target.value)}><option value="">All methods</option>{["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => <option key={method}>{method}</option>)}</select>
              <select aria-label="Filter HTTP status" value={filters.status_code} onChange={(event) => changeFilter("status_code", event.target.value)}><option value="">All statuses</option>{HTTP_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}</select>
              <select aria-label="Filter anomaly classification" value={filters.classification} onChange={(event) => changeFilter("classification", event.target.value)}><option value="all">All classifications</option><option value="normal">Normal</option><option value="suspicious">Suspicious</option><option value="anomalous">Anomalous</option><option value="heuristic">Heuristic finding</option><option value="unassessed">Unassessed</option></select>
              <select aria-label="Filter time range" value={filters.range} onChange={(event) => changeFilter("range", event.target.value)}><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option></select>
            </div>
            {events.length ? (
              <div className="website-event-table">
                <table><thead><tr><th>Timestamp</th><th>Method</th><th>Path</th><th>Status</th><th>Duration</th><th>Response size</th><th>Source IP</th><th>Classification</th></tr></thead>
                  <tbody>{events.map((event) => (
                    <tr key={event.id}>
                      <td>{formatTime(event.request_timestamp || event.received_at)}</td>
                      <td>{event.method}</td>
                      <td><code>{event.path}</code></td>
                      <td>{event.status_code}</td>
                      <td>{event.duration_measured ? `${Number(event.duration_ms || 0).toFixed(1)} ms` : "—"}</td>
                      <td>{formatBytes(event.response_bytes)}</td>
                      <td>{event.source_ip || "—"}</td>
                      <td><span className={`traffic-classification ${statusClass(event.classification)}`}>{event.classification || "UNASSESSED"}</span></td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ) : <div className="website-empty">{connection?.verified ? "No requests match these filters." : "WAITING_FOR_EVENTS — start the collector and generate a real website request. No sample traffic is shown."}</div>}
            <div className="historical-pagination"><span>{loadingEvents ? "Refreshing…" : `${filteredTotal.toLocaleString()} matching requests · page ${page + 1} of ${totalPages}`}</span><div><button type="button" className="secondary-button" onClick={() => setPage((value) => Math.max(0, value - 1))} disabled={page === 0 || loadingEvents}>Previous</button><button type="button" className="secondary-button" onClick={() => setPage((value) => Math.min(totalPages - 1, value + 1))} disabled={page >= totalPages - 1 || loadingEvents}>Next</button></div></div>
          </section>
        </>
      )}
    </div>
  );
}
