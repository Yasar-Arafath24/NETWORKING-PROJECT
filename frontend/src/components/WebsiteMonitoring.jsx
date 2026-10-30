import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Globe2, KeyRound, Plus, Radio, RefreshCw, Trash2 } from "lucide-react";
import { COLLECTOR_API_URL, addWebsite, deleteWebsite, getWebsiteEvents, getWebsites, rotateWebsiteToken, setWebsiteEnabled, websiteLiveUrl } from "../services/api";

const PAGE_SIZE = 50;
function timeLabel(value) { return value ? new Date(value).toLocaleString() : "—"; }

export default function WebsiteMonitoring({ embedded = false }) {
  const [websites, setWebsites] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [metrics, setMetrics] = useState({ total_requests: 0, requests_per_minute: 0, response_bytes: 0, heuristic_flags: 0, status_distribution: {} });
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [newSite, setNewSite] = useState(null);
  const [clock, setClock] = useState(0);
  const [page, setPage] = useState(0);
  const [filters, setFilters] = useState({ search: "", method: "", status_code: "", classification: "all", severity: "", range: "24h" });
  const [form, setForm] = useState({ name: "", url: "https://" });
  const selected = websites.find((site) => site.id === selectedId) || websites[0] || null;
  const query = useMemo(() => {
    const since = clock ? new Date(clock - ({ "1h": 3600000, "24h": 86400000, "7d": 604800000 }[filters.range] || 86400000)).toISOString() : undefined;
    return { skip: page * PAGE_SIZE, limit: PAGE_SIZE, search: filters.search.trim(), method: filters.method, status_code: filters.status_code, classification: filters.classification, severity: filters.severity, ...(since ? { since } : {}) };
  }, [clock, filters, page]);

  const loadSites = useCallback(async () => {
    try {
      const result = await getWebsites();
      setWebsites(result.websites || []);
      setError("");
      setSelectedId((current) => current && result.websites?.some((site) => site.id === current) ? current : result.websites?.[0]?.id ?? null);
    } catch (err) { setError(err.message); }
  }, []);
  const loadEvents = useCallback(async (siteId, options = query) => {
    if (!siteId) { setEvents([]); setTotal(0); setMetrics({ total_requests: 0, requests_per_minute: 0, response_bytes: 0, heuristic_flags: 0, status_distribution: {} }); return; }
    try {
      const result = await getWebsiteEvents(siteId, options);
      setEvents(result.events || []);
      setTotal(result.total || 0);
      setMetrics(result.summary || {});
      setError("");
    } catch (err) { setError(err.message); }
  }, [query]);

  useEffect(() => { const timer = window.setTimeout(loadSites, 0); return () => window.clearTimeout(timer); }, [loadSites]);
  useEffect(() => { const timer = window.setTimeout(() => loadEvents(selected?.id), 0); return () => window.clearTimeout(timer); }, [selected?.id, loadEvents]);
  useEffect(() => {
    if (!selected?.enabled) return undefined;
    const timer = window.setInterval(() => loadEvents(selected.id), 15000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.enabled, loadEvents]);
  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 30000);
    const initial = window.setTimeout(() => setClock(Date.now()), 0);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, []);
  useEffect(() => {
    if (!selected?.enabled) return undefined;
    const socket = new WebSocket(websiteLiveUrl(selected.id));
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);
        if (event.type !== "traffic_event") return;
        if (page === 0) loadEvents(selected.id, query);
      } catch { /* Ignore malformed messages from an interrupted stream. */ }
    };
    return () => { socket.close(); };
  }, [selected?.id, selected?.enabled, page, loadEvents, query]);

  const trafficBars = useMemo(() => {
    const buckets = Array(10).fill(0);
    for (const event of events) {
      const age = Math.floor((clock - new Date(event.received_at || event.created_at).getTime()) / 60000);
      if (age >= 0 && age < buckets.length) buckets[buckets.length - age - 1] += 1;
    }
    return buckets;
  }, [clock, events]);
  const receivingRecently = Number(metrics.requests_per_minute || 0) > 0;
  const hasReceivedEvents = Number(metrics.total_requests || 0) > 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function submit(event) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = await addWebsite({ ...form, authorization_confirmed: true });
      setNewSite({ id: result.id, name: result.name, token: result.ingest_token, rotated: false });
      setForm({ name: "", url: "https://" });
      await loadSites(); setSelectedId(result.id);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function toggleMonitoring() {
    if (!selected) return;
    try { const result = await setWebsiteEnabled(selected.id, !selected.enabled); setWebsites((items) => items.map((site) => site.id === result.id ? result : site)); }
    catch (err) { setError(err.message); }
  }
  async function removeSite() {
    if (!selected) return;
    try { await deleteWebsite(selected.id); setNewSite(null); await loadSites(); }
    catch (err) { setError(err.message); }
  }
  async function regenerateCollectorKey() {
    if (!selected) return;
    setError("");
    try {
      const result = await rotateWebsiteToken(selected.id);
      setNewSite({ id: result.id, name: result.name, token: result.ingest_token, rotated: true });
    } catch (err) { setError(err.message); }
  }
  function changeFilter(name, value) { setPage(0); setFilters((current) => ({ ...current, [name]: value })); }

  return (
    <div className="website-monitor-page">
      {!embedded && <section className="welcome-row"><div><div className="eyebrow">AUTHORIZED SITE TELEMETRY</div><h1>Website Monitoring</h1><p className="page-description">Collect request metadata from the access log or proxy on a website you own or are authorized to monitor. Adding a URL alone cannot expose its visitor traffic.</p></div>
        {selected && <button className={selected.enabled ? "website-stop-button" : "primary-button"} onClick={toggleMonitoring}><Radio size={16} /> {selected.enabled ? "Pause event intake" : "Enable event intake"}</button>}</section>}
      {embedded && <section className="website-embedded-bar"><div><strong>Live website traffic</strong><span>{selected ? selected.url : "Add a website to start a private traffic feed."}</span></div>
        {selected && <button className={selected.enabled ? "website-stop-button" : "primary-button"} onClick={toggleMonitoring}><Radio size={15} /> {selected.enabled ? "Pause event intake" : "Enable event intake"}</button>}</section>}
      <div className="website-telemetry-explainer"><strong>{selected?.enabled ? "Event intake is enabled" : "Collector setup required"}</strong><span>NetSentry does not scan or proxy the website URL. Real visitor events appear only after a server-side collector on that website sends its access-log entries.</span>{selected && <span className="website-stream-link">Dashboard stream: {connected ? "connected" : "disconnected"} · Collector: {!selected.enabled ? "paused" : receivingRecently ? "sending events" : hasReceivedEvents ? "no events in the last minute" : "no events received yet"}</span>}</div>
      <div className="website-layout">
        <section className="panel website-sidebar-panel"><div className="panel-heading"><div><h2>Your websites</h2><p>Private to your account</p></div><Globe2 size={19} /></div>
          {websites.length ? websites.map((site) => <button key={site.id} className={"website-choice " + (selected?.id === site.id ? "selected" : "")} onClick={() => { setPage(0); setSelectedId(site.id); }}><span className={"website-dot " + (selected?.id === site.id && receivingRecently ? "online" : "")} /><span><strong>{site.name}</strong><small>{site.url} · {site.enabled ? "intake enabled" : "paused"}</small></span></button>) : <p className="website-empty">Add an authorized website, then install its server-side collector to receive real traffic events.</p>}
          <form className="website-add-form" onSubmit={submit}><h3><Plus size={16} /> Add authorized website</h3><label>Display name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required maxLength="120" placeholder="My production site" /></label><label>Website URL<input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required type="url" placeholder="https://example.com" /></label><label className="website-authorize"><input type="checkbox" required /> I own this website or have permission to monitor its traffic.</label><button className="primary-button" disabled={busy}>{busy ? "Adding…" : "Add website"}</button></form>
        </section>
        <div className="website-main-column">
          {error && <div className="website-error" role="alert">{error}</div>}
          {newSite && <section className="website-token-card"><div><KeyRound size={19} /><strong>{newSite.rotated ? "New collector key — replace the old one" : "Save this ingestion key now"}</strong></div><p>It is shown only once. Keep it as a server-side secret; never put it in public browser JavaScript. {newSite.rotated ? "The previous key has been revoked, so update the collector before it can send more events." : "Install it in the collector running on your website server."}</p><code>{newSite.token}</code><p>Set <code>NETSENTRY_INGEST_TOKEN</code> in the collector server environment, then start the JSONL collector with the command below. The startup command does not contain the secret.</p><code>{`python scripts/generic_traffic_collector.py --site-id ${newSite.id} --api-url ${COLLECTOR_API_URL} --log-file "C:/logs/access.jsonl" --format jsonl`}</code><p>Each log line can be JSON containing <code>status_code</code>, plus optional path, method, duration_ms, response_bytes, source_ip, and user_agent.</p><button className="secondary-button" onClick={() => setNewSite(null)}>I saved the key</button></section>}
          {selected ? <>
            <section className="website-metrics"><article><span><Activity size={17} /> Requests / minute</span><strong>{metrics.requests_per_minute || 0}</strong></article><article><span><AlertTriangle size={17} /> Heuristic findings</span><strong>{metrics.heuristic_flags || 0}</strong></article><article><span><Radio size={17} /> Collector activity</span><strong className={receivingRecently ? "stream-live" : ""}>{selected.collector_revoked ? "REVOKED" : !selected.enabled ? "PAUSED" : receivingRecently ? "RECEIVING" : hasReceivedEvents ? "IDLE" : "WAITING_FOR_EVENTS"}</strong></article><article><span><Activity size={17} /> Response data</span><strong>{Number(metrics.response_bytes || 0).toLocaleString()} B</strong></article></section>
            <section className="panel website-chart"><div><h2>Recent request trend</h2><p>Events per minute · last 10 minutes from the current event window</p></div><div className="website-bars" role="img" aria-label="Recent requests per minute bar chart">{trafficBars.map((count, index) => <span key={index} title={(9 - index) + " minutes ago: " + count + " requests"} style={{ height: Math.max(5, count / Math.max(1, ...trafficBars) * 100) + "%" }} />)}</div></section>
            <section className="website-status-distribution"><strong>HTTP status distribution</strong>{Object.entries(metrics.status_distribution || {}).map(([range, count]) => <span key={range}>{range}: <b>{Number(count).toLocaleString()}</b></span>)}</section>
            <section className="panel"><div className="panel-heading"><div><h2>Live request events</h2><p>{selected.name} · {metrics.total_requests || 0} requests in selected period</p></div><button className="secondary-button" onClick={() => loadEvents(selected.id)}><RefreshCw size={14} /> Refresh</button></div>
              <div className="website-event-filters"><input aria-label="Search requests" placeholder="Search path, IP, or user agent" value={filters.search} onChange={(e) => changeFilter("search", e.target.value)} /><select aria-label="Filter method" value={filters.method} onChange={(e) => changeFilter("method", e.target.value)}><option value="">All methods</option>{["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((method) => <option key={method}>{method}</option>)}</select><select aria-label="Filter status" value={filters.status_code} onChange={(e) => changeFilter("status_code", e.target.value)}><option value="">All statuses</option>{[400, 401, 403, 404, 429, 500, 502, 503].map((status) => <option key={status} value={status}>{status}</option>)}</select><select aria-label="Filter classification" value={filters.classification} onChange={(e) => changeFilter("classification", e.target.value)}><option value="all">All classifications</option><option value="normal">Normal</option><option value="suspicious">Suspicious</option><option value="anomalous">Anomalous</option><option value="unassessed">Unassessed</option></select><select aria-label="Filter severity" value={filters.severity} onChange={(e) => changeFilter("severity", e.target.value)}><option value="">All risk levels</option>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((level) => <option key={level}>{level}</option>)}</select><select aria-label="Filter date range" value={filters.range} onChange={(e) => changeFilter("range", e.target.value)}><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option></select></div>
              {!selected.enabled && <div className="website-empty">Monitoring is paused. Resume it to accept events from the collector.</div>}
              {selected.enabled && !events.length && <div className="website-empty">{hasReceivedEvents ? "No telemetry matches these filters." : "No website traffic has reached NetSentry yet. Install the collector on the authorized website server and point it at the live access log; adding this URL does not capture visitors by itself."}</div>}
              {!!events.length && <div className="website-event-table"><table><thead><tr><th>Request time</th><th>Request</th><th>Status</th><th>Duration</th><th>Source</th><th>Classification</th><th>Risk</th><th>Detection reasons</th></tr></thead><tbody>{events.map((event, index) => <tr key={event.id || ((event.received_at || event.created_at) + "-" + index)}><td>{timeLabel(event.request_timestamp || event.received_at || event.created_at)}</td><td><b>{event.method}</b> {event.path}</td><td><span className={"website-status status-" + (event.status_code >= 500 ? "bad" : event.status_code >= 400 ? "warn" : "ok")}>{event.status_code}</span></td><td>{Number(event.duration_ms).toFixed(1)} ms</td><td>{event.source_ip || "—"}</td><td><span className={"website-status status-" + (event.classification === "NORMAL" ? "ok" : event.classification === "UNASSESSED" ? "neutral" : "warn")}>{event.classification || "UNASSESSED"}</span></td><td><b>{event.risk_score ?? 0}</b> / 100 · {event.risk_severity || "LOW"}</td><td title={(event.detection_reasons || []).map((reason) => reason.message).join("; ")}>{(event.detection_categories || []).join(", ") || "—"}{event.ml_status && <small className="website-ml-note"> · Rules only</small>}</td></tr>)}</tbody></table></div>}
              <div className="website-pagination"><span>{total ? `${page * PAGE_SIZE + 1}–${Math.min((page + 1) * PAGE_SIZE, total)} of ${total}` : "0 events"}</span><div><button className="secondary-button" disabled={page === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>Previous</button><span>Page {page + 1} of {pageCount}</span><button className="secondary-button" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => value + 1)}>Next</button></div></div>
            </section>
            {(metrics.status_distribution?.["4xx"] || metrics.status_distribution?.["5xx"]) > 0 && <section className="website-status-note">HTTP error responses are shown as response codes; they are not treated as malicious by themselves. Only provisional traffic-volume heuristics are flagged.</section>}
            <div className="website-actions"><button className="secondary-button" onClick={regenerateCollectorKey}><KeyRound size={14} /> Regenerate collector key</button><button className="secondary-button danger-action" onClick={removeSite}><Trash2 size={14} /> Remove website and its event history</button></div>
          </> : <section className="panel website-empty"><Globe2 size={25} /><h2>No website selected</h2><p>Add an authorized website to set up its traffic feed.</p></section>}
          <section className="panel website-setup"><h2>Connect the website’s real traffic</h2><p>Install/run the collector on the authorized website server, where its access log is written. It supports JSONL, Apache, Nginx, and IIS logs. Set the ingestion token as a server-side secret; never add it to public browser JavaScript.</p><p><code>python scripts/generic_traffic_collector.py --site-id SITE_ID --token INGESTION_TOKEN --api-url https://YOUR_NETSENTRY_HOST --log-file "/path/to/access.jsonl" --format jsonl</code></p><p>Use the real, existing access-log path and matching format. The collector starts at the end of the log, so start it first, then visit your site to generate new requests. For local testing, the API URL can be <code>http://127.0.0.1:8000</code> only when the collector runs on the same computer. For a separate website server, use an HTTPS URL reachable from that server. Forwarded events appear here and on Traffic Monitoring.</p></section>
        </div>
      </div>
    </div>
  );
}
