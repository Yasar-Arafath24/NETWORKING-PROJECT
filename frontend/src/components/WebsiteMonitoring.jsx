import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Globe2, KeyRound, Plus, Radio, RefreshCw, Trash2 } from "lucide-react";
import { API_BASE_URL, addWebsite, deleteWebsite, getWebsiteEvents, getWebsites, setWebsiteEnabled, websiteLiveUrl } from "../services/api";

function timeLabel(value) { return new Date(value).toLocaleTimeString(); }

export default function WebsiteMonitoring({ embedded = false }) {
  const [websites, setWebsites] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [events, setEvents] = useState([]);
  const [rpm, setRpm] = useState(0);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [newSite, setNewSite] = useState(null);
  const [form, setForm] = useState({ name: "", url: "https://" });
  const selected = websites.find((site) => site.id === selectedId) || websites[0] || null;

  const loadSites = useCallback(async () => {
    try {
      const result = await getWebsites();
      setWebsites(result.websites || []);
      setError("");
      setSelectedId((current) => current && result.websites?.some((site) => site.id === current) ? current : result.websites?.[0]?.id ?? null);
    } catch (err) { setError(err.message); }
  }, []);

  const loadEvents = useCallback(async (siteId) => {
    if (!siteId) return;
    try {
      const result = await getWebsiteEvents(siteId);
      setEvents(result.events || []);
      setRpm(result.requests_per_minute || 0);
    } catch (err) { setError(err.message); }
  }, []);

  useEffect(() => { loadSites(); }, [loadSites]);
  useEffect(() => { setEvents([]); loadEvents(selected?.id); }, [selected?.id, loadEvents]);
  useEffect(() => {
    if (!selected?.enabled) return undefined;
    const timer = window.setInterval(() => loadEvents(selected.id), 15000);
    return () => window.clearInterval(timer);
  }, [selected?.id, selected?.enabled, loadEvents]);

  useEffect(() => {
    if (!selected?.enabled) { setConnected(false); return undefined; }
    const socket = new WebSocket(websiteLiveUrl(selected.id));
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);
        if (event.type === "traffic_event") {
          setEvents((current) => [...current.slice(-99), event]);
          setRpm((current) => current + 1);
        }
      } catch { /* Ignore malformed messages from an interrupted stream. */ }
    };
    return () => { socket.close(); setConnected(false); };
  }, [selected?.id, selected?.enabled]);

  const summary = useMemo(() => ({
    suspicious: events.filter((event) => event.severity === "HIGH" || event.severity === "MEDIUM").length,
    errors: events.filter((event) => Number(event.status_code) >= 400).length,
  }), [events]);
  const trafficBars = useMemo(() => {
    const buckets = Array(10).fill(0);
    const now = Date.now();
    for (const event of events) {
      const age = Math.floor((now - new Date(event.created_at).getTime()) / 60000);
      if (age >= 0 && age < buckets.length) buckets[buckets.length - age - 1] += 1;
    }
    return buckets;
  }, [events]);
  const receivingRecently = events.some(
    (event) => Date.now() - new Date(event.created_at).getTime() < 60000
  );

  async function submit(event) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = await addWebsite({ ...form, authorization_confirmed: true });
      setNewSite({ id: result.id, name: result.name, token: result.ingest_token });
      setForm({ name: "", url: "https://" });
      await loadSites(); setSelectedId(result.id);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  async function toggleMonitoring() {
    if (!selected) return;
    try {
      const result = await setWebsiteEnabled(selected.id, !selected.enabled);
      setWebsites((items) => items.map((site) => site.id === result.id ? result : site));
    } catch (err) { setError(err.message); }
  }
  async function removeSite() {
    if (!selected) return;
    try { await deleteWebsite(selected.id); setNewSite(null); await loadSites(); }
    catch (err) { setError(err.message); }
  }

  return (
    <div className="website-monitor-page">
      {!embedded && <section className="welcome-row">
        <div><div className="eyebrow">AUTHORIZED SITE TELEMETRY</div><h1>Website Monitoring</h1>
          <p className="page-description">Stream request metadata from a log collector installed on a website you own or are authorized to monitor.</p></div>
        {selected && <button className={selected.enabled ? "website-stop-button" : "primary-button"} onClick={toggleMonitoring}>
          <Radio size={16} /> {selected.enabled ? "Pause ingestion" : "Resume monitoring"}
        </button>}
      </section>}
      {embedded && <section className="website-embedded-bar">
        <div>
          <strong>Live website traffic</strong>
          <span>{selected ? selected.url : "Add a website to start a private traffic feed."}</span>
        </div>
        {selected && <button className={selected.enabled ? "website-stop-button" : "primary-button"} onClick={toggleMonitoring}>
          <Radio size={15} /> {selected.enabled ? "Pause" : "Resume"}
        </button>}
      </section>}
      <div className="website-layout">
        <section className="panel website-sidebar-panel">
          <div className="panel-heading"><div><h2>Your websites</h2><p>Private to your account</p></div><Globe2 size={19} /></div>
          {websites.length ? websites.map((site) => (
            <button key={site.id} className={"website-choice " + (selected?.id === site.id ? "selected" : "")} onClick={() => setSelectedId(site.id)}>
              <span className={"website-dot " + (site.enabled ? "online" : "")} />
              <span><strong>{site.name}</strong><small>{site.url}</small></span>
            </button>
          )) : <p className="website-empty">Add a website to create its private traffic stream.</p>}
          <form className="website-add-form" onSubmit={submit}>
            <h3><Plus size={16} /> Add authorized website</h3>
            <label>Display name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required maxLength="120" placeholder="My production site" /></label>
            <label>Website URL<input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required type="url" placeholder="https://example.com" /></label>
            <label className="website-authorize"><input type="checkbox" required /> I own this website or have permission to monitor its traffic.</label>
            <button className="primary-button" disabled={busy}>{busy ? "Adding…" : "Add website"}</button>
          </form>
        </section>
        <div className="website-main-column">
          {error && <div className="website-error" role="alert">{error}</div>}
          {newSite && <section className="website-token-card">
            <div><KeyRound size={19} /><strong>Save this ingestion key now</strong></div>
            <p>It is shown only once. Install it as a server-side secret in your site's generic log collector; never put it in browser JavaScript.</p>
            <code>{newSite.token}</code>
            <p>Generic JSONL collector command:</p>
            <code>{`$env:NETSENTRY_INGEST_TOKEN="${newSite.token}"; python scripts/generic_traffic_collector.py --site-id ${newSite.id} --api-url ${API_BASE_URL} --log-file "C:/logs/access.jsonl" --format jsonl`}</code>
            <p>Each log line can be JSON containing <code>status_code</code>, plus optional path, method, duration_ms, response_bytes, source_ip, and user_agent.</p>
            <button className="secondary-button" onClick={() => setNewSite(null)}>I saved the key</button>
          </section>}
          {selected ? <>
            <section className="website-metrics">
              <article><span><Activity size={17} /> Requests / minute</span><strong>{rpm}</strong></article>
              <article><span><AlertTriangle size={17} /> Flagged recent events</span><strong>{summary.suspicious}</strong></article>
              <article><span><Radio size={17} /> Collector status</span><strong className={receivingRecently ? "stream-live" : ""}>{!selected.enabled ? "PAUSED" : receivingRecently ? "RECEIVING" : connected ? "WAITING" : "DISCONNECTED"}</strong></article>
            </section>
            <section className="panel website-chart">
              <div><h2>Recent request trend</h2><p>Events per minute · last 10 minutes from the current event window</p></div>
              <div className="website-bars" role="img" aria-label="Recent requests per minute bar chart">
                {trafficBars.map((count, index) => <span key={index} title={(9 - index) + " minutes ago: " + count + " requests"} style={{ height: Math.max(5, count / Math.max(1, ...trafficBars) * 100) + "%" }} />)}
              </div>
            </section>
            <section className="panel">
              <div className="panel-heading"><div><h2>Live request events</h2><p>{selected.name} · newest events appear automatically</p></div>
                <button className="secondary-button" onClick={() => loadEvents(selected.id)}><RefreshCw size={14} /> Refresh</button></div>
              {!selected.enabled && <div className="website-empty">Monitoring is paused. Resume it to accept events from the collector.</div>}
              {selected.enabled && !events.length && <div className="website-empty">Waiting for the authorized log collector to send its first event.</div>}
              {!!events.length && <div className="website-event-table"><table><thead><tr><th>Time</th><th>Request</th><th>Status</th><th>Duration</th><th>Source</th><th>Detection</th></tr></thead>
                <tbody>{[...events].reverse().map((event, index) => <tr key={event.id || (event.created_at + "-" + index)}>
                  <td>{timeLabel(event.created_at)}</td><td><b>{event.method}</b> {event.path}</td>
                  <td><span className={"website-status status-" + (event.status_code >= 500 ? "bad" : event.status_code >= 400 ? "warn" : "ok")}>{event.status_code}</span></td>
                  <td>{Number(event.duration_ms).toFixed(1)} ms</td><td>{event.source_ip || "—"}</td>
                  <td>{event.severity === "INFO" ? <span className="website-status status-ok">NORMAL</span> : <span className="website-status status-bad" title={event.reason}>{event.severity}</span>}</td>
                </tr>)}</tbody></table></div>}
            </section>
            {summary.suspicious > 0 && <section className="website-alert-note"><AlertTriangle size={18} /><span>Heuristic detections are provisional. 4xx/5xx responses and request-volume bursts are flagged with a reason; these are signals to investigate, not confirmed attacks.</span></section>}
            <div className="website-actions"><button className="secondary-button danger-action" onClick={removeSite}><Trash2 size={14} /> Remove website and its event history</button></div>
          </> : <section className="panel website-empty"><Globe2 size={25} /><h2>No website selected</h2><p>Add an authorized website to set up its traffic feed.</p></section>}
          <section className="panel website-setup"><h2>Connect server logs</h2>
            <p>Add an authorized website, then run the included generic collector on the server. It supports JSONL records and optional Apache, Nginx, or IIS text parsing adapters. It tails the configured log and sends normalized request metadata to NetSentry.</p>
            <p><code>python scripts/generic_traffic_collector.py --site-id SITE_ID --token INGESTION_TOKEN --log-file "/path/to/access.jsonl" --format jsonl</code></p>
            <p>Adapters: <code>--format jsonl</code>, <code>apache</code>, <code>nginx</code>, or <code>iis</code>. The Python process must be able to read the log file.</p>
          </section>
        </div>
      </div>
    </div>
  );
}
