import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Check, Clipboard, Globe2, KeyRound, Plus, RefreshCw, ShieldAlert, Trash2, Wifi } from "lucide-react";
import { COLLECTOR_API_URL, addWebsite, deleteWebsite, getWebsiteAlerts, getWebsiteConnectionStatus, getWebsiteEvents, getWebsites, revokeWebsiteCollector, rotateWebsiteToken, testWebsiteConnection, updateWebsitePlatform } from "../services/api";

const PLATFORMS = [
  ["custom", "Custom application (JSONL)"], ["nodejs", "Node.js / Express (JSONL)"], ["python", "Python application (JSONL)"],
  ["php", "PHP"], ["wordpress", "WordPress"], ["nginx", "Nginx"],
  ["apache", "Apache"], ["iis", "IIS"],
];
const PLATFORM_GUIDES = {
  custom: { format: "jsonl", path: "C:/netsentry/access.jsonl", linuxPath: "/var/log/my-app/access.jsonl", note: "Write one JSON object per access-log line with status_code, path, method, source_ip, duration_ms, response_bytes, and user_agent." },
  nodejs: { format: "jsonl", path: "C:/netsentry/access.jsonl", linuxPath: "/var/log/my-app/access.jsonl", note: "Configure Express or its reverse proxy to append one JSON access record per request. The collector tails this file; it does not instrument the public browser." },
  python: { format: "jsonl", path: "C:/netsentry/access.jsonl", linuxPath: "/var/log/my-app/access.jsonl", note: "Configure your Python application or reverse proxy to append one JSON access record per request. Keep the collector key only on the server." },
  php: { format: "apache", path: "C:/Apache24/logs/access.log", linuxPath: "/var/log/apache2/access.log", note: "Use the Apache or Nginx access log serving PHP requests. The collector reads request metadata; it does not inspect application source or request bodies." },
  wordpress: { format: "apache", path: "C:/Apache24/logs/access.log", linuxPath: "/var/log/apache2/access.log", note: "Use the web server access log for the WordPress site. NetSentry does not require a WordPress plugin or credentials to the site." },
  nginx: { format: "nginx", path: "C:/nginx/logs/access.log", linuxPath: "/var/log/nginx/access.log", note: "Use the active Nginx access log. The built-in Nginx parser accepts common combined access-log fields." },
  apache: { format: "apache", path: "C:/Apache24/logs/access.log", linuxPath: "/var/log/apache2/access.log", note: "Use the active Apache access log in common or combined format. On Windows, select the actual Apache log path." },
  iis: { format: "iis", path: "C:/inetpub/logs/LogFiles/W3SVC1/u_exYYYYMMDD.log", linuxPath: null, note: "The collector understands IIS W3C field headers and common request fields. Replace YYYYMMDD with the current log file name; wildcards are not supported. IIS instructions are Windows-only." },
};
const STEPS = ["Register website", "Choose platform", "Collector setup", "Environment", "Start collector", "Verify connection"];

function prettyDate(value) {
  return value ? new Date(value).toLocaleString() : "Never";
}

function statusLabel(status, apiError) {
  if (apiError) return "ERROR";
  return status || "WAITING_FOR_EVENTS";
}

export default function WebsiteIntegrations() {
  const [sites, setSites] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [connectionStatus, setConnectionStatus] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardSite, setWizardSite] = useState(null);
  const [wizardStep, setWizardStep] = useState(0);
  const [form, setForm] = useState({ name: "", url: "https://", platform: "custom", authorization_confirmed: false });
  const [logPath, setLogPath] = useState(PLATFORM_GUIDES.custom.path);
  const [linuxLogPath, setLinuxLogPath] = useState(PLATFORM_GUIDES.custom.linuxPath);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loadingSites, setLoadingSites] = useState(true);
  const selected = sites.find((site) => site.id === selectedId) || null;
  const guide = PLATFORM_GUIDES[wizardSite?.platform || selected?.platform || "custom"];
  const apiUrl = COLLECTOR_API_URL;

  const loadSites = useCallback(async () => {
    try {
      const result = await getWebsites();
      setSites(result.websites || []);
      setError("");
    } catch (err) {
      setError(err.message || "Unable to load your website integrations.");
    } finally {
      setLoadingSites(false);
    }
  }, []);

  const loadDetails = useCallback(async (siteId) => {
    if (!siteId) { setEvents([]); setAlerts([]); return; }
    try {
      const [eventResult, alertResult] = await Promise.all([
        getWebsiteEvents(siteId, { limit: 10, skip: 0 }),
        getWebsiteAlerts(siteId, { limit: 5, skip: 0 }),
      ]);
      setEvents(eventResult.events || []);
      setAlerts(alertResult.alerts || []);
      setError("");
    } catch (err) {
      setError(err.message || "Unable to load website integration details.");
      setEvents([]);
      setAlerts([]);
    }
  }, []);

  const loadConnectionStatus = useCallback(async (siteId) => {
    if (!siteId) { setConnectionStatus(null); return; }
    try {
      const result = await getWebsiteConnectionStatus(siteId);
      setConnectionStatus(result);
    } catch (err) {
      setConnectionStatus({ site_id: siteId, status: "ERROR", message: err.message || "Unable to check collector status." });
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(loadSites, 0);
    const timer = window.setInterval(loadSites, 2000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [loadSites]);
  useEffect(() => {
    if (!selectedId) return undefined;
    const initial = window.setTimeout(() => loadDetails(selectedId), 0);
    const timer = window.setInterval(() => loadDetails(selectedId), 2000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [selectedId, loadDetails]);
  useEffect(() => {
    if (!selectedId) return undefined;
    const initial = window.setTimeout(() => loadConnectionStatus(selectedId), 0);
    const timer = window.setInterval(() => loadConnectionStatus(selectedId), 2000);
    return () => { window.clearTimeout(initial); window.clearInterval(timer); };
  }, [selectedId, loadConnectionStatus]);

  const totals = useMemo(() => sites.reduce((result, site) => ({
    events: result.events + Number(site.total_events || 0),
    anomalies: result.anomalies + Number(site.anomaly_count || 0),
    connected: result.connected + Number(["CONNECTED", "RECEIVING"].includes(site.integration_status)),
  }), { events: 0, anomalies: 0, connected: 0 }), [sites]);

  async function submitWebsite(event) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    setConnectionStatus(null); setTestResult(null);
    try {
      const created = await addWebsite(form);
      setWizardSite(created);
      setWizardStep(1);
      setWizardOpen(true);
      setSelectedId(created.id);
      setLogPath(PLATFORM_GUIDES[created.platform || form.platform]?.path || PLATFORM_GUIDES.custom.path);
      setLinuxLogPath(PLATFORM_GUIDES[created.platform || form.platform]?.linuxPath || PLATFORM_GUIDES.custom.linuxPath);
      setForm({ name: "", url: "https://", platform: "custom", authorization_confirmed: false });
      await loadSites();
    } catch (err) {
      setError(err.message || "Unable to add this website.");
    } finally { setBusy(false); }
  }

  async function copyValue(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      window.setTimeout(() => setCopied(""), 1800);
    } catch {
      setError("Clipboard access failed. Select and copy the value manually.");
    }
  }

  async function choosePlatform(platform) {
    if (!wizardSite) return;
    setBusy(true); setError("");
    try {
      const updated = await updateWebsitePlatform(wizardSite.id, platform);
      setWizardSite((current) => ({ ...current, ...updated, ingest_token: current.ingest_token }));
      setLogPath(PLATFORM_GUIDES[platform]?.path || PLATFORM_GUIDES.custom.path);
      setLinuxLogPath(PLATFORM_GUIDES[platform]?.linuxPath || "");
      await loadSites();
    } catch (err) { setError(err.message || "Unable to save the selected platform."); }
    finally { setBusy(false); }
  }

  async function rotateKey(site) {
    if (!window.confirm(`Regenerate the collector key for ${site.name}? The current key will stop working immediately.`)) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const rotated = await rotateWebsiteToken(site.id);
      setWizardSite(rotated);
      setWizardStep(2);
      setConnectionStatus(null);
      setTestResult(null);
      setWizardOpen(true);
      setNotice("The previous collector key was revoked. Replace it in the collector server environment now.");
      await loadSites();
    } catch (err) { setError(err.message || "Unable to regenerate the collector key."); }
    finally { setBusy(false); }
  }

  async function removeSite(site) {
    if (!window.confirm(`Remove ${site.name} and permanently delete its received traffic and alert history?`)) return;
    setBusy(true); setError("");
    try {
      await deleteWebsite(site.id);
      if (selectedId === site.id) setSelectedId(null);
      if (wizardSite?.id === site.id) { setWizardSite(null); setWizardOpen(false); }
      await loadSites();
      setNotice("Website integration and its stored history were removed.");
    } catch (err) { setError(err.message || "Unable to remove this website."); }
    finally { setBusy(false); }
  }

  async function verifyConnection(site = wizardSite) {
    if (!site?.id) return;
    setBusy(true); setError(""); setTestResult(null);
    try {
      const result = await testWebsiteConnection(site.id);
      setTestResult(result);
      setConnectionStatus(result);
      await Promise.all([loadSites(), loadDetails(site.id)]);
    } catch (err) {
      setError(err.message || "Connection test failed. Check the backend and try again.");
      setConnectionStatus({ site_id: site.id, status: "ERROR", message: err.message || "Connection test failed." });
    } finally { setBusy(false); }
  }

  async function disconnectCollector(site) {
    if (!window.confirm(`Revoke the collector key for ${site.name}? The running collector will stop authenticating immediately.`)) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await revokeWebsiteCollector(site.id);
      setConnectionStatus({ site_id: site.id, status: result.status || "REVOKED", verified: false });
      if (wizardSite?.id === site.id) setWizardSite((current) => ({ ...current, ingest_token: undefined, enabled: false, collector_revoked: true }));
      setNotice("Collector credential revoked. No further events will be accepted until you generate a new key.");
      await loadSites();
    } catch (err) { setError(err.message || "Unable to revoke the collector key."); }
    finally { setBusy(false); }
  }

  const command = `python scripts/generic_traffic_collector.py --site-id ${wizardSite?.id || selected?.id || "<website-id>"} --api-url '${apiUrl}' --log-file '${logPath || "<actual-access-log-path>"}' --format ${guide?.format || "jsonl"}`;
  const selectedGuide = PLATFORM_GUIDES[selected?.platform || "custom"];
  const selectedCommand = `python scripts/generic_traffic_collector.py --site-id ${selected?.id || "<website-id>"} --api-url '${apiUrl}' --log-file '${selectedGuide.path}' --format ${selectedGuide.format}`;
  const powershellEnvironment = `$env:NETSENTRY_INGEST_TOKEN='${wizardSite?.ingest_token || "<one-time-token>"}'\n$env:NETSENTRY_API_URL='${apiUrl}'`;
  const bashEnvironment = `export NETSENTRY_INGEST_TOKEN='${wizardSite?.ingest_token || "<one-time-token>"}'\nexport NETSENTRY_API_URL='${apiUrl}'`;
  const bashCommand = `python scripts/generic_traffic_collector.py --site-id ${wizardSite?.id || selected?.id || "<website-id>"} --log-file '${linuxLogPath || "<actual-access-log-path>"}' --format ${guide?.format || "jsonl"}`;
  const bashSetup = `${bashEnvironment}\n${bashCommand}`;
  const powershellSetup = `${powershellEnvironment}\n${command}`;

  return (
    <main className="integration-page">
      <header className="welcome-row integration-heading">
        <div><div className="eyebrow">AUTHORIZED WEBSITE TELEMETRY</div><h1>Website Integrations</h1><p className="page-description">Connect a website you own or are authorized to monitor. Visitor traffic appears after its server-side access-log collector sends real events.</p></div>
        <button type="button" className="primary-button" onClick={() => { setWizardOpen(true); setWizardSite(null); setWizardStep(0); setError(""); }}><Plus size={17} /> Add New Website</button>
      </header>

      {error && <div className="website-error" role="alert">{error}</div>}
      {notice && <div className="integration-notice" role="status">{notice}<button type="button" onClick={() => setNotice("")} aria-label="Dismiss">×</button></div>}

      <section className="integration-overview-grid">
        <article><span>Connected websites</span><strong>{totals.connected} / {sites.length}</strong></article>
        <article><span>Events received</span><strong>{totals.events.toLocaleString()}</strong></article>
        <article><span>Anomaly findings</span><strong>{totals.anomalies.toLocaleString()}</strong></article>
      </section>

      {wizardOpen && (
        <section className="panel integration-wizard" aria-labelledby="integration-wizard-title">
          <div className="panel-heading"><div><h2 id="integration-wizard-title">{wizardSite ? `Connect ${wizardSite.name}` : "Add a website integration"}</h2><p>Step-by-step setup · connection is verified from actual collector events</p></div><button type="button" className="secondary-button" onClick={() => { setWizardOpen(false); setWizardSite(null); }}>Close</button></div>
          <ol className="integration-stepper">{STEPS.map((step, index) => <li key={step} className={index === wizardStep ? "active" : index < wizardStep ? "complete" : ""}><span>{index < wizardStep ? <Check size={14} /> : index + 1}</span><small>{step}</small></li>)}</ol>
          {!wizardSite ? (
            <form className="integration-form" onSubmit={submitWebsite}>
              <label>Website display name<input required minLength={1} maxLength={120} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="My production site" /></label>
              <label>Website URL<input required type="url" value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} placeholder="https://example.com" /></label>
              <label>Website platform<select value={form.platform} onChange={(event) => setForm({ ...form, platform: event.target.value })}>{PLATFORMS.map(([id, title]) => <option key={id} value={id}>{title}</option>)}</select></label>
              <label className="website-authorize"><input type="checkbox" checked={form.authorization_confirmed} onChange={(event) => setForm({ ...form, authorization_confirmed: event.target.checked })} required /> I own this website or have permission to monitor its traffic.</label>
              <p className="integration-help">The backend validates the URL, prevents duplicate registrations in your account, and creates a private collector key.</p>
              <button className="primary-button" disabled={busy}>{busy ? "Registering…" : "Register website and continue"}</button>
            </form>
          ) : (
            <div className="integration-step-content">
              {wizardSite.ingest_token && <div className="integration-token"><div><KeyRound size={17} /><strong>One-time collector key</strong></div><p>Website ID: {wizardSite.id}. Keep this secret on the website server. It is not saved in this browser after closing the setup. Regenerating it revokes the previous key.</p><code>{wizardSite.ingest_token}</code><button type="button" className="secondary-button" onClick={() => copyValue(wizardSite.ingest_token, "token")}>{copied === "token" ? <Check size={15} /> : <Clipboard size={15} />}{copied === "token" ? "Copied" : "Copy key"}</button></div>}
              <section className="integration-step-panel">
                {wizardStep === 1 && <><h3>Choose your website platform</h3><p>We use this choice to select a matching access-log parser. This does not install software on your website.</p><label>Platform<select value={wizardSite.platform || "custom"} disabled={busy} onChange={(event) => choosePlatform(event.target.value)}>{PLATFORMS.map(([id, title]) => <option key={id} value={id}>{title}</option>)}</select></label></>}
                {wizardStep === 2 && <><h3>Configure the supported access-log source</h3><p>{guide.note}</p><p>The collector script supports JSONL, Apache combined logs, Nginx access logs, and IIS W3C logs. It tails new lines only; start it before creating a test request. For PHP and WordPress, select the web server log that serves the application.</p><label>Windows access-log file path<input value={logPath} onChange={(event) => setLogPath(event.target.value)} placeholder="Enter the active Windows access-log file path" required /></label>{guide.linuxPath !== null && <label>Linux/macOS access-log file path<input value={linuxLogPath} onChange={(event) => setLinuxLogPath(event.target.value)} placeholder="Enter the active Linux/macOS access-log path" required /></label>}<div className="integration-help">Local URLs: backend API <code>{apiUrl}</code>, frontend dashboard <code>http://localhost:5173</code>, optional test website <code>http://127.0.0.1:9000</code>. The collector sends to the backend API and tails the configured website server log; it never reads the frontend URL or scans the website.</div><div className="integration-code-label">Selected parser <span>{guide.format.toUpperCase()}</span><button type="button" onClick={() => copyValue(logPath, "path")}>{copied === "path" ? "Copied" : "Copy Windows path"}</button>{guide.linuxPath !== null && <button type="button" onClick={() => copyValue(linuxLogPath, "linux-path")}>{copied === "linux-path" ? "Copied" : "Copy Linux path"}</button>}</div><code className="integration-code-block">Windows: {logPath}{guide.linuxPath !== null && `\nLinux/macOS: ${linuxLogPath}`}</code></>}
                {wizardStep === 3 && <><h3>Set server-side environment variables</h3><p>Save the collector key in a protected secret/environment on the collector host. Never put it in frontend code, a public Vite variable, a URL, or a checked-in file.</p><div className="integration-environment-grid"><div><b>Backend ingestion API</b><code>{apiUrl}</code></div><div><b>Frontend dashboard</b><code>http://localhost:5173</code><small>This is not the collector ingestion API.</small></div><div><b>Optional local test site</b><code>http://127.0.0.1:9000</code></div></div><div className="integration-code-label">PowerShell setup <button type="button" onClick={() => copyValue(powershellEnvironment, "env")}>{copied === "env" ? "Copied" : "Copy setup"}</button></div><code className="integration-code-block">{powershellEnvironment}</code><div className="integration-code-label">Linux/macOS setup <button type="button" onClick={() => copyValue(bashEnvironment, "bash-env")}>{copied === "bash-env" ? "Copied" : "Copy setup"}</button></div><code className="integration-code-block">{bashEnvironment}</code></>}
                {wizardStep === 4 && <><h3>Start the collector on the website server</h3><p>These commands only start after you run them manually. Copying a command does not mean the collector is running. Keep this terminal open to view errors; press Ctrl+C to stop the foreground collector. Use HTTPS for a remote production API.</p><div className="integration-code-label">PowerShell command <button type="button" onClick={() => copyValue(command, "command")}>{copied === "command" ? "Copied" : "Copy command"}</button></div><code className="integration-code-block">{command}</code>{guide.linuxPath !== null && <><div className="integration-code-label">Linux/macOS command <button type="button" onClick={() => copyValue(bashCommand, "linux-command")}>{copied === "linux-command" ? "Copied" : "Copy command"}</button></div><code className="integration-code-block">{bashCommand}</code></>}<div className="integration-wizard-actions"><button type="button" className="secondary-button" onClick={() => copyValue(powershellSetup, "powershell-setup")}>{copied === "powershell-setup" ? <Check size={14} /> : <Clipboard size={14} />} Copy PowerShell setup</button>{guide.linuxPath !== null && <button type="button" className="secondary-button" onClick={() => copyValue(bashSetup, "bash-setup")}>{copied === "bash-setup" ? <Check size={14} /> : <Clipboard size={14} />} Copy Linux/macOS setup</button>}</div></>}
                {wizardStep === 5 && <><h3>Verify with a real accepted event</h3><p>Connection verification reads the backend's stored ingestion records. No test event or collector heartbeat is fabricated. The collector process itself cannot be remotely inspected; a valid event proves that it reached NetSentry.</p><div className="integration-verify"><span className={`integration-status status-${String(connectionStatus?.status || "WAITING_FOR_EVENTS").toLowerCase()}`}>{connectionStatus?.status || "WAITING_FOR_EVENTS"}</span><span>Last successful ingestion: {prettyDate(connectionStatus?.last_event_received)}</span></div><div className="integration-detail-stats"><article><span>Total events</span><strong>{Number(connectionStatus?.total_events || 0).toLocaleString()}</strong></article><article><span>Anomalies</span><strong>{Number(connectionStatus?.anomaly_count || 0).toLocaleString()}</strong></article><article><span>Last seen</span><strong>{prettyDate(connectionStatus?.collector_last_seen)}</strong></article><article><span>Requests / min</span><strong>{Number(connectionStatus?.requests_per_minute || 0).toLocaleString()}</strong></article><article><span>Response bytes</span><strong>{Number(connectionStatus?.response_bytes || 0).toLocaleString()}</strong></article><article><span>Average duration</span><strong>{Number(connectionStatus?.average_duration_ms || 0).toFixed(1)} ms</strong></article></div><section className="integration-status-distribution"><strong>HTTP status distribution</strong>{Object.entries(connectionStatus?.status_distribution || {}).map(([range, count]) => <span key={range}>{range}: <b>{Number(count).toLocaleString()}</b></span>)}</section><div className="integration-progress-list"><div className="complete"><Check size={15} /> Website registered</div><div className="complete"><Check size={15} /> Platform selected: {PLATFORMS.find(([id]) => id === wizardSite.platform)?.[1] || "Custom"}</div><div className={connectionStatus?.verified ? "complete" : "pending"}>{connectionStatus?.verified ? <Check size={15} /> : <Wifi size={15} />} Collector configured and started: {connectionStatus?.verified ? "an authenticated event was received" : "not observable yet; run the collector manually"}</div><div className={connectionStatus?.verified ? "complete" : "pending"}>{connectionStatus?.verified ? <Check size={15} /> : <Wifi size={15} />} First event received</div><div className={connectionStatus?.verified ? "complete" : "pending"}>{connectionStatus?.verified ? <Check size={15} /> : <Wifi size={15} />} Connection verified</div></div>{(testResult || connectionStatus?.message) && <p className="integration-test-result" role="status">{testResult?.message || connectionStatus?.message}</p>}<p>{connectionStatus?.status === "ERROR" ? connectionStatus.message : connectionStatus?.verified ? "The backend has accepted an authenticated event for this website. Recent collector activity updates every two seconds." : "Waiting for an authenticated event. Check the actual log path, API URL, collector key, and collector terminal; then generate a request on the monitored site."}</p><div className="integration-wizard-actions"><button className="secondary-button" type="button" onClick={() => verifyConnection()} disabled={busy}><RefreshCw size={15} /> {busy ? "Testing…" : "Test connection"}</button><button className="secondary-button" type="button" onClick={() => loadConnectionStatus(wizardSite.id)} disabled={busy}><RefreshCw size={15} /> Refresh status</button><button className="secondary-button integration-remove" type="button" onClick={() => disconnectCollector(wizardSite)} disabled={busy || connectionStatus?.status === "REVOKED"}><Trash2 size={14} /> Disconnect collector</button></div></>}
              </section>
              <div className="integration-wizard-actions">{wizardStep > 1 && <button type="button" className="secondary-button" onClick={() => setWizardStep((step) => step - 1)}><ArrowLeft size={15} /> Back</button>}{wizardStep < 5 ? <button type="button" className="primary-button" disabled={busy} onClick={() => setWizardStep((step) => Math.min(step + 1, 5))}>Continue <ArrowRight size={15} /></button> : <button type="button" className="primary-button" onClick={() => { setWizardOpen(false); setWizardSite(null); setSelectedId(wizardSite.id); }}>Done</button>}</div>
            </div>
          )}
        </section>
      )}

      {selectedId && selected ? (
        <section className="panel integration-details">
          <div className="panel-heading"><div><button type="button" className="integration-back" onClick={() => setSelectedId(null)}><ArrowLeft size={15} /> All integrations</button><h2>{selected.name}</h2><p>{selected.url} · {PLATFORMS.find(([id]) => id === selected.platform)?.[1] || "Custom application"} · Website ID {selected.id}</p></div><button type="button" className="secondary-button" onClick={() => rotateKey(selected)} disabled={busy}><KeyRound size={15} /> Regenerate key</button></div>
          <div className="integration-detail-stats"><article><span>Connection</span><strong className={`integration-status status-${String(connectionStatus?.status || selected.integration_status || "WAITING_FOR_EVENTS").toLowerCase()}`}>{connectionStatus?.status || selected.integration_status || "WAITING_FOR_EVENTS"}</strong></article><article><span>Collector activity</span><strong>{selected.collector_revoked ? "REVOKED" : selected.enabled ? (connectionStatus?.status || selected.collector_status || selected.integration_status || "WAITING_FOR_EVENTS") : "PAUSED"}</strong></article><article><span>Events received</span><strong>{Number(connectionStatus?.total_events ?? selected.total_events ?? 0).toLocaleString()}</strong></article><article><span>Anomaly count</span><strong>{Number(connectionStatus?.anomaly_count ?? selected.anomaly_count ?? 0).toLocaleString()}</strong></article><article><span>Last successful ingestion</span><strong>{prettyDate(connectionStatus?.last_event_received || selected.last_event_received)}</strong></article><article><span>Requests / minute</span><strong>{Number(connectionStatus?.requests_per_minute || 0).toLocaleString()}</strong></article><article><span>Response bytes</span><strong>{Number(connectionStatus?.response_bytes || 0).toLocaleString()} B</strong></article><article><span>Average duration</span><strong>{Number(connectionStatus?.average_duration_ms || 0).toFixed(1)} ms</strong></article></div>
          <section className="integration-status-distribution"><strong>HTTP status distribution</strong>{Object.entries(connectionStatus?.status_distribution || {}).map(([range, count]) => <span key={range}>{range}: <b>{Number(count).toLocaleString()}</b></span>)}</section>
          <div className="integration-details-columns"><section><h3>Recent request events</h3>{events.length ? <div className="integration-recent-list">{events.map((event) => <div key={event.id}><span className="integration-http-code">{event.status_code}</span><span><b>{event.method}</b> {event.path}<small>{prettyDate(event.request_timestamp || event.created_at)} · {event.source_ip || "source unavailable"}</small></span><span>{event.risk_score || 0}/100</span></div>)}</div> : <p>No real events have been received yet.</p>}</section><section><h3>Recent security alerts</h3>{alerts.length ? <div className="integration-recent-list">{alerts.map((alert) => <div key={alert.id}><ShieldAlert size={16} /><span><b>{alert.title}</b><small>{alert.severity} · {alert.status} · {alert.related_event_count} related events</small></span><span>{alert.risk_score}/100</span></div>)}</div> : <p>No security alerts for this website.</p>}</section></div>
          <section className="integration-setup-compact"><h3>Collector configuration</h3><p>{selectedGuide.note}</p><p>Collector API endpoint: <code>{apiUrl}/api/v1/website-ingest/{selected.id}/events</code></p><p>Set <code>NETSENTRY_INGEST_TOKEN</code> to the one-time key generated for this site on the collector server. This page cannot retrieve it again; regenerate the key if you no longer have it.</p><p>Start command:</p><code className="integration-code-block">{selectedCommand}</code><button type="button" className="secondary-button" onClick={() => copyValue(selectedCommand, "selected-command")}>{copied === "selected-command" ? <Check size={14} /> : <Clipboard size={14} />}{copied === "selected-command" ? "Copied" : "Copy command"}</button><p>Make sure this API origin is reachable from the website server. Set <code>VITE_COLLECTOR_API_URL</code> to the public HTTPS backend origin if the frontend host and API host differ; this collector API URL is not the frontend dashboard URL.</p><div className="integration-wizard-actions"><button type="button" className="secondary-button" onClick={() => verifyConnection(selected)} disabled={busy}><RefreshCw size={14} /> Test connection</button><button type="button" className="secondary-button" onClick={() => rotateKey(selected)} disabled={busy}><KeyRound size={14} /> Regenerate key</button><button type="button" className="secondary-button integration-remove" onClick={() => disconnectCollector(selected)} disabled={busy || connectionStatus?.status === "REVOKED"}><Trash2 size={14} /> Disconnect collector</button></div><button type="button" className="secondary-button integration-remove" onClick={() => removeSite(selected)} disabled={busy}><Trash2 size={14} /> Remove integration and history</button></section>
        </section>
      ) : (
        <section className="integration-sites-grid">
          {loadingSites ? <section className="panel integration-empty"><RefreshCw size={22} /><p>Loading your private website integrations…</p></section> : sites.length ? sites.map((site) => <article className="panel integration-site-card" key={site.id}><div className="integration-site-title"><span className="integration-globe"><Globe2 size={18} /></span><div><h2>{site.name}</h2><p>{site.url}</p></div><span className={`integration-status status-${String(error ? "ERROR" : site.integration_status || "WAITING_FOR_EVENTS").toLowerCase()}`}>{statusLabel(site.integration_status, Boolean(error))}</span></div><div className="integration-site-meta"><span>Collector <b>{site.collector_revoked ? "REVOKED" : site.enabled ? (site.collector_status || site.integration_status || "WAITING_FOR_EVENTS") : "PAUSED"}</b></span><span>Platform <b>{PLATFORMS.find(([id]) => id === site.platform)?.[1] || "Custom"}</b></span><span>Last event <b>{prettyDate(site.last_event_received)}</b></span></div><div className="integration-site-stats"><div><small>Total events</small><strong>{Number(site.total_events || 0).toLocaleString()}</strong></div><div><small>Anomalies</small><strong>{Number(site.anomaly_count || 0).toLocaleString()}</strong></div></div><div className="integration-card-actions"><button type="button" className="primary-button" onClick={() => { setSelectedId(site.id); setConnectionStatus(null); setTestResult(null); }}>Manage integration</button><button type="button" className="secondary-button integration-remove" onClick={() => removeSite(site)} disabled={busy}><Trash2 size={14} /> Remove</button></div></article>) : <section className="panel integration-empty"><Globe2 size={28} /><h2>No websites connected yet</h2><p>Add an authorized website, then install its server-side collector. Registering a URL alone cannot read visitor traffic.</p><button type="button" className="primary-button" onClick={() => { setWizardOpen(true); setWizardSite(null); setWizardStep(0); }}><Plus size={16} /> Add New Website</button></section>}
        </section>
      )}
    </main>
  );
}
