import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowRight,
  Check,
  Clipboard,
  Download,
  Globe2,
  KeyRound,
  Plus,
  RefreshCw,
  ShieldAlert,
  Trash2,
  Wifi,
} from "lucide-react";
import {
  addWebsite,
  deleteWebsite,
  downloadWebsiteCollectorPackage,
  getWebsiteAlerts,
  getWebsiteConnectionStatus,
  getWebsiteEvents,
  getWebsites,
  revokeWebsiteCollector,
  rotateWebsiteToken,
  setWebsiteEnabled,
  testWebsiteConnection,
  updateWebsitePlatform,
} from "../services/api";

const PLATFORMS = [
  ["custom_html", "Custom HTML / application"],
  ["nodejs", "Node.js / Express"],
  ["python", "Python / FastAPI"],
  ["php", "PHP"],
  ["wordpress", "WordPress"],
  ["react", "React website"],
  ["nginx", "Nginx"],
  ["apache", "Apache"],
  ["iis", "IIS"],
  ["other", "Other"],
];

const PLATFORM_METHODS = {
  custom_html: [["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
  custom: [["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
  nodejs: [["nodejs_jsonl", "Node.js JSONL"], ["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
  python: [["fastapi_jsonl", "FastAPI JSONL"], ["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
  php: [["php_jsonl", "PHP JSONL"], ["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
  wordpress: [["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"]],
  react: [["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
  nginx: [["nginx_access_log", "Nginx"]],
  apache: [["apache_access_log", "Apache"]],
  iis: [["iis_w3c_log", "IIS W3C"]],
  other: [["generic_jsonl", "Generic JSONL"], ["apache_access_log", "Apache"], ["nginx_access_log", "Nginx"], ["iis_w3c_log", "IIS W3C"]],
};

const PLATFORM_LOG_HINTS = {
  nginx: "Use the active access_log path; /var/log/nginx/access.log is common on Linux.",
  apache: "Use the active CustomLog path; /var/log/apache2/access.log or /var/log/httpd/access_log is common on Linux.",
  iis: "Select the current W3C log under %SystemDrive%\\inetpub\\logs\\LogFiles\\W3SVC….",
  wordpress: "Select the Apache or Nginx access log serving the WordPress virtual host.",
  nodejs: "Select the server-side JSONL log written by your application or reverse proxy.",
  python: "Select the server-side JSONL log written by your application or reverse proxy.",
  php: "Select the server-side JSONL log or the web server access log that serves the application.",
  react: "Select the server-side web server log; browser-only React apps need their hosting server's access log.",
  custom_html: "Select the access log configured by your web server or hosting provider.",
  custom: "Select the access log configured by your web server or hosting provider.",
  other: "Select the access log configured by your web server or hosting provider.",
};

const STEPS = ["Website information", "Integration method", "Verify connection", "Connected"];

function prettyDate(value) {
  return value ? new Date(value).toLocaleString() : "Never";
}

function connectionLabel(status, collectorStatus) {
  if (status === "RECEIVING" || status === "CONNECTED") return "Connected";
  if (status === "ERROR" || status === "TOKEN_INVALID") return "Connection failed";
  if (status === "DISCONNECTED" || status === "REVOKED") return "Disconnected";
  if (status === "WAITING_FOR_EVENTS" && collectorStatus === "RUNNING") return "Installation detected";
  return "Waiting for events";
}

export default function CustomerWebsiteIntegrations({ initialView = "websites", onOpenLiveMonitoring }) {
  const [sites, setSites] = useState([]);
  const [wizardOpen, setWizardOpen] = useState(initialView === "connect");
  const [wizardSite, setWizardSite] = useState(null);
  const [wizardStep, setWizardStep] = useState(0);
  const [form, setForm] = useState({
    name: "",
    url: "https://",
    description: "",
    platform: "custom_html",
    authorization_confirmed: false,
  });
  const [connectionStatus, setConnectionStatus] = useState(null);
  const [detailSiteId, setDetailSiteId] = useState(null);
  const [detailEvents, setDetailEvents] = useState([]);
  const [detailAlerts, setDetailAlerts] = useState([]);
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(true);

  const selectedSite = sites.find((site) => site.id === detailSiteId) || null;
  const methods = PLATFORM_METHODS[wizardSite?.platform || form.platform] || PLATFORM_METHODS.custom_html;
  const connectedCount = sites.filter((site) => ["CONNECTED", "RECEIVING"].includes(site.integration_status)).length;
  const totals = useMemo(() => sites.reduce((sum, site) => ({
    events: sum.events + Number(site.total_events || 0),
    suspicious: sum.suspicious + Number(site.suspicious_requests || 0),
  }), { events: 0, suspicious: 0 }), [sites]);

  const loadSites = useCallback(async () => {
    try {
      const result = await getWebsites();
      setSites(result.websites || []);
      setError("");
    } catch (requestError) {
      setError(requestError.message || "Unable to load your websites.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const firstLoad = window.setTimeout(loadSites, 0);
    const refresh = window.setInterval(loadSites, 10000);
    return () => {
      window.clearTimeout(firstLoad);
      window.clearInterval(refresh);
    };
  }, [loadSites]);

  useEffect(() => {
    if (!wizardSite?.id || wizardStep !== 2) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const status = await getWebsiteConnectionStatus(wizardSite.id);
        if (active) setConnectionStatus(status);
      } catch (requestError) {
        if (active) setError(requestError.message || "Unable to verify the collector connection.");
      }
    };
    const firstLoad = window.setTimeout(refresh, 0);
    const timer = window.setInterval(refresh, 5000);
    return () => {
      active = false;
      window.clearTimeout(firstLoad);
      window.clearInterval(timer);
    };
  }, [wizardSite?.id, wizardStep]);

  useEffect(() => {
    if (!detailSiteId) return undefined;
    let active = true;
    Promise.all([
      getWebsiteEvents(detailSiteId, { limit: 10 }),
      getWebsiteAlerts(detailSiteId, { limit: 5 }),
    ]).then(([events, alerts]) => {
      if (!active) return;
      setDetailEvents(events.events || []);
      setDetailAlerts(alerts.alerts || []);
    }).catch((requestError) => {
      if (active) setError(requestError.message || "Unable to load website details.");
    });
    return () => { active = false; };
  }, [detailSiteId]);

  async function submitWebsite(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const created = await addWebsite(form);
      setWizardSite(created);
      setWizardStep(1);
      setWizardOpen(true);
      setConnectionStatus(null);
      setForm({ name: "", url: "https://", description: "", platform: "custom_html", authorization_confirmed: false });
      await loadSites();
    } catch (requestError) {
      setError(requestError.message || "Unable to register this website.");
    } finally {
      setBusy(false);
    }
  }

  async function selectMethod(method) {
    if (!wizardSite) return;
    setBusy(true);
    setError("");
    try {
      const updated = await updateWebsitePlatform(wizardSite.id, wizardSite.platform, method);
      setWizardSite((site) => ({ ...site, ...updated, ingest_token: site.ingest_token }));
      await loadSites();
    } catch (requestError) {
      setError(requestError.message || "Unable to save the selected log format.");
    } finally {
      setBusy(false);
    }
  }

  async function downloadPackage(targetOs) {
    if (!wizardSite) return;
    setDownloading(targetOs);
    setError("");
    try {
      await downloadWebsiteCollectorPackage(wizardSite.id, targetOs);
      setNotice(`${targetOs === "windows" ? "Windows" : "Linux"} agent package downloaded.`);
    } catch (requestError) {
      setError(requestError.message || "Unable to download the collector package.");
    } finally {
      setDownloading("");
    }
  }

  async function copyToken() {
    if (!wizardSite?.ingest_token) return;
    try {
      await navigator.clipboard.writeText(wizardSite.ingest_token);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setError("Clipboard access failed. Select and copy the key manually.");
    }
  }

  async function verifyNow() {
    if (!wizardSite) return;
    setBusy(true);
    setError("");
    try {
      const result = await testWebsiteConnection(wizardSite.id);
      setConnectionStatus(result);
      await loadSites();
    } catch (requestError) {
      setError(requestError.message || "Connection verification failed.");
    } finally {
      setBusy(false);
    }
  }

  async function regenerateToken(site) {
    if (!window.confirm(`Regenerate the collector key for ${site.name}? The current key will stop working immediately.`)) return;
    setBusy(true);
    setError("");
    try {
      const rotated = await rotateWebsiteToken(site.id);
      setWizardSite(rotated);
      setWizardStep(1);
      setConnectionStatus(null);
      setWizardOpen(true);
      setDetailSiteId(null);
      setNotice("The old collector key was revoked. Enter the new one in the customer-side agent.");
      await loadSites();
    } catch (requestError) {
      setError(requestError.message || "Unable to regenerate the collector key.");
    } finally {
      setBusy(false);
    }
  }

  async function disconnect(site) {
    if (!window.confirm(`Revoke the collector key for ${site.name}? The agent will stop authenticating immediately.`)) return;
    setBusy(true);
    setError("");
    try {
      await revokeWebsiteCollector(site.id);
      if (wizardSite?.id === site.id) {
        setWizardSite((current) => ({ ...current, ingest_token: undefined, enabled: false }));
        setConnectionStatus({ status: "REVOKED", verified: false });
      }
      setNotice("Collector key revoked. No new events will be accepted.");
      await loadSites();
    } catch (requestError) {
      setError(requestError.message || "Unable to disconnect this collector.");
    } finally {
      setBusy(false);
    }
  }

  async function reconnect(site) {
    setBusy(true);
    setError("");
    try {
      await setWebsiteEnabled(site.id, true);
      setNotice("Website monitoring is enabled. Start the collector on the customer server to resume events.");
      await loadSites();
    } catch (requestError) {
      setError(requestError.message || "Unable to reconnect this website. A revoked key must be regenerated.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(site) {
    if (!window.confirm(`Permanently remove ${site.name} and its event and alert history?`)) return;
    setBusy(true);
    setError("");
    try {
      await deleteWebsite(site.id);
      if (detailSiteId === site.id) setDetailSiteId(null);
      if (wizardSite?.id === site.id) {
        setWizardSite(null);
        setWizardOpen(false);
      }
      await loadSites();
      setNotice("Website and its stored history were removed.");
    } catch (requestError) {
      setError(requestError.message || "Unable to remove this website.");
    } finally {
      setBusy(false);
    }
  }

  const actuallyConnected = Boolean(
    connectionStatus?.verified &&
    connectionStatus?.enabled &&
    ["CONNECTED", "RECEIVING"].includes(connectionStatus?.status)
  );

  return (
    <main className="integration-page">
      <header className="welcome-row integration-heading">
        <div>
          <div className="eyebrow">AUTHORIZED WEBSITE TELEMETRY</div>
          <h1>{initialView === "connect" ? "Connect Website" : "My Websites"}</h1>
          <p className="page-description">Collect authorized access-log events with a customer-side agent. A website is marked connected only after real events are authenticated and stored.</p>
        </div>
        {initialView !== "connect" && (
          <button type="button" className="primary-button" onClick={() => { setWizardOpen(true); setWizardSite(null); setWizardStep(0); setError(""); }}>
            <Plus size={17} /> Add Website
          </button>
        )}
      </header>

      {error && <div className="website-error" role="alert">{error}</div>}
      {notice && <div className="integration-notice" role="status">{notice}<button type="button" onClick={() => setNotice("")} aria-label="Dismiss">×</button></div>}

      {initialView !== "connect" && (
        <section className="integration-overview-grid">
          <article><span>Connected websites</span><strong>{connectedCount} / {sites.length}</strong></article>
          <article><span>Requests received</span><strong>{totals.events.toLocaleString()}</strong></article>
          <article><span>Suspicious requests</span><strong>{totals.suspicious.toLocaleString()}</strong></article>
        </section>
      )}

      {wizardOpen && (
        <section className="panel integration-wizard" aria-labelledby="integration-wizard-title">
          <div className="panel-heading">
            <div><h2 id="integration-wizard-title">{wizardSite ? `Connect ${wizardSite.name}` : "Register a website"}</h2><p>Four steps · only real, authenticated traffic verifies connection</p></div>
            <button type="button" className="secondary-button" onClick={() => { setWizardOpen(false); setWizardSite(null); }}>Close</button>
          </div>
          <ol className="integration-stepper">
            {STEPS.map((step, index) => <li key={step} className={index === wizardStep ? "active" : index < wizardStep ? "complete" : ""}><span>{index < wizardStep ? <Check size={14} /> : index + 1}</span><small>{step}</small></li>)}
          </ol>

          {!wizardSite ? (
            <form className="integration-form" onSubmit={submitWebsite}>
              <label>Website name<input required minLength={1} maxLength={120} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="My production site" /></label>
              <label>Website URL<input required type="url" value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} placeholder="https://example.com" /></label>
              <label>Website platform<select value={form.platform} onChange={(event) => setForm({ ...form, platform: event.target.value })}>{PLATFORMS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
              <label>Website description (optional)<textarea maxLength={1000} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} placeholder="What does this website provide?" /></label>
              <label className="website-authorize"><input type="checkbox" checked={form.authorization_confirmed} onChange={(event) => setForm({ ...form, authorization_confirmed: event.target.checked })} required /> I own this website or have permission to monitor its traffic.</label>
              <p className="integration-help">Your website is associated with your account. NetSentry creates a unique ID and displays its collector key once.</p>
              <button className="primary-button" disabled={busy}>{busy ? "Registering…" : "Register website"} <ArrowRight size={15} /></button>
            </form>
          ) : (
            <div className="integration-step-content">
              {wizardStep === 1 && (
                <section className="integration-step-panel">
                  <h3>Choose how to send server access logs</h3>
                  <p>The standalone agent tails a log on the customer server and sends events to the configured NetSentry API. It does not modify website files.</p>
                  <label>Log format
                    <select value={wizardSite.integration_method} onChange={(event) => selectMethod(event.target.value)} disabled={busy}>
                      {methods.map(([method, label]) => <option key={method} value={method}>{label}</option>)}
                    </select>
                  </label>
                  <p className="integration-help"><strong>Finding your log:</strong> {PLATFORM_LOG_HINTS[wizardSite.platform] || PLATFORM_LOG_HINTS.other} Confirm the actual path with your hosting provider. The agent lets you browse to that file and never changes website files.</p>
                  <div className="integration-platform-cards">
                    <article className="integration-platform-card selected"><strong>Standalone NetSentry Agent</strong><small>Available for Windows and Linux. Token is entered securely when the agent starts.</small></article>
                    <article className="integration-platform-card" aria-disabled="true"><strong>Browser JavaScript snippet</strong><small>Unavailable: no safe public-token telemetry endpoint is implemented. Do not put a private collector key in browser code.</small></article>
                    <article className="integration-platform-card" aria-disabled="true"><strong>WordPress plugin</strong><small>Unavailable: a verified plugin integration has not been implemented.</small></article>
                  </div>
                  {wizardSite.ingest_token && (
                    <div className="integration-token">
                      <div><KeyRound size={17} /><strong>One-time collector key</strong></div>
                      <p>Website ID: {wizardSite.id}. Keep this key private. It is not included in the download and cannot be retrieved after this setup is closed.</p>
                      <code>{wizardSite.ingest_token}</code>
                      <button type="button" className="secondary-button" onClick={copyToken}>{copied ? <Check size={15} /> : <Clipboard size={15} />}{copied ? "Copied" : "Copy key"}</button>
                    </div>
                  )}
                  {!wizardSite.ingest_token && <div className="integration-help">The original one-time key is no longer available. <button type="button" className="secondary-button" onClick={() => regenerateToken(wizardSite)} disabled={busy}>Generate a new key</button></div>}
                  <div className="integration-wizard-actions">
                    <button type="button" className="secondary-button" disabled={Boolean(downloading)} onClick={() => downloadPackage("windows")}><Download size={15} />{downloading === "windows" ? "Preparing…" : "Download Windows Agent"}</button>
                    <button type="button" className="secondary-button" disabled={Boolean(downloading)} onClick={() => downloadPackage("linux")}><Download size={15} />{downloading === "linux" ? "Preparing…" : "Download Linux Agent"}</button>
                    <button type="button" className="primary-button" onClick={() => setWizardStep(2)}>Continue to verification <ArrowRight size={15} /></button>
                  </div>
                  <p className="integration-help">Extract and run the included installer on the customer server—not in the NetSentry repository. The agent prompts for the access-log path and one-time key. Python 3.10+ is required. The package contains no customer source code or backend secrets.</p>
                </section>
              )}

              {wizardStep === 2 && (
                <section className="integration-step-panel">
                  <h3>Verify real collector traffic</h3>
                  <p>Start the agent on the customer server and generate a real website request. The API updates this status only after it accepts and stores an authenticated event.</p>
                  <div className="integration-detail-stats">
                    <article><span>Website ID</span><strong>{wizardSite.id}</strong></article>
                    <article><span>Collector</span><strong>{connectionStatus?.collector_process_status || wizardSite.collector_process_status || "WAITING"}</strong></article>
                    <article><span>Events received</span><strong>{Number(connectionStatus?.total_events || 0).toLocaleString()}</strong></article>
                    <article><span>Connection</span><strong>{busy ? "Verifying connection…" : connectionLabel(connectionStatus?.status, connectionStatus?.collector_process_status)}</strong></article>
                    <article><span>Last event</span><strong>{prettyDate(connectionStatus?.last_event_received)}</strong></article>
                    <article><span>Last heartbeat</span><strong>{prettyDate(connectionStatus?.collector_last_seen_at)}</strong></article>
                  </div>
                  {connectionStatus?.latest_ingestion_error && <div className="website-error" role="alert">{connectionStatus.latest_ingestion_error}</div>}
                  <p className="integration-help">The frontend dashboard and NetSentry API are separate services. The agent sends HTTPS traffic to the API configured by your administrator; it does not send telemetry to the dashboard or a customer-selected endpoint.</p>
                  <div className="integration-wizard-actions">
                    <button type="button" className="secondary-button" onClick={() => setWizardStep(1)}>Back</button>
                    <button type="button" className="secondary-button" onClick={verifyNow} disabled={busy}><RefreshCw size={15} />{busy ? "Checking…" : "Check connection"}</button>
                    <button type="button" className="primary-button" onClick={() => setWizardStep(3)} disabled={!actuallyConnected}>Continue <ArrowRight size={15} /></button>
                  </div>
                  {!actuallyConnected && <p className="integration-help">Waiting for the first authenticated event. Copying instructions or downloading an agent does not mark the website connected.</p>}
                </section>
              )}

              {wizardStep === 3 && (
                <section className="integration-step-panel">
                  <h3><Wifi size={20} /> Your Website Is Successfully Connected to NetSentry AI</h3>
                  <div className="integration-detail-stats">
                    <article><span>Website</span><strong>{wizardSite.name}</strong></article>
                    <article><span>Website URL</span><strong>{wizardSite.url}</strong></article>
                    <article><span>Site ID</span><strong>{wizardSite.id}</strong></article>
                    <article><span>Integration method</span><strong>Customer-side collector</strong></article>
                    <article><span>Connection status</span><strong>{connectionLabel(connectionStatus?.status)}</strong></article>
                    <article><span>Last heartbeat</span><strong>{prettyDate(connectionStatus?.collector_last_seen_at)}</strong></article>
                    <article><span>Connected date</span><strong>{prettyDate(wizardSite.created_at)}</strong></article>
                  </div>
                  <div className="integration-wizard-actions">
                    <button type="button" className="primary-button" onClick={() => onOpenLiveMonitoring?.(wizardSite.id)}>Go to Website Monitoring</button>
                    <button type="button" className="secondary-button" onClick={() => setWizardStep(1)}>View Installation Instructions</button>
                    <button type="button" className="secondary-button integration-remove" onClick={() => disconnect(wizardSite)} disabled={busy}><Trash2 size={15} /> Disconnect</button>
                  </div>
                </section>
              )}
            </div>
          )}
        </section>
      )}

      {initialView !== "connect" && (
        <section className="integration-sites-grid">
          {loading ? (
            <section className="panel integration-empty"><RefreshCw size={22} /><p>Loading your websites…</p></section>
          ) : sites.length ? sites.map((site) => (
            <article className="panel integration-site-card" key={site.id}>
              <div className="integration-site-title">
                <span className="integration-globe"><Globe2 size={18} /></span>
                <div><h2>{site.name}</h2><p>{site.url}</p></div>
                <span className={`integration-status status-${String(site.integration_status || "WAITING_FOR_EVENTS").toLowerCase()}`}>{connectionLabel(site.integration_status, site.collector_process_status)}</span>
              </div>
              <p>{site.description || "No description provided."}</p>
              <div className="integration-site-meta">
                <span>Website ID <b>{site.id}</b></span>
                <span>Last heartbeat <b>{prettyDate(site.collector_last_seen_at)}</b></span>
                <span>Integration <b>Customer-side collector</b></span>
                <span>Platform <b>{PLATFORMS.find(([id]) => id === site.platform)?.[1] || site.platform}</b></span>
              </div>
              <div className="integration-site-stats">
                <div><small>Total requests</small><strong>{Number(site.total_events || 0).toLocaleString()}</strong></div>
                <div><small>Suspicious requests</small><strong>{Number(site.suspicious_requests || 0).toLocaleString()}</strong></div>
                <div><small>Blocked requests</small><strong>Not tracked</strong></div>
              </div>
              <div className="integration-card-actions">
                <button type="button" className="secondary-button" onClick={() => setDetailSiteId(site.id)}>View Details</button>
                <button type="button" className="primary-button" onClick={() => onOpenLiveMonitoring?.(site.id)}>Monitor Traffic</button>
                <button type="button" className="secondary-button" onClick={() => reconnect(site)} disabled={busy || site.collector_revoked}>Reconnect</button>
                <button type="button" className="secondary-button" onClick={() => regenerateToken(site)} disabled={busy}><KeyRound size={14} /> Regenerate Token</button>
                <button type="button" className="secondary-button integration-remove" onClick={() => disconnect(site)} disabled={busy || site.collector_revoked}><Trash2 size={14} /> Disconnect</button>
                <button type="button" className="secondary-button integration-remove" onClick={() => remove(site)} disabled={busy}>Remove</button>
              </div>
            </article>
          )) : (
            <section className="panel integration-empty"><Globe2 size={28} /><h2>No websites connected yet</h2><p>Register an authorized website to start its collector setup.</p><button type="button" className="primary-button" onClick={() => { setWizardOpen(true); setWizardSite(null); setWizardStep(0); }}>Add Website</button></section>
          )}
        </section>
      )}

      {selectedSite && (
        <section className="panel integration-details">
          <div className="panel-heading">
            <div><h2>{selectedSite.name}</h2><p>{selectedSite.url} · Site ID {selectedSite.id}</p></div>
            <button type="button" className="secondary-button" onClick={() => setDetailSiteId(null)}>Close</button>
          </div>
          <div className="integration-detail-stats">
            <article><span>Connection</span><strong>{connectionLabel(selectedSite.integration_status, selectedSite.collector_process_status)}</strong></article>
            <article><span>Total requests</span><strong>{Number(selectedSite.total_events || 0).toLocaleString()}</strong></article>
            <article><span>Suspicious requests</span><strong>{Number(selectedSite.suspicious_requests || 0).toLocaleString()}</strong></article>
            <article><span>Blocked requests</span><strong>Not tracked</strong></article>
            <article><span>Last event</span><strong>{prettyDate(selectedSite.last_event_received)}</strong></article>
            <article><span>Last heartbeat</span><strong>{prettyDate(selectedSite.collector_last_seen_at)}</strong></article>
          </div>
          <div className="integration-details-columns">
            <section><h3>Recent request events</h3>{detailEvents.length ? detailEvents.map((event) => <p key={event.id}><b>{event.method} {event.path}</b> · HTTP {event.status_code} · {event.source_ip || "source unavailable"} · {prettyDate(event.created_at)}<br />{event.user_agent || "User agent unavailable"}</p>) : <p>No traffic events received yet.</p>}</section>
            <section><h3>Recent security alerts</h3>{detailAlerts.length ? detailAlerts.map((alert) => <p key={alert.id}><ShieldAlert size={14} /> <b>{alert.title}</b> · {alert.severity} · {alert.status}</p>) : <p>No security alerts for this website.</p>}</section>
          </div>
        </section>
      )}
    </main>
  );
}
