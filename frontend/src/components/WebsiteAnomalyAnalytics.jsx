import { useEffect, useMemo, useState } from "react";
import { getWebsiteAnalytics } from "../services/api";

const RANGE_MS = { "1h": 60 * 60 * 1000, "24h": 24 * 60 * 60 * 1000, "7d": 7 * 24 * 60 * 60 * 1000 };
const EMPTY = {
  event_count: 0,
  normal_count: 0,
  suspicious_count: 0,
  category_distribution: {},
  severity_distribution: {},
  top_suspicious_sources: [],
  top_flagged_endpoints: [],
  ml_status: "unavailable_incompatible_features",
};

export default function WebsiteAnomalyAnalytics() {
  const [analytics, setAnalytics] = useState(EMPTY);
  const [range, setRange] = useState("24h");
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const since = new Date(Date.now() - RANGE_MS[range]).toISOString();
      try {
        const result = await getWebsiteAnalytics(undefined, since);
        if (active) {
          setAnalytics(result);
          setError("");
        }
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Unable to load website anomaly analytics.");
      }
    };
    refresh();
    const timer = window.setInterval(refresh, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [range]);

  const categories = useMemo(
    () => Object.entries(analytics.category_distribution || {}).sort((left, right) => right[1] - left[1]).slice(0, 6),
    [analytics.category_distribution],
  );
  const maxCategoryCount = Math.max(1, ...categories.map(([, count]) => count));

  return (
    <section className="panel website-anomaly-analytics">
      <div className="panel-heading">
        <div>
          <h2>Website anomaly analytics</h2>
          <p>{analytics.event_count || 0} real website events · heuristic rules</p>
        </div>
        <label className="website-analytics-range">
          Time range
          <select value={range} onChange={(event) => setRange(event.target.value)} aria-label="Website analytics time range">
            <option value="1h">Last hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
          </select>
        </label>
      </div>
      {error && <div className="website-error" role="alert">{error}</div>}
      <div className="website-analytics-ml-note">Website events use rule-based detection. The current ML model expects network-flow features and does not score website events.</div>
      <div className="website-analytics-summary">
        <article><small>Normal</small><strong>{analytics.normal_count || 0}</strong></article>
        <article><small>Suspicious / anomalous</small><strong>{analytics.suspicious_count || 0}</strong></article>
        <article><small>Critical</small><strong>{analytics.severity_distribution?.CRITICAL || 0}</strong></article>
        <article><small>High</small><strong>{analytics.severity_distribution?.HIGH || 0}</strong></article>
      </div>
      <div className="website-analytics-columns">
        <div>
          <h3>Detection categories</h3>
          {categories.length ? categories.map(([category, count]) => (
            <div className="website-analytics-row" key={category}>
              <span>{category.replaceAll("_", " ")}</span>
              <div><i style={{ width: `${Math.max(3, count / maxCategoryCount * 100)}%` }} /></div>
              <b>{count}</b>
            </div>
          )) : <p>No detection categories in this period.</p>}
        </div>
        <div>
          <h3>Top flagged endpoints</h3>
          {analytics.top_flagged_endpoints?.length ? analytics.top_flagged_endpoints.slice(0, 5).map((row) => (
            <div className="website-analytics-list-row" key={row.endpoint}><code>{row.endpoint}</code><b>{row.count}</b></div>
          )) : <p>No flagged endpoints.</p>}
          <h3>Suspicious sources</h3>
          {analytics.top_suspicious_sources?.length ? analytics.top_suspicious_sources.slice(0, 5).map((row) => (
            <div className="website-analytics-list-row" key={row.source_ip}><code>{row.source_ip}</code><b>{row.count}</b></div>
          )) : <p>No suspicious source activity.</p>}
        </div>
      </div>
    </section>
  );
}
