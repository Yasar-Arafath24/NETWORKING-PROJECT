
// Vite proxies /api/v1 to the IPv4 loopback backend in development. This
// keeps browser requests and session cookies on the frontend's origin.
// Set VITE_API_BASE_URL when the production API has a separate origin.
const API_BASE_URL = (import.meta.env?.VITE_API_BASE_URL || "").replace(/\/+$/, "");

const BACKEND_UNREACHABLE_MESSAGE =
  "Cannot reach the NetSentry API" +
  (API_BASE_URL ? " at " + API_BASE_URL : "") +
  ". Make sure it is running (python -m uvicorn backend.app.main:app --port 8000).";

export { API_BASE_URL };

/**
 * Parse API responses and handle errors consistently.
 */
async function parseResponse(response) {
  const contentType = response.headers.get("content-type") || "";

  const data = contentType.includes("application/json")
    ? await response.json()
    : await response.text();

  if (!response.ok) {
    const detail =
      typeof data === "object" && data !== null
        ? data.detail || data.message
        : data;

    const error = new Error(
      detail
        ? String(detail)
        : `Request failed with status ${response.status}`
    );
    error.status = response.status;
    throw error;
  }

  return data;
}

/**
 * Fetch a URL and turn network-level failures (for example a stopped
 * backend, which the browser reports as "Failed to fetch") into a clear,
 * actionable message instead of a raw browser error.
 */
export async function getCurrentUser() {
  return request(API_BASE_URL + "/api/v1/auth/me");
}

export async function authenticate(action, values) {
  return request(API_BASE_URL + "/api/v1/auth/" + action, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(values),
  });
}

export async function getGoogleSignInConfig() {
  return request(API_BASE_URL + "/api/v1/auth/google/config");
}

export async function authenticateWithGoogle(credential, nonce) {
  return request(API_BASE_URL + "/api/v1/auth/google", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential, nonce }),
  });
}

export async function signOut() {
  return request(API_BASE_URL + "/api/v1/auth/logout", { method: "POST" });
}

export async function getWebsites() {
  return request(API_BASE_URL + "/api/v1/websites");
}

export async function addWebsite(values) {
  return request(API_BASE_URL + "/api/v1/websites", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(values),
  });
}

export async function setWebsiteEnabled(id, enabled) {
  return request(API_BASE_URL + "/api/v1/websites/" + id + "?enabled=" + enabled, { method: "PATCH" });
}

export async function deleteWebsite(id) {
  return request(API_BASE_URL + "/api/v1/websites/" + id, { method: "DELETE" });
}

export async function getWebsiteEvents(id, options = {}) {
  const params = new URLSearchParams({
    skip: String(options.skip ?? 0),
    limit: String(options.limit ?? 50),
  });
  for (const key of ["search", "method", "status_code", "classification", "since", "until"]) {
    const value = options[key];
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  return request(API_BASE_URL + "/api/v1/websites/" + id + "/events?" + params);
}

export function websiteLiveUrl(id) {
  const url = new URL(
    API_BASE_URL + "/api/v1/websites/" + id + "/live",
    window.location.origin
  );
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

async function request(url, options) {
  let response;
  const csrf = document.cookie.match(/(?:^|; )netsentry_csrf=([^;]*)/)?.[1];
  const headers = new Headers(options?.headers || {});
  if (csrf && options?.method && options.method !== "GET") {
    headers.set("X-CSRF-Token", decodeURIComponent(csrf));
  }

  try {
    response = await fetch(url, { ...options, headers, credentials: "include" });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("The request timed out before the backend replied.", {
        cause: error,
      });
    }

    throw new Error(BACKEND_UNREACHABLE_MESSAGE, { cause: error });
  }

  return parseResponse(response);
}

/**
 * Upload a PCAP file and run backend analysis.
 * FastAPI expects a multipart field named "file".
 */
export async function uploadPcap(file) {
  if (!(file instanceof File)) {
    throw new Error("Please select a valid PCAP file.");
  }

  const formData = new FormData();
  formData.append("file", file);

  return request(`${API_BASE_URL}/api/v1/pcap/analyze`, {
    method: "POST",
    body: formData,
  });
}

/**
 * Retrieve recent PCAP analysis reports.
 */
export async function getAnalysisHistory({
  skip = 0,
  limit = 20,
} = {}) {
  const params = new URLSearchParams({
    skip: String(skip),
    limit: String(limit),
  });

  return request(`${API_BASE_URL}/api/v1/monitoring/history?${params}`);
}

/**
 * Check whether the backend is reachable.
 * Uses the existing history endpoint.
 */
export async function checkBackendConnection() {
  await request(API_BASE_URL + "/api/v1/health");

  return true;
}

/**
 * Retrieve the latest persisted PCAP analysis.
 * Returns 404 (detail message) when no analysis has been stored yet.
 */
export async function getLatestAnalysis() {
  return request(`${API_BASE_URL}/api/v1/monitoring/latest`);
}

/**
 * Retrieve recent security alerts.
 */
export async function getSecurityAlerts({ limit = 100 } = {}) {
  const params = new URLSearchParams({
    limit: String(limit),
  });

  return request(
    `${API_BASE_URL}/api/v1/monitoring/history/alerts?${params}`
  );
}

export async function getLatestTraffic() {
  const response = await fetch(`${API_BASE_URL}/api/v1/pcap/traffic`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Traffic request failed: ${response.status}`);
  }

  return response.json();
}

/**
 * Start live network capture.
 */
export async function startLiveCapture(iface = null) {
  return request(`${API_BASE_URL}/api/v1/monitoring/live/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interface: iface }),
  });
}

/**
 * Start PCAP replay for live monitoring.
 */
export async function startPcapReplay(pcapPath, speed = 1.0) {
  return request(`${API_BASE_URL}/api/v1/monitoring/live/replay`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pcap_path: pcapPath, speed }),
  });
}

/**
 * Stop live monitoring.
 */
export async function stopLiveMonitoring() {
  return request(`${API_BASE_URL}/api/v1/monitoring/live/stop`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Get live monitoring status.
 */
export async function getLiveMonitoringStatus() {
  return request(`${API_BASE_URL}/api/v1/monitoring/live/status`);
}

/**
 * Get network interfaces available for live capture.
 */
export async function getLiveCaptureInterfaces() {
  return request(`${API_BASE_URL}/api/v1/monitoring/live/interfaces`);
}

/**
 * Get live flows from active monitoring.
 */
export async function getLiveFlows(limit = 100) {
  const params = new URLSearchParams({ limit: String(limit) });
  return request(`${API_BASE_URL}/api/v1/monitoring/live/flows?${params}`);
}

/**
 * Get live packets from active monitoring.
 */
export async function getLivePackets(limit = 100) {
  const params = new URLSearchParams({ limit: String(limit) });
  return request(`${API_BASE_URL}/api/v1/monitoring/live/packets?${params}`);
}

/**
 * Get live detection status.
 */
export async function getLiveDetectionStatus() {
  return request(`${API_BASE_URL}/api/v1/monitoring/live/detection-status`);
}

/**
 * Get persisted live flows.
 */
export async function getPersistedLiveFlows(limit = 100) {
  const params = new URLSearchParams({ limit: String(limit) });
  return request(`${API_BASE_URL}/api/v1/monitoring/history/flows?${params}`);
}
