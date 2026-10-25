
// Base URL for the NetSentry backend API.
// Configure it with VITE_API_BASE_URL in frontend/.env; it falls back to the
// local development backend so the app works out of the box.
const API_BASE_URL = (
  import.meta.env?.VITE_API_BASE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const BACKEND_UNREACHABLE_MESSAGE =
  `Cannot reach the NetSentry backend at ${API_BASE_URL}. ` +
  'Make sure it is running (python -m uvicorn backend.app.main:app --port 8000).';

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

    throw new Error(
      detail
        ? String(detail)
        : `Request failed with status ${response.status}`
    );
  }

  return data;
}

/**
 * Fetch a URL and turn network-level failures (for example a stopped
 * backend, which the browser reports as "Failed to fetch") into a clear,
 * actionable message instead of a raw browser error.
 */
async function request(url, options) {
  let response;

  try {
    response = await fetch(url, options);
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
  await request(`${API_BASE_URL}/api/v1/monitoring/history?skip=0&limit=1`);

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
