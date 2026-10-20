
const API_BASE_URL = "http://127.0.0.1:8000";

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
 * Upload a PCAP file and run backend analysis.
 * FastAPI expects a multipart field named "file".
 */
export async function uploadPcap(file) {
  if (!(file instanceof File)) {
    throw new Error("Please select a valid PCAP file.");
  }

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/api/v1/pcap/analyze`,
    {
      method: "POST",
      body: formData,
    }
  );

  return parseResponse(response);
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

  const response = await fetch(
    `${API_BASE_URL}/api/v1/monitoring/history?${params}`
  );

  return parseResponse(response);
}

/**
 * Check whether the backend is reachable.
 * Uses the existing history endpoint.
 */
export async function checkBackendConnection() {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/monitoring/history?skip=0&limit=1`
  );

  await parseResponse(response);

  return true;
}
