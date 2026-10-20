
import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000",
  timeout: 15000,
  headers: {
    Accept: "application/json",
  },
});

export async function getHealth() {
  const response = await api.get("/health");
  return response.data;
}

export async function getAnalysisHistory() {
  const response = await api.get("/api/v1/monitoring/history", {
    params: {
      skip: 0,
      limit: 20,
    },
  });

  return response.data;
}

export async function uploadPcap(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await api.post("/api/v1/pcap/analyze", formData, {
    timeout: 120000,
  });

  return response.data;
}

export default api;
