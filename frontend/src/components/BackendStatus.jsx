
import { useEffect, useState } from "react";

import { API_BASE_URL } from "../services/api";

const HEALTH_URL = `${API_BASE_URL}/api/v1/health`;

export default function BackendStatus() {
  const [status, setStatus] = useState("checking");
  const [lastChecked, setLastChecked] = useState(null);

  useEffect(() => {
    let active = true;

    async function checkHealth() {
      try {
        const response = await fetch(HEALTH_URL, {
          signal: AbortSignal.timeout(5000),
        });

        if (!response.ok) {
          throw new Error("Backend health check failed");
        }

        const data = await response.json();

        if (data.status !== "healthy") {
          throw new Error("Backend is unhealthy");
        }

        if (active) {
          setStatus("online");
          setLastChecked(new Date());
        }
      } catch {
        if (active) {
          setStatus("offline");
          setLastChecked(new Date());
        }
      }
    }

    checkHealth();
    const intervalId = setInterval(checkHealth, 15000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, []);

  const colors = {
    checking: "#64748b",
    online: "#15803d",
    offline: "#dc2626",
  };

  const labels = {
    checking: "Checking backend...",
    online: "Backend online",
    offline: "Backend offline",
  };

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "8px",
        padding: "9px 12px",
        border: "1px solid #e2e8f0",
        borderRadius: "10px",
        background: "#ffffff",
        color: colors[status],
        fontSize: "13px",
        fontWeight: 600,
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: "8px",
          height: "8px",
          borderRadius: "50%",
          background: colors[status],
        }}
      />
      <span>{labels[status]}</span>
      {lastChecked && (
        <span style={{ color: "#64748b", fontWeight: 400 }}>
          · {lastChecked.toLocaleTimeString()}
        </span>
      )}
    </div>
  );
}
