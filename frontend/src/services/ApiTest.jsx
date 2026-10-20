
import { useEffect, useState } from "react";
import { getHealth, getAnalysisHistory } from "./api";

export default function ApiTest() {
  const [result, setResult] = useState({
    loading: true,
    health: null,
    history: null,
    error: null,
  });

  useEffect(() => {
    let active = true;

    async function checkApi() {
      try {
        const [healthResult, historyResult] = await Promise.allSettled([
          getHealth(),
          getAnalysisHistory(),
        ]);

        if (!active) return;

        setResult({
          loading: false,
          health:
            healthResult.status === "fulfilled"
              ? healthResult.value
              : null,
          history:
            historyResult.status === "fulfilled"
              ? historyResult.value
              : null,
          error: [
            healthResult.status === "rejected"
              ? `Health API: ${healthResult.reason.message}`
              : null,
            historyResult.status === "rejected"
              ? `History API: ${historyResult.reason.message}`
              : null,
          ]
            .filter(Boolean)
            .join("\n") || null,
        });
      } catch (error) {
        if (active) {
          setResult({
            loading: false,
            health: null,
            history: null,
            error: error.message,
          });
        }
      }
    }

    checkApi();

    return () => {
      active = false;
    };
  }, []);

  if (result.loading) {
    return <p>Checking NetSentry AI backend...</p>;
  }

  return (
    <section style={{ padding: 24, fontFamily: "system-ui" }}>
      <h2>Backend connection test</h2>

      <h3>Health endpoint</h3>
      <pre>{JSON.stringify(result.health, null, 2) || "Unavailable"}</pre>

      <h3>Analysis history</h3>
      <pre>{JSON.stringify(result.history, null, 2) || "Unavailable"}</pre>

      {result.error && (
        <pre style={{ color: "#b91c1c", whiteSpace: "pre-wrap" }}>
          {result.error}
        </pre>
      )}
    </section>
  );
}
