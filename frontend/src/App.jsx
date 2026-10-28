import { useEffect, useState } from "react";
import { Shield } from "lucide-react";
import Dashboard from "./components/Dashboard";

export default function App() {
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => setLoading(false), 3000);
    return () => window.clearTimeout(timer);
  }, []);

  if (loading) {
    return (
      <div className="netsentry-loader" role="status" aria-live="polite">
        <div className="netsentry-loader-mark" aria-hidden="true">
          <span className="netsentry-loader-orbit" />
          <Shield size={34} strokeWidth={1.65} />
          <span className="netsentry-loader-signal" />
        </div>
        <strong>NetSentry <span>AI</span></strong>
        <p>Preparing network intelligence</p>
        <div className="netsentry-loader-progress" aria-hidden="true">
          <span />
        </div>
      </div>
    );
  }

  return <Dashboard />;
}