import { useEffect, useState } from "react";
import { Shield } from "lucide-react";
import Dashboard from "./components/Dashboard";
import { authenticate, getCurrentUser, signOut } from "./services/api";

function AccountGate({ onAuthenticated }) {
  const [registering, setRegistering] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const payload = Object.fromEntries(form.entries());
    try {
      const result = await authenticate(registering ? "register" : "login", payload);
      onAuthenticated(result.user);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="account-gate">
      <form className="account-card" onSubmit={submit}>
        <div className="account-mark"><Shield size={22} /></div>
        <p className="account-eyebrow">NETSENTRY AI</p>
        <h1>{registering ? "Create your account" : "Welcome back"}</h1>
        <p className="account-copy">Sign in to access your private network analysis workspace.</p>
        {registering && <label>Name<input name="name" autoComplete="name" required maxLength="120" /></label>}
        <label>Email<input name="email" type="email" autoComplete="email" required /></label>
        <label>Password<input name="password" type="password" autoComplete={registering ? "new-password" : "current-password"} minLength={registering ? 12 : 1} required /></label>
        {registering && <small>At least 12 characters, with uppercase, lowercase, and a number.</small>}
        {error && <p className="account-error" role="alert">{error}</p>}
        <button disabled={busy}>{busy ? "Please wait…" : registering ? "Create account" : "Sign in"}</button>
        <p className="account-switch">{registering ? "Already have an account?" : "New to NetSentry?"}{" "}
          <button type="button" onClick={() => { setRegistering(!registering); setError(""); }}>
            {registering ? "Sign in" : "Create an account"}
          </button>
        </p>
      </form>
    </main>
  );
}

export default function App() {
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => setLoading(false), 3000);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    getCurrentUser().then((result) => setUser(result.user)).catch(() => {}).finally(() => setAuthChecked(true));
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

  if (!authChecked) return <div className="account-loading">Checking your session…</div>;
  if (!user) return <AccountGate onAuthenticated={setUser} />;
  return (
    <>
      <div className="account-bar">
        <span>{user.name}</span>
        <button onClick={async () => { await signOut(); setUser(null); }}>Sign out</button>
      </div>
      <Dashboard user={user} />
    </>
  );
}
