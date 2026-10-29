import { useEffect, useRef, useState } from "react";
import { Shield } from "lucide-react";
import Dashboard from "./components/Dashboard";
import { authenticate, authenticateWithGoogle, getCurrentUser, getGoogleSignInConfig, signOut } from "./services/api";

function loadGoogleIdentity() {
  if (window.google?.accounts?.id) return Promise.resolve(window.google);
  if (!window.netsentryGoogleIdentityPromise) {
    const promise = new Promise((resolve, reject) => {
      const existing = document.querySelector("script[data-netsentry-google]");
      const script = existing || document.createElement("script");
      script.async = true;
      script.src = "https://accounts.google.com/gsi/client";
      script.dataset.netsentryGoogle = "true";
      script.onload = () => resolve(window.google);
      script.onerror = () => reject(new Error("Google sign-in could not load. Check your connection and try again."));
      if (!existing) document.head.appendChild(script);
    });
    window.netsentryGoogleIdentityPromise = promise.catch((error) => {
      window.netsentryGoogleIdentityPromise = null;
      throw error;
    });
  }
  return window.netsentryGoogleIdentityPromise;
}

function isGmailAddress(value) {
  const email = value.trim().toLowerCase();
  return /^[^\s@]+@gmail\.com$/.test(email);
}

function AccountGate({ onAuthenticated }) {
  const [registering, setRegistering] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [emailTouched, setEmailTouched] = useState(false);
  const [googleBusy, setGoogleBusy] = useState(false);
  const googleBusyRef = useRef(false);
  const [googleError, setGoogleError] = useState("");
  const [googleConfig, setGoogleConfig] = useState({ client_id: "", checked: false });
  const googleButtonRef = useRef(null);
  const googleNonceRef = useRef("");
  const gmailValid = isGmailAddress(email);
  const isBusy = busy || googleBusy;
  const passwordValid = !registering || (
    password.length >= 12 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password)
  );
  const canSubmit = !isBusy && gmailValid && passwordValid &&
    Boolean(password) && (!registering || Boolean(name.trim()));

  useEffect(() => {
    let active = true;
    getGoogleSignInConfig()
      .then((config) => {
        if (!active) return;
        googleNonceRef.current = config.nonce || "";
        setGoogleConfig({ client_id: config.client_id || "", checked: true });
      })
      .catch((configError) => { if (active) { setGoogleConfig({ client_id: "", checked: true }); setGoogleError(configError.message); } });
    return () => { active = false; };
  }, [onAuthenticated]);

  useEffect(() => {
    let active = true;
    const buttonContainer = googleButtonRef.current;
    if (!googleConfig.client_id || !googleNonceRef.current || !buttonContainer) return undefined;
    loadGoogleIdentity()
      .then((google) => {
        if (!active || !google?.accounts?.id) return;
        google.accounts.id.initialize({
          client_id: googleConfig.client_id,
          nonce: googleNonceRef.current,
          callback: async (credentialResponse) => {
            if (!active || !credentialResponse?.credential || googleBusyRef.current) return;
            googleBusyRef.current = true;
            setGoogleBusy(true);
            setGoogleError("");
            setError("");
            try {
              const result = await authenticateWithGoogle(credentialResponse.credential, googleNonceRef.current);
              if (active) onAuthenticated(result.user);
            } catch (authError) {
              if (active) setGoogleError(authError.message || "Google sign-in failed. Please try again.");
            } finally {
              googleBusyRef.current = false;
              if (active) setGoogleBusy(false);
            }
          },
        });
        google.accounts.id.renderButton(googleButtonRef.current, {
          type: "standard", theme: "outline", size: "large", text: "continue_with",
          shape: "rectangular", width: Math.min(380, Math.max(220, buttonContainer.clientWidth || 340)),
        });
      })
      .catch((scriptError) => { if (active) setGoogleError(scriptError.message); });
    return () => {
      active = false;
      if (window.google?.accounts?.id) window.google.accounts.id.cancel();
      buttonContainer.replaceChildren();
    };
  }, [googleConfig.client_id, onAuthenticated]);

  async function submit(event) {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    const payload = { email: email.trim().toLowerCase(), password };
    if (registering) payload.name = name.trim();
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
        {registering && <label>Name<input name="name" autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} required maxLength="120" /></label>}
        <label>Email
          <input
            name="email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(event) => { setEmail(event.target.value); setError(""); }}
            onBlur={() => setEmailTouched(true)}
            aria-invalid={emailTouched && !gmailValid}
            aria-describedby="gmail-validation"
            required
          />
          <span id="gmail-validation" className="account-field-error" aria-live="polite">
            {emailTouched && email.trim() && !gmailValid
              ? "Enter a valid Gmail address ending in @gmail.com."
              : ""}
          </span>
        </label>
        <label>Password<input name="password" type="password" autoComplete={registering ? "new-password" : "current-password"} value={password} onChange={(event) => { setPassword(event.target.value); setError(""); }} minLength={registering ? 12 : 1} required /></label>
        {registering && <small>At least 12 characters, with uppercase, lowercase, and a number.</small>}
        {error && <p className="account-error" role="alert">{error}</p>}
        <button disabled={!canSubmit}>{busy ? "Authenticating…" : registering ? "Create account" : "Sign in"}</button>
        <div className="google-divider"><span>OR</span></div>
        <div className={googleBusy ? "google-button-slot is-loading" : "google-button-slot"} aria-busy={googleBusy}>
          {googleConfig.client_id && <div ref={googleButtonRef} className="google-button-target" />}
          {!googleConfig.client_id && googleConfig.checked && !googleError && <p className="google-config-note">Google sign-in is not configured for this site.</p>}
          {googleBusy && <span className="google-loading-label" role="status">Verifying Google account…</span>}
        </div>
        <p className="google-help">Use a verified Gmail address. Close the Google window to cancel, then try again.</p>
        {googleError && <p className="account-error" role="alert">{googleError}</p>}
        <p className="account-switch">{registering ? "Already have an account?" : "New to NetSentry?"}{" "}
          <button type="button" disabled={isBusy} onClick={() => { setRegistering(!registering); setError(""); setGoogleError(""); setEmailTouched(false); setPassword(""); }}>
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
      <Dashboard user={user} onSignOut={async () => { await signOut(); setUser(null); }} />
    </>
  );
}
