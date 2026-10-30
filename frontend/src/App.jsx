import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, LoaderCircle, Mail, Shield } from "lucide-react";
import Dashboard from "./components/Dashboard";
import { authenticate, authenticateWithGoogle, getCurrentUser, getGoogleSignInConfig, resendSignupCode, signOut, verifySignupEmail } from "./services/api";

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
  const [verificationPending, setVerificationPending] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
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
    password.length >= 6 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password)
  );
  const canSubmit = !isBusy && gmailValid && (verificationPending
    ? /^\d{6}$/.test(verificationCode)
    : Boolean(password) && passwordValid && (!registering || Boolean(name.trim())));

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
    setNotice("");
    try {
      if (verificationPending) {
        const result = await verifySignupEmail(email.trim().toLowerCase(), verificationCode);
        onAuthenticated(result.user);
      } else {
        const payload = { email: email.trim().toLowerCase(), password };
        if (registering) payload.name = name.trim();
        const result = await authenticate(registering ? "register" : "login", payload);
        if (registering) {
          setVerificationPending(true);
          setVerificationCode("");
          setPassword("");
          setNotice(result.message || "Verification code sent. Enter it to continue.");
        } else {
          onAuthenticated(result.user);
        }
      }
    } catch (err) {
      setError(err.message);
      if (!registering && err.status === 403 && /verify your email/i.test(err.message)) {
        setRegistering(true);
        setVerificationPending(true);
        setNotice("Your account needs email confirmation. Enter the code or request a new one.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function resendCode() {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await resendSignupCode(email.trim().toLowerCase());
      setNotice(result.message || "If an unverified account exists, a new code has been sent.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="account-gate">
      <form className="account-card" onSubmit={submit}>
        <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
        <p className="account-eyebrow">{verificationPending ? "EMAIL CONFIRMATION" : "SECURE WORKSPACE ACCESS"}</p>
        <h1>{verificationPending ? "Verify your email" : registering ? "Create your account" : "Welcome back"}</h1>
        <p className="account-copy">{verificationPending
          ? `Enter the six-digit code sent to ${email}. It expires in 10 minutes.`
          : registering
            ? "Set up your account to save your network analyses and alerts."
            : "Sign in to continue to your private network analysis workspace."}</p>
        {!verificationPending && registering && <label>Name<input name="name" autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} required maxLength="120" /></label>}
        {!verificationPending && <label>Email
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
        </label>}
        {verificationPending && <label>Verification code<input className="verification-code-input" name="verification-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={verificationCode} onChange={(event) => { setVerificationCode(event.target.value.replace(/\D/g, "").slice(0, 6)); setError(""); }} placeholder="000000" aria-label="Six-digit email verification code" required /></label>}
        {!verificationPending && <label>Password<input name="password" type="password" autoComplete={registering ? "new-password" : "current-password"} value={password} onChange={(event) => { setPassword(event.target.value); setError(""); }} minLength={registering ? 6 : 1} required /></label>}
        {!verificationPending && registering && <small className="account-password-help">At least 6 characters, including uppercase, lowercase, and a number.</small>}
        {error && <p className="account-error" role="alert">{error}</p>}
        {notice && <p className="account-success" role="status">{notice}</p>}
        <button className="account-primary-button" disabled={!canSubmit}>{busy ? <><LoaderCircle size={17} className="account-spin" /> {verificationPending ? "Verifying code…" : "Please wait…"}</> : <>{verificationPending ? "Verify email and continue" : registering ? "Create account" : "Sign in"}<ArrowRight size={17} /></>}</button>
        {verificationPending && <div className="account-verify-actions"><button type="button" className="account-link-button" disabled={isBusy} onClick={resendCode}><Mail size={15} /> Resend code</button><button type="button" className="account-link-button" disabled={isBusy} onClick={() => { setVerificationPending(false); setVerificationCode(""); setError(""); setNotice(""); }}><ArrowLeft size={15} /> Back to signup</button></div>}
        {!verificationPending && <>{googleConfig.client_id && <><div className="google-divider"><span>OR</span></div>
        <div className={googleBusy ? "google-button-slot is-loading" : "google-button-slot"} aria-busy={googleBusy}>
          <div ref={googleButtonRef} className="google-button-target" />
          {googleBusy && <span className="google-loading-label" role="status">Verifying Google account…</span>}
        </div></>}
        {googleError && <p className="account-error" role="alert">{googleError}</p>}
        <p className="account-switch">{registering ? "Already have an account?" : "New to NetSentry?"}{" "}
          <button type="button" disabled={isBusy} onClick={() => { setRegistering(!registering); setVerificationPending(false); setVerificationCode(""); setError(""); setNotice(""); setGoogleError(""); setEmailTouched(false); setPassword(""); }}>
            {registering ? "Sign in" : "Create an account"}
          </button>
        </p></>}
      </form>
    </main>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    getCurrentUser().then((result) => setUser(result.user)).catch(() => {}).finally(() => setAuthChecked(true));
  }, []);

  if (!authChecked) return <div className="account-loading"><LoaderCircle size={20} className="account-spin" /> Restoring your secure session…</div>;
  if (!user) return <AccountGate onAuthenticated={setUser} />;
  return (
    <>
      <Dashboard user={user} onSignOut={async () => { await signOut(); setUser(null); }} />
    </>
  );
}
