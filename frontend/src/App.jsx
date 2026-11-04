import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Eye, EyeOff, LoaderCircle, LockKeyhole, Mail, Shield, UserRound } from "lucide-react";
import { Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import LandingPage from "./components/LandingPage";
import {
  authenticate,
  authenticateWithGoogle,
  getCurrentUser,
  getGoogleSignInConfig,
  requestPasswordReset,
  resendEmailVerification,
  resetAccountPassword,
  signOut,
  verifyEmail,
  verifyPasswordResetOtp,
} from "./services/api";

const protectedPaths = [
  "/dashboard",
  "/website-integration",
  "/websites",
  "/my-websites",
  "/traffic-monitoring",
  "/pcap-analysis",
  "/alerts",
  "/ai-detection",
  "/analysis-history",
  "/settings",
];

const recoveryPaths = [
  "/login",
  "/register",
  "/verify-email",
  "/forgot-password",
  "/verify-reset-otp",
  "/reset-password",
];

function getPostAuthPath(locationState) {
  const requestedPath = locationState?.from?.pathname || locationState?.returnTo;
  const normalizedPath = typeof requestedPath === "string"
    ? requestedPath.replace(/\/+$/, "") || "/"
    : "";
  return protectedPaths.includes(normalizedPath) ? normalizedPath : "/dashboard";
}

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

function isValidEmail(value) {
  const email = value.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function AccountGate({ onAuthenticated, onPasswordReset }) {
  const navigate = useNavigate();
  const location = useLocation();
  const pathname = location.pathname.replace(/\/+$/, "") || "/";
  const registering = pathname === "/register";
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState(
    pathname === "/verify-email" ? location.state?.verificationEmail || "" : ""
  );
  const [password, setPassword] = useState("");
  const [emailTouched, setEmailTouched] = useState(false);
  const [googleBusy, setGoogleBusy] = useState(false);
  const googleBusyRef = useRef(false);
  const [googleError, setGoogleError] = useState("");
  const [googleConfig, setGoogleConfig] = useState({ client_id: "", checked: false });
  const googleButtonRef = useRef(null);
  const googleNonceRef = useRef("");
  const [resetCode, setResetCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [resendSeconds, setResendSeconds] = useState(0);
  const [resetComplete, setResetComplete] = useState(false);
  const [verificationCode, setVerificationCode] = useState("");
  const emailValid = isValidEmail(email);
  const isBusy = busy || googleBusy;
  const passwordValid = !registering || (
    password.length >= 6 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password)
  );
  const canSubmit = !isBusy && emailValid && Boolean(password) && passwordValid && (!registering || Boolean(name.trim()));

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
              if (active) {
                onAuthenticated(result.user);
                navigate(getPostAuthPath(location.state), { replace: true });
              }
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
  }, [googleConfig.client_id, location.state, navigate, onAuthenticated]);

  useEffect(() => {
    if (resendSeconds <= 0) return undefined;
    const timer = window.setInterval(() => {
      setResendSeconds((seconds) => Math.max(0, seconds - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [resendSeconds]);

  async function sendResetCode(event) {
    event?.preventDefault();
    if (!emailValid || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await requestPasswordReset(email.trim().toLowerCase());
      setNotice(result.message || "If an active account matches that email, a password reset code will be sent.");
      setResendSeconds(60);
      setResetCode("");
      navigate("/verify-reset-otp", { state: location.state });
    } catch (requestError) {
      setError(requestError.message || "Unable to process the password reset request.");
    } finally {
      setBusy(false);
    }
  }

  async function verifyResetCode(event) {
    event.preventDefault();
    if (!emailValid || !/^\d{6}$/.test(resetCode) || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await verifyPasswordResetOtp(email.trim().toLowerCase(), resetCode);
      setResetCode("");
      navigate("/reset-password", { state: location.state });
    } catch (requestError) {
      setError(requestError.message || "The reset code is invalid or expired.");
    } finally {
      setBusy(false);
    }
  }

  async function submitNewPassword(event) {
    event.preventDefault();
    if (newPassword.length < 8 || !/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword) || newPassword !== confirmPassword || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await resetAccountPassword(newPassword);
      setNotice(result.message || "Password reset successfully. Sign in with your new password.");
      setResetComplete(true);
      setNewPassword("");
      setConfirmPassword("");
      onPasswordReset?.();
    } catch (requestError) {
      setError(requestError.message || "Unable to reset the password. Verify your code again.");
    } finally {
      setBusy(false);
    }
  }

  async function submit(event) {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError("");
    setNotice("");
    const payload = { email: email.trim().toLowerCase(), password };
    if (registering) payload.name = name.trim();
    try {
      const result = await authenticate(registering ? "register" : "login", payload);
      if (registering && result.verification_required) {
        setEmail(payload.email);
        navigate("/verify-email", {
          state: { ...location.state, verificationEmail: payload.email },
        });
        setNotice("Verification code sent. Check your inbox.");
        return;
      }
      onAuthenticated(result.user);
      navigate(getPostAuthPath(location.state), { replace: true });
    } catch (err) {
      if (err.status === 403 && /verify your email/i.test(err.message)) {
        setEmail(payload.email);
        navigate("/verify-email", {
          state: { ...location.state, verificationEmail: payload.email },
        });
        setNotice("A verification code has been sent. Enter it to continue.");
        return;
      }
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function submitEmailVerification(event) {
    event.preventDefault();
    if (!emailValid || !/^\d{6}$/.test(verificationCode) || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await verifyEmail(email.trim().toLowerCase(), verificationCode);
      setVerificationCode("");
      onAuthenticated(result.user);
      navigate(getPostAuthPath(location.state), { replace: true });
    } catch (verificationError) {
      setError(verificationError.message || "The verification code is invalid or expired.");
    } finally {
      setBusy(false);
    }
  }

  async function resendVerificationCode() {
    if (!emailValid || busy || resendSeconds > 0) return;
    setBusy(true);
    setError("");
    try {
      const result = await resendEmailVerification(email.trim().toLowerCase());
      setNotice(result.message || "A new verification code has been sent.");
      setResendSeconds(60);
    } catch (verificationError) {
      setError(verificationError.message || "Unable to resend the verification code.");
    } finally {
      setBusy(false);
    }
  }

  if (pathname === "/verify-email") {
    return (
      <main className="account-gate">
        <form className="account-card" onSubmit={submitEmailVerification}>
          <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
          <p className="account-eyebrow">VERIFY YOUR EMAIL</p>
          <h1>Enter verification code</h1>
          <p className="account-copy">Enter the six-digit code sent to {email || "your email"}. It expires in five minutes.</p>
          {!emailValid && <label>Email<input name="verification-email" type="email" autoComplete="email" value={email} onChange={(event) => { setEmail(event.target.value); setError(""); }} required maxLength={254} /></label>}
          <label>One-time code<input className="verification-code-input" name="verification-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={verificationCode} onChange={(event) => { setVerificationCode(event.target.value.replace(/\D/g, "").slice(0, 6)); setError(""); }} required /></label>
          {error && <p className="account-error" role="alert">{error}</p>}
          {notice && <p className="account-success" role="status">{notice}</p>}
          <button className="account-primary-button" disabled={!emailValid || !/^\d{6}$/.test(verificationCode) || busy}>{busy ? <><LoaderCircle size={17} className="account-spin" /> Verifying…</> : <>Verify email <ArrowRight size={17} /></>}</button>
          <div className="account-verify-actions">
            <button type="button" className="account-link-button" disabled={busy || resendSeconds > 0 || !emailValid} onClick={resendVerificationCode}>{resendSeconds > 0 ? `Resend code in ${resendSeconds}s` : "Resend code"}</button>
            <button type="button" className="account-link-button" onClick={() => navigate("/login", { state: location.state })}><ArrowLeft size={15} /> Back to login</button>
          </div>
        </form>
      </main>
    );
  }

  if (pathname === "/forgot-password") {
    return (
      <main className="account-gate">
        <form className="account-card" onSubmit={sendResetCode}>
          <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
          <p className="account-eyebrow">ACCOUNT RECOVERY</p>
          <h1>Forgot password?</h1>
          <p className="account-copy">Enter your account email. If an active account matches, we’ll send a one-time reset code.</p>
          <label>Email<input name="email" type="email" autoComplete="email" value={email} onChange={(event) => { setEmail(event.target.value); setError(""); }} required maxLength={254} /></label>
          {error && <p className="account-error" role="alert">{error}</p>}
          {notice && <p className="account-success" role="status">{notice}</p>}
          <button className="account-primary-button" disabled={!emailValid || busy}>{busy ? <><LoaderCircle size={17} className="account-spin" /> Sending…</> : <>Send OTP <ArrowRight size={17} /></>}</button>
          <p className="account-switch"><button type="button" onClick={() => navigate("/login", { state: location.state })}>Back to Login</button></p>
        </form>
      </main>
    );
  }

  if (pathname === "/verify-reset-otp") {
    return (
      <main className="account-gate">
        <form className="account-card" onSubmit={verifyResetCode}>
          <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
          <p className="account-eyebrow">EMAIL VERIFICATION</p>
          <h1>Verify reset code</h1>
          <p className="account-copy">Enter the six-digit code sent to your email. It expires in five minutes.</p>
          <label>Email<input name="email" type="email" autoComplete="email" value={email} onChange={(event) => { setEmail(event.target.value); setError(""); }} required maxLength={254} /></label>
          <label>One-time code<input className="verification-code-input" name="reset-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={resetCode} onChange={(event) => { setResetCode(event.target.value.replace(/\D/g, "").slice(0, 6)); setError(""); }} aria-label="Six-digit password reset code" required /></label>
          {error && <p className="account-error" role="alert">{error}</p>}
          {notice && <p className="account-success" role="status">{notice}</p>}
          <button className="account-primary-button" disabled={!emailValid || !/^\d{6}$/.test(resetCode) || busy}>{busy ? <><LoaderCircle size={17} className="account-spin" /> Verifying…</> : <>Verify OTP <ArrowRight size={17} /></>}</button>
          <div className="account-verify-actions">
            <button type="button" className="account-link-button" disabled={busy || resendSeconds > 0 || !emailValid} onClick={sendResetCode}>{resendSeconds > 0 ? `Resend code in ${resendSeconds}s` : "Resend OTP"}</button>
            <button type="button" className="account-link-button" onClick={() => navigate("/forgot-password", { state: location.state })}><ArrowLeft size={15} /> Back</button>
          </div>
        </form>
      </main>
    );
  }

  if (pathname === "/reset-password") {
    return (
      <main className="account-gate">
        <form className="account-card" onSubmit={submitNewPassword}>
          <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
          <p className="account-eyebrow">SECURE YOUR ACCOUNT</p>
          <h1>{resetComplete ? "Password updated" : "Choose a new password"}</h1>
          <p className="account-copy">{resetComplete ? "Your password has been changed. Sign in using the new password." : "Create a strong password with at least eight characters, including uppercase, lowercase, and a number."}</p>
          {!resetComplete && <>
            <label>New password<span className="account-password-field"><input name="new-password" type={passwordVisible ? "text" : "password"} autoComplete="new-password" value={newPassword} onChange={(event) => { setNewPassword(event.target.value); setError(""); }} minLength={8} required /><button type="button" className="account-password-toggle" aria-label={passwordVisible ? "Hide password" : "Show password"} onClick={() => setPasswordVisible((visible) => !visible)}>{passwordVisible ? <EyeOff size={17} /> : <Eye size={17} />}</button></span></label>
            <label>Confirm password<input name="confirm-password" type={passwordVisible ? "text" : "password"} autoComplete="new-password" value={confirmPassword} onChange={(event) => { setConfirmPassword(event.target.value); setError(""); }} minLength={8} required /></label>
            {newPassword && confirmPassword && newPassword !== confirmPassword && <p className="account-error" role="alert">Passwords do not match.</p>}
          </>}
          {error && <p className="account-error" role="alert">{error}</p>}
          {notice && <p className="account-success" role="status">{notice}</p>}
          {!resetComplete && <button className="account-primary-button" disabled={busy || newPassword.length < 8 || !/[a-z]/.test(newPassword) || !/[A-Z]/.test(newPassword) || !/\d/.test(newPassword) || newPassword !== confirmPassword}>{busy ? <><LoaderCircle size={17} className="account-spin" /> Updating…</> : <>Reset password <ArrowRight size={17} /></>}</button>}
          {resetComplete && <button type="button" className="account-primary-button" onClick={() => navigate("/login", { replace: true, state: location.state })}>Return to Login <ArrowRight size={17} /></button>}
        </form>
      </main>
    );
  }

  return (
    <main className="account-gate">
      <form className="account-card" onSubmit={submit}>
        <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
        <p className="account-eyebrow">{registering ? "CREATE YOUR SECURE WORKSPACE" : "SECURE WORKSPACE ACCESS"}</p>
        <h1>{registering ? "Create your account" : "Welcome back"}</h1>
        <p className="account-copy">{registering
          ? "Set up your account to save your network analyses and alerts."
          : "Sign in to continue to your private network analysis workspace."}</p>
        {registering && <label>Name<span className="account-input-field"><UserRound size={17} aria-hidden="true" /><input name="name" autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} required maxLength="120" /></span></label>}
        <label>Email
          <span className="account-input-field">
            <Mail size={17} aria-hidden="true" />
            <input
              name="email"
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => { setEmail(event.target.value); setError(""); }}
              onBlur={() => setEmailTouched(true)}
              aria-invalid={emailTouched && !emailValid}
              aria-describedby="gmail-validation"
              required
            />
          </span>
          <span id="gmail-validation" className="account-field-error" aria-live="polite">
            {emailTouched && email.trim() && !emailValid
              ? "Enter a valid email address."
              : ""}
          </span>
        </label>
        <label>Password<span className="account-password-field account-input-field"><LockKeyhole size={17} aria-hidden="true" /><input name="password" type={passwordVisible ? "text" : "password"} autoComplete={registering ? "new-password" : "current-password"} value={password} onChange={(event) => { setPassword(event.target.value); setError(""); }} minLength={registering ? 6 : 1} required /><button type="button" className="account-password-toggle" aria-label={passwordVisible ? "Hide password" : "Show password"} onClick={() => setPasswordVisible((visible) => !visible)}>{passwordVisible ? <EyeOff size={17} /> : <Eye size={17} />}</button></span></label>
        {registering && <small className="account-password-help">At least 6 characters, including uppercase, lowercase, and a number.</small>}
        {!registering && <p className="account-forgot-link"><button type="button" className="account-link-button" onClick={() => { setError(""); setNotice(""); navigate("/forgot-password", { state: location.state }); }}>Forgot password?</button></p>}
        {error && <p className="account-error" role="alert">{error}</p>}
        {notice && <p className="account-success" role="status">{notice}</p>}
        <button className="account-primary-button" disabled={!canSubmit}>{busy ? <><LoaderCircle size={17} className="account-spin" /> Please wait…</> : <>{registering ? "Create account" : "Sign in"}<ArrowRight size={17} /></>}</button>
        {googleConfig.client_id && <><div className="google-divider"><span>OR</span></div>
        <div className={googleBusy ? "google-button-slot is-loading" : "google-button-slot"} aria-busy={googleBusy}>
          <div ref={googleButtonRef} className="google-button-target" />
          {googleBusy && <span className="google-loading-label" role="status">Verifying Google account…</span>}
        </div></>}
        {googleError && <p className="account-error" role="alert">{googleError}</p>}
        <p className="account-switch">{registering ? "Already have an account?" : "New to NetSentry?"}{" "}
          <button type="button" disabled={isBusy} onClick={() => { setError(""); setNotice(""); setGoogleError(""); setEmailTouched(false); setPassword(""); navigate(registering ? "/login" : "/register", { state: location.state }); }}>
            {registering ? "Sign in" : "Create an account"}
          </button>
        </p>
      </form>
    </main>
  );
}

function NotFoundPage({ authenticated }) {
  const navigate = useNavigate();

  return (
    <main className="not-found-page">
      <div>
        <p className="eyebrow">404 · PAGE NOT FOUND</p>
        <h1>This page doesn't exist</h1>
        <p>Check the address or return to your NetSentry workspace.</p>
        <button
          className="primary-button"
          type="button"
          onClick={() => navigate(authenticated ? "/dashboard" : "/login")}
        >
          {authenticated ? "Go to Dashboard" : "Go to Sign In"}
        </button>
      </div>
    </main>
  );
}

export default function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [startupComplete, setStartupComplete] = useState(false);

  useEffect(() => {
    getCurrentUser().then((result) => setUser(result.user)).catch(() => {}).finally(() => setAuthChecked(true));
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => setStartupComplete(true), 900);
    return () => window.clearTimeout(timer);
  }, []);

  const pathname = location.pathname.replace(/\/+$/, "") || "/";

  if (pathname !== "/" && (!authChecked || !startupComplete)) {
    return (
      <main className="startup-loading" role="status" aria-live="polite" aria-label="Loading NetSentry">
        <div className="startup-mark" aria-hidden="true">
          <span className="startup-mark-ring" />
          <Shield size={30} strokeWidth={1.7} />
        </div>
        <div className="startup-brand">
          <strong>NetSentry</strong>
          <span>NETWORK INTELLIGENCE</span>
        </div>
        <div className="startup-progress" aria-hidden="true">
          <span />
        </div>
        <p>{authChecked ? "Preparing your workspace…" : "Restoring your secure session…"}</p>
      </main>
    );
  }
  const recoveryRoute = recoveryPaths.includes(pathname);
  const knownRoute = pathname === "/"
    || recoveryRoute
    || protectedPaths.includes(pathname)
    || pathname === "/connect-website";

  if (!knownRoute) return <NotFoundPage authenticated={Boolean(user)} />;
  const protectedRoute = protectedPaths.includes(pathname) || pathname === "/connect-website";
  if (!user && protectedRoute) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  if (recoveryRoute) {
    if (user && (pathname === "/login" || pathname === "/register")) {
      return <Navigate to={getPostAuthPath(location.state)} replace />;
    }
    return <AccountGate onAuthenticated={setUser} onPasswordReset={() => setUser(null)} />;
  }

  return (
    <Routes>
      <Route path="/" element={<LandingPage authenticated={Boolean(user)} />} />
      {protectedPaths.filter((path) => path !== "/websites").map((path) => (
        <Route
          key={path}
          path={path}
          element={<Dashboard user={user} onSignOut={async () => {
            await signOut();
            setUser(null);
            navigate("/", { replace: true });
          }} />}
        />
      ))}
      <Route path="/websites" element={<Navigate to="/my-websites" replace />} />
      <Route path="/connect-website" element={<Navigate to="/website-integration" replace />} />
      <Route path="*" element={<NotFoundPage authenticated />} />
    </Routes>
  );
}
