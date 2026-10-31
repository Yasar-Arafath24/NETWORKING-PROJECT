import { useEffect, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, Eye, EyeOff, LoaderCircle, Mail, Shield } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import { authenticate, authenticateWithGoogle, getCurrentUser, getGoogleSignInConfig, requestPasswordReset, resendSignupCode, resetAccountPassword, signOut, verifyPasswordResetOtp, verifySignupEmail } from "./services/api";

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
  const [resetCode, setResetCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [resendSeconds, setResendSeconds] = useState(0);
  const [resetComplete, setResetComplete] = useState(false);
  const emailValid = isValidEmail(email);
  const isBusy = busy || googleBusy;
  const passwordValid = !registering || (
    password.length >= 6 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password)
  );
  const canSubmit = !isBusy && emailValid && (verificationPending
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
              if (active) {
                onAuthenticated(result.user);
                navigate("/dashboard", { replace: true });
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
  }, [googleConfig.client_id, navigate, onAuthenticated]);

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
      navigate("/verify-reset-otp");
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
      navigate("/reset-password");
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
    try {
      if (verificationPending) {
        const result = await verifySignupEmail(email.trim().toLowerCase(), verificationCode);
        onAuthenticated(result.user);
        navigate("/dashboard", { replace: true });
      } else {
        const payload = { email: email.trim().toLowerCase(), password };
        if (registering) payload.name = name.trim();
        const result = await authenticate(registering ? "register" : "login", payload);
        if (registering) {
          setVerificationPending(true);
          setVerificationCode("");
          setResendSeconds(60);
          setPassword("");
          setNotice(result.message || "Verification code sent. Enter it to continue.");
        } else {
          onAuthenticated(result.user);
          navigate("/dashboard", { replace: true });
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
      setResendSeconds(60);
      setNotice(result.message || "If an unverified account exists, a new code has been sent.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (location.pathname === "/forgot-password") {
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
          <p className="account-switch"><button type="button" onClick={() => navigate("/login")}>Back to Login</button></p>
        </form>
      </main>
    );
  }

  if (location.pathname === "/verify-reset-otp") {
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
            <button type="button" className="account-link-button" onClick={() => navigate("/forgot-password")}><ArrowLeft size={15} /> Back</button>
          </div>
        </form>
      </main>
    );
  }

  if (location.pathname === "/reset-password") {
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
          {resetComplete && <button type="button" className="account-primary-button" onClick={() => navigate("/login", { replace: true })}>Return to Login <ArrowRight size={17} /></button>}
        </form>
      </main>
    );
  }

  return (
    <main className="account-gate">
      <form className="account-card" onSubmit={submit}>
        <div className="account-brand"><div className="account-mark"><Shield size={22} /></div><div><strong>NetSentry AI</strong><span>Network intelligence workspace</span></div></div>
        <p className="account-eyebrow">{verificationPending ? "EMAIL CONFIRMATION" : "SECURE WORKSPACE ACCESS"}</p>
        <h1>{verificationPending ? "Verify your email" : registering ? "Create your account" : "Welcome back"}</h1>
        <p className="account-copy">{verificationPending
          ? `Enter the six-digit code sent to ${email}. It expires in five minutes.`
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
            aria-invalid={emailTouched && !emailValid}
            aria-describedby="gmail-validation"
            required
          />
          <span id="gmail-validation" className="account-field-error" aria-live="polite">
            {emailTouched && email.trim() && !emailValid
              ? "Enter a valid email address."
              : ""}
          </span>
        </label>}
        {verificationPending && <label>Verification code<input className="verification-code-input" name="verification-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={verificationCode} onChange={(event) => { setVerificationCode(event.target.value.replace(/\D/g, "").slice(0, 6)); setError(""); }} placeholder="000000" aria-label="Six-digit email verification code" required /></label>}
        {!verificationPending && <label>Password<input name="password" type="password" autoComplete={registering ? "new-password" : "current-password"} value={password} onChange={(event) => { setPassword(event.target.value); setError(""); }} minLength={registering ? 6 : 1} required /></label>}
        {!verificationPending && !registering && <p className="account-switch account-forgot-link"><button type="button" onClick={() => { setError(""); setNotice(""); navigate("/forgot-password"); }}>Forgot Password?</button></p>}
        {!verificationPending && registering && <small className="account-password-help">At least 6 characters, including uppercase, lowercase, and a number.</small>}
        {error && <p className="account-error" role="alert">{error}</p>}
        {notice && <p className="account-success" role="status">{notice}</p>}
        <button className="account-primary-button" disabled={!canSubmit}>{busy ? <><LoaderCircle size={17} className="account-spin" /> {verificationPending ? "Verifying code…" : "Please wait…"}</> : <>{verificationPending ? "Verify email and continue" : registering ? "Create account" : "Sign in"}<ArrowRight size={17} /></>}</button>
        {verificationPending && <div className="account-verify-actions"><button type="button" className="account-link-button" disabled={isBusy || resendSeconds > 0} onClick={resendCode}><Mail size={15} /> {resendSeconds > 0 ? `Resend code in ${resendSeconds}s` : "Resend code"}</button><button type="button" className="account-link-button" disabled={isBusy} onClick={() => { setVerificationPending(false); setVerificationCode(""); setError(""); setNotice(""); }}><ArrowLeft size={15} /> Back to signup</button></div>}
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
  const navigate = useNavigate();
  const location = useLocation();
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  useEffect(() => {
    getCurrentUser().then((result) => setUser(result.user)).catch(() => {}).finally(() => setAuthChecked(true));
  }, []);

  useEffect(() => {
    if (location.pathname === "/") navigate("/login", { replace: true });
  }, [location.pathname, navigate]);

  if (!authChecked) return <div className="account-loading"><LoaderCircle size={20} className="account-spin" /> Restoring your secure session…</div>;
  const recoveryRoute = ["/login", "/forgot-password", "/verify-reset-otp", "/reset-password"].includes(location.pathname);
  if (!user || recoveryRoute) return <AccountGate onAuthenticated={setUser} onPasswordReset={() => setUser(null)} />;
  return (
    <>
      <Dashboard user={user} onSignOut={async () => { await signOut(); setUser(null); }} />
    </>
  );
}
