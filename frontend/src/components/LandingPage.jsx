import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowDown,
  ArrowRight,
  BellRing,
  Check,
  ChevronRight,
  CircleDot,
  FileSearch,
  Globe2,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  ScanSearch,
  Shield,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from "lucide-react";
import "./LandingPage.css";

const features = [
  {
    icon: Activity,
    title: "Real-time network monitoring",
    description: "See network activity as it happens and keep an eye on the signals that matter to your team.",
  },
  {
    icon: ScanSearch,
    title: "AI-powered anomaly detection",
    description: "Surface unusual traffic patterns with intelligent analysis designed to help focus investigations.",
  },
  {
    icon: FileSearch,
    title: "PCAP file analysis",
    description: "Upload packet captures to inspect flows, protocols, and historical traffic from one workspace.",
  },
  {
    icon: Globe2,
    title: "Website traffic monitoring",
    description: "Connect your website collector and review real access-log events alongside your network activity.",
  },
  {
    icon: ShieldAlert,
    title: "Suspicious activity detection",
    description: "Bring suspicious requests and noteworthy findings into view so your team can respond with context.",
  },
  {
    icon: BellRing,
    title: "Actionable security alerts",
    description: "Keep alerts and investigation status together in a clear, account-specific security workspace.",
  },
  {
    icon: Layers3,
    title: "Analysis history",
    description: "Return to saved analysis and traffic history without losing the context of earlier investigations.",
  },
];

const steps = [
  { number: "01", title: "Connect your data", description: "Register an authorized website collector or bring in a packet capture." },
  { number: "02", title: "Understand activity", description: "Review traffic, flows, and AI-assisted signals in one focused workspace." },
  { number: "03", title: "Investigate with context", description: "Use alerts and saved analysis to follow findings through your workflow." },
];

const benefits = [
  {
    icon: Network,
    title: "See the full picture",
    description: "Bring network traffic and website activity together for clearer day-to-day visibility.",
  },
  {
    icon: ShieldCheck,
    title: "Focus investigations",
    description: "Use AI-assisted anomaly signals to prioritize unusual activity and investigate with context.",
  },
  {
    icon: FileSearch,
    title: "Work from evidence",
    description: "Move between live monitoring, PCAP analysis, alerts, and saved history in one workspace.",
  },
];

function BrandMark() {
  return (
    <span className="landing-brand-mark" aria-hidden="true">
      <ShieldCheck size={22} strokeWidth={2} />
      <span />
    </span>
  );
}

export default function LandingPage({ authenticated = false }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const closeMenu = () => setMenuOpen(false);

  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="landing-header-inner">
          <a className="landing-brand" href="#home" onClick={closeMenu} aria-label="NetSentry AI home">
            <BrandMark />
            <span>NetSentry <b>AI</b></span>
          </a>
          <button
            type="button"
            className="landing-menu-toggle"
            aria-label={menuOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((open) => !open)}
          >
            {menuOpen ? <X size={21} /> : <Menu size={21} />}
          </button>
          <nav className={`landing-nav ${menuOpen ? "is-open" : ""}`} aria-label="Main navigation">
            <a href="#home" onClick={closeMenu}>Home</a>
            <a href="#features" onClick={closeMenu}>Features</a>
            <a href="#how-it-works" onClick={closeMenu}>How It Works</a>
            <a href="#pricing" onClick={closeMenu}>Pricing</a>
            <a href="#about" onClick={closeMenu}>About</a>
            <a href="#contact" onClick={closeMenu}>Contact</a>
            <div className="landing-nav-actions">
              {authenticated ? (
                <Link className="landing-signin" to="/dashboard" onClick={closeMenu}>Open Dashboard</Link>
              ) : (
                <>
                  <Link className="landing-signin" to="/login" onClick={closeMenu}>Sign In</Link>
                  <Link className="landing-button landing-button-small" to="/register" onClick={closeMenu}>Get Started <ArrowRight size={15} /></Link>
                </>
              )}
            </div>
          </nav>
        </div>
      </header>

      <main>
        <section className="landing-hero" id="home">
          <div className="landing-hero-grid" aria-hidden="true" />
          <div className="landing-hero-inner">
            <div className="landing-hero-copy">
              <div className="landing-kicker"><span className="landing-kicker-pulse" /> NETWORK INTELLIGENCE, REIMAGINED</div>
              <h1>AI-Powered Network Security <span>&amp; Threat Detection</span></h1>
              <p>Monitor network traffic, analyze PCAP files, detect anomalies with AI, and secure your websites with a unified view of your digital infrastructure.</p>
              <div className="landing-hero-actions">
                <Link className="landing-button" to={authenticated ? "/dashboard" : "/register"}>
                  {authenticated ? "Open Dashboard" : "Get Started"} <ArrowRight size={17} />
                </Link>
                <a className="landing-button-secondary" href="#features">Explore Features <ArrowDown size={16} /></a>
              </div>
              <div className="landing-trust-line"><LockKeyhole size={14} /> Your security workspace. Your data. Your control.</div>
            </div>

            <div className="landing-visual" aria-label="Illustration of the NetSentry AI network security workspace">
              <div className="landing-visual-glow" />
              <div className="landing-orbit landing-orbit-one" />
              <div className="landing-orbit landing-orbit-two" />
              <div className="landing-visual-card">
                <div className="landing-visual-top">
                  <div className="landing-window-dots"><i /><i /><i /></div>
                  <span>NETSENTRY / SECURITY OVERVIEW</span>
                  <CircleDot size={14} />
                </div>
                <div className="landing-visual-title"><div><small>NETWORK INTELLIGENCE</small><strong>Security at a glance</strong></div><span className="landing-live"><i /> LIVE</span></div>
                <div className="landing-signal-panel">
                  <div className="landing-signal-heading"><span>Traffic activity</span><span>REAL-TIME SIGNALS</span></div>
                  <div className="landing-signal-chart" aria-hidden="true">
                    <div className="landing-chart-lines"><i /><i /><i /><i /></div>
                    <svg viewBox="0 0 540 150" preserveAspectRatio="none">
                      <defs><linearGradient id="landingChartFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#38e6a4" stopOpacity=".24" /><stop offset="1" stopColor="#38e6a4" stopOpacity="0" /></linearGradient></defs>
                      <path className="landing-chart-area" d="M0 112 C30 101 36 96 65 103 S100 119 128 93 S167 68 194 83 S230 106 256 73 S293 62 318 76 S354 93 380 53 S417 59 443 44 S480 65 505 30 S529 43 540 19 V150 H0Z" />
                      <path className="landing-chart-line" d="M0 112 C30 101 36 96 65 103 S100 119 128 93 S167 68 194 83 S230 106 256 73 S293 62 318 76 S354 93 380 53 S417 59 443 44 S480 65 505 30 S529 43 540 19" />
                    </svg>
                  </div>
                  <div className="landing-chart-time"><span>09:00</span><span>10:00</span><span>11:00</span><span>12:00</span><span>NOW</span></div>
                </div>
                <div className="landing-signal-cards">
                  <div><span><Network size={15} /> TRAFFIC</span><i className="landing-sparkline" /><small>Live visibility</small></div>
                  <div><span><ShieldAlert size={15} /> DETECTION</span><div className="landing-signal-status"><b /> AI analysis</div><small>Surface unusual patterns</small></div>
                  <div><span><BellRing size={15} /> ALERTS</span><div className="landing-alert-bars"><i /><i /><i /><i /><i /><i /><i /></div><small>Signals in context</small></div>
                </div>
                <div className="landing-visual-footer"><span><Shield size={14} /> NETSENTRY AI PROTECTION</span><span>MONITOR <ChevronRight size={13} /></span></div>
              </div>
              <div className="landing-float-badge"><Zap size={16} /><span><b>AI-powered insights</b><small>Built for your workflow</small></span></div>
            </div>
          </div>
          <a className="landing-scroll-cue" href="#features">SCROLL TO EXPLORE <ArrowDown size={13} /></a>
        </section>

        <section className="landing-section landing-features" id="features">
          <div className="landing-section-heading">
            <span className="landing-section-label">ONE CLEAR VIEW OF YOUR SECURITY</span>
            <h2>Visibility that helps you <span>stay ahead.</span></h2>
            <p>Bring monitoring, analysis, and investigation into one purposeful workspace.</p>
          </div>
          <div className="landing-feature-grid">
            {features.map(({ icon: Icon, title, description }, index) => (
              <article className="landing-feature-card" key={title} style={{ "--feature-index": index }}>
                <span className="landing-feature-icon"><Icon size={20} strokeWidth={1.8} /></span>
                <h3>{title}</h3>
                <p>{description}</p>
                <span className="landing-feature-arrow" aria-hidden="true"><ArrowRight size={16} /></span>
              </article>
            ))}
          </div>
        </section>

        <section className="landing-process" id="how-it-works">
          <div className="landing-process-inner">
            <div className="landing-process-intro">
              <span className="landing-section-label">A SIMPLER SECURITY WORKFLOW</span>
              <h2>From raw traffic to <span>clearer decisions.</span></h2>
              <p>NetSentry AI brings important signals together so your team can spend less time switching tools and more time understanding activity.</p>
              <Link className="landing-text-link" to={authenticated ? "/dashboard" : "/register"}>Explore your workspace <ArrowRight size={16} /></Link>
            </div>
            <div className="landing-steps">
              {steps.map((step) => (
                <article className="landing-step" key={step.number}>
                  <span>{step.number}</span>
                  <div><h3>{step.title}</h3><p>{step.description}</p></div>
                  <Check size={17} />
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="landing-section landing-benefits" id="benefits">
          <div className="landing-section-heading">
            <span className="landing-section-label">BUILT FOR PRACTICAL SECURITY WORK</span>
            <h2>Turn more signals into <span>useful context.</span></h2>
            <p>Support the people and teams responsible for keeping connected systems visible and protected.</p>
          </div>
          <div className="landing-feature-grid">
            {benefits.map(({ icon: Icon, title, description }, index) => (
              <article className="landing-feature-card" key={title} style={{ "--feature-index": index }}>
                <span className="landing-feature-icon"><Icon size={20} strokeWidth={1.8} /></span>
                <h3>{title}</h3>
                <p>{description}</p>
                <span className="landing-feature-arrow" aria-hidden="true"><ArrowRight size={16} /></span>
              </article>
            ))}
          </div>
        </section>

        <section className="landing-pricing" id="pricing">
          <div className="landing-section-heading">
            <span className="landing-section-label">PRICING</span>
            <h2>Security that scales <span>with you.</span></h2>
            <p>Start exploring NetSentry AI, then choose the setup that fits your team.</p>
          </div>
          <div className="landing-pricing-grid">
            <article className="landing-price-card">
              <span className="landing-plan-label">GET STARTED</span><h3>Starter</h3>
              <p>For individuals exploring network visibility.</p>
              <ul><li><Check size={15} /> Network analysis workspace</li><li><Check size={15} /> PCAP analysis tools</li><li><Check size={15} /> Saved analysis history</li></ul>
              <Link className="landing-price-link" to="/register">Create an account <ArrowRight size={15} /></Link>
            </article>
            <article className="landing-price-card landing-price-featured">
              <span className="landing-plan-label">FOR GROWING TEAMS</span><h3>Professional</h3>
              <p>For teams monitoring websites and investigating activity.</p>
              <ul><li><Check size={15} /> Website collector integration</li><li><Check size={15} /> Traffic and alert monitoring</li><li><Check size={15} /> AI-assisted detection</li></ul>
              <a className="landing-price-link" href="#contact">Talk to our team <ArrowRight size={15} /></a>
            </article>
            <article className="landing-price-card">
              <span className="landing-plan-label">TAILORED SECURITY</span><h3>Enterprise</h3>
              <p>For organizations with specialized deployment needs.</p>
              <ul><li><Check size={15} /> Deployment planning</li><li><Check size={15} /> Team-focused workflows</li><li><Check size={15} /> Dedicated conversation</li></ul>
              <a className="landing-price-link" href="#contact">Contact us <ArrowRight size={15} /></a>
            </article>
          </div>
          <p className="landing-pricing-note">Plan availability and deployment options can be discussed with our team.</p>
        </section>

        <section className="landing-about" id="about">
          <div className="landing-about-mark"><BrandMark /></div>
          <div><span className="landing-section-label">ABOUT NETSENTRY AI</span><h2>Clarity for a more <span>confident network.</span></h2><p>NetSentry AI is built to make network security signals easier to see and investigate. We bring traffic visibility, packet analysis, website telemetry, and AI-assisted detection together without losing sight of the data behind each finding.</p></div>
          <div className="landing-about-aside"><ShieldCheck size={24} /><span>BUILT FOR VISIBILITY</span><small>Designed to support your security workflow.</small></div>
        </section>

        <section className="landing-contact" id="contact">
          <div><span className="landing-section-label">LET'S TALK SECURITY</span><h2>Ready to see your network more clearly?</h2><p>Start with a workspace or get in touch to discuss your team's needs.</p></div>
          <div className="landing-contact-actions">
            <Link className="landing-button" to={authenticated ? "/dashboard" : "/register"}>{authenticated ? "Open Dashboard" : "Get Started"} <ArrowRight size={16} /></Link>
            <a className="landing-contact-link" href="mailto:contact@netsentry.ai">Contact Us <ArrowRight size={15} /></a>
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        <div className="landing-footer-main">
          <a className="landing-brand" href="#home"><BrandMark /><span>NetSentry <b>AI</b></span></a>
          <p>Intelligent network security for a clearer view of your digital infrastructure.</p>
          <div className="landing-footer-links"><a href="#features">Features</a><a href="#how-it-works">How It Works</a><a href="#pricing">Pricing</a><a href="#about">About</a><a href="#contact">Contact</a></div>
          <div className="landing-footer-auth">{authenticated ? <Link to="/dashboard">Dashboard</Link> : <><Link to="/login">Sign In</Link><Link to="/register">Get Started</Link></>}</div>
        </div>
        <div className="landing-footer-bottom"><span>© {new Date().getFullYear()} NetSentry AI. All rights reserved.</span><span><Shield size={13} /> Built for clearer network visibility.</span></div>
      </footer>
    </div>
  );
}
