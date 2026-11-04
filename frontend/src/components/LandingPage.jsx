import { ArrowRight, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import "./LandingPage.css";

export default function LandingPage({ authenticated = false }) {
  return (
    <main className="landing-page">
      <section className="landing-hero" aria-label="NetSentry AI">
        <div className="landing-light" aria-hidden="true" />
        <div className="landing-content">
          <div className="landing-mark" aria-hidden="true">
            <ShieldCheck />
          </div>
          <div className="landing-wordmark" aria-label="NetSentry AI">
            <span className="landing-wordmark-main">NetSentry</span>
            <span className="landing-wordmark-ai">AI</span>
          </div>
          <Link
            className="landing-get-started"
            to="/login"
          >
            Get Started
            <ArrowRight size={18} strokeWidth={1.8} />
          </Link>
        </div>
      </section>
      <footer className="landing-footer" aria-label="NetSentry credits">
        <div className="landing-footer-row">
          <span>NetSentry AI · Network traffic analysis</span>
          <span>Built for clearer network visibility</span>
        </div>
        <div className="landing-footer-row landing-footer-bottom">
          <span>© 2026 NetSentry AI</span>
          <span className="landing-developer-credits">
            Developed by
            <a href="https://github.com/Yasar-Arafath24" target="_blank" rel="noreferrer">Yasar Arafath</a>
            <i aria-hidden="true">·</i>
            <a href="https://github.com/mohamedthoufik003" target="_blank" rel="noreferrer">Moohamed Thavubik</a>
            <i aria-hidden="true">·</i>
            <a href="https://github.com/Techie-Imran" target="_blank" rel="noreferrer">Mohamed Imran</a>
          </span>
        </div>
      </footer>
    </main>
  );
}
