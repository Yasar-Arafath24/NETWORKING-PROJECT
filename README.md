# NetSentry AI

Privacy-Preserving Intelligent Network Traffic Classification & Adaptive Threat Defense.

## Requirements

- Python 3.12+ (tested on 3.14)
- Windows, Linux, or macOS

## Setup (every developer, once)

> **Never commit the `venv/` folder.** A virtual environment stores absolute
> paths to the machine that created it, so a committed `venv` breaks with
> `No Python at ...` on every other computer. It is already listed in
> `.gitignore` — recreate it locally instead of sharing it.

```powershell
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# macOS / Linux
# source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the API

```powershell
python -m uvicorn backend.app.main:app --reload
```

Then open the interactive docs at <http://127.0.0.1:8000/docs>.

## Accounts and private analysis history

The frontend supports account registration and sign-in. Password signup sends a
six-digit email verification code; verifying the code completes account creation
and signs the user in. Codes expire after 10 minutes and are limited to five
attempts. Configure `NETSENTRY_OTP_SECRET` (at least 32 random characters) and
the `NETSENTRY_SMTP_*` settings from `.env.example` to deliver verification
messages. For local testing only, `NETSENTRY_ENV=development` and
`NETSENTRY_EMAIL_DELIVERY=console` writes the real code to the backend console.
Console mode is only suitable for local testing; signup will attempt SMTP by
default and will report missing SMTP configuration rather than claiming an email
was sent. Keep SMTP delivery enabled for actual email. For Gmail SMTP, use an app password. Passwords must be at least six
characters and include uppercase, lowercase, and numeric characters. Accounts
and server-side sessions are stored in the configured SQLAlchemy database;
passwords are stored as salted scrypt hashes. The frontend restores a valid
HTTP-only session cookie automatically when it opens. New analysis reports are associated with the signed-in
user, and history/detail/latest-report endpoints only return that user's
reports. Existing reports from before this change remain unassigned and are
hidden from account dashboards.

Sign in with Google uses Google Identity Services. The backend verifies each
Google ID token with Google's `google-auth` library, checks its audience,
signature, issuer, expiry, signed nonce, verified email, and Gmail-only policy,
then issues the same NetSentry session cookie used by password sign-in.
Verified Google identities are linked by Google's stable subject ID; a password
account is linked only after Google cryptographically verifies control of its
matching Gmail address. No Google client secret or ID token is stored.

To configure Google sign-in, create an OAuth client of type **Web application**
in Google Cloud Console. Add `http://localhost:5173` and
`http://127.0.0.1:5173` as authorized JavaScript origins for local development,
plus your deployed frontend origin. The popup/ID-token flow does not use a
redirect URI. Copy the Web client ID into `GOOGLE_CLIENT_ID` in the backend
environment; `.env.example` shows the local configuration keys. No client
secret is required. Run the backend with `--env-file .env` locally, and set the
same variable in the production backend's secret/environment settings.

The Website Monitoring page lets each account register its authorized site,
create a private ingestion credential, and receive request events over an
authenticated WebSocket. Install a server-side collector on the monitored
site and POST JSON events to /api/v1/website-ingest/{site_id}/events with
Authorization: Bearer <site-ingest-key>. The site key is only shown when
created. The collector should send status code, path, method, duration, and
optional request metadata including the original request timestamp. A separate
deterministic website-event rule engine evaluates sensitive paths, multi-path
scanning, repeated failed login requests, source/site/endpoint request rates,
rate surges, repeated HTTP error patterns, repeated slow requests, unusual HTTP
methods, and configured scanner user-agent signatures. One ordinary HTTP error
does not create an alert. Rules attach category, evidence, classification, and
a 0–100 risk score to the received event. Scores map to LOW (0–24), MEDIUM
(25–49), HIGH (50–74), and CRITICAL (75–100). Evidence weights are added once
per category and capped at 100; defaults and thresholds can be configured in
`.env.example`. A flagged request is a heuristic finding, not proof of an
attack. NetSentry does not fetch a URL to obtain visitor traffic.

Repeated findings are grouped into website incidents. Authenticated endpoints
include `GET /api/v1/websites/{site_id}/alerts`, `GET
/api/v1/websites/{site_id}/alerts/{alert_id}`, `PATCH
/api/v1/websites/{site_id}/alerts/{alert_id}` (status values `OPEN`,
`INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`), and `GET
/api/v1/websites/analytics?site_id={site_id}`. Website ownership is checked for
all these operations. Event records retain detector metadata in the existing
JSON event payload; startup creates the new incident and status-history tables
without requiring changes to existing event rows.

The existing ML model consumes twelve numeric network-flow fields (packet and
byte counts, direction totals, and duration). Those inputs do not match website
request events, so the website detector deliberately does not call that model.
Website API responses report `ml_status=unavailable_incompatible_features`;
all current website findings are marked HEURISTIC. No website ML score is
claimed. A separately trained and validated website-event model would be
required before adding that classification.

NetSentry persists users, email verification, sessions, PCAP analysis reports,
network flow records, alerts, monitored websites, website traffic events, and
website alert changes through the backend database connection. Supabase
deployments must configure one backend database URL (`NETSENTRY_DATABASE_URL`,
`SUPABASE_DATABASE_URL`, or `SUPABASE_DB_URL`) and apply the SQL migrations in
`supabase/migrations/` before starting the API. The backend never falls back to
ephemeral in-memory storage for deployed reports.

For an Nginx JSON-lines access log, configure a format with fields such as
path, method, status_code, duration_ms, response_bytes, source_ip, and
user_agent. Then run scripts/netsentry_json_log_agent.py on that authorized
server with NETSENTRY_ACCESS_LOG, NETSENTRY_INGEST_URL, and
NETSENTRY_INGEST_KEY set in its environment. The agent tails new log lines and
forwards selected metadata; keep the ingestion key in a server-side secret
store and use HTTPS between the agent and NetSentry.

For local development, the default SQLite database and frontend origins are
configured automatically. For deployment, set NETSENTRY_DATABASE_URL,
NETSENTRY_CORS_ORIGINS to the exact frontend origins, and
NETSENTRY_COOKIE_SECURE=true behind HTTPS. For separate frontend/API origins, set
NETSENTRY_COOKIE_SAMESITE=none (HTTPS and NETSENTRY_COOKIE_SECURE=true are required
for browser SameSite=None cookies). Password reset and account deletion are not
implemented yet. Authorized
website records and telemetry are isolated by account. The existing
process-wide capture worker permits only its owner to view that live session;
persisted live flow records and alerts are owner-scoped. Legacy records without
an owner are hidden.

For Traffic Monitoring PCAP replay, use a path relative to the `datasets/`
folder, such as `samples/netsentry_sample.pcap`; paths prefixed with
`datasets/` are also accepted. On Windows, live interface capture requires
Npcap and appropriate capture permissions. PCAP replay does not require Npcap.

Existing Supabase databases should apply migrations `002_website_request_timestamp.sql`,
`003_google_auth.sql`, `004_live_monitor_ownership.sql`, and
`005_email_verification.sql`, `006_website_platform.sql`, and
`007_website_security_alerts.sql`, and `008_website_collector_revocation.sql` if they have not been applied already. Local
SQLite startup applies the additive columns and creates new tables automatically.

The **Website Integrations** page reuses website registration, token rotation,
event history, and alert APIs. `GET /api/v1/websites` returns per-owner event
counts, anomaly counts, last successful event time, and an activity status.
Status is based on actual ingestion timestamps (`WAITING_FOR_EVENTS` before the
first event, `RECEIVING` for very recent ingestion, `CONNECTED` while within
`NETSENTRY_WEBSITE_CONNECTED_SECONDS`, `IDLE` after that window, `DISCONNECTED`
when intake is paused, or `REVOKED` after the collector credential is revoked).
The status and Test Connection endpoints query accepted database events; they
do not synthesize heartbeats. A collector process is not directly observable
until it sends a valid event. New registrations can select a
platform; this is stored on the existing website record. Duplicate normalized
website URLs for one owner return HTTP 409. Registration and token rotation
share a per-user limit of five token-generating operations per minute. The
one-time raw token remains available only in the successful registration or
rotation response.

`frontend/.env.example` separates the dashboard API proxy from the collector's
reachable backend URL. For local development, collectors on the same computer
send to `http://127.0.0.1:8000`; `http://localhost:5173` is the frontend only.
Set `VITE_COLLECTOR_API_URL` to the public HTTPS backend origin for remote
collector hosts.

## Traffic monitoring pages

The workspace keeps three traffic views separate:

- **Traffic Monitoring** reads owner-scoped saved PCAP analysis reports through
  `GET /api/v1/monitoring/traffic-analytics`. It shows historical flow
  statistics, protocol/IP/port breakdowns, report-time trends, and a searchable
  paginated flow table. It does not start a capture.
- **Real-Time Monitoring** owns Scapy interface capture and local PCAP replay.
  Status, packet metadata, counters, rates, and detection summaries come from
  the live-monitoring APIs. On Windows, live interface capture requires Npcap
  and appropriate interface permissions; replay does not.
- **Website Traffic** shows authorized website access-log telemetry delivered
  by the configured collector. Adding a website URL alone does not grant access
  to its visitor traffic or create telemetry.

Historical charts use saved analysis timestamps because the existing PCAP
reports retain flow summaries, not per-packet timestamps. The analytics API
limits its summary window to the latest 250 reports, and existing report data
may retain only a bounded subset of flow rows.

The setup wizard uses `scripts/generic_traffic_collector.py`, which accepts
`jsonl`, `apache`, `nginx`, and `iis` formats. IIS parsing follows its `#Fields:`
header. Keep `NETSENTRY_INGEST_TOKEN` on the collector server, copy the collector
script there, use an API origin reachable from that server, then generate a new
request on the website after starting the collector to verify real ingestion.

Run the frontend and backend from the repository root in separate PowerShell
terminals:

```powershell
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --reload --port 8000 --env-file .env
```

```powershell
npm run dev
```

## ML pipeline (run from the repository root)

```powershell
python ml/build_dataset.py     # datasets/raw/*.pcapng  -> flow_features.csv
python ml/prepare_dataset.py   # flow_features.csv     -> ml_ready_flows.csv
python ml/train_model.py       # ml_ready_flows.csv    -> models/traffic_classifier.joblib (+ label encoder)
```

## Smoke checks

```powershell
python network/test_pcap.py
python network/test_flow_engine.py
```

## Project layout

| Path        | Purpose                                             |
| ----------- | --------------------------------------------------- |
| `backend/`  | FastAPI service and prediction/inference services   |
| `network/`  | Scapy flow engine and feature extraction            |
| `ml/`       | Dataset building, preparation, and model training    |
| `datasets/` | Sample PCAP captures and generated feature files     |
| `docs/`     | Project documentation                               |

## Generated files (do not commit)

`venv/`, `__pycache__/`, `*.joblib`, `models/`, and `datasets/processed/*`
are build artifacts. They are ignored by `.gitignore` and must not be tracked.
