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

The frontend supports account registration and sign-in. Accounts and server-side
sessions are stored in the configured SQLAlchemy database; passwords are stored
as salted scrypt hashes. New analysis reports are associated with the signed-in
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
optional request metadata including the original request timestamp. Current
heuristics flag unusually high request volume as a provisional signal. 4xx/5xx
HTTP responses are displayed as status codes and are not treated as attacks.
NetSentry does not fetch a URL to obtain visitor traffic.

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
for browser SameSite=None cookies). The current account flow does not
yet include email verification, password reset, or account deletion. Authorized
website records and telemetry are isolated by account. The existing
process-wide capture worker permits only its owner to view that live session;
persisted live flow records and alerts are owner-scoped. Legacy records without
an owner are hidden.

For Traffic Monitoring PCAP replay, use a path relative to the `datasets/`
folder, such as `samples/netsentry_sample.pcap`; paths prefixed with
`datasets/` are also accepted. On Windows, live interface capture requires
Npcap and appropriate capture permissions. PCAP replay does not require Npcap.

Existing Supabase databases should apply migrations `002_website_request_timestamp.sql`,
`003_google_auth.sql`, and `004_live_monitor_ownership.sql` if they have not been
applied already. Local SQLite startup applies the additive columns automatically.

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
