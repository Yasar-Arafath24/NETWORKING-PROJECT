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

The Website Monitoring page lets each account register its authorized site,
create a private ingestion credential, and receive request events over an
authenticated WebSocket. Install a server-side collector on the monitored
site and POST JSON events to /api/v1/website-ingest/{site_id}/events with
Authorization: Bearer <site-ingest-key>. The site key is only shown when
created. The collector should send status code, path, method, duration, and
optional request metadata. Detection currently uses explainable demo
heuristics for 4xx/5xx responses and request bursts; these are not verified
attack classifications. NetSentry does not fetch a URL to obtain visitor
traffic.

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
yet include email verification, password reset, account deletion, or
per-user isolation for the existing process-wide packet-capture worker and
its saved alerts/flows; those legacy capture records are not tenant-isolated.

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
