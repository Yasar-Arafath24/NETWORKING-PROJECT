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
