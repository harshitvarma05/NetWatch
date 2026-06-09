# NetWatch

NetWatch is a hybrid real-time intrusion detection system. It combines live packet-flow collection, trained ML models, explainable predictions, a professional dashboard, and an adaptive response simulator.

## What It Does

- Classifies traffic as:
  - Normal Traffic
  - DoS Attack
  - Probe / Scanning Attack
  - R2L Attack
  - U2R Attack
  - Botnet / Suspicious Traffic
- Captures live traffic with a C++ `libpcap` collector.
- Shows a rolling live packet feed with timestamp, source, destination, protocol, service, length, and flag.
- Aggregates packets into ML-ready flow windows for classification.
- Falls back to filtered Python/OS connection context if packet capture is blocked or temporarily idle.
- Uses a trained hybrid Random Forest model for Normal, DoS, Probe, and Botnet traffic.
- Uses imported NSL-KDD assets and specialist logic for R2L/U2R-style coverage.
- Explains each prediction with top contributing features.
- Simulates adaptive defenses:
  - block source IP
  - rate-limit traffic
  - raise alert
  - add to suspicious IP list
- Supports CSV batch prediction from the dashboard.
- Includes demo-mode buttons for known Normal, DoS, Probe, Botnet, and R2L cases.
- Persists prediction history, settings, and defense actions in SQLite.
- Provides local passcode authentication.
- Exports JSON reports plus prediction/defense CSV files.
- Includes reset, settings, system-info, and automated test workflows.


## Current Model Stack

The active backend uses an ensemble:

```text
Hybrid Flow Random Forest + NSL-KDD Specialist Layer
```

The hybrid model was trained from the included CICIDS2017 Friday dataset copy:

```text
CICIDS2017_friday.csv
```

Training summary:

```text
Rows used: 260,000
Accuracy: 99.90%
Classes: botnet, dos, normal, probe
Botnet rows used: 4,803
```

The imported NSL-KDD model assets are stored under:

```text
models/nsl_kdd/
```

The hybrid botnet-capable model assets are stored under:

```text
models/hybrid_flow/
```

## Run

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Or install the exact versions used during development:

```bash
python3 -m pip install -r requirements-lock.txt
```

Start the app:

```bash
./run.sh
```

Open:

```text
http://127.0.0.1:8010
```

Default passcode:

```text
netwatch
```

Use a custom passcode:

```bash
IDS_PASSCODE=your-passcode ./run.sh
```

Use another port:

```bash
PORT=8011 ./run.sh
```

Disable auth for automated/local testing:

```bash
IDS_AUTH_DISABLED=1 ./run.sh
```

## Dashboard Features

- Live monitoring panel
- Wireshark-style packet feed backed by the C++ collector
- Demo Mode with known traffic cases
- Model Status with training rows, classes, accuracy, and label counts
- CSV batch prediction
- Runtime Settings
- System Info
- Alert queue
- Investigation panel with confidence, explanation, and class probabilities
- Adaptive response controls
- JSON and CSV exports
- Runtime reset for clean demos

## Demo And Tests

Run repeatable API demo cases:

```bash
python3 demo_cases.py
```

Run demo cases and apply simulated defenses:

```bash
python3 demo_cases.py --apply-defense
```

Run automated tests:

```bash
./run_tests.sh
```

Current tests cover:

- demo-case routing
- credential-abuse R2L specialist logic
- CSV batch prediction
- settings bounds
- exports
- local auth behavior

## How It Works

1. Traffic enters from live capture, OS fallback, dashboard demo cases, or uploaded CSV.
2. Live packet capture stores recent packet rows for inspection while aggregating the same traffic into flow windows.
3. Flow features are normalized into the project schema:
   - source bytes
   - destination bytes
   - packet count
   - duration
   - protocol
   - service
   - flag
   - failed login count
   - connection rate
   - same-host rate
   - error rate
4. The ensemble model predicts the class.
5. The explainability module returns the top contributing features.
6. The dashboard shows packet rows, prediction, confidence, probabilities, and recommended response.
7. The adaptive response simulator updates blocked, rate-limited, suspicious, or alert lists.
8. Results are persisted in SQLite and can be exported.

## Live Collector

The C++ collector is located at:

```text
collector/live_collector.cpp
```

It captures TCP/UDP IPv4 packets with `libpcap`, keeps bounded packet rows for dashboard inspection, aggregates the same packets into flows, and streams JSON windows to the Python backend.

The Python app builds the collector automatically when possible. Manual build:

```bash
c++ -std=c++17 -O2 -Wall -Wextra collector/live_collector.cpp -lpcap -o collector/live_collector
```

Manual streaming run:

```bash
sudo ./collector/live_collector --stream --duration 1
```

Optional capture settings:

```bash
IDS_CAPTURE_DEVICE=en0 IDS_CAPTURE_SECONDS=2 PORT=8010 python3 app.py
```

## Project Structure

```text
app.py                         Python backend, API, ensemble routing, persistence, auth
collector/live_collector.cpp   C++ packet capture and flow aggregation
hybrid_flow_model.py           Runtime loader for hybrid flow model
nsl_kdd_adapter.py             NSL-KDD model adapter
demo_cases.py                  Repeatable API demo script
run.sh                         One-command startup
run_tests.sh                   Test runner
requirements.txt               Flexible dependency list
requirements-lock.txt          Exact dependency versions used locally
CICIDS2017_friday.csv          Dataset copy used for hybrid training
models/hybrid_flow/            Hybrid model trainer and trained artifacts
models/nsl_kdd/                Imported NSL-KDD assets and trainer
static/index.html              Dashboard layout
static/styles.css              Dashboard styling
static/app.js                  Dashboard behavior/API calls
tests/test_core.py             Automated backend tests
```

## API Endpoints

Authentication/session:

- `GET /api/session`
- `POST /api/login`

Monitoring and prediction:

- `GET /api/dashboard`
- `GET /api/live`
- `GET /api/sample`
- `GET /api/packets`
- `POST /api/predict`
- `POST /api/batch`
- `POST /api/csv`

Demo and defense:

- `GET /api/demo-cases`
- `POST /api/demo-case`
- `POST /api/defense`
- `GET /api/blocked`

Settings, system info, reset, exports:

- `GET /api/health`
- `GET /api/settings`
- `POST /api/settings`
- `GET /api/about`
- `POST /api/reset`
- `GET /api/export`
- `GET /api/export-predictions.csv`
- `GET /api/export-defense.csv`

## Notes And Limitations

- This is an IDS simulator, not a kernel-level firewall.
- Defense actions are simulated inside the app state; they do not modify OS firewall rules.
- Raw packet capture may require elevated permission depending on OS/network settings.
- CICIDS2017 supports the hybrid model classes well for Normal, DoS, Probe, and Botnet.
- R2L/U2R coverage is handled through NSL-KDD and specialist logic because CICIDS2017 Friday does not provide strong R2L/U2R examples.
