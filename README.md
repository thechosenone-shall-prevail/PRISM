# PRISM — APT Attribution Engine

PRISM is a threat attribution platform that traces malware samples and attack data back to known APT groups. It combines static analysis, MITRE ATT&CK mapping, sandbox behavioral analysis, and an XGBoost ML classifier to produce explainable attribution results with confidence scoring.

**Live instance**: [http://57.159.31.206/dashboard.html](http://57.159.31.206/dashboard.html)

---

## What it does

- Accepts malware binaries (PE files), attack scenario descriptions, TTP lists, IOC sets, and sysmon logs
- Runs static analysis on executables: PE headers, imports, strings, entropy, hashes
- Extracts MITRE ATT&CK techniques from all input types
- Matches against 50+ known malware families with similarity scoring
- Attributes to 14 tracked APT groups using a trained XGBoost model (85.6% accuracy, 407 features)
- Enriches with VirusTotal lookups when API key is configured
- Generates AI-powered threat reports via DeepSeek LLM with exportable PDF/HTML/JSON
- Visualizes blast radius as a 3D force-directed attack graph

## Architecture

```
dashboard.html (vanilla JS, Chart.js, 3D Force Graph)
        |
        | HTTP/JSON
        v
FastAPI backend (uvicorn, port 8000)
  |-- /api/analyze       Attribution engine
  |-- /api/retrace       Malware retrace pipeline
  |-- /api/sandbox       Static + behavioral analysis
  |-- /api/blast-radius  IOC graph expansion
  |-- /api/report        AI report generation (DeepSeek)
  |-- /api/ml/*          Model stats, drift, retraining
  |-- /api/intel/*       Threat intel feeds (CISA, NVD, ATT&CK)
  |-- /api/profiles      APT group profiles
  |-- /api/history       Analysis history (Supabase)
  |-- /api/auth          Session-based authentication
        |
        +-- engine.py        TTP extraction
        +-- ml_engine.py     XGBoost inference + SHAP
        +-- vt_client.py     VirusTotal API
        +-- blast_radius.py  Graph traversal
        +-- cluster_memory.py  Emerging threat clustering
        +-- intel_pipeline.py  Feed ingestion
```

## Tracked APT Groups

Lazarus Group, APT28, APT29, Sandworm, APT41, Volt Typhoon, Salt Typhoon, APT35, MuddyWater, OilRig, Kimsuky, Transparent Tribe, Turla, and an Unknown/Emerging class for novel threats.

## Setup

### Prerequisites

- Python 3.10+
- pip

### Quick start

**Windows:**
```
start.bat
```

**Linux/Mac:**
```
chmod +x start.sh
./start.sh
```

### Manual setup

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r backend/requirements.txt

# Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env with your API keys (all optional)

# Start the server
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open [http://localhost:8000/dashboard.html](http://localhost:8000/dashboard.html)

### Environment variables

All optional. Set in `backend/.env`:

| Variable | Purpose |
|----------|---------|
| `VT_API_KEY` | VirusTotal enrichment |
| `DEEPSEEK_API_KEY` | AI report generation |
| `SUPABASE_URL` | Cloud storage for history |
| `SUPABASE_ANON_KEY` | Supabase auth |
| `PRISM_AUTH_USER` | Login username (default: `admin@prism.local`) |
| `PRISM_AUTH_PASS` | Login password (default: `changeme`) |

### Azure deployment

A deployment script is included for Ubuntu VMs:

```bash
scp -r . azureuser@YOUR_IP:~/APTRACE-Malware-retrace/
ssh azureuser@YOUR_IP "bash ~/APTRACE-Malware-retrace/deploy_azure.sh"
```

This sets up a systemd service + nginx reverse proxy on port 80.

## Usage

### Dashboard

The dashboard has 9 tabs:

1. **Overview** — System health, recent analyses, threat feed summary
2. **Attribution** — Upload files (scenarios, TTPs, IOCs, logs, malware) and run multi-source attribution
3. **Threat Intel** — Live feeds from CISA KEV, NVD, and MITRE ATT&CK
4. **TTP Analysis** — MITRE technique breakdown with tactic heatmaps
5. **ML Engine** — Model performance metrics, per-group accuracy, feature importance
6. **Malware Families** — Known family database with APT mappings
7. **Sandbox Timeline** — Upload PE files for static analysis with kill-chain timeline
8. **Blast Radius** — 3D graph expansion from IOCs (hashes, IPs, domains)
9. **Report** — Generate comprehensive AI-powered threat reports

### API examples

**Analyze malware:**
```bash
curl -X POST http://localhost:8000/api/retrace -F "file=@sample.exe"
```

**Text-based attribution:**
```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "Spearphishing with macro-enabled docs, PowerShell C2, credential dumping via Mimikatz", "input_mode": "analyst_text"}'
```

**Blast radius expansion:**
```bash
curl -X POST http://localhost:8000/api/blast-radius \
  -H "Content-Type: application/json" \
  -d '{"ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "depth": 2}'
```

**API documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)

## ML Model

- **Algorithm**: XGBoost (multi-class)
- **Accuracy**: 85.6%
- **Features**: 407 (TTP presence, behavioral signals, string patterns, import patterns)
- **Training samples**: 5,600
- **Classes**: 14 (13 APT groups + Unknown)
- **Explainability**: SHAP feature importance per prediction

### Retraining

```bash
cd ml
python generate_training_data.py   # Generate synthetic training data
python train_model.py              # Train and evaluate
```

The trained model saves to `ml/models/prism_model.pkl`.

## Project structure

```
backend/
  main.py                 FastAPI app entry point
  ml_engine.py            XGBoost inference with sparse/rich prediction paths
  config.py               Environment config
  routers/                API endpoints (10 routers)

ml/
  train_model.py          Model training pipeline
  models/                 Saved model + metrics
  data/                   Training data + feature schema

data/                     APT profiles, malware families, emerging clusters
intel/                    Cached threat intel feeds
examples/                 Lazarus Group demo scenario files
tests/                    Test scripts and sample files
supabase/                 Database schema and migration
```

## License

Academic / research use.
