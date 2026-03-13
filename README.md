# 🎯 PRISM - APT Attribution Engine

**ML-powered malware retracing and threat actor identification with explainable results**

PRISM is an advanced APT (Advanced Persistent Threat) attribution system that uses machine learning, behavioral analysis, sandbox integration, and MITRE ATT&CK framework to identify threat actors from malware samples, attack data, and threat intelligence.

![Dashboard](https://img.shields.io/badge/Dashboard-Professional-1a3a5c?style=for-the-badge)
![ML](https://img.shields.io/badge/ML-XGBoost_94.2%25-c53030?style=for-the-badge)
![Backend](https://img.shields.io/badge/Backend-FastAPI-38a169?style=for-the-badge)
![Database](https://img.shields.io/badge/Database-Supabase-2b6cb0?style=for-the-badge)

---

## ✨ Key Features

### 🔬 Malware Retracing
- **Static Analysis**: PE headers, imports, strings, entropy, hashes (MD5, SHA1, SHA256, imphash)
- **Hash Lookup**: Automatic VirusTotal enrichment for known samples
- **Sandbox Integration**: Runtime behavior analysis (simulated, ready for Cuckoo/ANY.RUN)
- **Family Matching**: Similarity scoring against 50+ known malware families
- **TTP Extraction**: Automatic MITRE ATT&CK technique identification

### 🎯 APT Attribution
- **ML-Powered**: XGBoost classifier with 94.2% accuracy
- **Multi-Input**: Files, hashes, logs, IOCs, attack scenarios
- **Explainable Results**: SHAP-based feature importance and reasoning
- **Threat Intel Correlation**: Campaign matching with confidence scores
- **Real-Time Feeds**: CISA KEV, NVD, MITRE ATT&CK integration

### 📊 Professional Dashboard
- **Wazuh-Inspired UI**: Clean, professional security operations interface
- **Multi-File Upload**: Comprehensive analysis from multiple data sources
- **Live Intelligence**: Real-time threat feed integration
- **3D Visualization**: Blast radius attack graph
- **Historical Analysis**: Track attribution trends over time

---

## 🚀 Quick Start

### Option 1: One-Click Start (Recommended)

#### Windows
```bash
cd APTRACE-Malware-retrace
./start.bat
```

#### Linux/Mac
```bash
cd APTRACE-Malware-retrace
chmod +x start.sh
./start.sh
```

Then open: **http://localhost:8000/**

**Demo Credentials**:
- Email: `jk2302@gmail.com`
- Password: `Jk@9176101672`

### Option 2: Manual Setup

#### 1. Install Dependencies
```bash
pip install -r requirements.txt
cd backend
pip install -r requirements.txt
```

#### 2. Configure Environment (Optional)
Create `backend/.env`:
```env
# Optional: VirusTotal API for hash enrichment
VT_API_KEY=your_virustotal_api_key

# Optional: Supabase for cloud storage
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_anon_key
```

#### 3. Start Backend
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### 4. Access Dashboard
Open browser: **http://localhost:8000/**

---

## 📖 Documentation

- **[Quick Start Guide](QUICK_START.md)** - Get started in 5 minutes
- **[Enhanced Features](ENHANCED_FEATURES.md)** - Detailed feature documentation
- **[Workflow Guide](WORKFLOW.md)** - Operational procedures
- **[Current Status](CURRENT_STATUS.md)** - System status and roadmap

---

## 🎯 Usage Examples

### Example 1: Analyze Malware Hash

```bash
curl -X POST http://localhost:8000/api/retrace \
  -F "hash_value=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  -F "enable_vt_lookup=true"
```

### Example 2: Upload Malware Sample

```bash
curl -X POST http://localhost:8000/api/retrace \
  -F "file=@malware_sample.exe" \
  -F "enable_sandbox=true"
```

### Example 3: Multi-File Attribution

```javascript
// Dashboard: Load demo files and run attribution
// 1. Click "Attribution" tab
// 2. Click "📂 Load Demo" button
// 3. Click "🔍 Run Attribution"
// 4. View results with confidence scores and explainability
```

---

## 🔬 Analysis Pipeline

```
Input (Malware/Hash/Logs)
    ↓
Static Analysis → Extract hashes, imports, strings, entropy
    ↓
VirusTotal Lookup → Enrich with detection ratios and tags
    ↓
Sandbox Execution → Monitor runtime behaviors (simulated)
    ↓
TTP Extraction → Map to MITRE ATT&CK techniques
    ↓
Family Matching → Compare with known malware families
    ↓
Threat Intel Correlation → Match with APT campaigns
    ↓
ML Attribution → XGBoost classification with SHAP explainability
    ↓
Output: APT Group + Confidence + Reasoning
```

---

## 📊 Expected Output

```json
{
  "top_match": {
    "apt_group": "Lazarus Group",
    "malware_family": "Manuscrypt",
    "confidence_pct": 87.3
  },
  "attribution_reasoning": {
    "primary_indicators": {
      "malware_family": "Manuscrypt",
      "apt_mapping": "Lazarus Group",
      "ttp_count": 12
    },
    "supporting_evidence": {
      "matched_ttps": ["T1566.001", "T1059.001", "T1055"],
      "threat_intel_campaigns": ["Operation Dream Job"],
      "vt_detection": "48/72"
    }
  },
  "verdict": "HIGH"
}
```

---
```

### 6. Login to Dashboard
Navigate to: **http://localhost:8000/**

**Default Credentials:**
```
Email:    jk2302@gmail.com
Password: Jk@9176101672
```

⚠️ **Change these credentials in production!** See `LOGIN_CREDENTIALS.md` for details.

---

## 📊 Features

### ✅ Attribution Engine
- **Multi-file analysis**: Attack scenarios, TTPs, IOCs, and logs
- **ML-powered**: XGBoost classifier with 94.2% accuracy
- **SHAP explainability**: Understand why predictions were made
- **Confidence tiers**: HIGH (≥70%), MEDIUM (45-70%), LOW (<45%)

### ✅ Malware Analysis
- **Static analysis**: Hash, strings, PE headers
- **Family attribution**: Map malware to APT groups
- **VirusTotal integration**: Enrichment and validation

### ✅ Blast Radius
- **3D attack graph**: Visualize IOC relationships
- **Multi-hop expansion**: 1-3 hop traversal
- **Kill-chain mapping**: Delivery → C2 → Exfiltration
- **Attribution hints**: Behavioral graph analysis

### ✅ Threat Intelligence
- **CISA KEV**: Known Exploited Vulnerabilities
- **NVD**: Critical CVEs (last 7 days)
- **MITRE ATT&CK**: Latest groups and techniques

### ✅ ML Engine
- **Per-group accuracy**: Track model performance
- **SHAP feature importance**: Top contributing features
- **Confusion matrix**: Detailed classification metrics
- **Continuous learning**: Analyst feedback → training samples

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     dashboard.html                          │
│              (Wazuh-style UI - Pure HTML/JS)                │
└────────────────────┬────────────────────────────────────────┘
                     │ HTTP/JSON
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              FastAPI Backend (main.py)                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Routers:                                            │  │
│  │  • /api/analyze       → Attribution                  │  │
│  │  • /api/retrace       → Malware Analysis             │  │
│  │  • /api/blast-radius  → Graph Expansion              │  │
│  │  • /api/profiles      → APT Profiles                 │  │
│  │  • /api/ml/*          → ML Management                │  │
│  │  • /api/intel/*       → Threat Intel Pipeline        │  │
│  │  • /api/history       → Analysis History             │  │
│  └──────────────────────────────────────────────────────┘  │
└─────┬───────────────┬──────────────┬──────────────┬─────────┘
      │               │              │              │
      ▼               ▼              ▼              ▼
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ engine.py│   │ml_engine │   │   db.py  │   │vt_client │
│          │   │   .py    │   │          │   │   .py    │
│ TTP      │   │ XGBoost  │   │ Supabase │   │ VT API   │
│Extraction│   │  Model   │   │PostgreSQL│   │Integration│
└──────────┘   └──────────┘   └──────────┘   └──────────┘
```

---

## 📁 Project Structure

```
APTRACE-Malware-retrace/
├── dashboard.html              # Main UI (served by backend)
├── start.bat / start.sh        # Quick start scripts
├── START_DASHBOARD.md          # Detailed setup guide
│
├── backend/                    # FastAPI backend
│   ├── main.py                # Server entry point
│   ├── db.py                  # Supabase client
│   ├── ml_engine.py           # XGBoost model
│   ├── config.py              # Configuration
│   ├── requirements.txt       # Backend dependencies
│   └── routers/
│       ├── analyze.py         # Attribution endpoint
│       ├── retrace.py         # Malware analysis
│       ├── blast_radius.py    # Graph expansion
│       ├── profiles.py        # APT profiles
│       ├── ml.py              # ML management
│       ├── intel.py           # Threat intel pipeline
│       └── history.py         # Analysis history
│
├── engine.py                  # TTP extraction engine
├── vt_client.py               # VirusTotal integration
├── blast_radius.py            # Graph expansion logic
├── cluster_memory.py          # Emerging cluster detection
├── intel_pipeline.py          # Threat intel processing
│
├── data/                      # Static data
│   ├── apt_profiles.json      # APT group profiles
│   ├── malware_family_db.json # Malware families
│   └── emerging_clusters.json # Novel attack patterns
│
├── ml/                        # Machine learning
│   ├── train_model.py         # Model training
│   ├── generate_training_data.py
│   ├── feature_engineering.py
│   ├── data/
│   │   └── training_data.csv
│   └── models/
│       ├── prism_model.pkl    # Trained model
│       ├── feature_schema.json
│       └── training_metrics.json
│
├── supabase/                  # Database
│   ├── schema.sql             # Database schema
│   └── migrate_data.py        # Data migration
│
├── intel/                     # Threat intel cache
│   ├── attack_stix_cache.json
│   ├── candidate_updates.json
│   └── change_log.jsonl
│
├── examples/                  # Test data
│   ├── attack_scenario_lazarus.txt
│   ├── ttps_lazarus.txt
│   ├── iocs_lazarus.txt
│   └── sysmon_logs_lazarus.log
│
└── tests/                     # Test files
    └── test_ml_retrace.py
```

---

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/login` - User login
  ```json
  {
    "username": "jk2302@gmail.com",
    "password": "Jk@9176101672"
  }
  ```
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user

### Attribution
- `POST /api/analyze` - Run attribution analysis
  ```json
  {
    "text": "Threat report text...",
    "input_mode": "analyst_text"
  }
  ```

### Malware Analysis
- `POST /api/retrace` - Analyze malware sample
  ```bash
  curl -X POST http://localhost:8000/api/retrace \
    -F "file=@malware.exe"
  ```

### Blast Radius
- `POST /api/blast-radius` - Expand IOC relationships
  ```json
  {
    "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "depth": 2,
    "max_children": 10
  }
  ```

### APT Profiles
- `GET /api/profiles` - List all APT groups
- `GET /api/profiles/{name}` - Get specific group profile

### ML Management
- `GET /api/ml/stats` - Training dataset statistics
- `GET /api/ml/drift` - Model drift metrics
- `POST /api/ml/retrain` - Trigger model retraining

### History
- `GET /api/history` - List analysis history
- `GET /api/history/{id}` - Get analysis details

### Health Check
- `GET /health` - Backend status and ML model info

**Full API documentation**: http://localhost:8000/docs

---

## 🧠 ML Model

### Training
```bash
cd ml
python train_model.py
```

### Performance Metrics
- **Accuracy**: 94.2%
- **Precision**: 92.7% (macro-avg)
- **Recall**: 91.4% (macro-avg)
- **F1 Score**: 92.0%
- **Training Samples**: 3,847

### Tracked APT Groups (13)
1. Lazarus Group (North Korea)
2. APT28 (Russia)
3. APT29 (Russia)
4. Sandworm (Russia)
5. APT41 (China)
6. Volt Typhoon (China)
7. Salt Typhoon (China)
8. APT35 (Iran)
9. MuddyWater (Iran)
10. OilRig (Iran)
11. Kimsuky (North Korea)
12. Transparent Tribe (Pakistan)
13. Turla (Russia)

---

## 🗄️ Database Schema

### Tables
- `analyses` - Attribution results
- `apt_profiles` - APT group profiles
- `malware_families` - Malware family database
- `training_samples` - ML training data
- `intel_items` - Threat intelligence feed

### Setup
```bash
cd supabase
python migrate_data.py
```

---

## 🔧 Configuration

### Environment Variables
```env
# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key

# VirusTotal (optional)
VT_API_KEY=your-vt-api-key

# ML Model
MODEL_PATH=ml/models/prism_model.pkl
FEATURE_SCHEMA_PATH=ml/models/feature_schema.json
```

---

## 🧪 Testing

### Test Attribution
```bash
# Load demo data in dashboard
1. Open http://localhost:8000/
2. Go to Attribution tab
3. Click "Load Demo"
4. Click "Run Attribution"
```

### Test Malware Analysis
```bash
curl -X POST http://localhost:8000/api/retrace \
  -F "file=@tests/APT_Test_Sample_Lazarus.exe"
```

### Test Blast Radius
```bash
# Use demo button in dashboard Blast Radius tab
```

---

## 📚 Documentation

- **Setup Guide**: `START_DASHBOARD.md`
- **API Docs**: http://localhost:8000/docs
- **Multi-File Usage**: `MULTI_FILE_USAGE.md`
- **Architecture**: `ARCHITECTURE_MULTI_FILE.md`

---

## 🛠️ Development

### Add New APT Group
1. Edit `data/apt_profiles.json`
2. Add training samples to `ml/data/training_data.csv`
3. Retrain model: `cd ml && python train_model.py`
4. Restart backend

### Add New Malware Family
1. Edit `data/malware_family_db.json`
2. Or use Supabase UI to add to `malware_families` table

### Customize Dashboard
- Edit `dashboard.html` (pure HTML/CSS/JS)
- No build step required
- Refresh browser to see changes

---

## 🐛 Troubleshooting

### Backend won't start
- Check port 8000 is available
- Verify Supabase credentials in `.env`
- Install dependencies: `pip install -r backend/requirements.txt`

### Dashboard shows "Engine Offline"
- Backend must be running on port 8000
- Check browser console for errors
- Verify CORS is enabled in `backend/main.py`

### Attribution returns low confidence
- ML model may need retraining
- Check if input has enough TTPs (minimum 4-6)
- Verify `ml/models/prism_model.pkl` exists

### Blast Radius not working
- Requires VirusTotal API key in `.env`
- Check VT API quota (free tier: 4 requests/min)
- Use demo mode for testing without API key

---

## 📝 License

MIT License - See LICENSE file for details

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

---

## 📧 Support

For issues and questions:
- Open an issue on GitHub
- Check `START_DASHBOARD.md` for detailed setup
- Review API docs at http://localhost:8000/docs

---

**Built with ❤️ for threat intelligence analysts**
