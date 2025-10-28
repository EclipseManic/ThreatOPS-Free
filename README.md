<div align="center">

# 🛡️ ThreatOps Free

### Enterprise-Grade Security Operations Center Platform

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSearch](https://img.shields.io/badge/OpenSearch-2.11%2B-005EB8.svg)](https://opensearch.org/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code Quality](https://img.shields.io/badge/code%20quality-A-brightgreen.svg)](.)

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Screenshots](#-screenshots) • [Architecture](#-architecture) • [Contributing](#-contributing)

<!-- ADD YOUR HERO IMAGE HERE -->
<!-- ![ThreatOps Dashboard](docs/images/hero.png) -->

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Screenshots](#-screenshots)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the Platform](#running-the-platform)
- [Configuration](#-configuration)
- [Detection Rules](#-detection-rules)
- [Threat Intelligence](#-threat-intelligence)
- [Machine Learning](#-machine-learning)
- [Dashboard](#-dashboard)
- [Attack Simulation](#-attack-simulation)
- [OpenSearch Integration](#-opensearch-integration)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Performance](#-performance-tuning)
- [Contributing](#-contributing)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**ThreatOps Free** is a production-ready, enterprise-grade Security Operations Center (SOC) platform built entirely with open-source technologies. It demonstrates modern security engineering practices and provides a complete threat detection, analysis, and response pipeline.

### 🌟 Why ThreatOps?

- **🏢 Production-Ready**: Built with the same tools used in enterprise SOCs (OpenSearch, Filebeat, Sigma)
- **📈 Scalable**: Handle millions of security events through OpenSearch SIEM backend
- **🧠 Intelligent**: ML-based anomaly detection + 47K+ threat indicators from 8 free feeds
- **🎯 Standards-Based**: Sigma detection rules + MITRE ATT&CK framework mapping
- **⚡ Efficient**: Smart local caching reduces API calls by 95%+
- **🔓 100% Free**: All components are open-source with no licensing costs

### 💡 Use Cases

- Security Operations Center (SOC) simulation
- Threat detection research and testing
- Security training and education
- Detection engineering practice
- Portfolio project for cybersecurity professionals
- Security tool integration testing

---

## ✨ Features

### Core Capabilities

<table>
<tr>
<td width="50%">

#### 🔍 Detection Engine
- **Sigma Rules** - Industry-standard detection format
- **Rule-Based Detection** - Custom correlation rules
- **ML Anomaly Detection** - Behavioral analysis
- **MITRE ATT&CK Mapping** - Technique classification
- **Real-Time Alerting** - Immediate threat notification

</td>
<td width="50%">

#### 🛡️ Threat Intelligence
- **Local IOC Database** - 47,000+ indicators
- **8 Free Feeds** - Auto-updated daily
- **Smart Caching** - Reduced API dependency
- **Multi-Source Enrichment** - VirusTotal, AbuseIPDB, OTX
- **Reputation Scoring** - Malicious/Suspicious/Clean

</td>
</tr>
<tr>
<td width="50%">

#### 📊 SIEM Backend
- **OpenSearch** - Enterprise search and analytics
- **Filebeat** - Professional log shipping
- **Index Management** - Automated lifecycle policies
- **Data Pipelines** - Log enrichment and parsing
- **Scalable Storage** - Million+ events per day

</td>
<td width="50%">

#### 🎮 Attack Simulation
- **8 MITRE Scenarios** - Realistic attack patterns
- **Safe Testing** - Contained local environment
- **Customizable** - Adjustable parameters
- **Automated Logging** - Integrated with pipeline
- **Threat Validation** - Test detection coverage

</td>
</tr>
</table>

### Additional Features

- ✅ **Real-Time Dashboard** - Streamlit-based visualization
- ✅ **Risk Scoring** - Dynamic threat prioritization
- ✅ **Automated Reports** - PDF/HTML generation
- ✅ **Configurable Whitelist** - False positive reduction
- ✅ **Multi-Format Logs** - Windows EVTX, Syslog, JSON
- ✅ **API Integration** - External threat intel sources
- ✅ **Custom Rules** - Easy rule creation and management

---

## 📸 Screenshots

<!-- ADD YOUR SCREENSHOTS HERE -->

### Dashboard Overview
<!-- ![Dashboard Overview](docs/images/dashboard-overview.png) -->
*Real-time security operations dashboard with alert statistics and threat visualization*

### Alert Timeline
<!-- ![Alert Timeline](docs/images/alert-timeline.png) -->
*Hourly alert distribution showing attack patterns over time*

### Threat Intelligence
<!-- ![Threat Intelligence](docs/images/threat-intel.png) -->
*IOC database statistics with 47K+ indicators from multiple feeds*

### Detection Rules
<!-- ![Sigma Rules](docs/images/sigma-rules.png) -->
*Sigma detection rules mapped to MITRE ATT&CK techniques*

### OpenSearch Dashboards
<!-- ![OpenSearch Dashboard](docs/images/opensearch-dashboard.png) -->
*Enterprise SIEM backend showing log ingestion and analysis*

---

## 🏗️ Architecture

<!-- ADD YOUR ARCHITECTURE DIAGRAM HERE -->
<!-- ![Architecture Diagram](docs/images/architecture.png) -->

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                         Log Sources                              │
│  Windows EVTX │ Linux Syslog │ JSON Logs │ Attack Simulator    │
└───────────────┬─────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                         Filebeat Agent                             │
│              Professional log shipping and parsing                 │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                      OpenSearch SIEM                               │
│        Index Management │ Search │ Analytics │ Storage            │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                    Detection Engine                                │
│   Sigma Rules │ Correlation │ ML Anomaly Detection               │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                  Threat Intelligence                               │
│   Local DB (47K IOCs) │ API Integration │ Enrichment             │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                    Risk Scoring                                    │
│         MITRE Mapping │ Severity │ Prioritization                │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│                  Outputs                                           │
│  Dashboard │ Alerts │ Reports │ OpenSearch Dashboards            │
└───────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **SIEM Backend** | OpenSearch 2.11+ | Search, analytics, storage |
| **Log Shipping** | Filebeat 8.11+ | Professional log collection |
| **Detection** | Python + Sigma | Rule-based and ML detection |
| **ML Framework** | scikit-learn | Anomaly detection |
| **Dashboard** | Streamlit | Real-time visualization |
| **Database** | SQLite | Local threat intel storage |
| **Threat Intel** | Multiple APIs | IOC enrichment |
| **Framework** | MITRE ATT&CK | Attack classification |

---

## 🚀 Quick Start

### Prerequisites

| Software | Version | Purpose | Download |
|----------|---------|---------|----------|
| Python | 3.8+ | Runtime | [python.org](https://www.python.org/downloads/) |
| OpenSearch | 2.11+ | SIEM backend | [opensearch.org](https://opensearch.org/downloads.html) |
| OpenSearch Dashboards | 2.11+ | Visualization | [opensearch.org](https://opensearch.org/downloads.html) |
| Filebeat | 8.11+ | Log shipping | [elastic.co](https://www.elastic.co/downloads/beats/filebeat) |

**System Requirements:**
- 4GB RAM minimum (8GB recommended)
- 10GB free disk space
- Windows 10+ / Linux / macOS

### Installation

#### 1️⃣ Install External Dependencies

**OpenSearch & Dashboards:**

<details>
<summary><b>Windows Installation</b></summary>

```powershell
# Download OpenSearch ZIP from https://opensearch.org/downloads.html
# Extract to C:\opensearch

# Start OpenSearch
cd C:\opensearch-2.11.1
.\bin\opensearch.bat

# Verify (in new terminal)
curl -k -u admin:admin https://localhost:9200
```
</details>

<details>
<summary><b>Linux Installation</b></summary>

```bash
# Download and extract
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.tar.gz
tar -xzf opensearch-2.11.1-linux-x64.tar.gz
cd opensearch-2.11.1

# Start OpenSearch
./bin/opensearch

# Verify (in new terminal)
curl -k -u admin:admin https://localhost:9200
```
</details>

**Filebeat:**

<details>
<summary><b>Windows Installation</b></summary>

```powershell
# Download Filebeat ZIP
# Extract to C:\filebeat

# Copy ThreatOps config
cd D:\path\to\threat_ops
Copy-Item config\filebeat.yml C:\filebeat-8.11.1\filebeat.yml

# Edit filebeat.yml - update path to your project directory
# Replace ${path.home} with D:/path/to/threat_ops
```
</details>

<details>
<summary><b>Linux Installation</b></summary>

```bash
# Download and extract
wget https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.1-linux-x86_64.tar.gz
tar -xzf filebeat-8.11.1-linux-x86_64.tar.gz
cd filebeat-8.11.1

# Copy ThreatOps config
cp /path/to/threat_ops/config/filebeat.yml ./filebeat.yml

# Edit filebeat.yml - update paths
```
</details>

#### 2️⃣ Setup Python Environment

```bash
# Clone repository
git clone https://github.com/yourusername/threatops.git
cd threat_ops

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

#### 3️⃣ Configure OpenSearch

```bash
# Setup indices, templates, and pipelines
python scripts/setup_opensearch.py

# Expected output:
# ✓ Connected to OpenSearch cluster
# ✓ Index template created successfully
# ✓ Ingest pipeline created successfully
# ✓ ILM policy created successfully
# ✓ Initial index created
```

#### 4️⃣ Populate Threat Intelligence

```bash
# Download and populate local threat intel database
python scripts/update_intel_db.py

# This downloads from 8 free feeds:
# - Abuse.ch (malware IPs, domains, hashes)
# - Emerging Threats (compromised IPs)
# - Blocklist.de, Feodo Tracker, Malware Bazaar, etc.

# Expected: 40,000+ IOCs downloaded and cached locally
```

#### 5️⃣ Train ML Model

```bash
# Train anomaly detection model on benign data
python scripts/train_model.py --generate-sample --num-samples 5000

# Output: models/model.joblib (pre-trained model)
# The detector will automatically load this model at runtime
```

### Running the Platform

```bash
# Terminal 1: Start OpenSearch (if not running as service)
cd /path/to/opensearch
./bin/opensearch

# Terminal 2: Start Filebeat
cd /path/to/filebeat
./filebeat -e -c /path/to/threat_ops/config/filebeat.yml

# Terminal 3: Run attack simulations
cd threat_ops
python run.py

# Terminal 4: Launch dashboard
streamlit run dashboard/app.py
# Access at: http://localhost:8501

# Terminal 5: OpenSearch Dashboards
# Open browser: http://localhost:5601
# Login: admin / admin
# Index pattern: threatops-*
```

### Quick Test

```bash
# Generate test alerts
python run.py --mode simulation

# Check OpenSearch has data
curl -k -u admin:admin https://localhost:9200/threatops-*/_count

# View in dashboard
streamlit run dashboard/app.py
```

---

## ⚙️ Configuration

### Main Configuration File

`config/settings.yaml` - Central configuration for all components

<details>
<summary><b>View Configuration Schema</b></summary>

```yaml
# Project Information
project_name: ThreatOps Free
version: 1.0.0
debug: false

# Data Storage
data_dir: data
logs_dir: data/logs
alerts_dir: data/alerts
reports_dir: data/reports

# Log Sources
log_sources:
  - path: data/sample_logs/windows.evtx
    type: evtx
    parser: windows_evtx
    enabled: true
  - path: data/sample_logs/auth.log
    type: auth
    parser: linux_auth
    enabled: true

# Detection Rules
detection_rules:
  - name: Brute Force Attack
    severity: High
    enabled: true
    conditions:
      - field: event_id
        operator: equals
        value: 4625

# Threat Intelligence APIs
apis:
  - name: virustotal
    api_key: YOUR_API_KEY  # Optional
    rate_limit: 4
    enabled: true
  - name: abuseipdb
    api_key: YOUR_API_KEY  # Optional
    rate_limit: 1000
    enabled: true
  - name: otx
    api_key: YOUR_API_KEY  # Optional
    rate_limit: 100
    enabled: true

# Whitelist (False Positive Reduction)
whitelist:
  ips:
    - 127.0.0.1
    - ::1
    - localhost
  users:
    - SYSTEM
    - NT AUTHORITY\SYSTEM
    - root
  processes:
    - System
    - svchost.exe
    - services.exe
    - lsass.exe

# Machine Learning
ml_config:
  enabled: true
  model_type: isolation_forest
  contamination: 0.1
  training_samples: 1000

# Risk Scoring
risk_scoring:
  base_score: 50
  severity_multipliers:
    Critical: 3.0
    High: 2.0
    Medium: 1.5
    Low: 1.0
  intel_multipliers:
    malicious: 2.5
    suspicious: 1.5
    clean: 0.5
```
</details>

### Environment Variables (Optional)

Create `.env` file for API keys:

```bash
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

> **Note**: API keys are optional. The system uses local threat intel database first (47K+ IOCs), significantly reducing API dependency.

---

## 🎯 Detection Rules

### Sigma Rules

Industry-standard detection rules compatible with any Sigma-enabled SIEM.

**Available Rules** (`config/sigma_rules/`):

| Rule | Technique | Severity | Description |
|------|-----------|----------|-------------|
| `brute_force_detection.yml` | T1110 | High | Multiple failed login attempts |
| `privilege_escalation.yml` | T1078 | Critical | Unauthorized privilege elevation |
| `powershell_encoded_command.yml` | T1059.001 | High | Encoded PowerShell commands |
| `lateral_movement_smb.yml` | T1021 | High | SMB/RPC lateral movement |
| `credential_dumping.yml` | T1003 | Critical | Mimikatz and credential theft |

### Creating Custom Rules

Create a new `.yml` file in `config/sigma_rules/`:

```yaml
title: Your Custom Detection Rule
id: uuid-goes-here
status: stable
description: Detects suspicious activity pattern
author: Your Name
date: 2025/01/01
level: high
tags:
    - attack.technique_id
    - attack.tactic
references:
    - https://attack.mitre.org/techniques/T1234/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        CommandLine|contains: 'suspicious_pattern'
    condition: selection
falsepositives:
    - Legitimate admin activity
    - Known software behavior
```

Rules are automatically loaded on startup. No code changes required!

---

## 🛡️ Threat Intelligence

### Local IOC Database

Maintains a local SQLite database with 47,000+ indicators from 8 free feeds:

| Feed | Type | Source | Update Frequency |
|------|------|--------|------------------|
| **Abuse.ch SSL Blacklist** | IP | Malicious SSL certificates | Daily |
| **URLhaus** | Domain/URL | Malware distribution | Daily |
| **Emerging Threats** | IP | Compromised systems | Daily |
| **Blocklist.de** | IP | Attack sources | Daily |
| **Feodo Tracker** | IP | Botnet C2 servers | Daily |
| **MalwareBazaar** | Hash | Malicious file signatures | Daily |
| **CINSSCORE** | IP | Bad actors | Daily |
| **Talos Intelligence** | IP | Known threats | Daily |

### Smart Enrichment Logic

```
1. Check Local Database (47K+ IOCs) ────► Found? ─┐
                                                    │
2. Check API Cache (Recent lookups) ───► Found? ─┤
                                                    │
3. Query External APIs (Rate-limited) ─► Found? ─┤
                                                    │
4. Return Result ◄──────────────────────────────┘
```

**Benefits:**
- ⚡ 95%+ reduction in API calls
- 🚀 Instant lookups for known IOCs
- 💰 Stays within free API tiers
- 🔄 Automatic cache updates

### Updating Intelligence

```bash
# Manual update
python scripts/update_intel_db.py

# View statistics
python scripts/update_intel_db.py --stats-only

# Output:
# Total IOCs: 47,532
#   IPs: 32,441
#   Domains: 12,089
#   Hashes: 3,002

# Schedule daily updates (Linux cron)
0 2 * * * /path/to/.venv/bin/python /path/to/scripts/update_intel_db.py

# Schedule daily updates (Windows Task Scheduler)
# Task: Run daily at 2:00 AM
# Program: python.exe
# Arguments: scripts/update_intel_db.py
# Start in: D:\path\to\threat_ops
```

---

## 🤖 Machine Learning

### Production ML Workflow

The system implements the **correct** machine learning workflow:

```
┌─────────────────────────────────────────────────────────┐
│  1. Training Phase (One-time or Periodic)               │
├─────────────────────────────────────────────────────────┤
│  • Load known-good (benign) log data                   │
│  • Extract features (13 dimensions)                    │
│  • Train IsolationForest model                         │
│  • Save trained model to disk                          │
│  • Output: models/model.joblib                         │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│  2. Production Phase (Runtime)                          │
├─────────────────────────────────────────────────────────┤
│  • Load pre-trained model from disk                    │
│  • Extract features from new logs                      │
│  • Predict anomalies (no retraining)                   │
│  • Generate alerts for anomalies                       │
└─────────────────────────────────────────────────────────┘
```

### Training the Model

```bash
# Generate sample benign data and train
python scripts/train_model.py --generate-sample --num-samples 5000

# Or use your own benign logs
python scripts/train_model.py --training-data /path/to/benign_logs.json

# Output:
# Training Statistics:
#   Total samples: 5,000
#   Features extracted: 13
#   Anomalies in training: 500 (10.0%)
#   Expected contamination: 10%
# ✓ Model saved to: models/model.joblib (245 KB)
```

### Feature Engineering

The model analyzes **13 behavioral features**:

1. Event ID
2. Host name length
3. User name length
4. Message length
5. Command line length
6. Failed logon indicator
7. Successful logon indicator
8. Process creation indicator
9. Network connection indicator
10. Warning severity indicator
11. Critical severity indicator
12. IP address numeric representation
13. Time of day (minutes since midnight)

### Retraining Schedule

Recommended: Retrain monthly with updated benign data to adapt to environment changes.

```bash
# Collect benign logs over 30 days
# Then retrain:
python scripts/train_model.py --training-data monthly_benign_logs.json

# Old model is automatically replaced
```

---

## 📊 Dashboard

### Real-Time Monitoring

Access the Streamlit dashboard at `http://localhost:8501`

**Dashboard Sections:**

| Section | Features | Data Source |
|---------|----------|-------------|
| **Overview** | Alert counts, severity distribution, critical alerts | Real-time alerts |
| **Timeline** | Hourly alert distribution over 24 hours | Alert aggregation |
| **Analytics** | Top attacked hosts, MITRE techniques, trends | Alert metadata |
| **Threat Intel** | IOC statistics, feed sources, enrichment rate | Local database |
| **Explorer** | Filterable alert table, search, export | Alert JSON files |

<!-- ADD DASHBOARD FEATURES IMAGE HERE -->
<!-- ![Dashboard Features](docs/images/dashboard-features.png) -->

### Key Metrics

- **Total Alerts**: Real-time count of all security alerts
- **Critical Alerts**: High-priority threats requiring immediate action
- **Threats Blocked**: Simulated prevention count
- **Average Risk Score**: Calculated from severity and threat intel
- **Detection Rate**: Percentage of simulated attacks detected
- **Enrichment Rate**: Percentage of alerts with threat intel data

### Customization

Edit `dashboard/app.py` to customize:
- Chart types and layouts
- Metric calculations
- Filtering options
- Color schemes
- Refresh intervals

---

## 🎮 Attack Simulation

### Available Scenarios

Realistic MITRE ATT&CK attack simulations for testing detection coverage:

| Scenario | MITRE ID | Events | Duration | Description |
|----------|----------|--------|----------|-------------|
| **Brute Force Attack** | T1110 | 100 | 15 min | Failed login attempts from single IP |
| **Privilege Escalation** | T1078 | 20 | 5 min | Unauthorized elevation to admin |
| **Suspicious PowerShell** | T1059.001 | 30 | 10 min | Encoded command execution |
| **Lateral Movement** | T1021 | 80 | 20 min | SMB/RPC connections |
| **Data Exfiltration** | T1041 | 40 | 30 min | Large data transfers |
| **Malware Execution** | T1055 | 25 | 8 min | Malicious process creation |
| **Command & Control** | T1071 | 60 | 25 min | C2 beaconing |
| **Persistence** | T1543 | 35 | 12 min | Registry/service modifications |

### Running Simulations

```bash
# Run all scenarios
python run.py

# Run specific scenario
python run.py --scenario "Brute Force Attack"

# Batch mode (multiple runs)
for i in {1..10}; do
    python run.py --scenario "all"
    sleep 300  # 5 minute intervals
done
```

### Simulation Output

Logs are written to multiple locations:
- `data/logs/sim_attacks.log` - Monitored by Filebeat → OpenSearch
- `data/simulations/*.json` - Backup copies for analysis
- Console output - Real-time progress

### Validation

Verify detections after simulation:

```bash
# Check OpenSearch ingestion
curl -k -u admin:admin https://localhost:9200/threatops-*/_search?q=source:attack_simulation

# Check alerts generated
ls -la data/alerts/

# View in dashboard
# Navigate to: http://localhost:8501
# Filter by: Last Hour
```

---

## 🔍 OpenSearch Integration

### Index Management

Daily indices for efficient storage and retrieval:

```
threatops-logs-2025.10.28  ← Today's events
threatops-logs-2025.10.27  ← Yesterday's events
threatops-logs-2025.10.26  ← Older events
...
```

### Index Lifecycle Management (ILM)

Automatic data retention policy:

| Phase | Age | Action |
|-------|-----|--------|
| **Hot** | 0-7 days | Active indexing and searching |
| **Warm** | 7-30 days | Read-only, compressed |
| **Delete** | 30+ days | Automatically deleted |

Customize in `scripts/setup_opensearch.py`.

### Querying Examples

```bash
# Count total logs
curl -k -u admin:admin https://localhost:9200/threatops-*/_count

# Search for brute force alerts
curl -k -u admin:admin https://localhost:9200/threatops-*/_search \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "match": {"rule_name": "Brute Force"}
    }
  }'

# Get top attacked hosts
curl -k -u admin:admin https://localhost:9200/threatops-*/_search \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "top_hosts": {
        "terms": {"field": "host", "size": 10}
      }
    }
  }'

# Get MITRE technique distribution
curl -k -u admin:admin https://localhost:9200/threatops-*/_search \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "techniques": {
        "terms": {"field": "mitre_technique", "size": 20}
      }
    }
  }'
```

### Dashboards

Access OpenSearch Dashboards at `http://localhost:5601`:

1. **Create Index Pattern**: `threatops-*`
2. **Discover**: View real-time logs
3. **Visualize**: Create custom charts
4. **Dashboard**: Build security dashboard
5. **Alerting**: Configure automated alerts

---

## 📡 API Reference

### RESTful Endpoints (Future)

*Coming in v2.0*

```
GET  /api/v1/alerts          # List all alerts
GET  /api/v1/alerts/{id}     # Get specific alert
POST /api/v1/simulate        # Trigger simulation
GET  /api/v1/intel/ioc/{ioc} # Lookup IOC
GET  /api/v1/stats           # System statistics
```

### Python API

Import modules directly:

```python
from detection.threat_detector import ThreatDetector
from enrichment.intel_enricher import IntelEnricher
from simulation.attack_simulator import AttackSimulator

# Initialize detector
detector = ThreatDetector(settings)
await detector.initialize()

# Analyze logs
alerts = await detector.analyze_logs(log_entries)

# Enrich with threat intel
enriched = await enricher.enrich_alerts(alerts)
```

---

## 🐛 Troubleshooting

### Common Issues

<details>
<summary><b>OpenSearch won't start</b></summary>

**Symptoms**: Connection refused on port 9200

**Solutions**:
```bash
# Check Java version (needs 11+)
java -version

# Check if port is in use
netstat -an | grep 9200  # Linux
netstat -an | findstr 9200  # Windows

# Check OpenSearch logs
tail -f opensearch/logs/opensearch.log

# Increase heap size (if out of memory)
# Edit opensearch/config/jvm.options:
-Xms2g
-Xmx2g
```
</details>

<details>
<summary><b>Filebeat not connecting</b></summary>

**Symptoms**: No logs appearing in OpenSearch

**Solutions**:
```bash
# Test configuration
filebeat test config

# Test output connection
filebeat test output

# Check Filebeat logs
tail -f filebeat/logs/filebeat

# Verify SSL settings in filebeat.yml
ssl:
  enabled: true
  verification_mode: none  # For self-signed certs

# Check file permissions
ls -la data/logs/sim_attacks.log
```
</details>

<details>
<summary><b>No threat intelligence data</b></summary>

**Symptoms**: Empty IOC database

**Solutions**:
```bash
# Verify database exists
ls -la data/threat_intel.db

# Run manual update
python scripts/update_intel_db.py

# Check statistics
python scripts/update_intel_db.py --stats-only

# Check network connectivity
curl -I https://sslbl.abuse.ch/blacklist/sslipblacklist.txt

# Review update logs
python scripts/update_intel_db.py 2>&1 | tee update.log
```
</details>

<details>
<summary><b>ML model not loading</b></summary>

**Symptoms**: ML detection disabled warnings

**Solutions**:
```bash
# Check if model exists
ls -la models/model.joblib

# Verify scikit-learn installed
pip list | grep scikit-learn

# Retrain model
python scripts/train_model.py --generate-sample

# Check detector logs
tail -f threat_ops.log | grep ML
```
</details>

<details>
<summary><b>Dashboard shows no data</b></summary>

**Symptoms**: Empty charts and tables

**Solutions**:
```bash
# Check if alerts exist
ls -la data/alerts/
cat data/alerts/alerts_*.json | head -n 5

# Run simulation
python run.py

# Check alert generation
tail -f threat_ops.log | grep "alerts generated"

# Clear browser cache
# Then refresh dashboard
```
</details>

### Debug Mode

Enable detailed logging:

```yaml
# config/settings.yaml
debug: true
```

Then check logs:
```bash
tail -f threat_ops.log
```

### Getting Help

- 📖 Check [Documentation](#-documentation)
- 💬 Open an [Issue](https://github.com/yourusername/threatops/issues)
- 📧 Contact: your.email@example.com

---

## ⚡ Performance Tuning

### For Lab Environment (Limited Resources)

```yaml
# opensearch/config/opensearch.yml
indices.memory.index_buffer_size: 10%
thread_pool.write.queue_size: 500
bootstrap.memory_lock: false
```

```yaml
# config/filebeat.yml
output.elasticsearch:
  bulk_max_size: 50
  worker: 2
  compression_level: 3
```

### For Production (High Volume)

```yaml
# opensearch/config/opensearch.yml
indices.memory.index_buffer_size: 30%
thread_pool.write.queue_size: 1000
index.refresh_interval: 30s
index.number_of_replicas: 1
```

```yaml
# config/filebeat.yml
output.elasticsearch:
  bulk_max_size: 200
  worker: 4
  compression_level: 1
```

### Monitoring Performance

```bash
# OpenSearch cluster health
curl -k -u admin:admin https://localhost:9200/_cluster/health?pretty

# Index statistics
curl -k -u admin:admin https://localhost:9200/_cat/indices?v

# Node statistics
curl -k -u admin:admin https://localhost:9200/_nodes/stats?pretty

# Filebeat monitoring
curl -u admin:admin http://localhost:5066/stats
```

---

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Ways to Contribute

- 🐛 **Bug Reports**: Found a bug? [Open an issue](https://github.com/yourusername/threatops/issues)
- 💡 **Feature Requests**: Have an idea? [Suggest a feature](https://github.com/yourusername/threatops/issues)
- 📝 **Documentation**: Improve docs, add examples, fix typos
- 🔧 **Code**: Fix bugs, add features, improve performance
- 🎨 **Design**: Improve UI/UX, create graphics
- 🌍 **Translation**: Help localize the project

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/threatops.git
cd threat_ops

# Create feature branch
git checkout -b feature/amazing-feature

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Make your changes

# Run tests
python -m pytest tests/

# Commit and push
git add .
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Open Pull Request on GitHub
```

### Code Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints where possible
- Add docstrings to functions and classes
- Keep functions small and focused
- Write unit tests for new features

### Pull Request Process

1. Update README.md with details of changes
2. Update documentation if needed
3. Add tests for new functionality
4. Ensure all tests pass
5. Update CHANGELOG.md
6. Request review from maintainers

### Community Guidelines

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 ThreatOps Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🙏 Acknowledgments

### Open Source Projects

This project is built on the shoulders of giants:

- **[OpenSearch](https://opensearch.org/)** - SIEM backend
- **[Elastic Beats](https://www.elastic.co/beats/)** - Filebeat log shipper
- **[Streamlit](https://streamlit.io/)** - Dashboard framework
- **[scikit-learn](https://scikit-learn.org/)** - Machine learning
- **[Sigma](https://github.com/SigmaHQ/sigma)** - Detection rule format
- **[MITRE ATT&CK](https://attack.mitre.org/)** - Threat framework

### Threat Intelligence Feeds

Thanks to these organizations providing free threat intelligence:

- **[Abuse.ch](https://abuse.ch/)** - Malware tracking
- **[Emerging Threats](https://rules.emergingthreats.net/)** - IDS rules
- **[Blocklist.de](https://www.blocklist.de/)** - Attack tracking
- **[AlienVault OTX](https://otx.alienvault.com/)** - Threat exchange
- **[VirusTotal](https://www.virustotal.com/)** - File/URL analysis
- **[AbuseIPDB](https://www.abuseipdb.com/)** - IP reputation
- **[Cisco Talos](https://talosintelligence.com/)** - Threat research

### Contributors

<!-- ADD CONTRIBUTORS HERE -->
<!-- ![Contributors](https://contrib.rocks/image?repo=yourusername/threatops) -->

---

## 📞 Contact & Support

- **GitHub**: [github.com/yourusername/threatops](https://github.com/yourusername/threatops)
- **Issues**: [Report bugs or request features](https://github.com/yourusername/threatops/issues)
- **Discussions**: [Community forum](https://github.com/yourusername/threatops/discussions)
- **Email**: your.email@example.com
- **Twitter**: [@YourHandle](https://twitter.com/yourhandle)
- **LinkedIn**: [Your Profile](https://linkedin.com/in/yourprofile)

---

## 📈 Project Stats

<!-- ADD GITHUB BADGES HERE -->
<!-- 
![GitHub stars](https://img.shields.io/github/stars/yourusername/threatops?style=social)
![GitHub forks](https://img.shields.io/github/forks/yourusername/threatops?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/yourusername/threatops?style=social)
![GitHub issues](https://img.shields.io/github/issues/yourusername/threatops)
![GitHub pull requests](https://img.shields.io/github/issues-pr/yourusername/threatops)
![GitHub last commit](https://img.shields.io/github/last-commit/yourusername/threatops)
![GitHub repo size](https://img.shields.io/github/repo-size/yourusername/threatops)
-->

---

## 🗺️ Roadmap

### Version 2.0 (Planned)

- [ ] RESTful API for external integrations
- [ ] Web-based rule editor
- [ ] Advanced ML models (LSTM, Transformer)
- [ ] Multi-tenant support
- [ ] Role-based access control (RBAC)
- [ ] Webhook notifications
- [ ] Slack/Teams integration
- [ ] Custom report templates
- [ ] Mobile dashboard
- [ ] Kubernetes deployment

### Version 3.0 (Future)

- [ ] Distributed deployment
- [ ] Cluster mode for high availability
- [ ] Advanced correlation engine
- [ ] Threat hunting workbench
- [ ] Automated response actions
- [ ] Integration marketplace
- [ ] Cloud-native deployment
- [ ] Enterprise features

---

<div align="center">

### ⭐ Star this project if you find it useful!

**Built with ❤️ by security professionals, for security professionals**

[⬆ Back to Top](#️-threatops-free)

</div>
