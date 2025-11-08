# ThreatOps SIEM

Enterprise-grade Security Information and Event Management (SIEM) system built with OpenSearch, Filebeat, and Python.

## Features

- **Multi-Source Log Collection**: Monitors BOTH simulated attacks AND real Windows system logs
  - 🎯 Simulated MITRE ATT&CK scenarios
  - 🖥️ Real Windows Security events (logins, access control)
  - ⚙️ Real Windows System events (services, hardware)
  - 📱 Real Windows Application logs
- **Threat Detection**: ML-based anomaly detection with Sigma rule support
- **Threat Intelligence**: Enrichment using local database and external APIs
- **Risk Scoring**: Dynamic prioritization based on threat intel and MITRE mapping
- **Dual Dashboards**: 
  - **ThreatOps Dashboard** (port 8501): Security-focused view with log source separation
  - **OpenSearch Dashboards** (port 5601): Advanced analytics and raw log exploration
- **OpenSearch Integration**: Scalable log storage and analytics

## Architecture

```
Multi-Source Log Collection:

🎯 Simulated Attacks ────┐
🖥️ Windows Security ─────┤
⚙️ Windows System ───────├──→ Filebeat ──→ OpenSearch ──→ Detection ──→ Enrichment ──→ Scoring ──→ Alerts
📱 Windows Application ──┘                      ↓
                                         OpenSearch Dashboards
                                         (Advanced Analytics)
                                                ↓
                                         ThreatOps Dashboard
                                         (Security View)
```

### Why Two Dashboards?

**ThreatOps Dashboard** (http://localhost:8501)
- 🎯 **Purpose**: Security analyst view
- 📊 **Shows**: Alerts, threats, and incidents
- 🔍 **Features**: Log source separation, severity charts, MITRE mapping
- 👤 **For**: Daily security monitoring and incident response

**OpenSearch Dashboards** (http://localhost:5601)
- 🔧 **Purpose**: Deep dive analytics
- 📊 **Shows**: Raw logs, custom queries, system health
- 🔍 **Features**: Advanced filtering, custom visualizations, index management
- 👤 **For**: Threat hunting, debugging, and custom analysis

## Quick Start

### Prerequisites

- Python 3.8+
- OpenSearch 3.3+
- OpenSearch Dashboards 3.3+
- Filebeat 9.2+

### Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Setup OpenSearch
python run.py --setup

# 3. Train ML model (optional but recommended)
python run.py --train

# 4. Update threat intelligence (optional)
python run.py --update-intel
```

### One Command to Start Everything

```bash
python run.py --all
```

This starts:
1. ✅ OpenSearch (database - port 9200)
2. ✅ Filebeat (log collector)
3. ✅ OpenSearch Dashboards (analytics - port 5601)
4. ✅ Attack simulation (test data)
5. ✅ Detection pipeline (threat analysis)
6. ✅ ThreatOps Dashboard (main UI - port 8501)

All dashboards open automatically in your browser!

### All Available Commands

```bash
# Complete System
python run.py --all              # Start everything (recommended)

# Attack Simulation
python run.py --simulate         # Generate attack logs

# Detection & Analysis
python run.py --detect           # Run threat detection
python run.py --enrich           # Enrich with threat intel
python run.py --score            # Calculate risk scores
python run.py --pipeline         # Full pipeline (detect → enrich → score)

# Continuous Monitoring
python run.py --continuous       # Run every 60 seconds
python run.py --continuous --interval 120  # Custom interval

# Dashboard Only
python run.py --dashboard        # Start UI only

# Setup & Maintenance
python run.py --setup            # Setup OpenSearch
python run.py --train            # Train ML model
python run.py --update-intel     # Update threat intel database

# Help
python run.py --help             # Show all options
```

### Access Points

After running `--all`:
- **ThreatOps Dashboard**: http://localhost:8501 (Main SIEM interface)
- **OpenSearch Dashboards**: http://localhost:5601 (Advanced analytics)
- **OpenSearch API**: http://localhost:9200 (Backend API)

## Configuration

All settings in: `application.py` → `Settings` class

### API Keys (Optional)
Create `.env` file in project root:
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
```

### Customization
Edit `application.py` to configure:
- Detection thresholds
- ML model parameters
- Risk scoring weights
- Alert notification settings

## Project Structure (5-File Architecture)

```
threat_ops/
├── run.py                    # 🚀 Single entry point with CLI flags
├── core_detection.py         # 🔍 Log collection, detection, enrichment, scoring
├── reporting.py              # 📊 Reports, notifications, SOAR automation
├── simulation.py             # 🎯 Attack simulation (MITRE ATT&CK)
├── utilities.py              # ⚙️ Setup, model training, intel updates
├── application.py            # 🖥️ Dashboard UI & configuration
├── requirements.txt          # 📦 Python dependencies
├── README.md                 # 📖 Main documentation
├── TROUBLESHOOTING.md        # 🔧 Comprehensive troubleshooting guide
├── tests/                    # 🧪 Test suite
│   ├── __init__.py          # Package initialization
│   ├── conftest.py          # Pytest configuration & fixtures
│   ├── run_tests.py         # Test runner script
│   ├── test_core_detection.py  # Tests for core_detection.py
│   ├── test_simulation.py   # Tests for simulation.py
│   ├── test_reporting.py    # Tests for reporting.py
│   ├── test_utilities.py    # Tests for utilities.py
│   └── test_integration.py  # End-to-end integration tests
├── data/                     # 📁 Logs and simulation data
├── models/                   # 🤖 ML models
├── reports/                  # 📄 Generated reports
└── logs/                     # 📋 Application logs
    └── threat_ops.log
```

## Core Components

### 1. Log Collection & Detection (core_detection.py)
- Standardizes log entries from multiple sources
- ML-based anomaly detection (Isolation Forest)
- Rule-based threat detection
- MITRE ATT&CK mapping

### 2. Threat Intelligence (core_detection.py)
- Local SQLite database
- External APIs: VirusTotal, AbuseIPDB, AlienVault OTX
- Automatic enrichment of IPs, domains, hashes

### 3. Risk Scoring (core_detection.py)
- Dynamic scoring based on:
  - Alert severity
  - Threat intel reputation
  - Attack frequency
  - MITRE technique criticality

### 4. Reporting & Automation (reporting.py)
- HTML, PDF, JSON reports
- Email, Slack, webhook notifications
- SOAR actions: IP blocking, account disabling, host quarantine

### 5. Attack Simulation (simulation.py)
- 8 MITRE ATT&CK scenarios
- Realistic log generation
- Test data for detection validation

## OpenSearch Indices

- `filebeat-*`: Raw logs collected by Filebeat
- `security-alerts`: Generated alerts with enrichment and scores

## Testing

### Run All Tests

```bash
# Using pytest
pytest

# Using test runner
python tests/run_tests.py
```

### Run Specific Tests

```bash
# Test specific module
pytest tests/test_core_detection.py
pytest tests/test_simulation.py
pytest tests/test_reporting.py

# Integration tests
pytest tests/test_integration.py

# With coverage
pytest --cov=. --cov-report=term-missing
```

### Test Runner Options

```bash
python tests/run_tests.py all          # Run all tests
python tests/run_tests.py integration  # Integration tests only
python tests/run_tests.py coverage     # With coverage report
python tests/run_tests.py test_core_detection  # Specific test file
```

### Test Categories

The test suite includes:
- **Unit Tests**: Individual component testing (LogCollector, ThreatDetector, etc.)
- **Integration Tests**: End-to-end workflow testing (Simulation → Detection → Reporting)
- **Edge Cases**: Error handling, invalid inputs, system resilience

## Troubleshooting

### Quick Fixes

**OpenSearch not connecting:**
```bash
# Check if running
curl http://localhost:9200

# Verify security is disabled in opensearch.yml
plugins.security.disabled: true
```

**No logs appearing:**
```bash
# 1. Run simulation
python run.py --simulate

# 2. Wait 15 seconds for indexing

# 3. Run detection
python run.py --detect
```

**Dashboard issues:**
- Check logs: `logs/threat_ops.log`
- Restart: Press Ctrl+C and run `python run.py --all` again

### Complete Troubleshooting Guide

For detailed troubleshooting including OpenSearch login issues, service startup problems, and more:

📖 **See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)** for comprehensive solutions

## License

MIT License - See LICENSE file for details.

## Credits

Built with:
- [OpenSearch](https://opensearch.org/) - SIEM backend
- [Filebeat](https://www.elastic.co/beats/filebeat) - Log collection
- [Streamlit](https://streamlit.io/) - Dashboard
- [scikit-learn](https://scikit-learn.org/) - Machine learning
