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
- OpenSearch 3.3+ (included in D:\Cusor AI\opensearch-3.3.1-windows-x64)
- OpenSearch Dashboards 3.3+ (included in D:\Cusor AI\opensearch-dashboards-3.3.0)
- Filebeat 9.2+ (included in D:\Cusor AI\filebeat-9.2.0-windows-x86_64)

**All prerequisites are already installed in your setup!**

### One-Click Setup

**Option 1: Double-click START.bat**

Just double-click `START.bat` and everything starts automatically!

**Option 2: Run from command line**

```bash
python run.py --mode all
```

This ONE command will:
1. ✅ Start OpenSearch (database - port 9200)
2. ✅ Start Filebeat (collects logs from 4 sources)
3. ✅ Start OpenSearch Dashboards (analytics - port 5601)
4. ✅ Run attack simulation (generates test threats)
5. ✅ Run detection pipeline (analyzes ALL logs)
6. ✅ Open ThreatOps Dashboard (main UI - port 8501)

**That's it!** The system now monitors:
- Real security events from your Windows system
- Simulated attacks for testing
- All displayed separately in the dashboard

### Services Running

After startup, you'll have access to:
- **ThreatOps Dashboard**: http://localhost:8501 (Main Security Monitoring - opens automatically)
- **OpenSearch Dashboards**: http://localhost:5601 (Advanced Analytics - no login required)
- **OpenSearch API**: http://localhost:9200 (Backend - for developers)

### Advanced Usage

**Run individual components:**
```bash
# Generate simulated attacks only
python run.py --mode simulate

# Run detection only
python run.py --mode detect

# Run full pipeline only (detect + enrich + score)
python run.py --mode pipeline

# Run continuously (every 60 seconds)
python run.py --mode continuous
```

## Configuration

Main configuration: `config/settings.yaml`

Key settings:
- Detection rules and thresholds
- Threat intelligence API keys (optional)
- ML model parameters
- Risk scoring weights

OpenSearch configuration: `../opensearch-3.3.1-windows-x64/opensearch-3.3.1/config/opensearch.yml`

Filebeat configuration: `../filebeat-9.2.0-windows-x86_64/filebeat-9.2.0-windows-x86_64/filebeat.yml`

## System Components

### Attack Simulator
- Generates 8 MITRE ATT&CK scenarios
- Writes logs to `data/sim_attacks.log`
- Filebeat collects logs automatically

### Threat Detector
- Reads logs from OpenSearch `filebeat-*` index
- ML-based anomaly detection
- Writes alerts to `security-alerts` index

### Intel Enricher
- Enriches alerts with threat intelligence
- Uses local database + external APIs
- Updates alerts in OpenSearch

### Risk Scorer
- Calculates risk scores based on:
  - Alert severity
  - Threat intel reputation
  - MITRE technique criticality
- Updates alerts with final scores

## Project Structure

```
threat_ops/
├── simulation/          # Attack simulator
├── detection/           # Threat detector
├── enrichment/          # Intel enricher
├── scoring/             # Risk scorer
├── dashboard/           # Streamlit dashboard
├── config/              # Configuration files
├── data/                # Logs, alerts, reports
├── scripts/             # Setup and utility scripts
├── run.py               # Main orchestrator
└── START.bat            # One-click startup
```

## OpenSearch Indices

- `filebeat-*`: Raw logs collected by Filebeat
- `security-alerts`: Generated alerts with enrichment and scores

## Troubleshooting

**OpenSearch not connecting:**
- Verify OpenSearch is running: http://localhost:9200
- Check security is disabled: `plugins.security.disabled: true` in opensearch.yml

**No logs in OpenSearch:**
- Check Filebeat is running
- Verify `data/sim_attacks.log` exists
- Check Filebeat configuration paths

**No alerts generated:**
- Run simulation first: `python run.py --mode simulate`
- Check logs exist in OpenSearch: `filebeat-*` index
- Run detection: `python run.py --mode detect`

## License

MIT License - See LICENSE file for details.

## Credits

Built with:
- [OpenSearch](https://opensearch.org/) - SIEM backend
- [Filebeat](https://www.elastic.co/beats/filebeat) - Log collection
- [Streamlit](https://streamlit.io/) - Dashboard
- [scikit-learn](https://scikit-learn.org/) - Machine learning
