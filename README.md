# ThreatOps Free - SOC Simulator

## 🧠 Project Overview

**ThreatOps Free** is a comprehensive, open-source Security Operations Center (SOC) simulator that demonstrates real-world threat hunting, detection, and response capabilities. Built entirely with free and open-source technologies, this project serves as both an educational tool and a practical demonstration of modern SOC workflows.

The project uses asynchronous processing for efficient log collection, threat detection, and intelligence enrichment. It includes a modular architecture with components for log collection, threat detection, intelligence enrichment, attack simulation, risk scoring, and reporting - all accessible through a single entry point (`run.py`).

## 🎯 Key Features

- **Multi-source Log Collection**: Windows EVTX, Linux auth logs, JSON logs
- **Advanced Threat Detection**: Rule-based + ML anomaly detection
- **Threat Intelligence Enrichment**: Free APIs (VirusTotal, AbuseIPDB, OTX)
- **Attack Simulation**: Safe testing environment with realistic scenarios
- **Risk Scoring**: Dynamic scoring with MITRE ATT&CK mapping
- **Real-time Dashboard**: Streamlit-based visualization
- **Automated Reporting**: PDF/HTML reports with actionable insights

## 🚀 Quick Start

### Option 1: Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Unix/Linux/macOS:
source .venv/bin/activate

# Install dependencies (Full or Minimal)
# For full features:
pip install -r requirements.txt
# For minimal installation:
pip install -r requirements_minimal.txt

# Run the SOC simulator
python run.py --mode all

# Or start only the dashboard
python -m streamlit run run_streamlit.py -- --mode dashboard
```

### Option 2: Command Line Arguments

The project supports various command-line arguments for flexible execution:

```bash
# Run everything (simulation, tests, and dashboard)
python run.py --mode all

# Run only simulation
python run.py --mode simulation

# Run only dashboard
python run.py --mode dashboard

# Run only tests
python run.py --mode test

# Skip tests when running all modes
python run.py --mode all --skip-tests

# Install dependencies before running
python run.py --install-deps --mode all
```

## ▶️ Detailed Usage

### Main Entry Point

The project uses `run.py` as the single canonical entry point with multiple operation modes:

1. **All Components** (simulation, tests, dashboard):
```powershell
python run.py --mode all
```

2. **Dashboard Only** (Streamlit interface):
```powershell
python run.py --mode dashboard
# Or directly with Streamlit:
python -m streamlit run run_streamlit.py -- --mode dashboard
```

3. **Simulation Only** (headless):
```powershell
python run.py --mode simulation
```

4. **Test Suite**:
```powershell
python run.py --mode test
```

### Advanced Options

- Skip test suite: `--skip-tests`
- Install dependencies: `--install-deps`
- Skip pre-flight checks: `--skip-checks`
- Custom Streamlit port: Add `--server.port PORT` before `--` when using streamlit run

### Example Workflow

1. Run simulation with tests:
```powershell
python run.py --mode all
```

2. Start dashboard for development:
```powershell
python -m streamlit run run_streamlit.py -- --mode dashboard --server.port 8502
```


## 📁 Project Structure

```
threat_ops/
├── collectors/          # Log collection and processing modules
├── config/             # Configuration files (settings.yaml and Python settings)
├── dashboard/          # Streamlit-based interactive dashboard
├── data/               # Data storage (created at runtime)
│   ├── alerts/         # Generated threat alerts
│   ├── logs/          # Collected and processed logs
│   ├── reports/       # Generated HTML/JSON reports
│   ├── sample_logs/   # Sample log files for testing
│   └── simulations/   # Simulation scenario outputs
├── detection/          # Threat detection engine
├── enrichment/         # Threat intelligence enrichment
├── reporting/          # Report generation (HTML/JSON)
├── scoring/           # Risk scoring and MITRE mapping
├── simulation/         # Attack simulation scenarios
└── tests/             # Test modules and verification
```

## 🔧 Configuration

Edit `config/settings.yaml` to configure:
- Log sources
- Detection rules
- API keys
- Risk scoring parameters

## 📊 Dashboard Features

The Streamlit-based dashboard (`run_streamlit.py`) provides:
- Real-time alert monitoring and visualization
- Threat intelligence data enrichment display
- Risk score trend analysis and metrics
- MITRE ATT&CK technique mapping
- Interactive data filtering and search
- On-demand report generation (HTML/JSON)
- Simulation scenario results visualization

## 🛡️ Security Note

This tool is designed for educational and testing purposes. All attack simulations are safe and contained within the local environment.

## 📚 Requirements

### Minimum Requirements
Core dependencies are listed in `requirements_minimal.txt`:
- Python 3.8+
- PyYAML, Pydantic, python-dateutil
- Optional: Streamlit, Pandas, NumPy, Plotly

### Full Installation
Complete feature set requirements in `requirements.txt`:
- Machine Learning: scikit-learn 1.7.2
- Visualization: matplotlib, plotly, seaborn
- Reporting: reportlab, jinja2, weasyprint
- APIs: requests, aiohttp
- Testing: pytest, pytest-asyncio
- Development: black, flake8, mypy

## 🤝 Contributing

Contributions are welcome! Please read the documentation and follow the coding standards.

## 📄 License

This project is licensed under the MIT License.

---

**ThreatOps Free** - Empowering security teams with open-source SOC capabilities! 🛡️