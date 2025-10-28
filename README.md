# ThreatOps Free - SOC Simulator

## 🧠 Project Overview

**ThreatOps Free** is a comprehensive, open-source Security Operations Center (SOC) simulator that demonstrates real-world threat hunting, detection, and response capabilities. Built entirely with free and open-source technologies, this project serves as both an educational tool and a practical demonstration of modern SOC workflows.

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
# Setup virtual environment and install dependencies
python setup_venv.py

# Activate virtual environment
# Windows:
activate_env.bat
# Unix/Linux/macOS:
source activate_env.sh

# Run the SOC simulator
# Windows:
run_soc.bat
# Unix/Linux/macOS:
./run_soc.sh

# Start dashboard
# Windows:
run_dashboard.bat
# Unix/Linux/macOS:
./run_dashboard.sh
```

### Option 2: Manual Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Unix/Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the SOC simulator
python start.py --mode all

# Access dashboard
streamlit run dashboard/app.py
```

## ▶️ Running the project (examples)

The project exposes a single canonical entrypoint: `run.py`. For interactive use the dashboard is powered by Streamlit and should be launched through the Streamlit runner so it creates a web server and opens a browser.

Recommended flows (PowerShell examples):

1) Run simulation, tests and then open the dashboard (auto-launches Streamlit):

```powershell
& ".\.venv\Scripts\python.exe" run.py --mode all
# or skip tests if you want:
& ".\.venv\Scripts\python.exe" run.py --mode all --skip-tests
```

2) Start the dashboard only (Streamlit CLI — preferred when developing the UI):

```powershell
& ".\.venv\Scripts\python.exe" -m streamlit run run_streamlit.py -- --mode dashboard
```

3) Run just the simulation (headless):

```powershell
& ".\.venv\Scripts\python.exe" run.py --mode simulation --skip-tests
```

Notes:
- Use `--skip-tests` if you don't want the test-suite to run as part of `--mode all`.
- If you prefer to run Streamlit directly on a specific port, add the Streamlit `--server.port` argument before the `--` separator. Example:

```powershell
& ".\.venv\Scripts\python.exe" -m streamlit run run_streamlit.py -- --server.port 8502 --mode dashboard
```


## 📁 Project Structure

```
threat_ops/
├── collectors/          # Log collection modules
├── detection/           # Threat detection engine
├── enrichment/          # Threat intelligence enrichment
├── simulation/          # Attack simulation engine
├── scoring/            # Risk scoring and MITRE mapping
├── dashboard/          # Streamlit dashboard
├── reporting/          # Report generation
├── config/            # Configuration files
├── data/              # Data storage (created at runtime)
└── tests/             # Test modules
```

## 🔧 Configuration

Edit `config/settings.yaml` to configure:
- Log sources
- Detection rules
- API keys
- Risk scoring parameters

## 📊 Dashboard Features

- Real-time alert monitoring
- Threat intelligence visualization
- Risk trend analysis
- MITRE ATT&CK technique mapping
- Automated report generation

## 🛡️ Security Note

This tool is designed for educational and testing purposes. All attack simulations are safe and contained within the local environment.

## 📚 Documentation

- [Installation Guide](INSTALL.md)
- [Architecture Documentation](ARCHITECTURE.md)
- [API Documentation](API_DOCS.md)
- [Technical Documentation](TECHNICAL_DOCUMENTATION.md)
- [Virtual Environment Guide](VENV_GUIDE.md)

## 🤝 Contributing

Contributions are welcome! Please read the documentation and follow the coding standards.

## 📄 License

This project is licensed under the MIT License.

---

**ThreatOps Free** - Empowering security teams with open-source SOC capabilities! 🛡️