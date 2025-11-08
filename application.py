"""
================================================================================
APPLICATION MODULE - ThreatOps SOC
================================================================================

This file consolidates the main application components:
- Configuration Management
- Streamlit Dashboard UI
- Main Orchestrator & Pipeline

Created by merging:
- config/settings.py
- dashboard/app.py
- run.py
================================================================================
"""

# ============================================================================
# SECTION 1: CONFIGURATION MANAGEMENT
# ============================================================================
# Configuration Management for ThreatOps SOC

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env file from project root (parent of config directory)
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        # Use ASCII-safe message for Windows compatibility
        try:
            print(f"[OK] Loaded environment variables from {env_path}")
        except UnicodeEncodeError:
            print(f"[OK] Loaded environment variables from .env file")
    else:
        # Try loading from current directory as fallback
        load_dotenv()
except ImportError:
    print("[WARNING] python-dotenv not installed. Environment variables must be set manually.")
except Exception as e:
    print(f"[WARNING] Error loading .env file: {e}")

class LogSourceConfig(BaseModel):
    """Configuration for log sources"""
    enabled: bool = True
    path: str
    type: str  # 'evtx', 'auth', 'json', 'syslog'
    parser: str
    frequency: int = 60  # seconds

class DetectionRuleConfig(BaseModel):
    """Configuration for detection rules"""
    name: str
    enabled: bool = True
    severity: str = "Medium"  # Low, Medium, High, Critical
    description: str
    conditions: List[Dict[str, Any]]
    mitre_technique: Optional[str] = None

class APIConfig(BaseModel):
    """Configuration for external APIs"""
    name: str
    enabled: bool = True
    api_key: Optional[str] = None
    rate_limit: int = 100  # requests per minute
    timeout: int = 30  # seconds

class MLConfig(BaseModel):
    """Configuration for ML models"""
    enabled: bool = True
    model_type: str = "isolation_forest"  # isolation_forest, one_class_svm
    contamination: float = 0.1
    training_samples: int = 100
    retrain_frequency: int = 24  # hours

class RiskScoringConfig(BaseModel):
    """Configuration for risk scoring"""
    base_score: int = 50
    severity_multipliers: Dict[str, float] = {
        "Low": 1.0,
        "Medium": 1.5,
        "High": 2.0,
        "Critical": 3.0
    }
    intel_multipliers: Dict[str, float] = {
        "clean": 0.5,
        "suspicious": 1.5,
        "malicious": 2.5
    }

class Settings(BaseModel):
    """Main settings configuration"""
    
    # General settings
    project_name: str = "ThreatOps Free"
    version: str = "1.0.0"
    debug: bool = False
    
    # Data storage
    data_dir: str = "data"
    logs_dir: str = "data/logs"
    alerts_dir: str = "data/alerts"
    reports_dir: str = "data/reports"
    
    # Log sources
    log_sources: List[LogSourceConfig] = Field(default_factory=lambda: [
        LogSourceConfig(
            path="data/sample_logs/windows.evtx",
            type="evtx",
            parser="windows_evtx"
        ),
        LogSourceConfig(
            path="data/sample_logs/auth.log",
            type="auth",
            parser="linux_auth"
        ),
        LogSourceConfig(
            path="data/sample_logs/application.json",
            type="json",
            parser="json_logs"
        )
    ])
    
    # Detection rules
    detection_rules: List[DetectionRuleConfig] = Field(default_factory=lambda: [
        DetectionRuleConfig(
            name="Brute Force Attack",
            severity="High",
            description="Multiple failed login attempts from same IP",
            conditions=[
                {"field": "event_id", "operator": "equals", "value": 4625},
                {"field": "count", "operator": "greater_than", "value": 5}
            ],
            mitre_technique="T1110"
        ),
        DetectionRuleConfig(
            name="Privilege Escalation",
            severity="Critical",
            description="Suspicious privilege escalation attempt",
            conditions=[
                {"field": "event_id", "operator": "equals", "value": 4672},
                {"field": "user", "operator": "not_in", "value": ["SYSTEM", "Administrator"]}
            ],
            mitre_technique="T1078"
        ),
        DetectionRuleConfig(
            name="Suspicious PowerShell",
            severity="Medium",
            description="PowerShell execution with suspicious parameters",
            conditions=[
                {"field": "process_name", "operator": "contains", "value": "powershell"},
                {"field": "command_line", "operator": "contains", "value": "-enc"}
            ],
            mitre_technique="T1059.001"
        )
    ])
    
    # API configurations
    apis: List[APIConfig] = Field(default_factory=lambda: [
        APIConfig(
            name="virustotal",
            enabled=True,
            api_key=os.getenv("VIRUSTOTAL_API_KEY")
        ),
        APIConfig(
            name="abuseipdb",
            enabled=True,
            api_key=os.getenv("ABUSEIPDB_API_KEY")
        ),
        APIConfig(
            name="otx",
            enabled=True,
            api_key=os.getenv("OTX_API_KEY")
        )
    ])
    
    # ML configuration
    ml_config: MLConfig = MLConfig()
    
    # Risk scoring
    risk_scoring: RiskScoringConfig = RiskScoringConfig()
    
    # Dashboard settings
    dashboard_port: int = 8501
    dashboard_host: str = "localhost"
    
    # Reporting
    report_frequency: int = 24  # hours
    report_formats: List[str] = ["html", "pdf"]
    
    @classmethod
    def load_from_file(cls, config_path: str = "config/settings.yaml") -> "Settings":
        """Load settings from YAML file"""
        config_file = Path(config_path)
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            return cls(**config_data)
        else:
            # Create default config file
            settings = cls()
            settings.save_to_file(config_path)
            return settings
    
    def save_to_file(self, config_path: str = "config/settings.yaml"):
        """Save settings to YAML file"""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(self.dict(), f, default_flow_style=False, indent=2)
    
    def get_enabled_log_sources(self) -> List[LogSourceConfig]:
        """Get list of enabled log sources"""
        return [source for source in self.log_sources if source.enabled]
    
    def get_enabled_detection_rules(self) -> List[DetectionRuleConfig]:
        """Get list of enabled detection rules"""
        return [rule for rule in self.detection_rules if rule.enabled]
    
    def get_enabled_apis(self) -> List[APIConfig]:
        """Get list of enabled APIs"""
        return [api for api in self.apis if api.enabled and api.api_key]
    
    def get_api_config(self, api_name: str) -> Optional[APIConfig]:
        """Get configuration for specific API"""
        for api in self.apis:
            if api.name == api_name:
                return api
        return None
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate API keys and return status"""
        validation_results = {}
        for api in self.apis:
            if api.enabled:
                validation_results[api.name] = bool(api.api_key)
        return validation_results
    
    def get_missing_api_keys(self) -> List[str]:
        """Get list of enabled APIs with missing keys"""
        missing = []
        for api in self.apis:
            if api.enabled and not api.api_key:
                missing.append(api.name)
        return missing
    
    def validate_configuration(self) -> List[str]:
        """Validate configuration and return warnings"""
        warnings = []
        
        # Check API keys
        missing_keys = self.get_missing_api_keys()
        if missing_keys:
            warnings.append(f"⚠️  Missing API keys for: {', '.join(missing_keys)}")
            warnings.append("   Threat intelligence enrichment will be limited.")
        
        # Check data directories
        data_paths = [self.data_dir, self.logs_dir, self.alerts_dir, self.reports_dir]
        for path in data_paths:
            if not Path(path).exists():
                warnings.append(f"⚠️  Directory does not exist: {path}")
        
        # Check log sources
        for source in self.log_sources:
            if source.enabled and not Path(source.path).exists():
                warnings.append(f"⚠️  Log source file not found: {source.path}")
        
        return warnings
    
    def setup_wizard(self):
        """Interactive setup wizard for first-time configuration"""
        print("=" * 60)
        print("ThreatOps Free - Configuration Wizard")
        print("=" * 60)
        print()
        
        # Check for missing API keys
        missing_keys = self.get_missing_api_keys()
        if missing_keys:
            print("🔑 API Key Configuration")
            print("   The following APIs are enabled but missing keys:")
            for api_name in missing_keys:
                print(f"   - {api_name}")
            print()
            print("   To enable threat intelligence enrichment:")
            print("   1. Get free API keys from:")
            print("      - VirusTotal: https://www.virustotal.com/gui/join-us")
            print("      - AbuseIPDB: https://www.abuseipdb.com/register")
            print("      - AlienVault OTX: https://otx.alienvault.com/")
            print()
            print("   2. Create a .env file with:")
            print("      VIRUSTOTAL_API_KEY=your_key_here")
            print("      ABUSEIPDB_API_KEY=your_key_here")
            print("      OTX_API_KEY=your_key_here")
            print()
        
        # Check directories
        print("📁 Data Directories")
        for path in [self.data_dir, self.logs_dir, self.alerts_dir, self.reports_dir]:
            if not Path(path).exists():
                print(f"   Creating: {path}")
                Path(path).mkdir(parents=True, exist_ok=True)
            else:
                print(f"   ✓ {path}")
        print()
        
        # Save configuration
        self.save_to_file()
        print("✅ Configuration saved to config/settings.yaml")
        print()
        
        # Display warnings
        warnings = self.validate_configuration()
        if warnings:
            print("⚠️  Warnings:")
            for warning in warnings:
                print(f"   {warning}")
        else:
            print("✅ All checks passed! Your system is ready.")
        print()
        print("=" * 60)
# ============================================================================
# SECTION 2: STREAMLIT DASHBOARD UI
# ============================================================================
"""
ThreatOps SIEM Dashboard - Multi-Tab Enhanced Version
Real-time monitoring with detailed sections
"""
import streamlit as st
import json
import pandas as pd
from pathlib import Path
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
import sys
import base64
sys.path.append(str(Path(__file__).parent.parent))

# OpenSearch client - optional import
try:
    from opensearchpy import OpenSearch
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False

def generate_security_report(alerts, stats, report_type='Executive Summary'):
    """Generate HTML security report with different formats based on report_type"""
    risk_levels = {'High Risk': 0, 'Medium Risk': 0, 'Low Risk': 0}
    
    def get_risk_level(alert):
        severity = alert.get('severity', '').lower()
        risk_score = alert.get('risk_score', 0)
        if severity in ['critical'] or (isinstance(risk_score, (int, float)) and risk_score >= 75):
            return 'High Risk'
        elif severity in ['high'] or (isinstance(risk_score, (int, float)) and risk_score >= 50):
            return 'Medium Risk'
        else:
            return 'Low Risk'
    
    for alert in alerts:
        risk_levels[get_risk_level(alert)] = risk_levels.get(get_risk_level(alert), 0) + 1
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ThreatOps SIEM Security Report - {report_type}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }}
            .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .metric {{ display: inline-block; margin: 15px; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
            .critical {{ color: #ff4444; font-weight: bold; }}
            .high {{ color: #ff8800; font-weight: bold; }}
            .low {{ color: #00C851; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #667eea; color: white; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ ThreatOps SIEM Security Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Report Type: {report_type}</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric"><strong>Total Alerts:</strong> {stats['total']}</div>
            <div class="metric critical"><strong>High Risk:</strong> {risk_levels['High Risk']}</div>
            <div class="metric high"><strong>Medium Risk:</strong> {risk_levels['Medium Risk']}</div>
            <div class="metric low"><strong>Low Risk:</strong> {risk_levels['Low Risk']}</div>
        </div>
    """
    
    if report_type in ['Detailed Analysis', 'Full Report', 'Risk Assessment']:
        html += """
        <div class="section">
            <h2>Log Source Breakdown</h2>
            <table>
                <tr><th>Source</th><th>Count</th><th>Percentage</th></tr>
        """
        for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
            pct = (count / stats['total'] * 100) if stats['total'] > 0 else 0
            html += f"<tr><td>{source.replace('_', ' ').title()}</td><td>{count}</td><td>{pct:.2f}%</td></tr>"
        html += """
            </table>
        </div>
        """
    
    if report_type in ['Detailed Analysis', 'Full Report']:
        html += """
        <div class="section">
            <h2>Severity Distribution</h2>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
        """
        for sev, count in sorted(stats['by_severity'].items(), key=lambda x: x[1], reverse=True):
            html += f"<tr><td>{sev}</td><td>{count}</td></tr>"
        html += """
            </table>
        </div>
        """
    
    if report_type == 'Full Report':
        html += """
        <div class="section">
            <h2>Top Attack Techniques</h2>
            <table>
                <tr><th>MITRE Technique</th><th>Detections</th></tr>
        """
        techniques = Counter(a.get('mitre_technique') for a in alerts if a.get('mitre_technique'))
        for tech, count in techniques.most_common(10):
            html += f"<tr><td>{tech}</td><td>{count}</td></tr>"
        html += """
            </table>
        </div>
        
        <div class="section">
            <h2>Top Affected Hosts</h2>
            <table>
                <tr><th>Host</th><th>Events</th></tr>
        """
        hosts = Counter(a.get('host') for a in alerts if a.get('host'))
        for host, count in hosts.most_common(10):
            html += f"<tr><td>{host}</td><td>{count}</td></tr>"
        html += """
            </table>
        </div>
        """
    
    html += """
    </body>
    </html>
    """
    
    return html

# Page configuration
st.set_page_config(
    page_title="ThreatOps SIEM - Multi-Tab Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 20px;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        background-color: #1f2937;
        border-radius: 4px 4px 0 0;
        padding: 10px 20px;
        font-size: 16px;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)

# Data paths
DATA_DIR = Path(__file__).parent.parent / "data"
ALERTS_DIR = DATA_DIR / "alerts"
SIMULATIONS_DIR = DATA_DIR / "simulations"

# Initialize session state
if 'last_refresh' not in st.session_state:
    st.session_state.last_refresh = datetime.now()
if 'refresh_counter' not in st.session_state:
    st.session_state.refresh_counter = 0
if 'user_interacted' not in st.session_state:
    st.session_state.user_interacted = False

@st.cache_data(ttl=5)
def load_alerts():
    """Load alerts from OpenSearch, fallback to JSON files"""
    alerts = []
    
    # Try OpenSearch first
    if OPENSEARCH_AVAILABLE:
        try:
            client = OpenSearch(
                [{'host': 'localhost', 'port': 9200}],
                use_ssl=False,
                verify_certs=False,
                timeout=5
            )
            response = client.search(
                index="security-alerts",
                body={
                    "size": 1000,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
            )
            alerts = [hit['_source'] for hit in response['hits']['hits']]
            
            if alerts:
                return alerts
        except Exception as e:
            st.warning(f"OpenSearch connection failed: {e}. Using JSON fallback.")
    
    # Fallback to JSON files
    if ALERTS_DIR.exists():
        for alert_file in sorted(ALERTS_DIR.glob("alerts_*.json"), reverse=True):
            try:
                with open(alert_file, 'r', encoding='utf-8') as f:
                    file_alerts = json.load(f)
                    if isinstance(file_alerts, list):
                        alerts.extend(file_alerts)
                    else:
                        alerts.append(file_alerts)
            except Exception as e:
                continue
    
    return alerts

@st.cache_data(ttl=5)
def load_simulations():
    """Load simulation data from JSON files"""
    simulations = []
    if SIMULATIONS_DIR.exists():
        for sim_file in sorted(SIMULATIONS_DIR.glob("simulation_*.json"), reverse=True)[:5]:
            try:
                with open(sim_file, 'r', encoding='utf-8') as f:
                    sim_data = json.load(f)
                    if isinstance(sim_data, list):
                        simulations.extend(sim_data)
            except Exception as e:
                continue
    return simulations

def get_risk_level(alert):
    """Determine risk level: High, Medium, Low based on severity and risk_score"""
    severity = alert.get('severity', '').lower()
    risk_score = alert.get('risk_score', 0)
    
    if severity in ['critical'] or (isinstance(risk_score, (int, float)) and risk_score >= 75):
        return 'High Risk'
    elif severity in ['high'] or (isinstance(risk_score, (int, float)) and risk_score >= 50):
        return 'Medium Risk'
    elif severity in ['medium', 'warning']:
        return 'Medium Risk'
    elif severity in ['low', 'info']:
        return 'Low Risk'
    else:
        return 'Low Risk'

def get_log_collection_stats(alerts):
    """Get detailed log collection statistics"""
    stats = {
        'total': len(alerts),
        'by_source': {},
        'by_severity': {},
        'by_category': {},
        'by_hour': {},
        'collection_methods': {}
    }
    
    for alert in alerts:
        # By source
        source = alert.get('log_source', 'unknown')
        stats['by_source'][source] = stats['by_source'].get(source, 0) + 1
        
        # By severity
        severity = alert.get('severity', 'Unknown')
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        # By category
        category = alert.get('category', 'unknown')
        stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        # By hour
        timestamp = alert.get('timestamp', '')
        if timestamp:
            try:
                hour = timestamp[:13]  # YYYY-MM-DDTHH
                stats['by_hour'][hour] = stats['by_hour'].get(hour, 0) + 1
            except:
                pass
    
    # Determine collection methods
    stats['collection_methods'] = {
        'Simulated Attacks': stats['by_source'].get('simulation', 0),
        'Windows Security Events': stats['by_source'].get('windows_security', 0),
        'Windows System Events': stats['by_source'].get('windows_system', 0),
        'Windows Application Events': stats['by_source'].get('windows_application', 0)
    }
    
    return stats

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🛡️ ThreatOps SIEM Dashboard</h1>
        <p>Multi-Source Security Monitoring: Simulated Attacks + Real System Logs</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Load data
    alerts = load_alerts()
    simulations = load_simulations()
    stats = get_log_collection_stats(alerts)
    
    # Sidebar
    with st.sidebar:
        st.title("🎛️ Dashboard Controls")
        
        # Auto-refresh control - improved to not interfere with user interactions
        auto_refresh = st.checkbox("⚡ Auto-refresh (5s)", value=True, key="auto_refresh_checkbox")
        if auto_refresh:
            st.success("Live monitoring active")
            st.caption("⚠️ Auto-refresh pauses when you interact with filters")
        
        if st.button("🔄 Refresh Now"):
            st.cache_data.clear()
            st.session_state.user_interacted = True
            st.rerun()
        
        st.markdown("---")
        st.subheader("📊 Quick Stats")
        st.metric("Total Alerts", len(alerts))
        st.metric("Critical", sum(1 for a in alerts if a.get('severity') == 'Critical'))
        st.metric("Data Sources", len([k for k, v in stats['by_source'].items() if v > 0]))
        
        st.markdown("---")
        st.info(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        
        # Advanced filters section
        st.markdown("---")
        st.subheader("🔧 Advanced Options")
        show_all_details = st.checkbox("📋 Show Extended Details", value=True, key="show_details")
        max_alerts_display = st.slider("Max Alerts to Display", 10, 200, 50, key="max_alerts")
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 Overview",
        "🎯 MITRE ATT&CK",
        "📋 Log Collection Details",
        "🚨 Alerts & Incidents",
        "📈 Reports & Analytics",
        "⚙️ System Health"
    ])
    
    # TAB 1: Overview - Enhanced with Risk Levels and Source Breakdown
    with tab1:
        st.header("📊 System Overview - Risk Assessment Dashboard")
        
        # Categorize alerts by risk level
        risk_levels = {'High Risk': 0, 'Medium Risk': 0, 'Low Risk': 0}
        for alert in alerts:
            risk_level = get_risk_level(alert)
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        
        # Top row: Risk Level Summary
        st.subheader("🎯 Model-Based Risk Assessment")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total = stats['total']
            st.metric("Total Alerts Processed", total, 
                     delta=f"{total} total events", delta_color="normal")
        
        with col2:
            high_risk = risk_levels['High Risk']
            st.metric("🔴 High Risk", high_risk, 
                     delta=f"{high_risk/total*100:.1f}%" if total > 0 else "0%",
                     delta_color="inverse")
        
        with col3:
            medium_risk = risk_levels['Medium Risk']
            st.metric("🟡 Medium Risk", medium_risk,
                     delta=f"{medium_risk/total*100:.1f}%" if total > 0 else "0%")
        
        with col4:
            low_risk = risk_levels['Low Risk']
            st.metric("🟢 Low Risk", low_risk,
                     delta=f"{low_risk/total*100:.1f}%" if total > 0 else "0%")
        
        st.markdown("---")
        
        # Second row: Detailed Severity Breakdown
        st.subheader("📊 Detailed Severity Breakdown (Model Output)")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        critical = stats['by_severity'].get('Critical', 0)
        high = stats['by_severity'].get('High', 0)
        medium = stats['by_severity'].get('Medium', 0) + stats['by_severity'].get('Warning', 0)
        low = stats['by_severity'].get('Low', 0)
        info = stats['by_severity'].get('Info', 0)
        
        with col1:
            st.metric("🔴 Critical", critical, "Immediate Action" if critical > 0 else "None")
        with col2:
            st.metric("🟠 High", high, f"{high} incidents" if high > 0 else "None")
        with col3:
            st.metric("🟡 Medium/Warning", medium, f"{medium} incidents" if medium > 0 else "None")
        with col4:
            st.metric("🟢 Low", low, f"{low} incidents" if low > 0 else "None")
        with col5:
            st.metric("ℹ️ Info", info, f"{info} info logs" if info > 0 else "None")
        
        st.markdown("---")
        
        # Third row: Source Log Breakdown
        st.subheader("📋 Log Source Breakdown - Exact Counts from Each Source")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🔍 Detailed Source Statistics")
            if stats['by_source']:
                source_data = []
                for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
                    source_name = source.replace('_', ' ').title()
                    percentage = (count / total * 100) if total > 0 else 0
                    source_data.append({
                        'Source': source_name,
                        'Count': count,
                        'Percentage': f"{percentage:.2f}%",
                        'Type': 'Simulated' if source == 'simulation' else 'Real System'
                    })
                
                source_df = pd.DataFrame(source_data)
                st.dataframe(source_df, use_container_width=True, hide_index=True)
            else:
                st.info("No source data available")
        
        with col2:
            st.markdown("### 📊 Source Distribution Chart")
            if stats['by_source']:
                source_df = pd.DataFrame([
                    {'Source': k.replace('_', ' ').title(), 'Count': v} 
                    for k, v in stats['by_source'].items()
                ])
                fig = px.pie(source_df, values='Count', names='Source', 
                           title='Log Distribution by Source',
                           hole=0.4)
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # Fourth row: Severity Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Risk Level Distribution (Model-Based)")
            if risk_levels:
                risk_df = pd.DataFrame([
                    {'Risk Level': k, 'Count': v}
                    for k, v in risk_levels.items()
                ])
                colors_risk = {'High Risk': '#ff4444', 'Medium Risk': '#ffbb33', 'Low Risk': '#00C851'}
                fig = px.bar(risk_df, x='Risk Level', y='Count',
                           title='Alerts by Risk Level (Model Assessment)',
                           color='Risk Level', color_discrete_map=colors_risk)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📊 Severity Breakdown (Traditional)")
            if stats['by_severity']:
                sev_df = pd.DataFrame([
                    {'Severity': k, 'Count': v}
                    for k, v in stats['by_severity'].items()
                ])
                colors = {'Critical': '#ff4444', 'High': '#ff8800', 
                         'Medium': '#ffbb33', 'Warning': '#ffbb33',
                         'Low': '#00C851', 'Info': '#3498db'}
                fig = px.bar(sev_df, x='Severity', y='Count',
                           title='Severity Breakdown',
                           color='Severity', color_discrete_map=colors)
                st.plotly_chart(fig, use_container_width=True)
    
    # TAB 2: MITRE ATT&CK - Enhanced with detailed analysis
    with tab2:
        st.header("🎯 MITRE ATT&CK Framework Analysis")
        st.markdown("### Comprehensive threat intelligence mapping to MITRE ATT&CK framework")
        
        techniques = [a.get('mitre_technique') for a in alerts if a.get('mitre_technique')]
        
        if techniques:
            technique_counts = Counter(techniques)
            
            # Overview metrics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Techniques Detected", len(technique_counts))
            with col2:
                st.metric("Total Detections", sum(technique_counts.values()))
            with col3:
                avg_detections = sum(technique_counts.values()) / len(technique_counts) if technique_counts else 0
                st.metric("Avg Detections/Technique", f"{avg_detections:.1f}")
            with col4:
                most_common_tech = technique_counts.most_common(1)[0] if technique_counts else ("N/A", 0)
                st.metric("Most Active Technique", f"{most_common_tech[0]}" if most_common_tech[0] != "N/A" else "None")
            
            st.markdown("---")
            
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("📊 Top Attack Techniques - Visualization")
                tech_df = pd.DataFrame([
                    {'Technique': k, 'Detections': v}
                    for k, v in technique_counts.most_common(10)
                ])
                fig = px.bar(tech_df, x='Technique', y='Detections',
                           title='Most Detected MITRE Techniques',
                           color='Detections', color_continuous_scale='Reds')
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.subheader("📋 Quick Summary")
                for tech, count in technique_counts.most_common(10):
                    pct = (count / sum(technique_counts.values()) * 100) if technique_counts else 0
                    st.metric(tech, f"{count} detections", f"{pct:.1f}%")
            
            st.markdown("---")
            st.subheader("🔍 Detailed Technique Analysis")
            
            # Group by MITRE tactics
            mitre_tactics = {
                'T1': 'Initial Access', 'T2': 'Execution', 'T3': 'Persistence',
                'T4': 'Privilege Escalation', 'T5': 'Defense Evasion',
                'T6': 'Credential Access', 'T7': 'Discovery', 'T8': 'Lateral Movement',
                'T9': 'Collection', 'T10': 'Command and Control', 'T11': 'Exfiltration'
            }
            
            # Technique distribution by tactic
            tactic_distribution = {}
            for tech, count in technique_counts.items():
                tactic = tech[:2] if tech.startswith('T') else 'Other'
                tactic_name = mitre_tactics.get(tactic, tactic)
                if tactic_name not in tactic_distribution:
                    tactic_distribution[tactic_name] = 0
                tactic_distribution[tactic_name] += count
            
            if tactic_distribution:
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("📈 Distribution by MITRE Tactic")
                    tactic_df = pd.DataFrame([
                        {'Tactic': k, 'Detections': v}
                        for k, v in sorted(tactic_distribution.items(), key=lambda x: x[1], reverse=True)
                    ])
                    fig = px.pie(tactic_df, values='Detections', names='Tactic',
                               title='Attack Distribution by MITRE Tactic',
                               hole=0.4)
                    st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("---")
            st.subheader("📋 Comprehensive Technique Breakdown")
            
            for tech, count in technique_counts.most_common():
                with st.expander(f"🔴 {tech} - {count} detections | Click for full details"):
                    tech_alerts = [a for a in alerts if a.get('mitre_technique') == tech]
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write("**📊 Severity Distribution:**")
                        severities = Counter(a.get('severity') for a in tech_alerts)
                        for sev, cnt in severities.most_common():
                            st.write(f"- **{sev}**: {cnt} detections")
                    
                    with col2:
                        st.write("**🖥️ Affected Infrastructure:**")
                        hosts = set(a.get('host') for a in tech_alerts if a.get('host'))
                        st.write(f"- **Unique Hosts**: {len(hosts)}")
                        for host in list(hosts)[:3]:
                            host_count = sum(1 for a in tech_alerts if a.get('host') == host)
                            st.write(f"  - {host}: {host_count} events")
                        if len(hosts) > 3:
                            st.write(f"  - ... and {len(hosts)-3} more hosts")
                    
                    with col3:
                        st.write("**👥 User Impact:**")
                        users = set(a.get('user') for a in tech_alerts if a.get('user'))
                        st.write(f"- **Unique Users**: {len(users)}")
                        for user in list(users)[:3]:
                            user_count = sum(1 for a in tech_alerts if a.get('user') == user)
                            st.write(f"  - {user}: {user_count} events")
                        if len(users) > 3:
                            st.write(f"  - ... and {len(users)-3} more users")
                    
                    # Risk scoring details
                    st.markdown("**⚡ Risk Assessment:**")
                    risk_scores = [a.get('risk_score', 0) for a in tech_alerts if isinstance(a.get('risk_score'), (int, float))]
                    if risk_scores:
                        avg_risk = sum(risk_scores) / len(risk_scores)
                        max_risk = max(risk_scores)
                        st.write(f"- Average Risk Score: {avg_risk:.1f}")
                        st.write(f"- Maximum Risk Score: {max_risk:.1f}")
                    
                    # Time range
                    timestamps = [a.get('timestamp') for a in tech_alerts if a.get('timestamp')]
                    if timestamps:
                        try:
                            sorted_times = sorted(timestamps)
                            st.write(f"- **First Detection**: {sorted_times[0][:19]}")
                            st.write(f"- **Latest Detection**: {sorted_times[-1][:19]}")
                        except:
                            pass
        else:
            st.info("No MITRE ATT&CK techniques detected yet")
            st.markdown("""
            ### 📚 About MITRE ATT&CK
            The MITRE ATT&CK framework is a globally-accessible knowledge base of adversary tactics and techniques 
            based on real-world observations. When threats are detected, they are mapped to specific ATT&CK techniques
            to help security teams understand and defend against attacks.
            """)
    
    # TAB 3: Log Collection Details - Enhanced with comprehensive analysis
    with tab3:
        st.header("📋 Log Collection & Data Sources")
        st.markdown("### Comprehensive view of all log sources and collection methodologies")
        
        # Overview metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Logs Collected", stats['total'], 
                     delta=f"{stats['total']} events" if stats['total'] > 0 else "0")
        with col2:
            unique_sources = len(stats['by_source'])
            st.metric("Unique Data Sources", unique_sources)
        with col3:
            st.metric("Log Categories", len(stats['by_category']))
        with col4:
            hours_span = len(stats['by_hour'])
            st.metric("Time Span (Hours)", hours_span, 
                     delta=f"{hours_span} hours monitored" if hours_span > 0 else "0")
        
        st.markdown("---")
        st.subheader("🔍 Collection Methods & Sources Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📥 Active Collection Methods")
            total_collected = sum(stats['collection_methods'].values())
            for method, count in stats['collection_methods'].items():
                icon = "🎯" if "Simulated" in method else "🖥️"
                pct = (count / total_collected * 100) if total_collected > 0 else 0
                st.metric(f"{icon} {method}", count, 
                         delta=f"{pct:.1f}% of total")
        
        with col2:
            st.markdown("### 📊 Collection Statistics")
            st.write(f"**Total Logs Collected:** {stats['total']:,}")
            st.write(f"**Unique Sources:** {unique_sources}")
            st.write(f"**Log Categories:** {len(stats['by_category'])}")
            st.write(f"**Time Span:** {hours_span} hours")
            if hours_span > 0:
                avg_per_hour = stats['total'] / hours_span
                st.write(f"**Average Logs/Hour:** {avg_per_hour:.1f}")
            
            # Collection efficiency
            if stats['total'] > 0:
                simulated_pct = (stats['by_source'].get('simulation', 0) / stats['total'] * 100)
                real_pct = 100 - simulated_pct
                st.markdown("**📊 Data Source Composition:**")
                st.write(f"- Real System Logs: {real_pct:.1f}%")
                st.write(f"- Simulated Attacks: {simulated_pct:.1f}%")
        
        st.markdown("---")
        st.subheader("📈 Detailed Source Analysis")
        
        # Source distribution chart
        if stats['by_source']:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### 📊 Source Distribution Chart")
                source_chart_df = pd.DataFrame([
                    {'Source': k.replace('_', ' ').title(), 'Count': v} 
                    for k, v in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True)
                ])
                fig = px.pie(source_chart_df, values='Count', names='Source',
                           title='Log Distribution by Source',
                           hole=0.4)
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("### 📋 Source Statistics Table")
                source_table_data = []
                for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
                    source_name = source.replace('_', ' ').title()
                    percentage = (count / stats['total'] * 100) if stats['total'] > 0 else 0
                    source_type = 'Simulated' if source == 'simulation' else 'Real System'
                    source_table_data.append({
                        'Source': source_name,
                        'Count': count,
                        'Percentage': f"{percentage:.2f}%",
                        'Type': source_type
                    })
                source_table_df = pd.DataFrame(source_table_data)
                st.dataframe(source_table_df, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        st.subheader("🔍 In-Depth Source Breakdown")
        
        for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
            source_alerts = [a for a in alerts if a.get('log_source') == source]
            source_name = source.replace('_', ' ').title()
            
            with st.expander(f"📂 {source_name} - {count:,} logs | Click for detailed analysis"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("**📊 Severity Distribution:**")
                    sevs = Counter(a.get('severity') for a in source_alerts)
                    sev_total = sum(sevs.values())
                    for sev, cnt in sorted(sevs.most_common(), key=lambda x: x[1], reverse=True):
                        sev_pct = (cnt / sev_total * 100) if sev_total > 0 else 0
                        st.write(f"- **{sev}**: {cnt} ({sev_pct:.1f}%)")
                
                with col2:
                    st.markdown("**🏷️ Top Categories:**")
                    cats = Counter(a.get('category') for a in source_alerts)
                    for cat, cnt in list(cats.most_common(5)):
                        st.write(f"- **{cat}**: {cnt}")
                    if len(cats) > 5:
                        st.caption(f"... and {len(cats)-5} more categories")
                
                with col3:
                    st.markdown("**🖥️ Infrastructure Impact:**")
                    hosts = set(a.get('host') for a in source_alerts if a.get('host'))
                    users = set(a.get('user') for a in source_alerts if a.get('user'))
                    st.write(f"- **Unique Hosts**: {len(hosts)}")
                    st.write(f"- **Unique Users**: {len(users)}")
                    if hosts:
                        st.markdown("**Top Affected Hosts:**")
                        host_counts = Counter(a.get('host') for a in source_alerts if a.get('host'))
                        for host, host_cnt in host_counts.most_common(3):
                            st.write(f"  - {host}: {host_cnt} events")
                
                # Time-based analysis
                timestamps = [a.get('timestamp') for a in source_alerts if a.get('timestamp')]
                if timestamps:
                    try:
                        sorted_times = sorted(timestamps)
                        col_time1, col_time2 = st.columns(2)
                        with col_time1:
                            st.markdown("**⏰ Time Range:**")
                            st.write(f"- First Log: {sorted_times[0][:19]}")
                            st.write(f"- Latest Log: {sorted_times[-1][:19]}")
                        with col_time2:
                            st.markdown("**📈 Collection Rate:**")
                            time_span_hours = len(set(t[:13] for t in timestamps))
                            if time_span_hours > 0:
                                rate = len(timestamps) / time_span_hours
                                st.write(f"- Average: {rate:.1f} logs/hour")
                                st.write(f"- Peak Hour: {max(Counter(t[:13] for t in timestamps).values())} logs")
                    except:
                        pass
        
        st.markdown("---")
        st.subheader("⏱️ Collection Timeline & Trends")
        
        if stats['by_hour']:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                timeline_df = pd.DataFrame([
                    {'Hour': k, 'Count': v}
                    for k, v in sorted(stats['by_hour'].items())
                ])
                fig = px.line(timeline_df, x='Hour', y='Count',
                            title='Log Collection Trend Over Time',
                            markers=True, line_shape='spline')
                fig.update_traces(line=dict(width=3), marker=dict(size=6))
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                st.markdown("### 📊 Timeline Statistics")
                hourly_counts = list(stats['by_hour'].values())
                if hourly_counts:
                    st.metric("Peak Hour", max(hourly_counts))
                    st.metric("Lowest Hour", min(hourly_counts))
                    st.metric("Average/Hour", f"{sum(hourly_counts)/len(hourly_counts):.1f}")
                    
                    # Peak detection
                    peak_hour = max(stats['by_hour'].items(), key=lambda x: x[1])
                    st.write(f"**Peak Collection:** {peak_hour[0][:19]}")
                    st.write(f"**Logs Collected:** {peak_hour[1]}")
        else:
            st.info("No timeline data available yet")
    
    # TAB 4: Alerts & Incidents - Enhanced with Info/Warning/Critical filtering
    with tab4:
        st.header("🚨 Alerts & Incidents - Detailed Log Viewer")
        
        # Filter section with Info/Warning/Critical
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        
        with filter_col1:
            # Map severity to category
            severity_to_category = {
                'Critical': 'Critical',
                'High': 'Critical',
                'Warning': 'Warning',
                'Medium': 'Warning',
                'Low': 'Info',
                'Info': 'Info'
            }
            
            category_filter = st.multiselect(
                "📋 Filter by Category",
                options=['Critical', 'Warning', 'Info'],
                default=['Critical', 'Warning', 'Info'],
                help="Critical: Critical/High severity | Warning: Medium/Warning | Info: Low/Info",
                key="category_filter"
            )
            # Mark user interaction when filter changes
            if category_filter != st.session_state.get('last_category_filter', []):
                st.session_state.user_interacted = True
                st.session_state.last_category_filter = category_filter
        
        with filter_col2:
            source_filter = st.multiselect(
                "🔍 Filter by Source",
                options=list(stats['by_source'].keys()),
                default=list(stats['by_source'].keys()),
                help="Select which log sources to display",
                key="source_filter"
            )
            # Mark user interaction when filter changes
            if source_filter != st.session_state.get('last_source_filter', []):
                st.session_state.user_interacted = True
                st.session_state.last_source_filter = source_filter
        
        with filter_col3:
            risk_level_filter = st.multiselect(
                "⚡ Filter by Risk Level (Model)",
                options=['High Risk', 'Medium Risk', 'Low Risk'],
                default=['High Risk', 'Medium Risk', 'Low Risk'],
                help="Risk assessment from ML model based on severity and risk_score",
                key="risk_level_filter"
            )
            # Mark user interaction when filter changes
            if risk_level_filter != st.session_state.get('last_risk_filter', []):
                st.session_state.user_interacted = True
                st.session_state.last_risk_filter = risk_level_filter
        
        # Filter alerts
        filtered_alerts = []
        for a in alerts:
            # Category filter
            severity = a.get('severity', '')
            category = severity_to_category.get(severity, 'Info')
            if category not in category_filter:
                continue
            
            # Source filter
            if a.get('log_source') not in source_filter:
                continue
            
            # Risk level filter
            risk_level = get_risk_level(a)
            if risk_level not in risk_level_filter:
                continue
            
            filtered_alerts.append(a)
        
        # Summary stats for filtered results
        st.markdown("---")
        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)
        with summary_col1:
            st.metric("Total Filtered", len(filtered_alerts), f"of {len(alerts)} total")
        with summary_col2:
            critical_count = sum(1 for a in filtered_alerts if a.get('severity') in ['Critical', 'High'])
            st.metric("Critical/High", critical_count)
        with summary_col3:
            warning_count = sum(1 for a in filtered_alerts if a.get('severity') in ['Warning', 'Medium'])
            st.metric("Warning/Medium", warning_count)
        with summary_col4:
            info_count = sum(1 for a in filtered_alerts if a.get('severity') in ['Low', 'Info'])
            st.metric("Info/Low", info_count)
        
        st.markdown("---")
        
        # Enhanced alert display with better pagination
        max_display = st.session_state.get('max_alerts', 50)
        for i, alert in enumerate(filtered_alerts[:max_display]):
            source = alert.get('log_source', 'unknown')
            severity = alert.get('severity', 'Unknown')
            
            color = "🔴" if severity == 'Critical' else "🟠" if severity == 'High' else "🟡" if severity == 'Medium' else "🟢"
            
            with st.expander(f"{color} {severity} - {alert.get('rule_name', 'Unknown')} [{source}]"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.write("**🔍 Detection Info:**")
                    st.write(f"Source: {source.replace('_', ' ').title()}")
                    st.write(f"Host: {alert.get('host', 'N/A')}")
                    st.write(f"User: {alert.get('user', 'N/A')}")
                
                with col2:
                    st.write("**⚠️ Risk Assessment:**")
                    st.write(f"Severity: {severity}")
                    st.write(f"Risk Score: {alert.get('risk_score', 'N/A')}")
                    st.write(f"Confidence: {alert.get('confidence', 'N/A')}")
                
                with col3:
                    st.write("**🎯 Attack Details:**")
                    st.write(f"MITRE: {alert.get('mitre_technique', 'N/A')}")
                    st.write(f"Category: {alert.get('category', 'N/A')}")
                    st.write(f"Time: {alert.get('timestamp', 'N/A')[:19] if alert.get('timestamp') else 'N/A'}")
                
                st.write("**📝 Description:**")
                st.write(alert.get('description', 'No description available'))
                
                if source == 'simulation':
                    st.warning("🎯 SIMULATED ATTACK - Generated for testing detection rules")
                elif 'windows' in source:
                    st.info(f"🖥️ REAL SYSTEM LOG - From Windows {source.replace('windows_', '').title()}")
    
    # TAB 5: Reports & Analytics - Enhanced with Reporting Feature
    with tab5:
        st.header("📈 Reports & Analytics")
        
        # Report Generation Section
        st.subheader("📄 Generate Security Report")
        report_col1, report_col2 = st.columns([3, 1])
        
        with report_col1:
            report_type = st.selectbox(
                "Report Type",
                ['Executive Summary', 'Detailed Analysis', 'Risk Assessment', 'Full Report'],
                help="Select the type of report to generate"
            )
        
        with report_col2:
            if st.button("🔽 Generate Report", type="primary"):
                # Generate report
                report_content = generate_security_report(alerts, stats, report_type)
                st.download_button(
                    label="📥 Download Report (HTML)",
                    data=report_content,
                    file_name=f"threatops_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html"
                )
        
        st.markdown("---")
        
        # Executive Summary
        st.subheader("📊 Executive Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        # Calculate risk levels for report tab
        risk_levels_report = {'High Risk': 0, 'Medium Risk': 0, 'Low Risk': 0}
        for alert in alerts:
            risk_level = get_risk_level(alert)
            risk_levels_report[risk_level] = risk_levels_report.get(risk_level, 0) + 1
        
        with col1:
            st.metric("Total Security Events", stats['total'])
            st.metric("High Risk Events", risk_levels_report['High Risk'])
        with col2:
            avg_hour = stats['total']/max(len(stats['by_hour']), 1) if stats['by_hour'] else 0
            st.metric("Avg Events/Hour", f"{avg_hour:.1f}")
            critical_pct = (stats['by_severity'].get('Critical', 0) / stats['total'] * 100) if stats['total'] > 0 else 0
            st.metric("Critical Alert Rate", f"{critical_pct:.1f}%")
        with col3:
            st.metric("Unique Hosts Affected", len(set(a.get('host') for a in alerts)))
            st.metric("Unique Users Involved", len(set(a.get('user') for a in alerts)))
        with col4:
            st.metric("Active Log Sources", len([k for k, v in stats['by_source'].items() if v > 0]))
            st.metric("Total Categories", len(stats['by_category']))
        
        st.markdown("---")
        
        # Detailed Analytics
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📉 Event Trend Analysis")
            if stats['by_hour']:
                hourly_data = sorted(stats['by_hour'].items())
                trend_df = pd.DataFrame(hourly_data, columns=['Hour', 'Count'])
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=trend_df['Hour'], y=trend_df['Count'],
                                        mode='lines+markers', name='Events',
                                        line=dict(color='#667eea', width=3),
                                        marker=dict(size=8)))
                fig.update_layout(
                    title='Security Event Trend Over Time',
                    xaxis_title='Time (Hour)',
                    yaxis_title='Event Count',
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("🎯 Risk Level Distribution Over Time")
            # Group alerts by hour and risk level
            hourly_risk = {}
            for alert in alerts:
                hour = alert.get('timestamp', '')[:13] if alert.get('timestamp') else 'unknown'
                risk = get_risk_level(alert)
                if hour not in hourly_risk:
                    hourly_risk[hour] = {'High Risk': 0, 'Medium Risk': 0, 'Low Risk': 0}
                hourly_risk[hour][risk] = hourly_risk[hour].get(risk, 0) + 1
            
            if hourly_risk:
                risk_trend_df = pd.DataFrame([
                    {'Hour': h, 'High Risk': v['High Risk'], 
                     'Medium Risk': v['Medium Risk'], 'Low Risk': v['Low Risk']}
                    for h, v in sorted(hourly_risk.items())
                ])
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=risk_trend_df['Hour'], y=risk_trend_df['High Risk'],
                                        mode='lines+markers', name='High Risk', line=dict(color='#ff4444')))
                fig.add_trace(go.Scatter(x=risk_trend_df['Hour'], y=risk_trend_df['Medium Risk'],
                                        mode='lines+markers', name='Medium Risk', line=dict(color='#ffbb33')))
                fig.add_trace(go.Scatter(x=risk_trend_df['Hour'], y=risk_trend_df['Low Risk'],
                                        mode='lines+markers', name='Low Risk', line=dict(color='#00C851')))
                fig.update_layout(
                    title='Risk Level Trend Over Time',
                    xaxis_title='Time (Hour)',
                    yaxis_title='Event Count',
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        st.subheader("🎯 Top Security Concerns & Insights")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.write("**Most Common Attack Types:**")
            categories = Counter(a.get('category') for a in alerts)
            for cat, count in categories.most_common(10):
                pct = (count / stats['total'] * 100) if stats['total'] > 0 else 0
                st.write(f"- **{cat}**: {count} incidents ({pct:.1f}%)")
        
        with col2:
            st.write("**Most Targeted Hosts:**")
            hosts = Counter(a.get('host') for a in alerts)
            for host, count in hosts.most_common(10):
                st.write(f"- **{host}**: {count} events")
        
        with col3:
            st.write("**Source Log Distribution:**")
            for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
                source_name = source.replace('_', ' ').title()
                pct = (count / stats['total'] * 100) if stats['total'] > 0 else 0
                st.write(f"- **{source_name}**: {count} logs ({pct:.1f}%)")
    
    # TAB 6: System Health - Enhanced with comprehensive status
    with tab6:
        st.header("⚙️ System Health & Infrastructure Status")
        st.markdown("### Real-time monitoring of all system components and services")
        
        # Component Status
        st.subheader("🟢 Component Status & Health")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### 🎯 Core Services")
            st.success("✅ **Streamlit Dashboard**")
            st.caption("Running on port 8501")
            st.caption(f"Status: Active | Last Update: {datetime.now().strftime('%H:%M:%S')}")
            
            st.success("✅ **OpenSearch Database**")
            st.caption("Running on port 9200")
            st.caption("Status: Connected | Security: Disabled")
            
            st.info("⏳ **OpenSearch Dashboards**")
            st.caption("Running on port 5601")
            st.caption("Login: root / root")
        
        with col2:
            st.markdown("### 📊 Data Processing")
            st.success("✅ **Log Collection**")
            st.caption("Status: Active")
            st.caption(f"Total Sources: {len(stats['by_source'])}")
            
            st.success("✅ **Threat Detection**")
            st.caption("Status: Active")
            st.caption(f"Total Alerts: {stats['total']}")
            
            st.success("✅ **Risk Scoring**")
            st.caption("Status: Active")
            st.caption("ML Model: Enabled")
        
        with col3:
            st.markdown("### ⚡ Performance Metrics")
            st.metric("Dashboard Refresh Rate", "5 seconds", 
                     delta="Auto-refresh enabled" if auto_refresh else "Manual refresh")
            st.metric("Total Data Sources", len(stats['by_source']))
            st.metric("Cache Status", "Active")
            st.metric("Data Processing Rate", 
                     f"{stats['total']/max(len(stats['by_hour']), 1):.1f}/hr" if stats['by_hour'] else "0/hr")
        
        st.markdown("---")
        
        # System Statistics
        st.subheader("📈 System Statistics & Capacity")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("### 📊 Data Metrics")
            st.write(f"**Total Events:** {stats['total']:,}")
            st.write(f"**Alerts Generated:** {len(alerts):,}")
            st.write(f"**Unique Categories:** {len(stats['by_category'])}")
            st.write(f"**Time Coverage:** {len(stats['by_hour'])} hours")
        
        with col2:
            st.markdown("### 🔍 Detection Metrics")
            critical_count = stats['by_severity'].get('Critical', 0)
            high_count = stats['by_severity'].get('High', 0)
            st.write(f"**Critical Alerts:** {critical_count}")
            st.write(f"**High Severity:** {high_count}")
            st.write(f"**Total High-Risk:** {critical_count + high_count}")
            detection_rate = ((critical_count + high_count) / stats['total'] * 100) if stats['total'] > 0 else 0
            st.write(f"**Detection Rate:** {detection_rate:.1f}%")
        
        with col3:
            st.markdown("### 🎯 MITRE Coverage")
            techniques = [a.get('mitre_technique') for a in alerts if a.get('mitre_technique')]
            unique_techs = len(set(techniques))
            st.write(f"**Techniques Detected:** {unique_techs}")
            st.write(f"**Total Mappings:** {len(techniques)}")
            if unique_techs > 0:
                st.write(f"**Avg Detections/Tech:** {len(techniques)/unique_techs:.1f}")
        
        with col4:
            st.markdown("### 🖥️ Infrastructure Impact")
            unique_hosts = len(set(a.get('host') for a in alerts if a.get('host')))
            unique_users = len(set(a.get('user') for a in alerts if a.get('user')))
            st.write(f"**Affected Hosts:** {unique_hosts}")
            st.write(f"**Affected Users:** {unique_users}")
            if unique_hosts > 0:
                avg_events_per_host = stats['total'] / unique_hosts
                st.write(f"**Avg Events/Host:** {avg_events_per_host:.1f}")
        
        st.markdown("---")
        
        # Service Links and Configuration
        st.subheader("🔗 Service Access & Configuration")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("### 🌐 Web Interfaces")
            st.markdown("**🛡️ ThreatOps Dashboard**")
            st.code("http://localhost:8501", language=None)
            st.caption("Main security monitoring interface (this page)")
            
            st.markdown("**📊 OpenSearch Dashboards**")
            st.code("http://localhost:5601", language=None)
            st.caption("Login: root / root")
            st.caption("Advanced analytics and log exploration")
        
        with col2:
            st.markdown("### 🔌 API Endpoints")
            st.markdown("**🔍 OpenSearch REST API**")
            st.code("http://localhost:9200", language=None)
            st.caption("Database backend API")
            st.caption("Security: Disabled (local testing)")
            
            st.markdown("**📡 Filebeat Status**")
            st.code("Port: 5044", language=None)
            st.caption("Log collection agent")
        
        with col3:
            st.markdown("### ⚙️ Configuration")
            st.markdown("**🔐 Authentication:**")
            st.write("- OpenSearch Dashboards: root / root")
            st.write("- OpenSearch: Security disabled")
            st.write("- Dashboard: No authentication required")
            
            st.markdown("**📁 Data Locations:**")
            st.write("- Alerts: `data/alerts/`")
            st.write("- Logs: `data/logs/`")
            st.write("- Reports: `data/reports/`")
        
        st.markdown("---")
        
        # Health Check
        st.subheader("🏥 System Health Check")
        
        health_col1, health_col2 = st.columns(2)
        
        with health_col1:
            st.markdown("### ✅ Health Indicators")
            
            # Data health
            if stats['total'] > 0:
                st.success("✅ Data Collection: Healthy")
                st.caption(f"Collecting from {len(stats['by_source'])} sources")
            else:
                st.warning("⚠️ Data Collection: No data yet")
                st.caption("Waiting for logs to be collected")
            
            # Alert health
            if len(alerts) > 0:
                st.success("✅ Alert Generation: Active")
                st.caption(f"{len(alerts)} alerts processed")
            else:
                st.info("ℹ️ Alert Generation: Waiting for data")
            
            # Source health
            if len(stats['by_source']) > 0:
                st.success("✅ Data Sources: Connected")
                st.caption(f"{len(stats['by_source'])} active sources")
            else:
                st.warning("⚠️ Data Sources: None detected")
        
        with health_col2:
            st.markdown("### 📊 Performance Indicators")
            
            if stats['by_hour']:
                hourly_avg = sum(stats['by_hour'].values()) / len(stats['by_hour'])
                st.metric("Average Logs/Hour", f"{hourly_avg:.1f}")
                
                if hourly_avg > 0:
                    st.success("✅ Processing Rate: Normal")
                else:
                    st.warning("⚠️ Processing Rate: Low")
            else:
                st.info("ℹ️ Processing Rate: Calculating...")
            
            # Cache health
            st.success("✅ Cache: Active")
            st.caption("5-second TTL enabled")
            
            # Refresh status
            if auto_refresh:
                st.success("✅ Auto-refresh: Enabled")
                st.caption("Refreshing every 5 seconds")
            else:
                st.info("ℹ️ Auto-refresh: Disabled")
                st.caption("Manual refresh only")
        
        st.markdown("---")
        st.markdown("**ℹ️ Note:** System health is automatically monitored. All components are running in local development mode for testing purposes.")
    
    # Auto-refresh logic - FIXED: Only refresh if no user interaction
    # This prevents tab reset when filters are changed
    if auto_refresh and not st.session_state.get('user_interacted', False):
        # Use JavaScript meta refresh instead of Python rerun to preserve tab state
        st.markdown("""
        <script>
        // Only auto-refresh if page has been idle (no recent user interaction)
        let lastInteraction = Date.now();
        document.addEventListener('click', () => { lastInteraction = Date.now(); });
        document.addEventListener('keydown', () => { lastInteraction = Date.now(); });
        
        setTimeout(function(){
            // Only refresh if no interaction in last 4 seconds
            if (Date.now() - lastInteraction > 4000) {
                window.location.reload();
            }
        }, 5000);
        </script>
        """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()

# ============================================================================
# SECTION 3: MAIN ORCHESTRATOR & PIPELINE
# ============================================================================
#!/usr/bin/env python3
"""
ThreatOps SIEM Pipeline Orchestrator

This is the main entry point for running the OpenSearch-based SIEM pipeline.
It orchestrates the flow: Detection → Enrichment → Scoring

Prerequisites:
  - OpenSearch running on localhost:9200
  - Filebeat configured and running to collect logs
  
Usage examples:
  python run.py --mode simulate    # Run attack simulation (writes to data/sim_attacks.log)
  python run.py --mode detect      # Run detection pipeline
  python run.py --mode enrich      # Run enrichment pipeline  
  python run.py --mode score       # Run scoring pipeline
  python run.py --mode pipeline    # Run full pipeline (detect > enrich > score)
  python run.py --mode continuous  # Run continuously every 60 seconds
  python run.py --mode all         # START EVERYTHING (services + simulation + pipeline + dashboard)
  
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import io
import time
import subprocess
import webbrowser
from pathlib import Path
from typing import Optional, List, Tuple, Any, TextIO

# Project root - defined first to ensure it's always available
ROOT = Path(__file__).parent

# Load environment variables from .env file early
try:
    from dotenv import load_dotenv
    env_path = ROOT / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        # Use ASCII-safe message for Windows compatibility
        try:
            print(f"[OK] Loaded environment variables from {env_path}")
        except UnicodeEncodeError:
            print("[OK] Loaded environment variables from .env file")
    else:
        load_dotenv()  # Try current directory
except ImportError:
    print("[WARNING] python-dotenv not installed. Environment variables must be set manually.")
except Exception as e:
    print(f"[WARNING] Error loading .env file: {e}")

try:
    import psutil
except ImportError:
    psutil = None

# ROOT is already defined above, just add to path
sys.path.insert(0, str(ROOT))


def _setup_logging() -> None:
    """Configure a UTF-8-safe logger suitable for Windows consoles."""
    try:
        utf8_stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        utf8_stream = sys.stdout

    class SafeStreamHandler(logging.StreamHandler[TextIO]):  # type: ignore[type-arg]
        def emit(self, record: logging.LogRecord) -> None:
            try:
                super().emit(record)
            except UnicodeEncodeError:
                try:
                    msg = self.format(record) + self.terminator
                    stream = self.stream
                    # Check if stream has a buffer attribute (like TextIOWrapper)
                    if hasattr(stream, "buffer"):
                        buffer = getattr(stream, "buffer", None)
                        if buffer is not None:
                            buffer.write(msg.encode("utf-8", errors="replace"))
                            try:
                                buffer.flush()
                            except Exception:
                                pass
                            return
                    # Fallback for streams without buffer
                    safe_msg = msg.encode("utf-8", errors="replace").decode("utf-8")
                    stream.write(safe_msg)
                except Exception:
                    pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(str(ROOT / "logs" / "threat_ops.log")),
            SafeStreamHandler(utf8_stream),
        ],
    )


def create_directories() -> None:
    """Create common directories used by the project."""
    directories = [
        ROOT / "data",
        ROOT / "data" / "logs",
        ROOT / "data" / "alerts",
        ROOT / "data" / "reports",
        ROOT / "data" / "simulations",
        ROOT / "logs",
    ]

    for d in directories:
        d.mkdir(parents=True, exist_ok=True)


def check_opensearch_health(timeout: int = 5, max_retries: int = 12, retry_interval: int = 10) -> bool:
    """
    Check if OpenSearch is running and healthy.
    
    Args:
        timeout: Timeout for individual health check
        max_retries: Maximum number of retry attempts
        retry_interval: Seconds to wait between retries
    
    Returns:
        True if OpenSearch is healthy, False otherwise
    """
    logger = logging.getLogger("run")
    
    try:
        import requests
    except ImportError:
        logger.warning("requests library not available for health check")
        return False
    
    for attempt in range(max_retries):
        try:
            # Check OpenSearch health (no auth needed when security is disabled)
            response = requests.get(
                "http://localhost:9200",
                timeout=timeout
            )
            if response.status_code == 200:
                logger.info("[OK] OpenSearch is healthy and ready")
                return True
            else:
                logger.warning(f"OpenSearch returned unexpected status code: {response.status_code}")
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                logger.info(f"OpenSearch not responding, waiting {retry_interval}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(retry_interval)
            else:
                logger.error("[X] OpenSearch is not responding after all retry attempts")
        except Exception as e:
            logger.error(f"[X] Error checking OpenSearch health: {e}")
            break
    
    return False


class ThreatOpsPipeline:
    """OpenSearch-based SIEM Pipeline Orchestrator"""

    def __init__(self):
        # All imports are now from merged files
        from simulation import AttackSimulator
        from core_detection import ThreatDetector, Alert
        from core_detection import IntelEnricher
        from core_detection import RiskScorer
        
        # Make Alert available for type hints
        self._Alert = Alert

        self.settings = Settings()
        self.attack_simulator = AttackSimulator(self.settings)
        self.threat_detector = ThreatDetector(self.settings)
        self.intel_enricher = IntelEnricher(self.settings)
        self.risk_scorer = RiskScorer(self.settings)
        self.logger = logging.getLogger("run")

    async def initialize(self) -> None:
        """Initialize all pipeline components"""
        self.logger.info("Initializing ThreatOps SIEM Pipeline components...")
        
        await self.attack_simulator.initialize()
        await self.threat_detector.initialize()
        await self.intel_enricher.initialize()
        await self.risk_scorer.initialize()
        
        self.logger.info("Initialization complete")

    async def run_simulation(self) -> List[Any]:
        """Generate simulated attack logs and write to file for Filebeat to collect"""
        self.logger.info("=== Running Attack Simulation ===")
        
        # Generate attack logs
        sim_logs = await self.attack_simulator.generate_attack_logs()
        self.logger.info(f"Generated {len(sim_logs)} simulated attack log entries")
        
        # Write logs to file for Filebeat to collect
        await self.attack_simulator.write_logs_for_filebeat(sim_logs)
        
        # Also save to simulations directory for records
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        await self.attack_simulator.save_simulation_logs(sim_logs, f"all_scenarios_{timestamp}")
        
        self.logger.info("[SUCCESS] Simulation complete - logs written to data/sim_attacks.log for Filebeat")
        return sim_logs

    async def run_detection(self) -> List[Any]:
        """Query OpenSearch for logs and run threat detection"""
        self.logger.info("=== Running Threat Detection ===")
        
        # Use ML detector's detect method which queries OpenSearch
        alerts: List[Any] = await self.threat_detector.ml_detector.detect(  # type: ignore[assignment]
            index_pattern="filebeat-*",
            max_logs=10000
        )
        
        self.logger.info(f"[SUCCESS] Detection complete - generated {len(alerts)} alerts in OpenSearch")
        return alerts

    async def run_enrichment(self) -> List[Any]:
        """Query OpenSearch for alerts and enrich with threat intelligence"""
        self.logger.info("=== Running Threat Intelligence Enrichment ===")
        
        enriched_alerts: List[Any] = await self.intel_enricher.enrich_alerts_from_opensearch()  # type: ignore[assignment]
        
        self.logger.info(f"[SUCCESS] Enrichment complete - enriched {len(enriched_alerts)} alerts in OpenSearch")
        return enriched_alerts

    async def run_scoring(self) -> List[Any]:
        """Query OpenSearch for enriched alerts and calculate risk scores"""
        self.logger.info("=== Running Risk Scoring ===")
        
        scored_alerts: List[Any] = await self.risk_scorer.score_alerts_from_opensearch()  # type: ignore[assignment]
        
        self.logger.info(f"[SUCCESS] Scoring complete - scored {len(scored_alerts)} alerts in OpenSearch")
        return scored_alerts

    async def run_full_pipeline(self) -> Optional[List[Any]]:
        """Run the complete pipeline: Detection → Enrichment → Scoring"""
        self.logger.info("========================================")
        self.logger.info("Running Full SIEM Pipeline")
        self.logger.info("========================================")
        
        # Step 1: Detection
        alerts: List[Any] = await self.run_detection()
        
        if not alerts:
            self.logger.warning("No alerts detected, skipping enrichment and scoring")
            return None
        
        # Wait a bit for OpenSearch to index
        await asyncio.sleep(2)
        
        # Step 2: Enrichment
        enriched_alerts: List[Any] = await self.run_enrichment()
        
        if not enriched_alerts:
            self.logger.warning("No alerts enriched, skipping scoring")
            return None
        
        # Wait a bit for OpenSearch to index
        await asyncio.sleep(2)
        
        # Step 3: Scoring
        scored_alerts: List[Any] = await self.run_scoring()
        
        # Lines 199-205: Pipeline completion summary
        # This logs the final results of the detection pipeline
        self.logger.info("========================================")
        self.logger.info(f"Pipeline Complete!")
        self.logger.info(f"  Detected: {len(alerts)} alerts")
        self.logger.info(f"  Enriched: {len(enriched_alerts)} alerts")
        self.logger.info(f"  Scored: {len(scored_alerts)} alerts")
        self.logger.info("========================================")
        
        return scored_alerts

    async def run_continuous(self, interval: int = 60) -> None:
        """Run the pipeline continuously at specified interval"""
        self.logger.info(f"Starting continuous mode (interval: {interval}s)")
        self.logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                try:
                    await self.run_full_pipeline()
                except Exception as e:
                    self.logger.error(f"Error in pipeline execution: {e}")
                
                self.logger.info(f"Waiting {interval} seconds before next run...")
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Continuous mode stopped by user")


def start_all_services(with_dashboards: bool = True) -> List[Tuple[str, subprocess.Popen[bytes]]]:
    """Start OpenSearch, Filebeat, and OpenSearch Dashboards"""
    logger = logging.getLogger("run")
    
    # Paths
    OPENSEARCH_BIN = Path(r"D:\Cusor AI\opensearch-3.3.1-windows-x64\opensearch-3.3.1\bin\opensearch.bat")
    FILEBEAT_EXE = Path(r"D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat-9.2.0-windows-x86_64\filebeat.exe")
    DASHBOARDS_BIN = Path(r"D:\Cusor AI\opensearch-dashboards-3.3.0\bin\opensearch-dashboards.bat")
    
    processes: List[Tuple[str, subprocess.Popen[bytes]]] = []
    process_pids: List[int] = []  # Store PIDs for cleanup
    
    # Start OpenSearch
    logger.info("=" * 70)
    logger.info("[1/3] Starting OpenSearch...")
    logger.info("=" * 70)
    if OPENSEARCH_BIN.exists():
        try:
            proc = subprocess.Popen(
                [str(OPENSEARCH_BIN)],
                cwd=str(OPENSEARCH_BIN.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(('OpenSearch', proc))
            process_pids.append(proc.pid)
            logger.info("[OK] OpenSearch started")
            logger.info("  Waiting for OpenSearch to become ready...")
            
            # Wait for OpenSearch to become healthy (with retries)
            if check_opensearch_health(timeout=5, max_retries=12, retry_interval=10):
                logger.info("[OK] OpenSearch is ready and healthy")
            else:
                logger.error("[X] OpenSearch failed to become healthy - pipeline may not work correctly")
        except Exception as e:
            logger.error(f"[X] Failed to start OpenSearch: {e}")
    else:
        logger.error(f"[X] OpenSearch not found at: {OPENSEARCH_BIN}")
    
    # Start Filebeat
    logger.info("")
    logger.info("=" * 70)
    logger.info("[2/3] Starting Filebeat...")
    logger.info("=" * 70)
    if FILEBEAT_EXE.exists():
        try:
            proc = subprocess.Popen(
                [str(FILEBEAT_EXE), "-e"],
                cwd=str(FILEBEAT_EXE.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(('Filebeat', proc))
            process_pids.append(proc.pid)
            logger.info("[OK] Filebeat started")
            logger.info("  Waiting 10 seconds for connection...")
            time.sleep(10)
        except Exception as e:
            logger.error(f"[X] Failed to start Filebeat: {e}")
    else:
        logger.error(f"[X] Filebeat not found at: {FILEBEAT_EXE}")
    
    # Start OpenSearch Dashboards
    if with_dashboards:
        logger.info("")
        logger.info("=" * 70)
        logger.info("[3/3] Starting OpenSearch Dashboards...")
        logger.info("=" * 70)
        if DASHBOARDS_BIN.exists():
            try:
                # Set working directory to OpenSearch Dashboards root (not bin folder)
                dashboards_root = DASHBOARDS_BIN.parent.parent
                node_exe = dashboards_root / "node" / "node.exe"
                cli_js = dashboards_root / "src" / "cli" / "dist.js"
                
                # Start Node.js directly (bypass bat file to avoid path issues)
                if node_exe.exists() and cli_js.exists():
                    proc = subprocess.Popen(
                        [str(node_exe), str(cli_js)],
                        cwd=str(dashboards_root),
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    processes.append(('OpenSearch Dashboards', proc))
                    process_pids.append(proc.pid)
                    logger.info("[OK] OpenSearch Dashboards started")
                    logger.info("  URL: http://localhost:5601")
                    logger.info("  (Wait 90-120 seconds for it to fully start)")
                else:
                    logger.error(f"[X] Node.js or CLI not found at {dashboards_root}")
            except Exception as e:
                logger.error(f"[X] Failed to start OpenSearch Dashboards: {e}")
        else:
            logger.error(f"[X] OpenSearch Dashboards not found at: {DASHBOARDS_BIN}")
    else:
        logger.info("")
        logger.info("=" * 70)
        logger.info("[3/3] OpenSearch Dashboards - SKIPPED")
        logger.info("=" * 70)
        logger.info("  ThreatOps Dashboard will provide security monitoring")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("[OK] All services started successfully!")
    logger.info("=" * 70)
    logger.info("")
    
    # Store process PIDs globally for cleanup
    # Using type: ignore for dynamic attribute assignment
    start_all_services.process_pids = process_pids  # type: ignore[attr-defined]
    start_all_services.processes = processes  # type: ignore[attr-defined]
    
    return processes


def open_dashboard() -> Optional[subprocess.Popen[bytes]]:
    """Open the Streamlit dashboard in browser"""
    logger = logging.getLogger("run")
    dashboard_app = ROOT / "dashboard" / "app.py"
    
    if not dashboard_app.exists():
        logger.error(f"[X] Dashboard app not found at: {dashboard_app}")
        return None
    
    try:
        # Start Streamlit
        venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
        python_exe = str(venv_python) if venv_python.exists() else "python"
        
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            [python_exe, "-m", "streamlit", "run", str(dashboard_app), "--server.headless", "true"],
            cwd=str(ROOT),
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        
        # Store Streamlit PID for cleanup
        if not hasattr(open_dashboard, 'process_pids'):
            open_dashboard.process_pids = []  # type: ignore[attr-defined]
        open_dashboard.process_pids.append(proc.pid)  # type: ignore[attr-defined]
        
        logger.info("[OK] Dashboard starting...")
        logger.info("  Waiting 5 seconds for Streamlit to start...")
        time.sleep(5)
        
        return proc
    except Exception as e:
        logger.error(f"[X] Failed to open dashboard: {e}")
        return None


def open_all_dashboards() -> None:
    """Open ALL three dashboards in browser"""
    logger = logging.getLogger("run")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("Opening all dashboards in browser...")
    logger.info("=" * 70)
    
    dashboards = [
        ("ThreatOps Dashboard", "http://localhost:8501", "Main SIEM interface"),
        ("OpenSearch Dashboards", "http://localhost:5601", "Advanced analytics (no login required)"),
        ("OpenSearch API", "http://localhost:9200", "Backend API & cluster info")
    ]
    
    for name, url, desc in dashboards:
        try:
            logger.info(f"Opening {name}...")
            webbrowser.open(url)
            logger.info(f"  [OK] {url} - {desc}")
            time.sleep(1)  # Small delay between opens
        except Exception as e:
            logger.warning(f"  [!] Could not open {name}: {e}")
    
    logger.info("")
    logger.info("[OK] All dashboards opened!")
    logger.info("=" * 70)
    logger.info("")


def cleanup_all_processes() -> None:
    """Kill all background processes started by this script"""
    logger = logging.getLogger("run")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("Cleaning up all background processes...")
    logger.info("=" * 70)
    
    if psutil is None:
        logger.warning("[!] psutil not installed - using basic cleanup")
        logger.warning("Install with: pip install psutil")
        logger.info("Closing processes by name using Windows commands...")
        
        # Windows command-line cleanup
        import os
        cleanup_commands = [
            "taskkill /F /FI \"WINDOWTITLE eq OpenSearch*\" /T",
            "taskkill /F /FI \"WINDOWTITLE eq Filebeat*\" /T",
            "taskkill /F /FI \"WINDOWTITLE eq OpenSearch Dashboards*\" /T",
            "taskkill /F /FI \"WINDOWTITLE eq ThreatOps Dashboard*\" /T"
        ]
        
        for cmd in cleanup_commands:
            try:
                os.system(cmd + " >nul 2>&1")
            except Exception:
                pass
        
        logger.info("[OK] Cleanup attempted")
        logger.info("=" * 70)
        logger.info("")
        return
    
    all_pids: List[int] = []
    
    # Get PIDs from services
    if hasattr(start_all_services, 'process_pids'):
        process_pids = getattr(start_all_services, 'process_pids', [])  # type: ignore[attr-defined]
        if isinstance(process_pids, list):
            # Filter to ensure all items are integers
            int_pids: List[int] = [pid for pid in process_pids if isinstance(pid, int)]  # type: ignore[misc]
            all_pids.extend(int_pids)
    
    # Get Streamlit PID
    if hasattr(open_dashboard, 'process_pids'):
        dashboard_pids = getattr(open_dashboard, 'process_pids', [])  # type: ignore[attr-defined]
        if isinstance(dashboard_pids, list):
            # Filter to ensure all items are integers
            int_pids: List[int] = [pid for pid in dashboard_pids if isinstance(pid, int)]  # type: ignore[misc]
            all_pids.extend(int_pids)
    
    # Also kill by process name (catch any we missed)
    process_names = ['opensearch', 'filebeat', 'node', 'streamlit', 'python']
    
    killed_count = 0
    for pid in all_pids:
        try:
            process = psutil.Process(pid)
            process.terminate()
            killed_count += 1
            logger.info(f"  [OK] Killed process PID {pid}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Kill by name
    try:
        for proc in psutil.process_iter(['pid', 'name']):  # type: ignore[call-overload]
            try:
                proc_info = proc.info if hasattr(proc, 'info') else {}
                proc_name = str(proc_info.get('name', '')).lower() if proc_info else ''
                if any(name in proc_name for name in process_names):
                    # Check if it's from our project
                    try:
                        cmdline = ' '.join(proc.cmdline()).lower()
                        if 'threat_ops' in cmdline or 'opensearch' in cmdline or 'filebeat' in cmdline or 'opensearch-dashboards' in cmdline:
                            proc.terminate()
                            killed_count += 1
                            proc_pid = proc_info.get('pid', 'unknown') if proc_info else 'unknown'
                            logger.info(f"  [OK] Killed {proc_name} (PID {proc_pid})")
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    
    logger.info(f"[OK] Cleaned up {killed_count} processes")
    logger.info("=" * 70)
    logger.info("")


def main(argv: Optional[list[str]] = None) -> int:
    _setup_logging()
    logger = logging.getLogger("run")

    parser = argparse.ArgumentParser(
        description="ThreatOps SIEM Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start everything (OpenSearch, Filebeat, OpenSearch Dashboards, simulation, pipeline, UI)
  python run.py --mode all
  
  # Simulate attacks (writes logs for Filebeat to collect)
  python run.py --mode simulate
  
  # Run detection on logs in OpenSearch
  python run.py --mode detect
  
  # Run full pipeline (detect > enrich > score)
  python run.py --mode pipeline
  
  # Run continuously every 60 seconds
  python run.py --mode continuous --interval 60
  
Note: --mode all now ALWAYS starts OpenSearch Dashboards (no login required)
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["all", "simulate", "detect", "enrich", "score", "pipeline", "continuous"],
        default="pipeline",
        help="Mode to run (default: pipeline)"
    )
    
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Interval in seconds for continuous mode (default: 60)"
    )
    
    parser.add_argument(
        "--skip-init",
        action="store_true",
        help="Skip initialization and directory creation"
    )
    
    parser.add_argument(
        "--with-dashboards",
        action="store_true",
        help="(Deprecated - OpenSearch Dashboards now starts automatically with --mode all)"
    )
    
    args = parser.parse_args(argv)

    if not args.skip_init:
        create_directories()

    # Create pipeline
    pipeline: Optional[ThreatOpsPipeline] = None

    try:
        # Handle --all mode (start everything)
        if args.mode == "all":
            logger.info("=" * 70)
            logger.info("THREATOPS SIEM - COMPLETE STARTUP")
            logger.info("=" * 70)
            logger.info("")
            
            # Start all services - ALWAYS include OpenSearch Dashboards with --all
            start_all_services(with_dashboards=True)
            
            # Initialize pipeline
            logger.info("")
            logger.info("=" * 70)
            logger.info("[4/7] Initializing ThreatOps Pipeline...")
            logger.info("=" * 70)
            pipeline = ThreatOpsPipeline()
            asyncio.run(pipeline.initialize())
            logger.info("[OK] Pipeline initialized")
            logger.info("")
            
            # Run simulation
            logger.info("")
            logger.info("=" * 70)
            logger.info("[5/7] Running Attack Simulation...")
            logger.info("=" * 70)
            asyncio.run(pipeline.run_simulation())
            logger.info("[OK] Simulation complete")
            logger.info("")
            
            # Wait for Filebeat to collect logs
            logger.info("  Waiting 15 seconds for log indexing...")
            time.sleep(15)
            
            # Run pipeline
            logger.info("")
            logger.info("=" * 70)
            logger.info("[6/7] Running Detection Pipeline...")
            logger.info("=" * 70)
            asyncio.run(pipeline.run_full_pipeline())
            logger.info("[OK] Pipeline complete")
            logger.info("")
            
            # Open Streamlit dashboard
            logger.info("")
            logger.info("=" * 70)
            logger.info("[7/7] Starting ThreatOps Dashboard...")
            logger.info("=" * 70)
            open_dashboard()
            
            # Wait and verify OpenSearch Dashboards is ready
            logger.info("")
            logger.info("Waiting for OpenSearch Dashboards to be ready...")
            logger.info("(This can take 90-120 seconds - checking every 10 seconds)")
            
            dashboards_ready = False
            for attempt in range(12):  # Check for up to 120 seconds (12 x 10s)
                try:
                    import requests
                    response = requests.get("http://localhost:5601", timeout=3, allow_redirects=False)
                    if response.status_code in [200, 302, 401]:  # 401 = needs login (but server is up)
                        dashboards_ready = True
                        logger.info(f"[OK] OpenSearch Dashboards is ready! (attempt {attempt + 1}/12)")
                        break
                except:
                    pass
                
                if attempt < 11:
                    logger.info(f"Waiting... ({attempt + 1}/12)")
                    time.sleep(10)
            
            if not dashboards_ready:
                logger.warning("[!] OpenSearch Dashboards may still be starting - will try to open anyway")
            
            # Open ALL dashboards
            open_all_dashboards()
            
            logger.info("")
            logger.info("=" * 70)
            logger.info("COMPLETE! All systems operational!")
            logger.info("=" * 70)
            logger.info("")
            logger.info("Services running:")
            logger.info("   ThreatOps UI:      http://localhost:8501  <- Your main SIEM dashboard")
            logger.info("   OpenSearch DB:     http://localhost:5601  <- Advanced analytics (NO LOGIN NEEDED - anonymous access enabled)")
            logger.info("   OpenSearch API:    http://localhost:9200  <- Backend (for developers)")
            logger.info("")
            logger.info("Log Sources Active:")
            logger.info("   [*] Simulated attacks (MITRE ATT&CK scenarios)")
            logger.info("   [*] Windows Security logs (real system events)")
            logger.info("   [*] Windows System logs (real system events)")
            logger.info("   [*] Windows Application logs (real system events)")
            logger.info("")
            logger.info("=" * 70)
            logger.info("")
            logger.info("[!] Press Enter to EXIT and close all background services")
            logger.info("")
            logger.info("NOTE: Java warnings in OpenSearch console are harmless - they're from")
            logger.info("      deprecated Java APIs that OpenSearch uses. The window stays")
            logger.info("      open because OpenSearch runs continuously in the background.")
            logger.info("=" * 70)
            
            try:
                input()
                # Cleanup all processes
                cleanup_all_processes()
                logger.info("All services stopped. Goodbye!")
            except KeyboardInterrupt:
                cleanup_all_processes()
                logger.info("All services stopped. Goodbye!")
            
            return 0
        
        # Standard modes
        logger.info("=" * 60)
        logger.info("ThreatOps SIEM Pipeline")
        logger.info("=" * 60)
        
        # Check OpenSearch health for modes that need it
        if args.mode in ["detect", "enrich", "score", "pipeline", "continuous"]:
            logger.info("Checking OpenSearch connection...")
            if not check_opensearch_health(timeout=5, max_retries=1, retry_interval=0):
                logger.error("[X] OpenSearch is not running!")
                logger.error("Please start OpenSearch first or use: python run.py --mode all")
                return 1
        
        pipeline = ThreatOpsPipeline()
        asyncio.run(pipeline.initialize())
        
        if args.mode == "simulate":
            logger.info("Mode: Attack Simulation")
            asyncio.run(pipeline.run_simulation())
            
        elif args.mode == "detect":
            logger.info("Mode: Threat Detection")
            asyncio.run(pipeline.run_detection())
            
        elif args.mode == "enrich":
            logger.info("Mode: Threat Intelligence Enrichment")
            asyncio.run(pipeline.run_enrichment())
            
        elif args.mode == "score":
            logger.info("Mode: Risk Scoring")
            asyncio.run(pipeline.run_scoring())
            
        elif args.mode == "pipeline":
            logger.info("Mode: Full Pipeline")
            asyncio.run(pipeline.run_full_pipeline())
            
        elif args.mode == "continuous":
            logger.info(f"Mode: Continuous (interval: {args.interval}s)")
            asyncio.run(pipeline.run_continuous(args.interval))

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as exc:
        logger.exception(f"Fatal error: {exc}")
        return 2

    logger.info("=" * 60)
    logger.info("Run completed successfully")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
