"""
ThreatOps SIEM Dashboard - Multi-Source Security Monitoring
Real-time monitoring of simulated attacks AND real system logs
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
sys.path.append(str(Path(__file__).parent.parent))

# Page configuration
st.set_page_config(
    page_title="ThreatOps SIEM - Multi-Source Monitoring",
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
    .metric-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        padding: 15px;
        border-radius: 10px;
        color: white;
    }
    .source-badge {
        padding: 5px 10px;
        border-radius: 5px;
        font-weight: bold;
        font-size: 12px;
    }
    .simulation-badge {
        background-color: #ff6b6b;
        color: white;
    }
    .windows-badge {
        background-color: #4dabf7;
        color: white;
    }
    .alert-critical {
        background-color: #ff4444;
        padding: 10px;
        border-radius: 5px;
        color: white;
        margin: 5px 0;
    }
    .alert-high {
        background-color: #ff8800;
        padding: 10px;
        border-radius: 5px;
        color: white;
        margin: 5px 0;
    }
</style>
""", unsafe_allow_html=True)

# Data paths
DATA_DIR = Path(__file__).parent.parent / "data"
ALERTS_DIR = DATA_DIR / "alerts"
SIMULATIONS_DIR = DATA_DIR / "simulations"


@st.cache_data(ttl=5)  # Faster refresh - 5 seconds
def load_alerts():
    """Load all alerts from JSON files"""
    alerts = []
    if ALERTS_DIR.exists():
        for alert_file in sorted(ALERTS_DIR.glob("alerts_*.json"), reverse=True):
            try:
                with open(alert_file, 'r', encoding='utf-8') as f:
                    file_alerts = json.load(f)
                    if isinstance(file_alerts, list):
                        alerts.extend(file_alerts)
                    else:
                        alerts.append(file_alerts)
            except json.JSONDecodeError:
                # Skip corrupted or empty JSON files silently
                continue
            except Exception:
                # Skip any other file errors silently
                continue
    return alerts


@st.cache_data(ttl=5)
def load_simulations():
    """Load simulation data"""
    simulations = []
    if SIMULATIONS_DIR.exists():
        for sim_file in sorted(SIMULATIONS_DIR.glob("simulation_*.json"), reverse=True)[:5]:  # Last 5 files
            try:
                with open(sim_file, 'r', encoding='utf-8') as f:
                    sim_data = json.load(f)
                    if isinstance(sim_data, list):
                        simulations.extend(sim_data)
            except:
                # Skip any file errors silently
                continue
    return simulations


def get_log_source_stats(alerts):
    """Get statistics by log source"""
    sources = {}
    for alert in alerts:
        # Check if alert has log_source from the original log
        source = alert.get('log_source', 'unknown')
        if source not in sources:
            sources[source] = {'count': 0, 'critical': 0, 'high': 0}
        sources[source]['count'] += 1
        severity = alert.get('severity', '')
        if severity == 'Critical':
            sources[source]['critical'] += 1
        elif severity == 'High':
            sources[source]['high'] += 1
    return sources


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
    
    # Sidebar
    st.sidebar.title("🎛️ Dashboard Controls")
    
    # Auto-refresh
    auto_refresh = st.sidebar.checkbox("⚡ Auto-refresh (5s)", value=True)
    if auto_refresh:
        st.sidebar.success("Live monitoring active")
    
    # Refresh button
    if st.sidebar.button("🔄 Refresh Now"):
        st.cache_data.clear()
        st.rerun()
    
    st.sidebar.markdown("---")
    
    # Log Source Filter
    st.sidebar.subheader("📊 Log Sources")
    show_simulation = st.sidebar.checkbox("🎯 Simulated Attacks", value=True)
    show_windows_security = st.sidebar.checkbox("🖥️ Windows Security", value=True)
    show_windows_system = st.sidebar.checkbox("⚙️ Windows System", value=True)
    show_windows_app = st.sidebar.checkbox("📱 Windows Application", value=True)
    
    st.sidebar.markdown("---")
    st.sidebar.info("""
    **Log Sources Explained:**
    
    🎯 **Simulated Attacks**: Generated by ThreatOps for testing detection rules
    
    🖥️ **Windows Security**: Real security events from your Windows system (logins, access control, etc.)
    
    ⚙️ **Windows System**: Real system events (services, hardware, errors)
    
    📱 **Windows Application**: Real application logs from installed software
    """)
    
    # Key Metrics Row
    st.header("📈 Real-Time Statistics")
    
    # First row - Severity levels
    col1, col2, col3, col4, col5 = st.columns(5)
    
    # Get source statistics
    source_stats = get_log_source_stats(alerts)
    
    with col1:
        st.metric(
            label="Total Alerts",
            value=len(alerts),
            delta=f"+{len(alerts)}" if alerts else "0"
        )
    
    with col2:
        critical_count = sum(1 for a in alerts if a.get('severity') == 'Critical')
        st.metric(
            label="🔴 Critical",
            value=critical_count,
            delta="Immediate Action" if critical_count > 0 else "None"
        )
    
    with col3:
        high_count = sum(1 for a in alerts if a.get('severity') == 'High')
        st.metric(
            label="🟠 High",
            value=high_count,
            delta=f"{high_count} high severity" if high_count > 0 else "None"
        )
    
    with col4:
        medium_count = sum(1 for a in alerts if a.get('severity') == 'Medium')
        st.metric(
            label="🟡 Medium",
            value=medium_count,
            delta=f"{medium_count} medium severity" if medium_count > 0 else "None"
        )
    
    with col5:
        low_count = sum(1 for a in alerts if a.get('severity') == 'Low')
        st.metric(
            label="🟢 Low",
            value=low_count,
            delta=f"{low_count} low severity" if low_count > 0 else "None"
        )
    
    # Second row - Log sources
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        sim_count = source_stats.get('simulation', {}).get('count', 0)
        st.metric(
            label="🎯 Simulated Attacks",
            value=sim_count,
            delta=f"{sim_count} attack logs"
        )
    
    with col2:
        win_sec = source_stats.get('windows_security', {}).get('count', 0)
        st.metric(
            label="🔐 Windows Security",
            value=win_sec,
            delta=f"{win_sec} security events" if win_sec > 0 else "None"
        )
    
    with col3:
        win_sys = source_stats.get('windows_system', {}).get('count', 0)
        st.metric(
            label="⚙️ Windows System",
            value=win_sys,
            delta=f"{win_sys} system events" if win_sys > 0 else "None"
        )
    
    with col4:
        win_app = source_stats.get('windows_application', {}).get('count', 0)
        st.metric(
            label="📱 Windows Application",
            value=win_app,
            delta=f"{win_app} app events" if win_app > 0 else "None"
        )
    
    with col5:
        real_count = win_sec + win_sys + win_app
        st.metric(
            label="🖥️ Total Real System",
            value=real_count,
            delta=f"{real_count} real events" if real_count > 0 else "None"
        )
    
    st.markdown("---")
    
    # Show data or empty state
    if not alerts and not simulations:
        st.info("""
        ### 👋 Welcome to ThreatOps SIEM!
        
        **No data yet. Let's get started:**
        
        1. **Run the complete setup:**
        ```bash
        python run.py --mode all
        ```
        
        2. **Or run step by step:**
        ```bash
        # Generate simulated attacks
        python run.py --mode simulate
        
        # Run detection
        python run.py --mode pipeline
        ```
        
        **The system will monitor:**
        - 🎯 Simulated attack scenarios (MITRE ATT&CK)
        - 🖥️ Real Windows Security logs
        - ⚙️ Real Windows System logs
        - 📱 Real Windows Application logs
        """)
        
        st.success("""
        ### 🔗 Available Dashboards:
        
        - **ThreatOps Dashboard** (This page) - http://localhost:8501
        - **OpenSearch Dashboards** - http://localhost:5601 (No login required)
        
        ℹ️ **OpenSearch Dashboards** provides advanced analytics and raw data exploration.
        """)
        
        if simulations:
            st.success(f"✓ Found {len(simulations)} simulation log entries ready for processing!")
    
    else:
        # Multi-Source Visualization
        st.header("🔍 Log Source Distribution")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Log source breakdown
            st.subheader("Log Sources Overview")
            if source_stats:
                source_df = pd.DataFrame([
                    {
                        'Source': '🎯 Simulated Attacks' if k == 'simulation' 
                                 else f'🖥️ {k.replace("_", " ").title()}',
                        'Total': v['count'],
                        'Critical': v['critical'],
                        'High': v['high']
                    }
                    for k, v in source_stats.items()
                ])
                
                # Pie chart
                fig = px.pie(
                    source_df,
                    values='Total',
                    names='Source',
                    title='Alerts by Log Source',
                    color_discrete_sequence=px.colors.sequential.Reds
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No log source data yet")
        
        with col2:
            # Severity by source
            st.subheader("Severity Distribution by Source")
            if alerts:
                severity_by_source = []
                for alert in alerts:
                    source = alert.get('log_source', 'unknown')
                    source_label = '🎯 Simulated' if source == 'simulation' else f'🖥️ {source.replace("_", " ").title()}'
                    severity_by_source.append({
                        'Source': source_label,
                        'Severity': alert.get('severity', 'Unknown')
                    })
                
                df_sev = pd.DataFrame(severity_by_source)
                severity_counts = df_sev.groupby(['Source', 'Severity']).size().reset_index(name='Count')
                
                fig = px.bar(
                    severity_counts,
                    x='Source',
                    y='Count',
                    color='Severity',
                    title='Severity Breakdown',
                    color_discrete_map={
                        'Critical': '#ff4444',
                        'High': '#ff8800',
                        'Medium': '#ffbb33',
                        'Low': '#00C851'
                    }
                )
                st.plotly_chart(fig, use_container_width=True)
        
        st.markdown("---")
        
        # MITRE ATT&CK Techniques
        st.header("🎯 MITRE ATT&CK Techniques Detected")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            techniques = [a.get('mitre_technique', 'Unknown') for a in alerts if a.get('mitre_technique')]
            if techniques:
                technique_counts = Counter(techniques)
                fig = px.bar(
                    x=list(technique_counts.keys()),
                    y=list(technique_counts.values()),
                    labels={'x': 'MITRE Technique', 'y': 'Detections'},
                    title='Top Attack Techniques',
                    color=list(technique_counts.values()),
                    color_continuous_scale='Reds'
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("Technique Summary")
            if techniques:
                for tech, count in Counter(techniques).most_common(5):
                    st.markdown(f"**{tech}**: {count} detections")
        
        st.markdown("---")
        
        # Alerts Table with Source Indicator
        st.header("📋 Alert Details")
        
        # Severity filter
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=['Critical', 'High', 'Medium', 'Low'],
            default=['Critical', 'High', 'Medium', 'Low']
        )
        
        # Filter alerts by severity and source
        filtered_alerts = []
        for alert in alerts:
            if alert.get('severity') in severity_filter:
                source = alert.get('log_source', 'unknown')
                if ((source == 'simulation' and show_simulation) or
                    (source == 'windows_security' and show_windows_security) or
                    (source == 'windows_system' and show_windows_system) or
                    (source == 'windows_application' and show_windows_app) or
                    (source not in ['simulation', 'windows_security', 'windows_system', 'windows_application'])):
                    filtered_alerts.append(alert)
        
        if filtered_alerts:
            # Display as expandable cards with source badges
            for i, alert in enumerate(filtered_alerts[:20]):  # Show top 20
                source = alert.get('log_source', 'unknown')
                
                # Source badge
                if source == 'simulation':
                    source_badge = '<span class="source-badge simulation-badge">🎯 SIMULATED ATTACK</span>'
                elif 'windows' in source:
                    source_badge = f'<span class="source-badge windows-badge">🖥️ REAL SYSTEM: {source.replace("_", " ").upper()}</span>'
                else:
                    source_badge = f'<span class="source-badge">{source.upper()}</span>'
                
                with st.expander(f"{alert.get('severity', 'Unknown')} - {alert.get('rule_name', 'Unknown')} {source_badge}", expanded=False):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write("**🔍 Detection Info:**")
                        st.write(f"Source: {source.replace('_', ' ').title()}")
                        st.write(f"Host: {alert.get('host', 'N/A')}")
                        st.write(f"User: {alert.get('user', 'N/A')}")
                    
                    with col2:
                        st.write("**⚠️ Risk Assessment:**")
                        st.write(f"Severity: {alert.get('severity', 'N/A')}")
                        st.write(f"Risk Score: {alert.get('risk_score', 'N/A')}")
                        st.write(f"Confidence: {alert.get('confidence', 'N/A')}")
                    
                    with col3:
                        st.write("**🎯 Attack Details:**")
                        st.write(f"MITRE: {alert.get('mitre_technique', 'N/A')}")
                        st.write(f"Category: {alert.get('category', 'N/A')}")
                        st.write(f"Time: {alert.get('timestamp', 'N/A')}")
                    
                    st.write("**📝 Description:**")
                    st.write(alert.get('description', 'No description available'))
                    
                    if alert.get('threat_intel'):
                        st.write("**🔎 Threat Intelligence:**")
                        st.json(alert.get('threat_intel'))
                    
                    # Show if this is real or simulated
                    if source == 'simulation':
                        st.warning("🎯 SIMULATED ATTACK - Generated by ThreatOps for testing detection rules")
                    elif 'windows' in source:
                        st.info(f"🖥️ REAL SYSTEM LOG - From your Windows {source.replace('windows_', '').title()} event log")
                    else:
                        st.error("🚨 REAL SECURITY EVENT - Investigate immediately!")
        else:
            st.info("No alerts match the selected filters")
        
        st.markdown("---")
        
        # Statistics Summary
        st.header("📊 Summary Statistics")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("Log Sources Active")
            for source, stats in source_stats.items():
                source_label = '🎯 Simulated' if source == 'simulation' else f'🖥️ {source.replace("_", " ").title()}'
                st.metric(source_label, stats['count'])
        
        with col2:
            st.subheader("All Severity Levels")
            for sev in ['Critical', 'High', 'Medium', 'Low']:
                count = sum(1 for a in alerts if a.get('severity') == sev)
                icon = "🔴" if sev == 'Critical' else "🟠" if sev == 'High' else "🟡" if sev == 'Medium' else "🟢"
                st.metric(f"{icon} {sev}", count)
        
        with col3:
            st.subheader("Detection Performance")
            st.metric("Total Logs Analyzed", len(simulations))
            st.metric("Alerts Generated", len(alerts))
            if simulations:
                detection_rate = (len(alerts) / len(simulations)) * 100
                st.metric("Detection Rate", f"{detection_rate:.1f}%")
    
    # Footer
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.caption(f"🕐 Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    with col2:
        st.caption("🛡️ ThreatOps SIEM v2.0")
    with col3:
        st.caption("📊 Multi-Source Monitoring Active")
    
    # Auto-refresh logic
    if auto_refresh:
        import time
        time.sleep(5)
        st.rerun()


if __name__ == "__main__":
    main()
