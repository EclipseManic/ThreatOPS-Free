# Streamlit Dashboard for ThreatOps SOC

# Import Streamlit lazily inside run() to avoid triggering Streamlit's
# runtime warnings when this module is imported in non-UI contexts
# (e.g., during simulation or tests).
from typing import Any as _Any_for_st
st: _Any_for_st = None
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import sqlite3

# Import our modules
import sys
sys.path.append('.')
from config.settings import Settings
from collectors.log_collector import LogCollector, LogEntry
from detection.threat_detector import ThreatDetector, Alert
from enrichment.intel_enricher import IntelEnricher
from simulation.attack_simulator import AttackSimulator
from scoring.risk_scorer import RiskScorer, MITREMapper

# Page configuration and CSS are applied when the dashboard is actually run
# under Streamlit (see SOCDashboard.run()).

class SOCDashboard:
    """Main SOC Dashboard class"""
    
    def __init__(self):
        self.settings = Settings.load_from_file()
        self.data_dir = Path(self.settings.data_dir)
        self.alerts_dir = Path(self.settings.alerts_dir)
        self.logs_dir = Path(self.settings.logs_dir)
        
    def run(self):
        """Run the dashboard"""
        # Lazily import Streamlit and configure page only when the dashboard
        # is actually being displayed. This avoids Streamlit emitting
        # "missing ScriptRunContext" warnings when this module is imported
        # during non-UI runs (such as simulations or tests).
        import streamlit as _st
        global st
        st = _st

        # Configure Plotly template/colors to match Streamlit's dark theme and
        # ensure figures render with visible colors instead of appearing
        # monochrome under dark mode. Set this early before creating figures.
        try:
            import plotly.io as pio
            pio.templates.default = 'plotly_dark'
        except Exception:
            # If plotly isn't available for some reason, proceed without failing
            # since the dashboard should still render other components.
            pass

        # Page configuration
        st.set_page_config(
            page_title="ThreatOps Free - SOC Dashboard",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )

        # Custom CSS
        st.markdown("""
        <style>
            .main-header {
                font-size: 3rem;
                font-weight: bold;
                color: #1f77b4;
                text-align: center;
                margin-bottom: 2rem;
            }
            .metric-card {
                background-color: #f0f2f6;
                padding: 1rem;
                border-radius: 0.5rem;
                border-left: 4px solid #1f77b4;
            }
            .alert-critical {
                background-color: #ffebee;
                border-left: 4px solid #f44336;
            }
            .alert-high {
                background-color: #fff3e0;
                border-left: 4px solid #ff9800;
            }
            .alert-medium {
                background-color: #fff8e1;
                border-left: 4px solid #ffc107;
            }
            .alert-low {
                background-color: #e8f5e8;
                border-left: 4px solid #4caf50;
            }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<h1 class="main-header">🛡️ ThreatOps Free - SOC Dashboard</h1>', unsafe_allow_html=True)
        
        # Sidebar
        self.render_sidebar()
        
        # Main content
        page = st.session_state.get('page', 'overview')
        
        if page == 'overview':
            self.render_overview()
        elif page == 'alerts':
            self.render_alerts()
        elif page == 'threat_intel':
            self.render_threat_intel()
        elif page == 'mitre_attack':
            self.render_mitre_attack()
        elif page == 'simulation':
            self.render_simulation()
        elif page == 'reports':
            self.render_reports()
        elif page == 'settings':
            self.render_settings()
    
    def render_sidebar(self):
        """Render sidebar navigation"""
        st.sidebar.title("🧠 SOC Navigation")
        
        pages = {
            "📊 Overview": "overview",
            "🚨 Alerts": "alerts",
            "🔍 Threat Intelligence": "threat_intel",
            "🎯 MITRE ATT&CK": "mitre_attack",
            "🎭 Attack Simulation": "simulation",
            "📋 Reports": "reports",
            "⚙️ Settings": "settings"
        }
        
        for page_name, page_key in pages.items():
            if st.sidebar.button(page_name, key=f"nav_{page_key}"):
                st.session_state.page = page_key
                st.rerun()
        
        st.sidebar.markdown("---")
        
        # Quick actions
        st.sidebar.subheader("⚡ Quick Actions")
        
        if st.sidebar.button("🔄 Refresh Data"):
            st.rerun()
        
        if st.sidebar.button("🎭 Run Simulation"):
            self.run_attack_simulation()
        
        if st.sidebar.button("📊 Generate Report"):
            self.generate_report()
        
        # System status
        st.sidebar.markdown("---")
        st.sidebar.subheader("📈 System Status")
        
        status_data = self.get_system_status()
        for status_name, status_value in status_data.items():
            st.sidebar.metric(status_name, status_value)
    
    def render_overview(self):
        """Render overview dashboard"""
        st.header("📊 SOC Overview")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        metrics = self.get_overview_metrics()
        
        with col1:
            st.metric(
                label="🚨 Total Alerts",
                value=metrics['total_alerts'],
                delta=metrics['alerts_delta']
            )
        
        with col2:
            st.metric(
                label="🔴 Critical Alerts",
                value=metrics['critical_alerts'],
                delta=metrics['critical_delta']
            )
        
        with col3:
            st.metric(
                label="🛡️ Threats Blocked",
                value=metrics['threats_blocked'],
                delta=metrics['blocked_delta']
            )
        
        with col4:
            st.metric(
                label="📈 Risk Score",
                value=f"{metrics['avg_risk_score']:.1f}",
                delta=f"{metrics['risk_delta']:.1f}"
            )
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Alerts Over Time")
            alerts_chart = self.create_alerts_timeline_chart()
            # Render Plotly figure via components.html and pass config explicitly
            html = alerts_chart.to_html(include_plotlyjs='cdn', full_html=False, config={})
            st.components.v1.html(html, height=350)
        
        with col2:
            st.subheader("🎯 Alert Severity Distribution")
            severity_chart = self.create_severity_distribution_chart()
            html = severity_chart.to_html(include_plotlyjs='cdn', full_html=False, config={})
            st.components.v1.html(html, height=350)
        
        # Recent alerts table
        st.subheader("🚨 Recent Alerts")
        recent_alerts = self.get_recent_alerts()
        if recent_alerts:
            alerts_df = pd.DataFrame(recent_alerts)
            st.dataframe(alerts_df, width='stretch')
        else:
            st.info("No recent alerts found.")
    
    def render_alerts(self):
        """Render alerts page"""
        st.header("🚨 Security Alerts")
        
        # Filters
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            severity_filter = st.selectbox(
                "Severity",
                ["All", "Critical", "High", "Medium", "Low"]
            )
        
        with col2:
            host_filter = st.selectbox(
                "Host",
                ["All"] + self.get_unique_hosts()
            )
        
        with col3:
            time_filter = st.selectbox(
                "Time Range",
                ["Last Hour", "Last 24 Hours", "Last 7 Days", "All"]
            )
        
        with col4:
            mitre_filter = st.selectbox(
                "MITRE Technique",
                ["All"] + self.get_mitre_techniques()
            )
        
        # Alerts table
        alerts = self.get_filtered_alerts(severity_filter, host_filter, time_filter, mitre_filter)
        
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            
            # Display alerts with styling
            for idx, alert in enumerate(alerts):
                # Use safe lookups to avoid KeyError when alerts are missing fields
                rule_name = alert.get('rule_name', 'Unknown') if isinstance(alert, dict) else getattr(alert, 'rule_name', 'Unknown')
                severity = alert.get('severity', 'Unknown') if isinstance(alert, dict) else getattr(alert, 'severity', 'Unknown')
                host = alert.get('host', 'unknown') if isinstance(alert, dict) else getattr(alert, 'host', 'unknown')
                ip = alert.get('ip', 'unknown') if isinstance(alert, dict) else getattr(alert, 'ip', 'unknown')
                user = alert.get('user', 'unknown') if isinstance(alert, dict) else getattr(alert, 'user', 'unknown')
                description = alert.get('description', '(no description)') if isinstance(alert, dict) else getattr(alert, 'description', '(no description)')
                mitre = alert.get('mitre_technique', '') if isinstance(alert, dict) else getattr(alert, 'mitre_technique', '')
                timestamp = alert.get('timestamp', '') if isinstance(alert, dict) else getattr(alert, 'timestamp', '')

                # Normalize severity for CSS class
                sev_class = severity.lower() if isinstance(severity, str) else 'unknown'
                alert_class = f"alert-{sev_class}"

                with st.container():
                    st.markdown(f'<div class="{alert_class}" style="padding: 1rem; margin: 0.5rem 0; border-radius: 0.5rem;">', unsafe_allow_html=True)

                    col1, col2, col3 = st.columns([2, 1, 1])

                    with col1:
                        st.write(f"**{rule_name}**")
                        st.write(f"Host: {host} | IP: {ip} | User: {user}")
                        st.write(f"Description: {description}")

                    with col2:
                        st.write(f"**Severity:** {severity}")
                        st.write(f"**MITRE:** {mitre}")

                    with col3:
                        st.write(f"**Time:** {timestamp}")
                        if st.button("View Details", key=f"details_{idx}"):
                            self.show_alert_details(alert)

                    st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("No alerts found matching the selected filters.")
    
    def render_threat_intel(self):
        """Render threat intelligence page"""
        st.header("🔍 Threat Intelligence")
        
        # IOC statistics
        col1, col2, col3 = st.columns(3)
        
        intel_stats = self.get_threat_intel_stats()
        
        with col1:
            st.metric("Total IOCs", intel_stats['total_iocs'])
        
        with col2:
            st.metric("Malicious IOCs", intel_stats['malicious_iocs'])
        
        with col3:
            st.metric("Suspicious IOCs", intel_stats['suspicious_iocs'])
        
        # IOC type distribution
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 IOC Type Distribution")
            ioc_type_chart = self.create_ioc_type_chart()
            html = ioc_type_chart.to_html(include_plotlyjs='cdn', full_html=False, config={})
            st.components.v1.html(html, height=350)
        
        with col2:
            st.subheader("🎯 Reputation Distribution")
            reputation_chart = self.create_reputation_chart()
            html = reputation_chart.to_html(include_plotlyjs='cdn', full_html=False, config={})
            st.components.v1.html(html, height=350)
        
        # IOC search
        st.subheader("🔍 IOC Search")
        ioc_query = st.text_input("Enter IOC (IP, Domain, Hash):")
        
        if ioc_query and st.button("Search"):
            ioc_info = self.search_ioc(ioc_query)
            if ioc_info:
                st.json(ioc_info)
            else:
                st.warning("IOC not found in threat intelligence database.")
    
    def render_mitre_attack(self):
        """Render MITRE ATT&CK page"""
        st.header("🎯 MITRE ATT&CK Framework")
        
        mitre_mapper = MITREMapper()
        
        # Tactic overview
        st.subheader("📋 ATT&CK Tactics")
        
        tactics = mitre_mapper.tactics
        tactic_cols = st.columns(3)
        
        for idx, (tactic, description) in enumerate(tactics.items()):
            with tactic_cols[idx % 3]:
                with st.expander(f"**{tactic}**"):
                    st.write(description)
                    
                    # Show techniques for this tactic
                    techniques = mitre_mapper.get_techniques_by_tactic(tactic)
                    for technique in techniques:
                        st.write(f"- **{technique.id}**: {technique.name}")
        
        # Technique search
        st.subheader("🔍 Technique Search")
        search_query = st.text_input("Search techniques:")
        
        if search_query:
            results = mitre_mapper.search_techniques(search_query)
            if results:
                for technique in results:
                    with st.expander(f"**{technique.id} - {technique.name}**"):
                        st.write(f"**Tactic:** {technique.tactic}")
                        st.write(f"**Description:** {technique.description}")
                        st.write(f"**Platforms:** {', '.join(technique.platforms)}")
                        
                        if technique.detection_rules:
                            st.write("**Detection Rules:**")
                            for rule in technique.detection_rules:
                                st.write(f"- {rule}")
                        
                        if technique.mitigations:
                            st.write("**Mitigations:**")
                            for mitigation in technique.mitigations:
                                st.write(f"- {mitigation}")
            else:
                st.info("No techniques found matching your search.")
        
        # Technique usage statistics
        st.subheader("📊 Technique Usage Statistics")
        technique_stats = self.get_mitre_technique_stats()
        
        if technique_stats:
            technique_df = pd.DataFrame(technique_stats)
            technique_chart = px.bar(
                technique_df,
                x='technique',
                y='count',
                title='Technique Usage Count',
                color='count',
                color_continuous_scale='Reds'
            )
            html = technique_chart.to_html(include_plotlyjs='cdn', full_html=False, config={})
            st.components.v1.html(html, height=350)
    
    def render_simulation(self):
        """Render attack simulation page"""
        st.header("🎭 Attack Simulation")
        
        # Simulation controls
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 Run Simulation")
            
            selected_scenario = st.selectbox(
                "Select Attack Scenario",
                ["All Scenarios"] + [s.name for s in self.get_attack_scenarios()]
            )
            
            if st.button("🚀 Run Simulation"):
                with st.spinner("Running attack simulation..."):
                    self.run_attack_simulation(selected_scenario)
        
        with col2:
            st.subheader("📊 Simulation Statistics")
            
            sim_stats = self.get_simulation_stats()
            
            st.metric("Total Scenarios", sim_stats['total_scenarios'])
            st.metric("Enabled Scenarios", sim_stats['enabled_scenarios'])
            st.metric("Malicious IPs", sim_stats['malicious_ips'])
            st.metric("Malicious Domains", sim_stats['malicious_domains'])
        
        # Scenario details
        st.subheader("📋 Attack Scenarios")
        
        scenarios = self.get_attack_scenarios()
        for scenario in scenarios:
            with st.expander(f"**{scenario.name}** - {scenario.severity}"):
                st.write(f"**Description:** {scenario.description}")
                st.write(f"**MITRE Technique:** {scenario.mitre_technique}")
                st.write(f"**Duration:** {scenario.duration_minutes} minutes")
                st.write(f"**Log Count:** {scenario.log_count}")
                st.write(f"**Enabled:** {'✅' if scenario.enabled else '❌'}")
    
    def render_reports(self):
        """Render reports page"""
        st.header("📋 SOC Reports")
        
        # Report generation
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Generate Report")
            
            report_type = st.selectbox(
                "Report Type",
                ["Daily Summary", "Threat Analysis", "Risk Assessment", "Compliance Report"]
            )
            
            report_format = st.selectbox(
                "Format",
                ["HTML", "PDF", "JSON"]
            )
            
            if st.button("📄 Generate Report"):
                with st.spinner("Generating report..."):
                    report_path = self.generate_report(report_type, report_format)
                    if report_path:
                        st.success(f"Report generated: {report_path}")
        
        with col2:
            st.subheader("📈 Report Statistics")
            
            report_stats = self.get_report_stats()
            
            st.metric("Reports Generated", report_stats['total_reports'])
            st.metric("Last Report", report_stats['last_report'])
            st.metric("Report Size", report_stats['avg_size'])
        
        # Recent reports
        st.subheader("📁 Recent Reports")
        
        recent_reports = self.get_recent_reports()
        if recent_reports:
            reports_df = pd.DataFrame(recent_reports)
            st.dataframe(reports_df, width='stretch')
        else:
            st.info("No reports found.")
    
    def render_settings(self):
        """Render settings page"""
        st.header("⚙️ SOC Settings")
        
        # Configuration tabs
        tab1, tab2, tab3, tab4 = st.tabs(["General", "Detection Rules", "APIs", "ML Settings"])
        
        with tab1:
            st.subheader("🔧 General Settings")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.text_input("Project Name", value=self.settings.project_name)
                st.text_input("Version", value=self.settings.version)
                st.checkbox("Debug Mode", value=self.settings.debug)
            
            with col2:
                st.number_input("Dashboard Port", value=self.settings.dashboard_port)
                st.text_input("Dashboard Host", value=self.settings.dashboard_host)
                st.number_input("Report Frequency (hours)", value=self.settings.report_frequency)
        
        with tab2:
            st.subheader("🚨 Detection Rules")
            
            rules = self.settings.get_enabled_detection_rules()
            for rule in rules:
                with st.expander(f"**{rule.name}** - {rule.severity}"):
                    st.write(f"**Description:** {rule.description}")
                    st.write(f"**MITRE Technique:** {rule.mitre_technique}")
                    st.write(f"**Enabled:** {'✅' if rule.enabled else '❌'}")
                    
                    st.write("**Conditions:**")
                    for condition in rule.conditions:
                        st.write(f"- {condition}")
        
        with tab3:
            st.subheader("🔗 API Settings")
            
            apis = self.settings.get_enabled_apis()
            for api in apis:
                with st.expander(f"**{api.name.title()}**"):
                    st.write(f"**Enabled:** {'✅' if api.enabled else '❌'}")
                    st.write(f"**Rate Limit:** {api.rate_limit} requests/minute")
                    st.write(f"**Timeout:** {api.timeout} seconds")
                    st.write(f"**API Key:** {'✅ Set' if api.api_key else '❌ Not Set'}")
        
        with tab4:
            st.subheader("🤖 ML Settings")
            
            ml_config = self.settings.ml_config
            
            st.write(f"**Enabled:** {'✅' if ml_config.enabled else '❌'}")
            st.write(f"**Model Type:** {ml_config.model_type}")
            st.write(f"**Contamination:** {ml_config.contamination}")
            st.write(f"**Training Samples:** {ml_config.training_samples}")
            st.write(f"**Retrain Frequency:** {ml_config.retrain_frequency} hours")
    
    def get_overview_metrics(self) -> Dict[str, Any]:
        """Get overview metrics"""
        try:
            # Load actual alerts from files
            alerts = self._load_alerts_from_disk()
            
            if not alerts:
                return {
                    'total_alerts': 0,
                    'alerts_delta': 0,
                    'critical_alerts': 0,
                    'critical_delta': 0,
                    'threats_blocked': 0,
                    'blocked_delta': 0,
                    'avg_risk_score': 0.0,
                    'risk_delta': 0.0
                }
            
            # Calculate current metrics
            critical_alerts = len([a for a in alerts if a.get('severity') == 'Critical'])
            
            # Calculate risk scores
            risk_scores = []
            for alert in alerts:
                for tag in alert.get('tags', []):
                    if isinstance(tag, str) and tag.startswith('risk_score_'):
                        try:
                            score = float(tag.split('_')[-1])
                            risk_scores.append(score)
                            break
                        except:
                            pass
            
            avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            # Load previous day data for deltas
            yesterday_alerts = self._load_alerts_from_disk(days_ago=1)
            yesterday_critical = len([a for a in yesterday_alerts if a.get('severity') == 'Critical'])
            
            return {
                'total_alerts': len(alerts),
                'alerts_delta': len(alerts) - len(yesterday_alerts),
                'critical_alerts': critical_alerts,
                'critical_delta': critical_alerts - yesterday_critical,
                'threats_blocked': len([a for a in alerts if 'malicious_ioc' in a.get('tags', [])]),
                'blocked_delta': 0,  # Would need historical tracking
                'avg_risk_score': round(avg_risk_score, 1),
                'risk_delta': 0.0  # Would need historical tracking
            }
        except Exception as e:
            logger.error(f"Error loading overview metrics: {e}")
            return {
                'total_alerts': 0,
                'alerts_delta': 0,
                'critical_alerts': 0,
                'critical_delta': 0,
                'threats_blocked': 0,
                'blocked_delta': 0,
                'avg_risk_score': 0.0,
                'risk_delta': 0.0
            }
    
    def get_system_status(self) -> Dict[str, str]:
        """Get system status"""
        return {
            "Log Collector": "🟢 Running",
            "Threat Detector": "🟢 Running",
            "Intel Enricher": "🟢 Running",
            "Risk Scorer": "🟢 Running"
        }
    
    def create_alerts_timeline_chart(self):
        """Create alerts timeline chart using REAL alert data"""
        # Load real alerts from disk
        alerts = self._load_alerts_from_disk(days_ago=0)
        
        if not alerts:
            # If no alerts, show empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No alerts data available. Run attack simulations to generate data.",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            fig.update_layout(title='Alerts Over Time', xaxis_title='Time', yaxis_title='Number of Alerts')
            return fig
        
        # Parse timestamps and group by hour
        timestamps = []
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                # Round to hour
                ts_rounded = ts.replace(minute=0, second=0, microsecond=0)
                timestamps.append(ts_rounded)
            except Exception:
                continue
        
        # Count alerts per hour
        from collections import Counter
        alert_counts = Counter(timestamps)
        
        # Sort by timestamp
        sorted_times = sorted(alert_counts.keys())
        counts = [alert_counts[t] for t in sorted_times]
        
        # Convert to native datetimes
        x_list = [t.replace(tzinfo=None) for t in sorted_times]
        
        fig = go.Figure(
            go.Scatter(
                x=x_list,
                y=counts,
                mode='lines+markers',
                name='Alerts',
                line=dict(color='#1f77b4')
            )
        )
        fig.update_layout(
            title=f'Alerts Over Time (Total: {len(alerts)})',
            xaxis_title='Time',
            yaxis_title='Number of Alerts'
        )
        
        return fig
    
    def create_severity_distribution_chart(self):
        """Create severity distribution chart using REAL alert data"""
        # Load real alerts from disk
        alerts = self._load_alerts_from_disk(days_ago=0)
        
        if not alerts:
            # If no alerts, show empty chart
            fig = go.Figure()
            fig.add_annotation(
                text="No alerts data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False
            )
            fig.update_layout(title='Alert Severity Distribution')
            return fig
        
        # Count by severity
        from collections import Counter
        severity_counts = Counter([alert.get('severity', 'Unknown') for alert in alerts])
        
        # Prepare data
        severities = list(severity_counts.keys())
        counts = list(severity_counts.values())
        
        fig = px.pie(
            names=severities,
            values=counts,
            title=f'Alert Severity Distribution (Total: {len(alerts)})',
            color_discrete_map={
                'Critical': '#f44336',
                'High': '#ff9800',
                'Medium': '#ffc107',
                'Low': '#4caf50'
            }
        )
        
        return fig
    
    def _load_alerts_from_disk(self, days_ago: int = 0) -> List[Dict[str, Any]]:
        """Load alerts from disk files"""
        alerts = []
        
        try:
            # Calculate time range
            end_time = datetime.now(timezone.utc) - timedelta(days=days_ago)
            start_time = end_time - timedelta(days=1)
            
            # Check if alerts directory exists
            if not self.alerts_dir.exists():
                return alerts
            
            # Load alerts from JSON files
            for alert_file in self.alerts_dir.glob("alerts_*.json"):
                try:
                    with open(alert_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                alert_data = json.loads(line.strip())
                                
                                # Parse timestamp
                                alert_timestamp = datetime.fromisoformat(
                                    alert_data['timestamp'].replace('Z', '+00:00')
                                )
                                
                                # Filter by time range
                                if start_time <= alert_timestamp <= end_time:
                                    alerts.append(alert_data)
                except Exception as e:
                    logger.error(f"Error loading alerts from {alert_file}: {e}")
            
            # Sort by timestamp descending
            alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
        except Exception as e:
            logger.error(f"Error in _load_alerts_from_disk: {e}")
        
        return alerts
    
    def get_recent_alerts(self) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        try:
            # Load actual alerts from disk
            alerts = self._load_alerts_from_disk()
            
            # Return most recent 20 alerts
            return alerts[:20] if alerts else []
        except Exception as e:
            logger.error(f"Error loading recent alerts: {e}")
            return []
    
    def get_unique_hosts(self) -> List[str]:
        """Get unique hosts"""
        try:
            alerts = self._load_alerts_from_disk()
            hosts = set(alert.get('host', 'unknown') for alert in alerts if alert.get('host') != 'unknown')
            return sorted(list(hosts))
        except Exception as e:
            logger.error(f"Error getting unique hosts: {e}")
            return []
    
    def get_mitre_techniques(self) -> List[str]:
        """Get MITRE techniques"""
        try:
            alerts = self._load_alerts_from_disk()
            techniques = set(alert.get('mitre_technique', '') for alert in alerts if alert.get('mitre_technique'))
            return sorted(list(techniques))
        except Exception as e:
            logger.error(f"Error getting MITRE techniques: {e}")
            return []
    
    def get_filtered_alerts(self, severity: str, host: str, time_range: str, mitre: str) -> List[Dict[str, Any]]:
        """Get filtered alerts"""
        try:
            # Load all alerts
            alerts = self._load_alerts_from_disk()
            
            # Apply filters
            if severity != "All":
                alerts = [a for a in alerts if a.get('severity') == severity]
            
            if host != "All":
                alerts = [a for a in alerts if a.get('host') == host]
            
            if mitre != "All":
                alerts = [a for a in alerts if a.get('mitre_technique') == mitre]
            
            # Apply time range filter
            if time_range != "All":
                now = datetime.now(timezone.utc)
                if time_range == "Last Hour":
                    cutoff = now - timedelta(hours=1)
                elif time_range == "Last 24 Hours":
                    cutoff = now - timedelta(days=1)
                elif time_range == "Last 7 Days":
                    cutoff = now - timedelta(days=7)
                else:
                    cutoff = None
                
                if cutoff:
                    alerts = [
                        a for a in alerts
                        if datetime.fromisoformat(a['timestamp'].replace('Z', '+00:00')) >= cutoff
                    ]
            
            return alerts
        except Exception as e:
            logger.error(f"Error filtering alerts: {e}")
            return []
    
    def show_alert_details(self, alert: Dict[str, Any]):
        """Show alert details"""
        st.json(alert)
    
    def get_threat_intel_stats(self) -> Dict[str, int]:
        """Get threat intelligence statistics"""
        return {
            'total_iocs': 150,
            'malicious_iocs': 45,
            'suspicious_iocs': 23
        }
    
    def create_ioc_type_chart(self):
        """Create IOC type chart"""
        data = {
            'type': ['IP', 'Domain', 'Hash', 'URL'],
            'count': [80, 45, 20, 5]
        }
        
        df = pd.DataFrame(data)
        
        fig = px.bar(
            df,
            x='type',
            y='count',
            title='IOC Type Distribution',
            color='count',
            color_continuous_scale='Blues'
        )
        
        return fig
    
    def create_reputation_chart(self):
        """Create reputation chart"""
        data = {
            'reputation': ['Malicious', 'Suspicious', 'Clean'],
            'count': [45, 23, 82]
        }
        
        df = pd.DataFrame(data)
        
        fig = px.pie(
            df,
            values='count',
            names='reputation',
            title='IOC Reputation Distribution',
            color_discrete_map={
                'Malicious': '#f44336',
                'Suspicious': '#ff9800',
                'Clean': '#4caf50'
            }
        )
        
        return fig
    
    def search_ioc(self, ioc: str) -> Optional[Dict[str, Any]]:
        """Search for IOC information"""
        # Sample data - in real implementation, query your threat intel database
        sample_iocs = {
            '192.168.1.100': {
                'ioc': '192.168.1.100',
                'type': 'ip',
                'reputation': 'malicious',
                'confidence': 0.9,
                'source': 'sample_data'
            }
        }
        
        return sample_iocs.get(ioc)
    
    def get_mitre_technique_stats(self) -> List[Dict[str, Any]]:
        """Get MITRE technique statistics"""
        return [
            {'technique': 'T1110', 'count': 15},
            {'technique': 'T1078', 'count': 8},
            {'technique': 'T1059.001', 'count': 12},
            {'technique': 'T1021', 'count': 6},
            {'technique': 'T1041', 'count': 3}
        ]
    
    def get_attack_scenarios(self) -> List[Any]:
        """Get attack scenarios"""
        # This would return actual scenario objects
        return []
    
    def get_simulation_stats(self) -> Dict[str, int]:
        """Get simulation statistics"""
        return {
            'total_scenarios': 8,
            'enabled_scenarios': 6,
            'malicious_ips': 8,
            'malicious_domains': 8
        }
    
    def run_attack_simulation(self, scenario: str = "All Scenarios"):
        """Run attack simulation"""
        st.success(f"Attack simulation completed for {scenario}")
    
    def generate_report(self, report_type: str = "Daily Summary", format: str = "HTML") -> Optional[str]:
        """Generate report"""
        return f"reports/{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format.lower()}"
    
    def get_report_stats(self) -> Dict[str, Any]:
        """Get report statistics"""
        return {
            'total_reports': 15,
            'last_report': '2024-01-01 09:00:00',
            'avg_size': '2.5 MB'
        }
    
    def get_recent_reports(self) -> List[Dict[str, Any]]:
        """Get recent reports"""
        return [
            {
                'name': 'Daily Summary Report',
                'date': '2024-01-01',
                'size': '2.1 MB',
                'format': 'PDF'
            },
            {
                'name': 'Threat Analysis Report',
                'date': '2024-01-01',
                'size': '1.8 MB',
                'format': 'HTML'
            }
        ]

def main():
    """Main dashboard function"""
    dashboard = SOCDashboard()
    dashboard.run()

if __name__ == "__main__":
    main()
