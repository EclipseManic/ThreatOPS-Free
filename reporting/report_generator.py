# Automated Reporting System for ThreatOps SOC

import asyncio
import logging
import json
import sqlite3
import smtplib
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pandas as pd
from collections import defaultdict, Counter
import aiohttp

# Report generation imports
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab not available, PDF reports disabled")

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    logger.warning("jinja2 not available, HTML templates disabled")

from detection.threat_detector import Alert
from scoring.risk_scorer import MITREMapper

logger = logging.getLogger(__name__)

class ReportTemplate:
    """Report template definition"""
    
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', '')
        self.name = kwargs.get('name', '')
        self.description = kwargs.get('description', '')
        self.template_type = kwargs.get('template_type', 'html')  # html, pdf, json
        self.sections = kwargs.get('sections', [])
        self.frequency = kwargs.get('frequency', 'daily')  # daily, weekly, monthly
        self.enabled = kwargs.get('enabled', True)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'template_type': self.template_type,
            'sections': self.sections,
            'frequency': self.frequency,
            'enabled': self.enabled
        }

class ReportSection:
    """Report section definition"""
    
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', '')
        self.title = kwargs.get('title', '')
        self.content_type = kwargs.get('content_type', 'text')  # text, table, chart, metrics
        self.data_source = kwargs.get('data_source', '')
        self.template = kwargs.get('template', '')
        self.order = kwargs.get('order', 0)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'content_type': self.content_type,
            'data_source': self.data_source,
            'template': self.template,
            'order': self.order
        }

class ReportData:
    """Report data container"""
    
    def __init__(self, **kwargs):
        self.report_id = kwargs.get('report_id', '')
        self.report_type = kwargs.get('report_type', '')
        self.generated_at = kwargs.get('generated_at', datetime.now(timezone.utc))
        self.period_start = kwargs.get('period_start', datetime.now(timezone.utc) - timedelta(days=1))
        self.period_end = kwargs.get('period_end', datetime.now(timezone.utc))
        self.summary = kwargs.get('summary', {})
        self.alerts = kwargs.get('alerts', [])
        self.threat_intel = kwargs.get('threat_intel', {})
        self.mitre_stats = kwargs.get('mitre_stats', {})
        self.recommendations = kwargs.get('recommendations', [])
        self.metrics = kwargs.get('metrics', {})
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'report_id': self.report_id,
            'report_type': self.report_type,
            'generated_at': self.generated_at.isoformat(),
            'period_start': self.period_start.isoformat(),
            'period_end': self.period_end.isoformat(),
            'summary': self.summary,
            'alerts': [alert.to_dict() if hasattr(alert, 'to_dict') else alert for alert in self.alerts],
            'threat_intel': self.threat_intel,
            'mitre_stats': self.mitre_stats,
            'recommendations': [rec.to_dict() if hasattr(rec, 'to_dict') else rec for rec in self.recommendations],
            'metrics': self.metrics
        }

class HTMLReportGenerator:
    """HTML report generator"""
    
    def __init__(self):
        self.templates = self._load_html_templates()
    
    def _load_html_templates(self) -> Dict[str, str]:
        """Load HTML templates"""
        templates = {
            'daily_summary': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report_type }} - {{ generated_at }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #1f77b4; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; background-color: #f0f2f6; border-radius: 5px; }
        .alert-critical { background-color: #ffebee; border-left: 4px solid #f44336; }
        .alert-high { background-color: #fff3e0; border-left: 4px solid #ff9800; }
        .alert-medium { background-color: #fff8e1; border-left: 4px solid #ffc107; }
        .alert-low { background-color: #e8f5e8; border-left: 4px solid #4caf50; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ThreatOps SOC Report</h1>
        <h2>{{ report_type }}</h2>
        <p>Generated: {{ generated_at }}</p>
        <p>Period: {{ period_start }} to {{ period_end }}</p>
    </div>
    
    <div class="section">
        <h3>📊 Executive Summary</h3>
        <div class="metric">
            <strong>Total Alerts:</strong> {{ summary.total_alerts }}
        </div>
        <div class="metric">
            <strong>Critical Alerts:</strong> {{ summary.critical_alerts }}
        </div>
        <div class="metric">
            <strong>High Alerts:</strong> {{ summary.high_alerts }}
        </div>
        <div class="metric">
            <strong>Average Risk Score:</strong> {{ summary.avg_risk_score }}
        </div>
    </div>
    
    <div class="section">
        <h3>🚨 Security Alerts</h3>
        {% for alert in alerts %}
        <div class="alert-{{ alert.severity.lower() }}">
            <h4>{{ alert.rule_name }} - {{ alert.severity }}</h4>
            <p><strong>Host:</strong> {{ alert.host }} | <strong>IP:</strong> {{ alert.ip }} | <strong>User:</strong> {{ alert.user }}</p>
            <p><strong>Description:</strong> {{ alert.description }}</p>
            <p><strong>MITRE Technique:</strong> {{ alert.mitre_technique }}</p>
            <p><strong>Timestamp:</strong> {{ alert.timestamp }}</p>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h3>🔍 Threat Intelligence</h3>
        <table>
            <tr>
                <th>IOC Type</th>
                <th>Count</th>
                <th>Malicious</th>
                <th>Suspicious</th>
            </tr>
            {% for type, stats in threat_intel.items() %}
            <tr>
                <td>{{ type }}</td>
                <td>{{ stats.total }}</td>
                <td>{{ stats.malicious }}</td>
                <td>{{ stats.suspicious }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h3>🎯 MITRE ATT&CK Statistics</h3>
        <table>
            <tr>
                <th>Technique</th>
                <th>Count</th>
                <th>Tactic</th>
            </tr>
            {% for technique, count in mitre_stats.items() %}
            <tr>
                <td>{{ technique }}</td>
                <td>{{ count }}</td>
                <td>{{ mitre_mapper.get_technique(technique).tactic if mitre_mapper.get_technique(technique) else 'Unknown' }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section">
        <h3>💡 Recommendations</h3>
        {% for rec in recommendations %}
        <div style="margin: 10px 0; padding: 10px; background-color: #f9f9f9; border-radius: 5px;">
            <h4>{{ rec.title }}</h4>
            <p><strong>Priority:</strong> {{ rec.priority }}</p>
            <p><strong>Category:</strong> {{ rec.category }}</p>
            <p>{{ rec.description }}</p>
            {% if rec.actions %}
            <p><strong>Actions:</strong></p>
            <ul>
                {% for action in rec.actions %}
                <li>{{ action }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h3>📈 Metrics</h3>
        {% for metric, value in metrics.items() %}
        <div class="metric">
            <strong>{{ metric }}:</strong> {{ value }}
        </div>
        {% endfor %}
    </div>
</body>
</html>
            """,
            
            'threat_analysis': """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Analysis Report - {{ generated_at }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #d32f2f; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .threat-level-critical { background-color: #ffebee; border-left: 4px solid #f44336; }
        .threat-level-high { background-color: #fff3e0; border-left: 4px solid #ff9800; }
        .threat-level-medium { background-color: #fff8e1; border-left: 4px solid #ffc107; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Threat Analysis Report</h1>
        <p>Generated: {{ generated_at }}</p>
        <p>Period: {{ period_start }} to {{ period_end }}</p>
    </div>
    
    <div class="section">
        <h3>🎯 Threat Landscape Overview</h3>
        <p>This report provides a comprehensive analysis of threats detected during the reporting period.</p>
    </div>
    
    <div class="section">
        <h3>🚨 Critical Threats</h3>
        {% for alert in alerts %}
        {% if alert.severity == 'Critical' %}
        <div class="threat-level-critical">
            <h4>{{ alert.rule_name }}</h4>
            <p><strong>Host:</strong> {{ alert.host }} | <strong>IP:</strong> {{ alert.ip }}</p>
            <p><strong>MITRE Technique:</strong> {{ alert.mitre_technique }}</p>
            <p><strong>Description:</strong> {{ alert.description }}</p>
        </div>
        {% endif %}
        {% endfor %}
    </div>
    
    <div class="section">
        <h3>📊 Threat Statistics</h3>
        <table>
            <tr>
                <th>Threat Type</th>
                <th>Count</th>
                <th>Severity</th>
                <th>MITRE Technique</th>
            </tr>
            {% for alert in alerts %}
            <tr>
                <td>{{ alert.rule_name }}</td>
                <td>1</td>
                <td>{{ alert.severity }}</td>
                <td>{{ alert.mitre_technique }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
            """
        }
        
        return templates
    
    def generate_report(self, report_data: ReportData, template_name: str = 'daily_summary') -> str:
        """Generate HTML report"""
        if not JINJA2_AVAILABLE:
            return self._generate_simple_html(report_data)
        
        template_str = self.templates.get(template_name, self.templates['daily_summary'])
        template = Template(template_str)
        
        # Prepare context
        context = {
            'report_type': report_data.report_type,
            'generated_at': report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
            'period_start': report_data.period_start.strftime('%Y-%m-%d %H:%M:%S'),
            'period_end': report_data.period_end.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': report_data.summary,
            'alerts': report_data.alerts,
            'threat_intel': report_data.threat_intel,
            'mitre_stats': report_data.mitre_stats,
            'recommendations': report_data.recommendations,
            'metrics': report_data.metrics,
            'mitre_mapper': MITREMapper()
        }
        
        html_content = template.render(**context)
        return html_content
    
    def _generate_simple_html(self, report_data: ReportData) -> str:
        """Generate simple HTML without templates"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>ThreatOps SOC Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #1f77b4; color: white; padding: 20px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ ThreatOps SOC Report</h1>
        <p>Generated: {report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="section">
        <h3>📊 Summary</h3>
        <p>Total Alerts: {report_data.summary.get('total_alerts', 0)}</p>
        <p>Critical Alerts: {report_data.summary.get('critical_alerts', 0)}</p>
    </div>
    
    <div class="section">
        <h3>🚨 Alerts</h3>
        <ul>
        """
        
        for alert in report_data.alerts:
            html += f"<li>{alert.rule_name} - {alert.severity} - {alert.host}</li>"
        
        html += """
        </ul>
    </div>
</body>
</html>
        """
        
        return html

class PDFReportGenerator:
    """PDF report generator"""
    
    def __init__(self):
        self.styles = self._get_styles()
    
    def _get_styles(self):
        """Get PDF styles"""
        if not REPORTLAB_AVAILABLE:
            return {}
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1f77b4')
        ))
        
        styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.HexColor('#2c3e50')
        ))
        
        return styles
    
    def generate_report(self, report_data: ReportData) -> List:
        """Generate PDF report content"""
        if not REPORTLAB_AVAILABLE:
            return []
        
        content = []
        
        # Title
        content.append(Paragraph("🛡️ ThreatOps SOC Report", self.styles['CustomTitle']))
        content.append(Spacer(1, 20))
        
        # Report info
        info_data = [
            ['Report Type:', report_data.report_type],
            ['Generated:', report_data.generated_at.strftime('%Y-%m-%d %H:%M:%S')],
            ['Period:', f"{report_data.period_start.strftime('%Y-%m-%d')} to {report_data.period_end.strftime('%Y-%m-%d')}"]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f2f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        content.append(info_table)
        content.append(Spacer(1, 20))
        
        # Executive Summary
        content.append(Paragraph("📊 Executive Summary", self.styles['SectionHeader']))
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Alerts', str(report_data.summary.get('total_alerts', 0))],
            ['Critical Alerts', str(report_data.summary.get('critical_alerts', 0))],
            ['High Alerts', str(report_data.summary.get('high_alerts', 0))],
            ['Average Risk Score', str(report_data.summary.get('avg_risk_score', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        content.append(summary_table)
        content.append(Spacer(1, 20))
        
        # Alerts section
        content.append(Paragraph("🚨 Security Alerts", self.styles['SectionHeader']))
        
        if report_data.alerts:
            alerts_data = [['Rule Name', 'Severity', 'Host', 'IP', 'MITRE Technique']]
            
            for alert in report_data.alerts[:20]:  # Limit to first 20 alerts
                alerts_data.append([
                    alert.rule_name,
                    alert.severity,
                    alert.host,
                    alert.ip,
                    alert.mitre_technique
                ])
            
            alerts_table = Table(alerts_data, colWidths=[1.5*inch, 0.8*inch, 1*inch, 1*inch, 1*inch])
            alerts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            
            content.append(alerts_table)
        else:
            content.append(Paragraph("No alerts found for this period.", self.styles['Normal']))
        
        content.append(Spacer(1, 20))
        
        # Recommendations
        content.append(Paragraph("💡 Recommendations", self.styles['SectionHeader']))
        
        for rec in report_data.recommendations:
            # Handle both dict and object formats
            if isinstance(rec, dict):
                title = rec.get('title', 'Recommendation')
                priority = rec.get('priority', 'Medium')
                description = rec.get('description', '')
            else:
                title = rec.title
                priority = rec.priority
                description = rec.description
            
            content.append(Paragraph(f"<b>{title}</b> - {priority}", self.styles['Normal']))
            content.append(Paragraph(description, self.styles['Normal']))
            content.append(Spacer(1, 10))
        
        return content
    
    def save_pdf(self, content: List, file_path: str):
        """Save PDF report"""
        if not REPORTLAB_AVAILABLE:
            logger.error("reportlab not available, cannot generate PDF")
            return
        
        doc = SimpleDocTemplate(file_path, pagesize=A4)
        doc.build(content)

class JSONReportGenerator:
    """JSON report generator"""
    
    def generate_report(self, report_data: ReportData) -> str:
        """Generate JSON report"""
        return json.dumps(report_data.to_dict(), indent=2, default=str)

class AlertNotifier:
    """Alert notification system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.smtp_host = config.get('smtp_host', 'smtp.gmail.com')
        self.smtp_port = config.get('smtp_port', 587)
        self.smtp_user = config.get('smtp_user')
        self.smtp_password = config.get('smtp_password')
        self.slack_webhook = config.get('slack_webhook')
        self.custom_webhook = config.get('custom_webhook')
    
    async def send_email_alert(self, alert: Alert, recipients: List[str]):
        """Send email alert"""
        if not self.smtp_user or not self.smtp_password:
            logger.warning("Email configuration not set, skipping email alert")
            return
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[ThreatOps] {alert.severity} Alert: {alert.rule_name}"
            msg['From'] = self.smtp_user
            msg['To'] = ', '.join(recipients)
            
            # Create email content
            text_content = f"""
ThreatOps Security Alert

Alert: {alert.rule_name}
Severity: {alert.severity}
Host: {alert.host}
User: {alert.user}
IP: {alert.ip}
Time: {alert.timestamp}

Description: {alert.description}

MITRE Technique: {alert.mitre_technique}
Confidence: {alert.confidence:.2f}

---
This is an automated alert from ThreatOps SOC.
            """
            
            html_content = f"""
<html>
<head>
    <style>
        .alert-container {{ font-family: Arial, sans-serif; padding: 20px; }}
        .alert-header {{ background-color: {'#f44336' if alert.severity == 'Critical' else '#ff9800' if alert.severity == 'High' else '#ffc107'}; color: white; padding: 15px; border-radius: 5px; }}
        .alert-content {{ padding: 15px; border: 1px solid #ddd; margin-top: 10px; }}
        .alert-field {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="alert-container">
        <div class="alert-header">
            <h2>🚨 ThreatOps Security Alert</h2>
            <h3>{alert.severity}: {alert.rule_name}</h3>
        </div>
        <div class="alert-content">
            <div class="alert-field"><strong>Host:</strong> {alert.host}</div>
            <div class="alert-field"><strong>User:</strong> {alert.user}</div>
            <div class="alert-field"><strong>IP:</strong> {alert.ip}</div>
            <div class="alert-field"><strong>Time:</strong> {alert.timestamp}</div>
            <div class="alert-field"><strong>Description:</strong> {alert.description}</div>
            <div class="alert-field"><strong>MITRE Technique:</strong> {alert.mitre_technique}</div>
            <div class="alert-field"><strong>Confidence:</strong> {alert.confidence:.2f}</div>
        </div>
    </div>
</body>
</html>
            """
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent for {alert.rule_name}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    async def send_slack_alert(self, alert: Alert):
        """Send Slack alert"""
        if not self.slack_webhook:
            logger.warning("Slack webhook not configured, skipping Slack alert")
            return
        
        try:
            color = {
                'Critical': '#f44336',
                'High': '#ff9800',
                'Medium': '#ffc107',
                'Low': '#4caf50'
            }.get(alert.severity, '#9e9e9e')
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": f"🚨 {alert.severity} Alert: {alert.rule_name}",
                    "text": alert.description,
                    "fields": [
                        {"title": "Host", "value": alert.host, "short": True},
                        {"title": "User", "value": alert.user, "short": True},
                        {"title": "IP", "value": alert.ip, "short": True},
                        {"title": "MITRE", "value": alert.mitre_technique, "short": True},
                        {"title": "Confidence", "value": f"{alert.confidence:.2f}", "short": True},
                        {"title": "Time", "value": str(alert.timestamp), "short": True}
                    ],
                    "footer": "ThreatOps SOC",
                    "ts": int(alert.timestamp.timestamp())
                }]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.slack_webhook, json=payload) as response:
                    if response.status == 200:
                        logger.info(f"Slack alert sent for {alert.rule_name}")
                    else:
                        logger.error(f"Failed to send Slack alert: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    async def send_webhook_alert(self, alert: Alert):
        """Send webhook alert"""
        if not self.custom_webhook:
            logger.warning("Custom webhook not configured, skipping webhook alert")
            return
        
        try:
            payload = {
                "event_type": "security_alert",
                "severity": alert.severity,
                "alert": alert.to_dict()
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.custom_webhook, json=payload) as response:
                    if response.status in [200, 201, 204]:
                        logger.info(f"Webhook alert sent for {alert.rule_name}")
                    else:
                        logger.error(f"Failed to send webhook alert: {response.status}")
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
    
    async def notify(self, alert: Alert, channels: List[str] = None):
        """Send notifications through specified channels"""
        if channels is None:
            channels = ['email', 'slack', 'webhook']
        
        tasks = []
        
        if 'email' in channels:
            recipients = self.config.get('email_recipients', [])
            if recipients:
                tasks.append(self.send_email_alert(alert, recipients))
        
        if 'slack' in channels:
            tasks.append(self.send_slack_alert(alert))
        
        if 'webhook' in channels:
            tasks.append(self.send_webhook_alert(alert))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

class ResponseAutomation:
    """Automated response system (SOAR capabilities)"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', False)
        self.auto_block_ips = config.get('auto_block_ips', False)
        self.auto_disable_accounts = config.get('auto_disable_accounts', False)
        self.quarantine_files = config.get('quarantine_files', False)
        self.action_log = []
    
    async def execute_response(self, alert: Alert):
        """Execute automated response based on alert"""
        if not self.enabled:
            logger.info("Response automation is disabled")
            return
        
        logger.info(f"Executing automated response for alert: {alert.rule_name}")
        
        actions_taken = []
        
        # Block malicious IPs
        if self.auto_block_ips and alert.ip != 'unknown' and 'malicious_ioc' in alert.tags:
            action_result = await self._block_ip(alert.ip)
            actions_taken.append(action_result)
        
        # Disable compromised accounts
        if self.auto_disable_accounts and alert.user != 'unknown' and alert.severity in ['Critical', 'High']:
            if 'credential_dumping' in alert.tags or 'compromised' in alert.tags:
                action_result = await self._disable_account(alert.user)
                actions_taken.append(action_result)
        
        # Quarantine malicious files
        if self.quarantine_files and alert.severity == 'Critical':
            if 'ransomware' in alert.tags or 'malware' in alert.tags:
                action_result = await self._quarantine_host(alert.host)
                actions_taken.append(action_result)
        
        # Log actions
        for action in actions_taken:
            self.action_log.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'alert_id': alert.id,
                'action': action
            })
        
        if actions_taken:
            logger.info(f"Automated actions taken: {len(actions_taken)}")
        
        return actions_taken
    
    async def _block_ip(self, ip: str) -> Dict[str, Any]:
        """Block IP address"""
        logger.info(f"Blocking IP: {ip}")
        
        try:
            # On Windows: Add firewall rule
            if subprocess.os.name == 'nt':
                cmd = f'netsh advfirewall firewall add rule name="ThreatOps Block {ip}" dir=in action=block remoteip={ip}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                success = result.returncode == 0
            # On Linux: Add iptables rule
            else:
                cmd = f'iptables -A INPUT -s {ip} -j DROP'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                success = result.returncode == 0
            
            return {
                'action': 'block_ip',
                'target': ip,
                'success': success,
                'message': f"IP {ip} blocked" if success else f"Failed to block IP {ip}",
                'command': cmd
            }
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return {
                'action': 'block_ip',
                'target': ip,
                'success': False,
                'message': str(e)
            }
    
    async def _disable_account(self, username: str) -> Dict[str, Any]:
        """Disable user account"""
        logger.warning(f"Disabling account: {username}")
        
        try:
            # On Windows: Disable user
            if subprocess.os.name == 'nt':
                cmd = f'net user {username} /active:no'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                success = result.returncode == 0
            # On Linux: Lock user
            else:
                cmd = f'usermod -L {username}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                success = result.returncode == 0
            
            return {
                'action': 'disable_account',
                'target': username,
                'success': success,
                'message': f"Account {username} disabled" if success else f"Failed to disable account {username}",
                'command': cmd
            }
        except Exception as e:
            logger.error(f"Failed to disable account {username}: {e}")
            return {
                'action': 'disable_account',
                'target': username,
                'success': False,
                'message': str(e)
            }
    
    async def _quarantine_host(self, hostname: str) -> Dict[str, Any]:
        """Quarantine infected host"""
        logger.warning(f"Quarantining host: {hostname}")
        
        # Note: This is a simulated action - actual implementation would require network infrastructure integration
        return {
            'action': 'quarantine_host',
            'target': hostname,
            'success': True,
            'message': f"Host {hostname} quarantine initiated (simulated)",
            'note': 'This action requires network infrastructure integration to fully implement'
        }
    
    def get_action_log(self) -> List[Dict[str, Any]]:
        """Get log of automated actions"""
        return self.action_log

class ReportGenerator:
    """Main report generator"""
    
    def __init__(self, settings):
        self.settings = settings
        self.html_generator = HTMLReportGenerator()
        self.pdf_generator = PDFReportGenerator()
        self.json_generator = JSONReportGenerator()
        self.templates = self._load_report_templates()
        
    def _load_report_templates(self) -> Dict[str, ReportTemplate]:
        """Load report templates"""
        templates = {
            'daily_summary': ReportTemplate(
                id='daily_summary',
                name='Daily Summary Report',
                description='Comprehensive daily SOC summary',
                template_type='html',
                frequency='daily',
                sections=[
                    ReportSection(id='summary', title='Executive Summary', content_type='metrics', order=1),
                    ReportSection(id='alerts', title='Security Alerts', content_type='table', order=2),
                    ReportSection(id='threat_intel', title='Threat Intelligence', content_type='table', order=3),
                    ReportSection(id='mitre_stats', title='MITRE ATT&CK Statistics', content_type='table', order=4),
                    ReportSection(id='recommendations', title='Recommendations', content_type='text', order=5)
                ]
            ),
            'threat_analysis': ReportTemplate(
                id='threat_analysis',
                name='Threat Analysis Report',
                description='Detailed threat analysis and trends',
                template_type='html',
                frequency='weekly',
                sections=[
                    ReportSection(id='threat_overview', title='Threat Landscape', content_type='text', order=1),
                    ReportSection(id='critical_threats', title='Critical Threats', content_type='table', order=2),
                    ReportSection(id='threat_stats', title='Threat Statistics', content_type='table', order=3),
                    ReportSection(id='trends', title='Threat Trends', content_type='text', order=4)
                ]
            ),
            'risk_assessment': ReportTemplate(
                id='risk_assessment',
                name='Risk Assessment Report',
                description='Risk assessment and scoring analysis',
                template_type='pdf',
                frequency='monthly',
                sections=[
                    ReportSection(id='risk_overview', title='Risk Overview', content_type='metrics', order=1),
                    ReportSection(id='risk_trends', title='Risk Trends', content_type='chart', order=2),
                    ReportSection(id='high_risk_alerts', title='High Risk Alerts', content_type='table', order=3),
                    ReportSection(id='risk_recommendations', title='Risk Mitigation', content_type='text', order=4)
                ]
            ),
            'pci_dss_compliance': ReportTemplate(
                id='pci_dss_compliance',
                name='PCI-DSS Compliance Report',
                description='Payment Card Industry Data Security Standard compliance report',
                template_type='pdf',
                frequency='quarterly',
                sections=[
                    ReportSection(id='exec_summary', title='Executive Summary', content_type='text', order=1),
                    ReportSection(id='req10_logging', title='Requirement 10: Logging and Monitoring', content_type='table', order=2),
                    ReportSection(id='req11_testing', title='Requirement 11: Security Testing', content_type='table', order=3),
                    ReportSection(id='findings', title='Security Findings', content_type='table', order=4),
                    ReportSection(id='remediation', title='Remediation Plan', content_type='text', order=5)
                ]
            ),
            'hipaa_compliance': ReportTemplate(
                id='hipaa_compliance',
                name='HIPAA Compliance Report',
                description='Health Insurance Portability and Accountability Act compliance report',
                template_type='pdf',
                frequency='quarterly',
                sections=[
                    ReportSection(id='exec_summary', title='Executive Summary', content_type='text', order=1),
                    ReportSection(id='access_controls', title='Access Controls (164.312(a))', content_type='table', order=2),
                    ReportSection(id='audit_controls', title='Audit Controls (164.312(b))', content_type='table', order=3),
                    ReportSection(id='integrity', title='Integrity Controls (164.312(c))', content_type='table', order=4),
                    ReportSection(id='transmission', title='Transmission Security (164.312(e))', content_type='table', order=5),
                    ReportSection(id='incidents', title='Security Incidents', content_type='table', order=6)
                ]
            ),
            'iso27001_compliance': ReportTemplate(
                id='iso27001_compliance',
                name='ISO 27001 Compliance Report',
                description='ISO 27001 Information Security Management compliance report',
                template_type='pdf',
                frequency='monthly',
                sections=[
                    ReportSection(id='exec_summary', title='Executive Summary', content_type='text', order=1),
                    ReportSection(id='a12_operations', title='A.12 Operations Security', content_type='table', order=2),
                    ReportSection(id='a16_incidents', title='A.16 Security Incident Management', content_type='table', order=3),
                    ReportSection(id='a18_compliance', title='A.18 Compliance', content_type='table', order=4),
                    ReportSection(id='nonconformities', title='Non-Conformities', content_type='table', order=5),
                    ReportSection(id='corrective_actions', title='Corrective Actions', content_type='text', order=6)
                ]
            )
        }
        
        return templates
    
    async def initialize(self):
        """Initialize report generator"""
        logger.info("Initializing report generator...")
        
        # Create reports directory
        Path(self.settings.reports_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info("Report generator initialized successfully")
    
    async def generate_daily_report(self) -> str:
        """Generate daily SOC report"""
        logger.info("Generating daily SOC report...")
        
        # Collect data for the last 24 hours
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=1)
        
        # Generate report data
        report_data = await self._collect_report_data('Daily Summary', start_time, end_time)
        
        # Generate reports in different formats
        reports_generated = []
        
        # HTML report
        html_content = self.html_generator.generate_report(report_data, 'daily_summary')
        html_path = Path(self.settings.reports_dir) / f"daily_summary_{end_time.strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        reports_generated.append(str(html_path))
        
        # PDF report
        if REPORTLAB_AVAILABLE:
            pdf_content = self.pdf_generator.generate_report(report_data)
            pdf_path = Path(self.settings.reports_dir) / f"daily_summary_{end_time.strftime('%Y%m%d_%H%M%S')}.pdf"
            self.pdf_generator.save_pdf(pdf_content, str(pdf_path))
            reports_generated.append(str(pdf_path))
        
        # JSON report
        json_content = self.json_generator.generate_report(report_data)
        json_path = Path(self.settings.reports_dir) / f"daily_summary_{end_time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(json_content)
        reports_generated.append(str(json_path))
        
        logger.info(f"Daily report generated: {reports_generated}")
        return str(html_path)
    
    async def generate_threat_analysis_report(self) -> str:
        """Generate threat analysis report"""
        logger.info("Generating threat analysis report...")
        
        # Collect data for the last 7 days
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=7)
        
        # Generate report data
        report_data = await self._collect_report_data('Threat Analysis', start_time, end_time)
        
        # Generate HTML report
        html_content = self.html_generator.generate_report(report_data, 'threat_analysis')
        html_path = Path(self.settings.reports_dir) / f"threat_analysis_{end_time.strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Threat analysis report generated: {html_path}")
        return str(html_path)
    
    async def generate_risk_assessment_report(self) -> str:
        """Generate risk assessment report"""
        logger.info("Generating risk assessment report...")
        
        # Collect data for the last 30 days
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=30)
        
        # Generate report data
        report_data = await self._collect_report_data('Risk Assessment', start_time, end_time)
        
        # Generate PDF report
        if REPORTLAB_AVAILABLE:
            pdf_content = self.pdf_generator.generate_report(report_data)
            pdf_path = Path(self.settings.reports_dir) / f"risk_assessment_{end_time.strftime('%Y%m%d_%H%M%S')}.pdf"
            self.pdf_generator.save_pdf(pdf_content, str(pdf_path))
            
            logger.info(f"Risk assessment report generated: {pdf_path}")
            return str(pdf_path)
        else:
            logger.warning("PDF generation not available, generating HTML instead")
            html_content = self.html_generator.generate_report(report_data, 'daily_summary')
            html_path = Path(self.settings.reports_dir) / f"risk_assessment_{end_time.strftime('%Y%m%d_%H%M%S')}.html"
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"Risk assessment report generated: {html_path}")
            return str(html_path)
    
    async def _collect_report_data(self, report_type: str, start_time: datetime, end_time: datetime) -> ReportData:
        """Collect data for report generation"""
        
        # Load alerts from files
        alerts = await self._load_alerts_from_files(start_time, end_time)
        
        # Calculate summary metrics
        summary = self._calculate_summary_metrics(alerts)
        
        # Calculate threat intelligence statistics
        threat_intel = self._calculate_threat_intel_stats(alerts)
        
        # Calculate MITRE statistics
        mitre_stats = self._calculate_mitre_stats(alerts)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(alerts)
        
        # Calculate additional metrics
        metrics = self._calculate_additional_metrics(alerts)
        
        return ReportData(
            report_id=f"{report_type.lower().replace(' ', '_')}_{end_time.strftime('%Y%m%d_%H%M%S')}",
            report_type=report_type,
            period_start=start_time,
            period_end=end_time,
            summary=summary,
            alerts=alerts,
            threat_intel=threat_intel,
            mitre_stats=mitre_stats,
            recommendations=recommendations,
            metrics=metrics
        )
    
    async def _load_alerts_from_files(self, start_time: datetime, end_time: datetime) -> List[Alert]:
        """Load alerts from files within time range"""
        alerts = []
        
        alerts_dir = Path(self.settings.alerts_dir)
        if not alerts_dir.exists():
            return alerts
        
        for alert_file in alerts_dir.glob("alerts_*.json"):
            try:
                with open(alert_file, 'r') as f:
                    for line in f:
                        alert_data = json.loads(line.strip())
                        alert_timestamp = datetime.fromisoformat(alert_data['timestamp'].replace('Z', '+00:00'))
                        
                        if start_time <= alert_timestamp <= end_time:
                            alert = Alert.from_dict(alert_data)
                            alerts.append(alert)
            except Exception as e:
                logger.error(f"Error loading alerts from {alert_file}: {e}")
        
        return alerts
    
    def _calculate_summary_metrics(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Calculate summary metrics"""
        if not alerts:
            return {
                'total_alerts': 0,
                'critical_alerts': 0,
                'high_alerts': 0,
                'medium_alerts': 0,
                'low_alerts': 0,
                'avg_risk_score': 0.0
            }
        
        severity_counts = Counter(alert.severity for alert in alerts)
        
        # Calculate average risk score
        risk_scores = []
        for alert in alerts:
            for tag in alert.tags:
                if tag.startswith('risk_score_'):
                    try:
                        score = float(tag.split('_')[-1])
                        risk_scores.append(score)
                        break
                    except:
                        pass
        
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        return {
            'total_alerts': len(alerts),
            'critical_alerts': severity_counts.get('Critical', 0),
            'high_alerts': severity_counts.get('High', 0),
            'medium_alerts': severity_counts.get('Medium', 0),
            'low_alerts': severity_counts.get('Low', 0),
            'avg_risk_score': round(avg_risk_score, 2)
        }
    
    def _calculate_threat_intel_stats(self, alerts: List[Alert]) -> Dict[str, Dict[str, int]]:
        """Calculate threat intelligence statistics"""
        ioc_stats = defaultdict(lambda: {'total': 0, 'malicious': 0, 'suspicious': 0})
        
        for alert in alerts:
            if 'malicious_ioc' in alert.tags:
                ioc_stats['IP']['malicious'] += 1
                ioc_stats['IP']['total'] += 1
            elif 'suspicious_ioc' in alert.tags:
                ioc_stats['IP']['suspicious'] += 1
                ioc_stats['IP']['total'] += 1
        
        return dict(ioc_stats)
    
    def _calculate_mitre_stats(self, alerts: List[Alert]) -> Dict[str, int]:
        """Calculate MITRE ATT&CK statistics"""
        mitre_counts = Counter(alert.mitre_technique for alert in alerts if alert.mitre_technique)
        return dict(mitre_counts)
    
    def _generate_recommendations(self, alerts: List[Alert]) -> List[Dict[str, Any]]:
        """Generate recommendations based on alerts"""
        recommendations = []
        
        # Count alerts by type
        alert_counts = Counter(alert.rule_name for alert in alerts)
        
        # Generate recommendations for top alert types
        for alert_type, count in alert_counts.most_common(5):
            if alert_type == 'Brute Force Attack':
                recommendations.append({
                    'title': 'Implement Account Lockout Policy',
                    'description': 'Configure account lockout policies to prevent brute force attacks.',
                    'priority': 'High',
                    'category': 'Authentication',
                    'actions': [
                        'Configure account lockout threshold (e.g., 5 failed attempts)',
                        'Set lockout duration (e.g., 30 minutes)',
                        'Monitor failed login attempts'
                    ]
                })
            elif alert_type == 'Privilege Escalation':
                recommendations.append({
                    'title': 'Implement Privilege Management',
                    'description': 'Implement proper privilege management to prevent unauthorized escalation.',
                    'priority': 'Critical',
                    'category': 'Authorization',
                    'actions': [
                        'Implement principle of least privilege',
                        'Regular access reviews',
                        'Monitor privilege escalation attempts'
                    ]
                })
        
        return recommendations
    
    def _calculate_additional_metrics(self, alerts: List[Alert]) -> Dict[str, Any]:
        """Calculate additional metrics"""
        if not alerts:
            return {}
        
        # Host statistics
        host_counts = Counter(alert.host for alert in alerts)
        
        # IP statistics
        ip_counts = Counter(alert.ip for alert in alerts if alert.ip != 'unknown')
        
        # Time-based statistics
        hour_counts = Counter(alert.timestamp.hour for alert in alerts)
        
        return {
            'top_hosts': dict(host_counts.most_common(5)),
            'top_ips': dict(ip_counts.most_common(5)),
            'peak_hours': dict(hour_counts.most_common(3)),
            'unique_hosts': len(host_counts),
            'unique_ips': len(ip_counts)
        }
    
    async def get_report_statistics(self) -> Dict[str, Any]:
        """Get report generation statistics"""
        reports_dir = Path(self.settings.reports_dir)
        
        if not reports_dir.exists():
            return {
                'total_reports': 0,
                'reports_by_type': {},
                'reports_by_format': {},
                'last_report': None
            }
        
        reports = list(reports_dir.glob("*"))
        report_types = Counter()
        report_formats = Counter()
        last_report = None
        
        for report_file in reports:
            if report_file.is_file():
                # Extract report type and format from filename
                filename = report_file.stem
                if '_' in filename:
                    report_type = filename.split('_')[0]
                    report_types[report_type] += 1
                
                format_ext = report_file.suffix[1:]  # Remove the dot
                report_formats[format_ext] += 1
                
                # Get modification time
                mod_time = datetime.fromtimestamp(report_file.stat().st_mtime)
                if last_report is None or mod_time > last_report:
                    last_report = mod_time
        
        return {
            'total_reports': len(reports),
            'reports_by_type': dict(report_types),
            'reports_by_format': dict(report_formats),
            'last_report': last_report.isoformat() if last_report else None
        }
