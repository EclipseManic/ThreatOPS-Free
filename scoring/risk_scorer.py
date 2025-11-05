# Risk Scoring and MITRE ATT&CK Mapping System for ThreatOps SOC

import asyncio
import logging
import json
import sqlite3
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from collections import defaultdict, Counter
import math

from detection.threat_detector import Alert

logger = logging.getLogger(__name__)

# OpenSearch client - optional import
try:
    from opensearchpy import OpenSearch
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False
    logger.warning("opensearch-py not available, OpenSearch integration disabled")

class MITRETechnique:
    """MITRE ATT&CK technique definition"""
    
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', '')
        self.name = kwargs.get('name', '')
        self.tactic = kwargs.get('tactic', '')
        self.description = kwargs.get('description', '')
        self.platforms = kwargs.get('platforms', [])
        self.data_sources = kwargs.get('data_sources', [])
        self.detection_rules = kwargs.get('detection_rules', [])
        self.mitigations = kwargs.get('mitigations', [])
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'tactic': self.tactic,
            'description': self.description,
            'platforms': self.platforms,
            'data_sources': self.data_sources,
            'detection_rules': self.detection_rules,
            'mitigations': self.mitigations
        }

class RiskScore:
    """Risk score calculation result"""
    
    def __init__(self, **kwargs):
        self.base_score = kwargs.get('base_score', 0)
        self.severity_multiplier = kwargs.get('severity_multiplier', 1.0)
        self.intel_multiplier = kwargs.get('intel_multiplier', 1.0)
        self.frequency_multiplier = kwargs.get('frequency_multiplier', 1.0)
        self.context_multiplier = kwargs.get('context_multiplier', 1.0)
        self.final_score = kwargs.get('final_score', 0)
        self.risk_level = kwargs.get('risk_level', 'Low')
        self.factors = kwargs.get('factors', [])
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'base_score': self.base_score,
            'severity_multiplier': self.severity_multiplier,
            'intel_multiplier': self.intel_multiplier,
            'frequency_multiplier': self.frequency_multiplier,
            'context_multiplier': self.context_multiplier,
            'final_score': self.final_score,
            'risk_level': self.risk_level,
            'factors': self.factors
        }

class Recommendation:
    """Security recommendation"""
    
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', '')
        self.title = kwargs.get('title', '')
        self.description = kwargs.get('description', '')
        self.priority = kwargs.get('priority', 'Medium')
        self.category = kwargs.get('category', '')
        self.mitre_technique = kwargs.get('mitre_technique', '')
        self.actions = kwargs.get('actions', [])
        self.references = kwargs.get('references', [])
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'category': self.category,
            'mitre_technique': self.mitre_technique,
            'actions': self.actions,
            'references': self.references
        }

class MITREMapper:
    """MITRE ATT&CK mapping system"""
    
    def __init__(self):
        self.techniques = self._load_mitre_techniques()
        self.tactics = self._load_mitre_tactics()
        
    def _load_mitre_techniques(self) -> Dict[str, MITRETechnique]:
        """Load MITRE ATT&CK techniques"""
        techniques = {
            'T1110': MITRETechnique(
                id='T1110',
                name='Brute Force',
                tactic='Credential Access',
                description='Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.',
                platforms=['Windows', 'Linux', 'macOS'],
                data_sources=['Authentication logs', 'Network traffic'],
                detection_rules=['Multiple failed login attempts', 'Unusual login patterns'],
                mitigations=['Account lockout policies', 'Strong password requirements', 'Multi-factor authentication']
            ),
            'T1078': MITRETechnique(
                id='T1078',
                name='Valid Accounts',
                tactic='Defense Evasion',
                description='Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
                platforms=['Windows', 'Linux', 'macOS'],
                data_sources=['Authentication logs', 'Process monitoring'],
                detection_rules=['Privilege escalation', 'Unusual account activity'],
                mitigations=['Account monitoring', 'Privilege management', 'Regular access reviews']
            ),
            'T1059.001': MITRETechnique(
                id='T1059.001',
                name='PowerShell',
                tactic='Execution',
                description='Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment.',
                platforms=['Windows'],
                data_sources=['Process monitoring', 'Command line logging'],
                detection_rules=['Suspicious PowerShell commands', 'Encoded commands'],
                mitigations=['PowerShell logging', 'Execution policy restrictions', 'Script block logging']
            ),
            'T1021': MITRETechnique(
                id='T1021',
                name='Remote Services',
                tactic='Lateral Movement',
                description='Adversaries may use remote services to initially access and/or persist within a network.',
                platforms=['Windows', 'Linux'],
                data_sources=['Network monitoring', 'Authentication logs'],
                detection_rules=['Unusual network connections', 'Lateral movement patterns'],
                mitigations=['Network segmentation', 'Access controls', 'Monitoring']
            ),
            'T1041': MITRETechnique(
                id='T1041',
                name='Exfiltration Over C2 Channel',
                tactic='Exfiltration',
                description='Adversaries may steal data by exfiltrating it over an existing command and control channel.',
                platforms=['Windows', 'Linux', 'macOS'],
                data_sources=['Network monitoring', 'Data loss prevention'],
                detection_rules=['Large data transfers', 'Unusual network traffic'],
                mitigations=['Data loss prevention', 'Network monitoring', 'Data classification']
            ),
            'T1055': MITRETechnique(
                id='T1055',
                name='Process Injection',
                tactic='Defense Evasion',
                description='Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.',
                platforms=['Windows', 'Linux'],
                data_sources=['Process monitoring', 'API monitoring'],
                detection_rules=['Process injection patterns', 'Unusual process behavior'],
                mitigations=['Process monitoring', 'API monitoring', 'Behavioral analysis']
            ),
            'T1071': MITRETechnique(
                id='T1071',
                name='Application Layer Protocol',
                tactic='Command and Control',
                description='Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic.',
                platforms=['Windows', 'Linux', 'macOS'],
                data_sources=['Network monitoring', 'DNS monitoring'],
                detection_rules=['Unusual network traffic', 'DNS anomalies'],
                mitigations=['Network monitoring', 'DNS filtering', 'Traffic analysis']
            ),
            'T1543': MITRETechnique(
                id='T1543',
                name='Create or Modify System Process',
                tactic='Persistence',
                description='Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.',
                platforms=['Windows', 'Linux'],
                data_sources=['Process monitoring', 'Service monitoring'],
                detection_rules=['Service creation', 'Process modification'],
                mitigations=['Service monitoring', 'Process monitoring', 'System integrity checks']
            )
        }
        
        logger.info(f"Loaded {len(techniques)} MITRE ATT&CK techniques")
        return techniques
    
    def _load_mitre_tactics(self) -> Dict[str, str]:
        """Load MITRE ATT&CK tactics"""
        tactics = {
            'Initial Access': 'The adversary is trying to get into your network.',
            'Execution': 'The adversary is trying to run malicious code.',
            'Persistence': 'The adversary is trying to maintain their foothold.',
            'Privilege Escalation': 'The adversary is trying to gain higher-level permissions.',
            'Defense Evasion': 'The adversary is trying to avoid being detected.',
            'Credential Access': 'The adversary is trying to steal account names and passwords.',
            'Discovery': 'The adversary is trying to figure out your environment.',
            'Lateral Movement': 'The adversary is trying to move through your environment.',
            'Collection': 'The adversary is trying to gather data of interest to their goal.',
            'Command and Control': 'The adversary is trying to communicate with compromised systems.',
            'Exfiltration': 'The adversary is trying to steal data.',
            'Impact': 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.'
        }
        
        return tactics
    
    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get MITRE technique by ID"""
        return self.techniques.get(technique_id)
    
    def get_tactic_description(self, tactic: str) -> Optional[str]:
        """Get MITRE tactic description"""
        return self.tactics.get(tactic)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MITRETechnique]:
        """Get all techniques for a specific tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def search_techniques(self, query: str) -> List[MITRETechnique]:
        """Search techniques by name or description"""
        query_lower = query.lower()
        results = []
        
        for technique in self.techniques.values():
            if (query_lower in technique.name.lower() or 
                query_lower in technique.description.lower() or
                query_lower in technique.tactic.lower()):
                results.append(technique)
        
        return results

class RiskCalculator:
    """Risk scoring calculator"""
    
    def __init__(self, settings):
        self.settings = settings
        self.mitre_mapper = MITREMapper()
        self.historical_data = defaultdict(list)
        
    def calculate_risk_score(self, alert: Alert, historical_alerts: List[Alert] = None) -> RiskScore:
        """Calculate comprehensive risk score for an alert"""
        
        # Base score from configuration
        base_score = self.settings.risk_scoring.base_score
        
        # Severity multiplier
        severity_multiplier = self.settings.risk_scoring.severity_multipliers.get(alert.severity, 1.0)
        
        # Threat intelligence multiplier
        intel_multiplier = self._calculate_intel_multiplier(alert)
        
        # Frequency multiplier (based on historical data)
        frequency_multiplier = self._calculate_frequency_multiplier(alert, historical_alerts or [])
        
        # Context multiplier (based on MITRE technique and environment)
        context_multiplier = self._calculate_context_multiplier(alert)
        
        # Calculate final score
        final_score = (base_score * severity_multiplier * intel_multiplier * 
                      frequency_multiplier * context_multiplier)
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Collect factors
        factors = [
            f"Base score: {base_score}",
            f"Severity multiplier ({alert.severity}): {severity_multiplier:.2f}",
            f"Intel multiplier: {intel_multiplier:.2f}",
            f"Frequency multiplier: {frequency_multiplier:.2f}",
            f"Context multiplier: {context_multiplier:.2f}"
        ]
        
        return RiskScore(
            base_score=base_score,
            severity_multiplier=severity_multiplier,
            intel_multiplier=intel_multiplier,
            frequency_multiplier=frequency_multiplier,
            context_multiplier=context_multiplier,
            final_score=final_score,
            risk_level=risk_level,
            factors=factors
        )
    
    def _calculate_intel_multiplier(self, alert: Alert) -> float:
        """Calculate threat intelligence multiplier"""
        if not alert.tags:
            return 1.0
        
        # Check for threat intelligence tags
        if 'malicious_ioc' in alert.tags:
            return self.settings.risk_scoring.intel_multipliers.get('malicious', 2.5)
        elif 'suspicious_ioc' in alert.tags:
            return self.settings.risk_scoring.intel_multipliers.get('suspicious', 1.5)
        else:
            return self.settings.risk_scoring.intel_multipliers.get('clean', 0.5)
    
    def _calculate_frequency_multiplier(self, alert: Alert, historical_alerts: List[Alert]) -> float:
        """Calculate frequency-based multiplier"""
        if not historical_alerts:
            return 1.0
        
        # Count similar alerts in the last 24 hours
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
        recent_alerts = [a for a in historical_alerts if a.timestamp > cutoff_time]
        
        # Count alerts with same characteristics
        similar_count = 0
        for hist_alert in recent_alerts:
            if (hist_alert.rule_name == alert.rule_name and 
                hist_alert.host == alert.host and
                hist_alert.ip == alert.ip):
                similar_count += 1
        
        # Increase multiplier for repeated alerts
        if similar_count > 10:
            return 2.0
        elif similar_count > 5:
            return 1.5
        elif similar_count > 2:
            return 1.2
        else:
            return 1.0
    
    def _calculate_context_multiplier(self, alert: Alert) -> float:
        """Calculate context-based multiplier"""
        multiplier = 1.0
        
        # MITRE technique multiplier
        if alert.mitre_technique:
            technique = self.mitre_mapper.get_technique(alert.mitre_technique)
            if technique:
                # Higher multiplier for critical tactics
                critical_tactics = ['Privilege Escalation', 'Defense Evasion', 'Exfiltration']
                if technique.tactic in critical_tactics:
                    multiplier *= 1.5
        
        # Host-based multiplier
        if 'server' in alert.host.lower() or 'dc' in alert.host.lower():
            multiplier *= 1.3  # Higher risk for servers
        
        # Time-based multiplier (business hours vs off-hours)
        hour = alert.timestamp.hour
        if hour < 6 or hour > 22:  # Off-hours
            multiplier *= 1.2
        
        # IP-based multiplier
        if alert.ip and alert.ip != 'unknown':
            if self._is_external_ip(alert.ip):
                multiplier *= 1.4  # Higher risk for external IPs
        
        return multiplier
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not ip_obj.is_private
        except:
            return True
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
        if score >= 200:
            return 'Critical'
        elif score >= 100:
            return 'High'
        elif score >= 50:
            return 'Medium'
        else:
            return 'Low'

class RecommendationEngine:
    """Security recommendation engine"""
    
    def __init__(self):
        self.recommendations = self._load_recommendations()
        
    def _load_recommendations(self) -> Dict[str, Recommendation]:
        """Load security recommendations"""
        recommendations = {
            'brute_force': Recommendation(
                id='brute_force_001',
                title='Implement Account Lockout Policy',
                description='Configure account lockout policies to prevent brute force attacks.',
                priority='High',
                category='Authentication',
                mitre_technique='T1110',
                actions=[
                    'Configure account lockout threshold (e.g., 5 failed attempts)',
                    'Set lockout duration (e.g., 30 minutes)',
                    'Enable account lockout counter reset',
                    'Monitor failed login attempts'
                ],
                references=[
                    'https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy',
                    'NIST SP 800-53 AC-7'
                ]
            ),
            'privilege_escalation': Recommendation(
                id='priv_esc_001',
                title='Implement Privilege Management',
                description='Implement proper privilege management to prevent unauthorized escalation.',
                priority='Critical',
                category='Authorization',
                mitre_technique='T1078',
                actions=[
                    'Implement principle of least privilege',
                    'Regular access reviews',
                    'Monitor privilege escalation attempts',
                    'Implement privileged access management (PAM)'
                ],
                references=[
                    'https://www.sans.org/white-papers/privilege-management/',
                    'NIST SP 800-53 AC-6'
                ]
            ),
            'powershell': Recommendation(
                id='powershell_001',
                title='Enable PowerShell Logging',
                description='Enable comprehensive PowerShell logging to detect malicious activity.',
                priority='Medium',
                category='Monitoring',
                mitre_technique='T1059.001',
                actions=[
                    'Enable PowerShell script block logging',
                    'Enable PowerShell module logging',
                    'Enable PowerShell transcription',
                    'Monitor PowerShell execution'
                ],
                references=[
                    'https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows',
                    'https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html'
                ]
            ),
            'lateral_movement': Recommendation(
                id='lateral_001',
                title='Implement Network Segmentation',
                description='Implement network segmentation to limit lateral movement.',
                priority='High',
                category='Network Security',
                mitre_technique='T1021',
                actions=[
                    'Implement network segmentation',
                    'Deploy network access controls',
                    'Monitor lateral movement',
                    'Implement micro-segmentation'
                ],
                references=[
                    'https://www.sans.org/white-papers/network-segmentation/',
                    'NIST SP 800-53 SC-7'
                ]
            ),
            'data_exfiltration': Recommendation(
                id='exfil_001',
                title='Implement Data Loss Prevention',
                description='Implement data loss prevention controls to prevent unauthorized data exfiltration.',
                priority='Critical',
                category='Data Protection',
                mitre_technique='T1041',
                actions=[
                    'Deploy data loss prevention (DLP) solution',
                    'Implement data classification',
                    'Monitor data transfers',
                    'Implement encryption for sensitive data'
                ],
                references=[
                    'https://www.sans.org/white-papers/data-loss-prevention/',
                    'NIST SP 800-53 SC-28'
                ]
            )
        }
        
        return recommendations
    
    def generate_recommendations(self, alert: Alert) -> List[Recommendation]:
        """Generate recommendations for an alert"""
        recommendations = []
        
        # Get recommendations based on MITRE technique
        if alert.mitre_technique:
            technique_recommendations = self._get_recommendations_by_technique(alert.mitre_technique)
            recommendations.extend(technique_recommendations)
        
        # Get recommendations based on alert type
        alert_type_recommendations = self._get_recommendations_by_alert_type(alert.rule_name)
        recommendations.extend(alert_type_recommendations)
        
        # Get general recommendations based on severity
        severity_recommendations = self._get_recommendations_by_severity(alert.severity)
        recommendations.extend(severity_recommendations)
        
        # Remove duplicates
        unique_recommendations = []
        seen_ids = set()
        for rec in recommendations:
            if rec.id not in seen_ids:
                unique_recommendations.append(rec)
                seen_ids.add(rec.id)
        
        return unique_recommendations
    
    def _get_recommendations_by_technique(self, technique_id: str) -> List[Recommendation]:
        """Get recommendations for specific MITRE technique"""
        return [rec for rec in self.recommendations.values() 
                if rec.mitre_technique == technique_id]
    
    def _get_recommendations_by_alert_type(self, alert_type: str) -> List[Recommendation]:
        """Get recommendations for specific alert type"""
        alert_type_mapping = {
            'Brute Force Attack': 'brute_force',
            'Privilege Escalation': 'privilege_escalation',
            'Suspicious PowerShell': 'powershell',
            'Lateral Movement': 'lateral_movement',
            'Data Exfiltration': 'data_exfiltration'
        }
        
        recommendation_key = alert_type_mapping.get(alert_type)
        if recommendation_key and recommendation_key in self.recommendations:
            return [self.recommendations[recommendation_key]]
        
        return []
    
    def _get_recommendations_by_severity(self, severity: str) -> List[Recommendation]:
        """Get general recommendations based on severity"""
        if severity in ['Critical', 'High']:
            return [
                self.recommendations['brute_force'],
                self.recommendations['privilege_escalation']
            ]
        else:
            return [self.recommendations['powershell']]

class RiskScorer:
    """Main risk scoring engine"""
    
    def __init__(self, settings, opensearch_client=None):
        self.settings = settings
        self.risk_calculator = RiskCalculator(settings)
        self.recommendation_engine = RecommendationEngine()
        self.mitre_mapper = MITREMapper()
        self.opensearch_client = opensearch_client
        
    async def initialize(self):
        """Initialize risk scorer"""
        logger.info("Initializing risk scorer...")
        
        # Initialize OpenSearch client if not provided
        if not self.opensearch_client and OPENSEARCH_AVAILABLE:
            try:
                self.opensearch_client = OpenSearch(
                    hosts=[{'host': 'localhost', 'port': 9200}],
                    use_ssl=False,
                    verify_certs=False,
                    timeout=10,
                    max_retries=3,
                    retry_on_timeout=True
                )
                # Verify connection by making a health check
                self.opensearch_client.info()
                logger.info("Connected to OpenSearch and verified")
            except Exception as e:
                logger.error(f"Failed to connect to OpenSearch: {e}")
                self.opensearch_client = None
        
        # Create data directory
        Path(self.settings.data_dir).mkdir(parents=True, exist_ok=True)
        
        logger.info("Risk scorer initialized successfully")
    
    async def score_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """Score alerts and add risk information"""
        logger.info(f"Scoring {len(alerts)} alerts...")
        
        scored_alerts = []
        
        for alert in alerts:
            try:
                # Calculate risk score
                risk_score = self.risk_calculator.calculate_risk_score(alert, alerts)
                
                # Generate recommendations
                recommendations = self.recommendation_engine.generate_recommendations(alert)
                
                # Add risk information to alert
                alert.tags.append(f"risk_level_{risk_score.risk_level.lower()}")
                alert.tags.append(f"risk_score_{int(risk_score.final_score)}")
                
                # Add risk score and recommendations to raw data
                if alert.raw_events:
                    for event in alert.raw_events:
                        if hasattr(event, 'raw_data'):
                            event.raw_data['risk_score'] = risk_score.to_dict()
                            event.raw_data['recommendations'] = [rec.to_dict() for rec in recommendations]
                
                scored_alerts.append(alert)
                
            except Exception as e:
                logger.error(f"Error scoring alert {alert.id}: {e}")
                scored_alerts.append(alert)
        
        # Sort by risk score
        scored_alerts.sort(key=lambda x: self._extract_risk_score(x), reverse=True)
        
        logger.info(f"Scored {len(scored_alerts)} alerts")
        return scored_alerts
    
    def _extract_risk_score(self, alert: Alert) -> float:
        """Extract risk score from alert tags"""
        for tag in alert.tags:
            if tag.startswith('risk_score_'):
                try:
                    return float(tag.split('_')[-1])
                except:
                    pass
        return 0.0
    
    async def get_risk_statistics(self) -> Dict[str, Any]:
        """Get risk scoring statistics"""
        return {
            'risk_levels': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0
            },
            'average_risk_score': 0.0,
            'total_alerts_scored': 0,
            'mitre_techniques': {},
            'top_recommendations': []
        }
    
    async def save_risk_data(self, alerts: List[Alert], filename: Optional[str] = None):
        """Save risk scoring data"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"risk_scores_{timestamp}.json"
        
        file_path = Path(self.settings.data_dir) / filename
        
        risk_data = []
        for alert in alerts:
            alert_data = alert.to_dict()
            
            # Extract risk score from raw events
            if alert.raw_events:
                for event in alert.raw_events:
                    if hasattr(event, 'raw_data') and 'risk_score' in event.raw_data:
                        alert_data['risk_score'] = event.raw_data['risk_score']
                        alert_data['recommendations'] = event.raw_data.get('recommendations', [])
                        break
            
            risk_data.append(alert_data)
        
        with open(file_path, 'w') as f:
            json.dump(risk_data, f, indent=2)
        
        logger.info(f"Saved risk data for {len(alerts)} alerts to {file_path}")
        return file_path
    
    async def score_alerts_from_opensearch(self):
        """Query OpenSearch for alerts needing scoring, score them, and update"""
        if not self.opensearch_client:
            logger.warning("OpenSearch not available, skipping alert scoring")
            return []
        
        try:
            # Query for alerts that need scoring (enriched but not scored)
            query = {
                "query": {
                    "bool": {
                        "must": {
                            "term": {"tags": "threat_intel_enriched"}
                        },
                        "must_not": {
                            "wildcard": {"tags": "risk_level_*"}
                        },
                        "filter": {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-24h"
                                }
                            }
                        }
                    }
                },
                "size": 1000
            }
            
            response = self.opensearch_client.search(
                index='security-alerts',
                body=query
            )
            
            # Convert hits to Alert objects
            alerts = []
            for hit in response['hits']['hits']:
                alert = Alert.from_dict(hit['_source'])
                alert.id = hit['_id']
                alerts.append(alert)
            
            logger.info(f"Retrieved {len(alerts)} alerts needing scoring from OpenSearch")
            
            # Score alerts
            scored_alerts = await self.score_alerts(alerts)
            
            # Update alerts in OpenSearch
            if scored_alerts:
                await self._update_alerts_in_opensearch(scored_alerts)
            
            return scored_alerts
            
        except Exception as e:
            logger.error(f"Error scoring alerts from OpenSearch: {e}")
            return []
    
    async def _update_alerts_in_opensearch(self, alerts: List[Alert]):
        """Update scored alerts in OpenSearch"""
        if not self.opensearch_client:
            return
        
        try:
            for alert in alerts:
                alert_dict = alert.to_dict()
                alert_dict['@timestamp'] = alert.timestamp.isoformat()
                
                # Update the alert document
                self.opensearch_client.update(
                    index='security-alerts',
                    id=alert.id,
                    body={'doc': alert_dict},
                    refresh=True
                )
            
            logger.info(f"Updated {len(alerts)} scored alerts in OpenSearch")
            
        except Exception as e:
            logger.error(f"Error updating alerts in OpenSearch: {e}")
