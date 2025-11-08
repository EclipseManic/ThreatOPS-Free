"""
================================================================================
CORE DETECTION ENGINE - ThreatOps SOC
================================================================================

This file consolidates all core detection, enrichment, and scoring components:
- Log Collector (LogEntry class)
- Threat Detector (Alert generation & ML anomaly detection)
- Intel Enricher (Threat intelligence APIs)
- Risk Scorer (MITRE ATT&CK mapping & risk calculation)

Created by merging:
- collectors/log_collector.py
- detection/threat_detector.py
- enrichment/intel_enricher.py
- scoring/risk_scorer.py
================================================================================
"""

# ============================================================================
# SECTION 1: LOG COLLECTOR - LogEntry Class
# ============================================================================
# Minimal Log Collector - LogEntry class for compatibility
# Note: Actual log collection is now handled by Filebeat

from datetime import datetime, timezone
from typing import Dict, Any, Optional


class LogEntry:
    """Standardized log entry format"""
    
    def __init__(self, **kwargs):
        self.timestamp = kwargs.get('timestamp', datetime.now(timezone.utc))
        self.host = kwargs.get('host', 'unknown')
        self.user = kwargs.get('user', 'unknown')
        self.event_id = kwargs.get('event_id', 0)
        self.ip = kwargs.get('ip', 'unknown')
        self.message = kwargs.get('message', '')
        self.process_name = kwargs.get('process_name', '')
        self.command_line = kwargs.get('command_line', '')
        self.event_type = kwargs.get('event_type', 'unknown')
        self.severity = kwargs.get('severity', 'info')
        self.source = kwargs.get('source', 'unknown')
        self.raw_data = kwargs.get('raw_data', {})
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'timestamp': self.timestamp.isoformat(),
            'host': self.host,
            'user': self.user,
            'event_id': self.event_id,
            'ip': self.ip,
            'message': self.message,
            'process_name': self.process_name,
            'command_line': self.command_line,
            'event_type': self.event_type,
            'severity': self.severity,
            'source': self.source,
            'raw_data': self.raw_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEntry':
        """Create LogEntry from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)

# ============================================================================
# SECTION 2: THREAT DETECTOR - Alert Generation & ML Anomaly Detection
# ============================================================================
# Threat Detection Engine for ThreatOps SOC

import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import json
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

# OpenSearch client - optional import
try:
    from opensearchpy import OpenSearch
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False
    logger.warning("opensearch-py not available, OpenSearch integration disabled")

# Machine Learning imports are deferred; set ML_AVAILABLE after attempting imports
try:
    import numpy as np  # type: ignore
    from sklearn.ensemble import IsolationForest  # type: ignore
    from sklearn.preprocessing import StandardScaler  # type: ignore
    from sklearn.decomposition import PCA  # type: ignore
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False
    # logger is available above so we can emit a safe warning
    logger.warning("scikit-learn or numpy not available, ML detection disabled")

# LogEntry is defined above in this same file

logger = logging.getLogger(__name__)

class Alert:
    """Standardized alert format"""
    
    def __init__(self, **kwargs):
        self.id = kwargs.get('id', '')
        self.timestamp = kwargs.get('timestamp', datetime.now(timezone.utc))
        self.rule_name = kwargs.get('rule_name', '')
        self.severity = kwargs.get('severity', 'Medium')
        self.description = kwargs.get('description', '')
        self.host = kwargs.get('host', 'unknown')
        self.user = kwargs.get('user', 'unknown')
        self.ip = kwargs.get('ip', 'unknown')
        self.event_ids = kwargs.get('event_ids', [])
        self.mitre_technique = kwargs.get('mitre_technique', '')
        self.confidence = kwargs.get('confidence', 0.0)
        self.raw_events = kwargs.get('raw_events', [])
        self.tags = kwargs.get('tags', [])
        self.status = kwargs.get('status', 'open')  # open, investigating, resolved, false_positive
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'rule_name': self.rule_name,
            'severity': self.severity,
            'description': self.description,
            'host': self.host,
            'user': self.user,
            'ip': self.ip,
            'event_ids': self.event_ids,
            'mitre_technique': self.mitre_technique,
            'confidence': self.confidence,
            'raw_events': [event.to_dict() if hasattr(event, 'to_dict') else event for event in self.raw_events],
            'tags': self.tags,
            'status': self.status
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create Alert from dictionary"""
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        return cls(**data)

class Whitelist:
    """Whitelist manager for false positive reduction"""
    
    def __init__(self):
        self.whitelisted_ips = set()
        self.whitelisted_users = set()
        self.whitelisted_hosts = set()
        self.whitelisted_processes = set()
        self._load_whitelist()
    
    def _load_whitelist(self):
        """Load whitelist from configuration"""
        # Default whitelist entries
        self.whitelisted_ips.update(['127.0.0.1', '::1', 'localhost'])
        self.whitelisted_users.update(['SYSTEM', 'NT AUTHORITY\\SYSTEM', 'root'])
        self.whitelisted_processes.update([
            'System', 'svchost.exe', 'services.exe', 'lsass.exe',
            'csrss.exe', 'winlogon.exe', 'wininit.exe'
        ])
    
    def is_whitelisted(self, log: 'LogEntry') -> bool:
        """Check if log entry is whitelisted"""
        if log.ip in self.whitelisted_ips:
            return True
        if log.user in self.whitelisted_users:
            return True
        if log.host in self.whitelisted_hosts:
            return True
        if log.process_name in self.whitelisted_processes:
            return True
        return False
    
    def add_to_whitelist(self, whitelist_type: str, value: str):
        """Add entry to whitelist"""
        if whitelist_type == 'ip':
            self.whitelisted_ips.add(value)
        elif whitelist_type == 'user':
            self.whitelisted_users.add(value)
        elif whitelist_type == 'host':
            self.whitelisted_hosts.add(value)
        elif whitelist_type == 'process':
            self.whitelisted_processes.add(value)

class RuleEngine:
    """Rule-based detection engine"""
    
    def __init__(self, settings):
        self.settings = settings
        self.rules = {}
        self.whitelist = Whitelist()
        self._load_rules()
        
    def _load_rules(self):
        """Load detection rules from configuration"""
        for rule_config in self.settings.get_enabled_detection_rules():
            self.rules[rule_config.name] = rule_config
        logger.info(f"Loaded {len(self.rules)} detection rules")
    
    def evaluate_rules(self, logs: List[LogEntry]) -> List[Alert]:
        """Evaluate all rules against the logs"""
        alerts = []
        
        # Filter out whitelisted logs
        filtered_logs = [log for log in logs if not self.whitelist.is_whitelisted(log)]
        logger.info(f"Filtered {len(logs) - len(filtered_logs)} whitelisted log entries")
        
        # Group logs by time windows for correlation
        time_windows = self._create_time_windows(filtered_logs)
        
        for rule_name, rule_config in self.rules.items():
            try:
                rule_alerts = self._evaluate_rule(rule_config, filtered_logs, time_windows)
                alerts.extend(rule_alerts)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule_name}: {e}")
        
        return alerts
    
    def _create_time_windows(self, logs: List[LogEntry], window_minutes: int = 5) -> Dict[str, List[LogEntry]]:
        """Create time windows for correlation analysis"""
        windows = defaultdict(list)
        
        for log in logs:
            # Create window key (rounded to nearest window)
            window_start = log.timestamp.replace(second=0, microsecond=0)
            window_start = window_start.replace(minute=(window_start.minute // window_minutes) * window_minutes)
            window_key = f"{window_start.isoformat()}_{window_minutes}min"
            windows[window_key].append(log)
        
        return windows
    
    def _evaluate_rule(self, rule_config, logs: List[LogEntry], time_windows: Dict[str, List[LogEntry]]) -> List[Alert]:
        """Evaluate a specific rule"""
        alerts = []
        
        if rule_config.name == "Brute Force Attack":
            alerts.extend(self._detect_brute_force(logs, time_windows))
        elif rule_config.name == "Privilege Escalation":
            alerts.extend(self._detect_privilege_escalation(logs))
        elif rule_config.name == "Suspicious PowerShell":
            alerts.extend(self._detect_suspicious_powershell(logs))
        elif rule_config.name == "Lateral Movement":
            alerts.extend(self._detect_lateral_movement(logs))
        elif rule_config.name == "Data Exfiltration":
            alerts.extend(self._detect_data_exfiltration(logs))
        elif rule_config.name == "Ransomware Activity":
            alerts.extend(self._detect_ransomware(logs))
        elif rule_config.name == "Credential Dumping":
            alerts.extend(self._detect_credential_dumping(logs))
        elif rule_config.name == "Webshell Activity":
            alerts.extend(self._detect_webshell(logs))
        elif rule_config.name == "DLL Injection":
            alerts.extend(self._detect_dll_injection(logs))
        elif rule_config.name == "Suspicious Registry":
            alerts.extend(self._detect_suspicious_registry(logs))
        else:
            # Generic rule evaluation
            alerts.extend(self._evaluate_generic_rule(rule_config, logs))
        
        return alerts
    
    def _detect_brute_force(self, logs: List[LogEntry], time_windows: Dict[str, List[LogEntry]]) -> List[Alert]:
        """Detect brute force attacks"""
        alerts = []
        
        for window_key, window_logs in time_windows.items():
            # Count failed logins by IP
            failed_logins = defaultdict(int)
            failed_users = defaultdict(set)
            
            for log in window_logs:
                if log.event_id == 4625 and log.ip != 'unknown':  # Failed logon
                    failed_logins[log.ip] += 1
                    failed_users[log.ip].add(log.user)
            
            # Generate alerts for IPs with > 5 failed logins
            for ip, count in failed_logins.items():
                if count > 5:
                    alert = Alert(
                        id=f"brute_force_{ip}_{window_key}",
                        rule_name="Brute Force Attack",
                        severity="High",
                        description=f"Brute force attack detected from IP {ip} with {count} failed login attempts",
                        ip=ip,
                        host=window_logs[0].host if window_logs else 'unknown',
                        mitre_technique="T1110",
                        confidence=min(count / 10.0, 1.0),
                        tags=["brute_force", "authentication", "network"],
                        raw_events=[log for log in window_logs if log.event_id == 4625 and log.ip == ip]
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_privilege_escalation(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect privilege escalation attempts"""
        alerts = []
        
        for log in logs:
            if log.event_id == 4672:  # Privilege escalation
                # Check if user is not in allowed list
                allowed_users = ["SYSTEM", "Administrator", "root"]
                if log.user not in allowed_users:
                    alert = Alert(
                        id=f"priv_esc_{log.host}_{log.timestamp.isoformat()}",
                        rule_name="Privilege Escalation",
                        severity="Critical",
                        description=f"Suspicious privilege escalation by user {log.user} on {log.host}",
                        host=log.host,
                        user=log.user,
                        mitre_technique="T1078",
                        confidence=0.9,
                        tags=["privilege_escalation", "authorization"],
                        raw_events=[log]
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_suspicious_powershell(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect suspicious PowerShell execution"""
        alerts = []
        
        suspicious_patterns = [
            r'-enc\s+',  # Encoded commands
            r'-w\s+hidden',  # Hidden window
            r'-nop\s+-ep\s+bypass',  # Execution policy bypass
            r'Invoke-Expression',  # IEX
            r'DownloadString',  # Download and execute
            r'WebClient',  # Web client usage
        ]
        
        for log in logs:
            if 'powershell' in log.process_name.lower():
                for pattern in suspicious_patterns:
                    if re.search(pattern, log.command_line, re.IGNORECASE):
                        alert = Alert(
                            id=f"susp_powershell_{log.host}_{log.timestamp.isoformat()}",
                            rule_name="Suspicious PowerShell",
                            severity="Medium",
                            description=f"Suspicious PowerShell execution detected on {log.host}",
                            host=log.host,
                            user=log.user,
                            mitre_technique="T1059.001",
                            confidence=0.8,
                            tags=["powershell", "execution", "suspicious"],
                            raw_events=[log]
                        )
                        alerts.append(alert)
                        break
        
        return alerts
    
    def _detect_lateral_movement(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect lateral movement indicators"""
        alerts = []
        
        # Look for suspicious network connections
        suspicious_ports = [135, 139, 445, 5985, 5986]  # RPC, SMB, WinRM
        
        for log in logs:
            if log.event_type == "network_connection":
                # Extract port from raw data
                port = log.raw_data.get('destination_port', 0)
                if port in suspicious_ports:
                    alert = Alert(
                        id=f"lateral_movement_{log.host}_{log.timestamp.isoformat()}",
                        rule_name="Lateral Movement",
                        severity="High",
                        description=f"Suspicious network connection to port {port} from {log.host}",
                        host=log.host,
                        user=log.user,
                        ip=log.ip,
                        mitre_technique="T1021",
                        confidence=0.7,
                        tags=["lateral_movement", "network", "suspicious"],
                        raw_events=[log]
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_data_exfiltration(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect data exfiltration attempts"""
        alerts = []
        
        for log in logs:
            if log.event_type == "data_transfer":
                # Check data size and destination
                data_size = log.raw_data.get('data_size', 0)
                dest_ip = log.raw_data.get('destination_ip', '')
                
                # Check if destination is external
                external_ips = self._is_external_ip(dest_ip)
                
                if data_size > 10485760 and external_ips:  # 10MB threshold
                    alert = Alert(
                        id=f"data_exfil_{log.host}_{log.timestamp.isoformat()}",
                        rule_name="Data Exfiltration",
                        severity="Critical",
                        description=f"Large data transfer ({data_size} bytes) to external IP {dest_ip} from {log.host}",
                        host=log.host,
                        user=log.user,
                        ip=dest_ip,
                        mitre_technique="T1041",
                        confidence=0.9,
                        tags=["data_exfiltration", "network", "critical"],
                        raw_events=[log]
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private)"""
        if not ip or ip == 'unknown':
            return False
        
        # Private IP ranges
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255')
        ]
        
        try:
            ip_parts = [int(x) for x in ip.split('.')]
            if len(ip_parts) != 4:
                return True
            
            for start_range, end_range in private_ranges:
                start_parts = [int(x) for x in start_range.split('.')]
                end_parts = [int(x) for x in end_range.split('.')]
                
                if (start_parts <= ip_parts <= end_parts):
                    return False
            
            return True
        except:
            return True
    
    def _detect_ransomware(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect ransomware activity"""
        alerts = []
        
        ransomware_indicators = [
            r'\.encrypted$', r'\.locked$', r'\.crypto$', r'\.crypt$',
            r'DECRYPT', r'RECOVERY', r'README', r'HOW_TO_DECRYPT'
        ]
        
        for log in logs:
            if log.event_type == 'process_creation':
                for indicator in ransomware_indicators:
                    if re.search(indicator, log.command_line, re.IGNORECASE):
                        alert = Alert(
                            id=f"ransomware_{log.host}_{log.timestamp.isoformat()}",
                            rule_name="Ransomware Activity",
                            severity="Critical",
                            description=f"Potential ransomware activity detected on {log.host}",
                            host=log.host,
                            user=log.user,
                            mitre_technique="T1486",
                            confidence=0.85,
                            tags=["ransomware", "critical", "encryption"],
                            raw_events=[log]
                        )
                        alerts.append(alert)
                        break
        
        return alerts
    
    def _detect_credential_dumping(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect credential dumping attempts"""
        alerts = []
        
        cred_dump_tools = ['mimikatz', 'procdump', 'pwdump', 'gsecdump', 'wce.exe']
        cred_dump_processes = ['lsass.exe', 'ntds.dit']
        
        for log in logs:
            if log.process_name:
                process_lower = log.process_name.lower()
                if any(tool in process_lower for tool in cred_dump_tools):
                    alert = Alert(
                        id=f"cred_dump_{log.host}_{log.timestamp.isoformat()}",
                        rule_name="Credential Dumping",
                        severity="Critical",
                        description=f"Credential dumping tool detected: {log.process_name}",
                        host=log.host,
                        user=log.user,
                        mitre_technique="T1003",
                        confidence=0.95,
                        tags=["credential_dumping", "theft", "critical"],
                        raw_events=[log]
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_webshell(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect webshell activity"""
        alerts = []
        
        webshell_patterns = [
            r'eval\(', r'base64_decode', r'system\(', r'exec\(',
            r'shell_exec', r'passthru', r'cmd\.exe', r'powershell\.exe'
        ]
        
        for log in logs:
            if log.event_type == 'http_request' or 'web' in log.source.lower():
                for pattern in webshell_patterns:
                    if re.search(pattern, log.message, re.IGNORECASE):
                        alert = Alert(
                            id=f"webshell_{log.host}_{log.timestamp.isoformat()}",
                            rule_name="Webshell Activity",
                            severity="High",
                            description=f"Potential webshell detected on {log.host}",
                            host=log.host,
                            user=log.user,
                            ip=log.ip,
                            mitre_technique="T1505.003",
                            confidence=0.8,
                            tags=["webshell", "persistence", "web_attack"],
                            raw_events=[log]
                        )
                        alerts.append(alert)
                        break
        
        return alerts
    
    def _detect_dll_injection(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect DLL injection attempts"""
        alerts = []
        
        suspicious_dlls = [
            'kernel32.dll', 'ntdll.dll', 'advapi32.dll',
            'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx'
        ]
        
        for log in logs:
            if log.event_type == 'process_creation':
                for dll_indicator in suspicious_dlls:
                    if dll_indicator.lower() in log.command_line.lower():
                        alert = Alert(
                            id=f"dll_inject_{log.host}_{log.timestamp.isoformat()}",
                            rule_name="DLL Injection",
                            severity="High",
                            description=f"DLL injection detected on {log.host}",
                            host=log.host,
                            user=log.user,
                            mitre_technique="T1055",
                            confidence=0.75,
                            tags=["dll_injection", "process_injection", "evasion"],
                            raw_events=[log]
                        )
                        alerts.append(alert)
                        break
        
        return alerts
    
    def _detect_suspicious_registry(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect suspicious registry modifications"""
        alerts = []
        
        persistence_keys = [
            r'\\Run', r'\\RunOnce', r'\\RunServices',
            r'\\Winlogon', r'\\Image File Execution Options',
            r'\\AppInit_DLLs', r'\\Shell\\Open\\Command'
        ]
        
        for log in logs:
            if 'registry' in log.event_type.lower() or 'reg.exe' in log.process_name.lower():
                for key_pattern in persistence_keys:
                    if re.search(key_pattern, log.command_line, re.IGNORECASE):
                        alert = Alert(
                            id=f"sus_reg_{log.host}_{log.timestamp.isoformat()}",
                            rule_name="Suspicious Registry",
                            severity="Medium",
                            description=f"Suspicious registry modification on {log.host}",
                            host=log.host,
                            user=log.user,
                            mitre_technique="T1547",
                            confidence=0.7,
                            tags=["registry", "persistence", "suspicious"],
                            raw_events=[log]
                        )
                        alerts.append(alert)
                        break
        
        return alerts
    
    def _evaluate_generic_rule(self, rule_config, logs: List[LogEntry]) -> List[Alert]:
        """Evaluate generic rules based on conditions"""
        alerts = []
        
        for log in logs:
            if self._evaluate_conditions(rule_config.conditions, log):
                alert = Alert(
                    id=f"generic_{rule_config.name}_{log.host}_{log.timestamp.isoformat()}",
                    rule_name=rule_config.name,
                    severity=rule_config.severity,
                    description=rule_config.description,
                    host=log.host,
                    user=log.user,
                    ip=log.ip,
                    mitre_technique=rule_config.mitre_technique or '',
                    confidence=0.5,
                    tags=["generic_rule"],
                    raw_events=[log]
                )
                alerts.append(alert)
        
        return alerts
    
    def _evaluate_conditions(self, conditions: List[Dict[str, Any]], log: LogEntry) -> bool:
        """Evaluate rule conditions against a log entry"""
        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')
            
            if not self._evaluate_condition(field, operator, value, log):
                return False
        
        return True
    
    def _evaluate_condition(self, field: str, operator: str, value: Any, log: LogEntry) -> bool:
        """Evaluate a single condition"""
        log_value = getattr(log, field, None)
        
        if operator == 'equals':
            return log_value == value
        elif operator == 'not_equals':
            return log_value != value
        elif operator == 'contains':
            return value in str(log_value).lower()
        elif operator == 'not_contains':
            return value not in str(log_value).lower()
        elif operator == 'greater_than':
            return float(log_value) > float(value)
        elif operator == 'less_than':
            return float(log_value) < float(value)
        elif operator == 'in':
            return log_value in value
        elif operator == 'not_in':
            return log_value not in value
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False

class BehavioralBaseline:
    """Track behavioral baselines for users and entities"""
    
    def __init__(self, baseline_path: Optional[str] = None):
        self.user_baselines = defaultdict(lambda: {
            'login_hours': set(),
            'login_hosts': set(),
            'login_ips': set(),
            'process_counts': Counter(),
            'command_patterns': []
        })
        self.host_baselines = defaultdict(lambda: {
            'typical_users': set(),
            'typical_processes': set(),
            'network_connections': set()
        })
        
        # Setup persistence
        ROOT = Path(__file__).parent.parent
        self.baseline_path = Path(baseline_path) if baseline_path else ROOT / "models" / "baseline.json"
        self._load_baseline()
    
    def update_baseline(self, log: 'LogEntry'):
        """Update baseline with new log entry"""
        hour = log.timestamp.hour
        
        # Update user baseline
        if log.user != 'unknown':
            self.user_baselines[log.user]['login_hours'].add(hour)
            self.user_baselines[log.user]['login_hosts'].add(log.host)
            self.user_baselines[log.user]['login_ips'].add(log.ip)
            if log.process_name:
                self.user_baselines[log.user]['process_counts'][log.process_name] += 1
        
        # Update host baseline
        if log.host != 'unknown':
            self.host_baselines[log.host]['typical_users'].add(log.user)
            if log.process_name:
                self.host_baselines[log.host]['typical_processes'].add(log.process_name)
    
    def is_anomalous(self, log: 'LogEntry') -> Tuple[bool, str]:
        """Check if log entry is anomalous based on baseline"""
        hour = log.timestamp.hour
        anomalies = []
        
        # Check user anomalies
        if log.user in self.user_baselines:
            baseline = self.user_baselines[log.user]
            
            # Check unusual login hour
            if baseline['login_hours'] and hour not in baseline['login_hours']:
                anomalies.append(f"Unusual login hour: {hour}")
            
            # Check unusual host
            if baseline['login_hosts'] and log.host not in baseline['login_hosts']:
                anomalies.append(f"Unusual host: {log.host}")
            
            # Check unusual IP
            if baseline['login_ips'] and log.ip not in baseline['login_ips'] and log.ip != 'unknown':
                anomalies.append(f"Unusual IP: {log.ip}")
        
        # Check host anomalies
        if log.host in self.host_baselines:
            baseline = self.host_baselines[log.host]
            
            # Check unusual user
            if baseline['typical_users'] and log.user not in baseline['typical_users']:
                anomalies.append(f"Unusual user: {log.user}")
        
        return len(anomalies) > 0, "; ".join(anomalies)
    
    def _load_baseline(self):
        """Load baseline from disk"""
        if not self.baseline_path.exists():
            return
        
        try:
            with open(self.baseline_path, 'r') as f:
                data = json.load(f)
            
            # Restore user baselines
            for user, baseline in data.get('user_baselines', {}).items():
                self.user_baselines[user] = {
                    'login_hours': set(baseline.get('login_hours', [])),
                    'login_hosts': set(baseline.get('login_hosts', [])),
                    'login_ips': set(baseline.get('login_ips', [])),
                    'process_counts': Counter(baseline.get('process_counts', {})),
                    'command_patterns': baseline.get('command_patterns', [])
                }
            
            # Restore host baselines
            for host, baseline in data.get('host_baselines', {}).items():
                self.host_baselines[host] = {
                    'typical_users': set(baseline.get('typical_users', [])),
                    'typical_processes': set(baseline.get('typical_processes', [])),
                    'network_connections': set(baseline.get('network_connections', []))
                }
            
            logger.info(f"Loaded behavioral baseline from {self.baseline_path}")
        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")
    
    def save_baseline(self):
        """Save baseline to disk"""
        try:
            self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                'user_baselines': {
                    user: {
                        'login_hours': list(baseline['login_hours']),
                        'login_hosts': list(baseline['login_hosts']),
                        'login_ips': list(baseline['login_ips']),
                        'process_counts': dict(baseline['process_counts']),
                        'command_patterns': baseline['command_patterns']
                    }
                    for user, baseline in self.user_baselines.items()
                },
                'host_baselines': {
                    host: {
                        'typical_users': list(baseline['typical_users']),
                        'typical_processes': list(baseline['typical_processes']),
                        'network_connections': list(baseline['network_connections'])
                    }
                    for host, baseline in self.host_baselines.items()
                }
            }
            
            with open(self.baseline_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved behavioral baseline to {self.baseline_path}")
        except Exception as e:
            logger.warning(f"Failed to save baseline: {e}")

class MLDetector:
    """Machine Learning-based anomaly detection"""
    
    def __init__(self, settings, opensearch_client=None):
        self.settings = settings
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.baseline = BehavioralBaseline()
        self.opensearch_client = opensearch_client
        
        # Setup model path
        ROOT = Path(__file__).parent.parent
        self.models_dir = ROOT / "models"
        self.model_path = self.models_dir / "model.joblib"
        self.scaler_path = self.models_dir / "scaler.joblib"
        
    async def initialize(self):
        """Initialize ML detector"""
        if not ML_AVAILABLE:
            logger.warning("ML detection disabled - scikit-learn not available")
            return
        
        logger.info("Initializing ML detector...")
        
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
        
        # Try to load existing model
        if self.model_path.exists():
            try:
                import joblib
                self.model = joblib.load(self.model_path)
                if self.scaler_path.exists():
                    self.scaler = joblib.load(self.scaler_path)
                else:
                    self.scaler = StandardScaler()
                self.is_trained = True
                logger.info(f"Loaded trained model from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load saved model: {e}. Will train new model.")
                self.model = None
                self.scaler = StandardScaler()
                self.is_trained = False
        else:
            # Initialize models
            if self.settings.ml_config.model_type == "isolation_forest":
                # Create IsolationForest with public API only. Avoid relying on private
                # attributes (like estimators_) that may change between sklearn versions.
                try:
                    self.model = IsolationForest(
                        contamination=self.settings.ml_config.contamination,
                        random_state=42
                    )
                except Exception as e:
                    logger.error(f"Failed to initialize IsolationForest: {e}")
                    self.model = None
            else:
                logger.error(f"Unsupported ML model type: {self.settings.ml_config.model_type}")
                return
            
            self.scaler = StandardScaler()
            self.is_trained = False
        
        logger.info("ML detector initialized successfully")
    
    def extract_features(self, logs: List[LogEntry]) -> np.ndarray:
        """Extract numerical features from logs"""
        features = []
        
        for log in logs:
            feature_vector = [
                log.event_id,
                len(log.host),
                len(log.user),
                len(log.message),
                len(log.command_line),
                1 if log.event_type == 'failed_logon' else 0,
                1 if log.event_type == 'successful_logon' else 0,
                1 if log.event_type == 'process_creation' else 0,
                1 if log.event_type == 'network_connection' else 0,
                1 if log.severity == 'warning' else 0,
                1 if log.severity == 'critical' else 0,
                self._extract_ip_features(log.ip),
                self._extract_time_features(log.timestamp)
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def _extract_ip_features(self, ip: str) -> int:
        """Extract features from IP address"""
        if not ip or ip == 'unknown':
            return 0
        
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                # Convert to integer representation
                return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])
        except:
            pass
        
        return 0
    
    def _extract_time_features(self, timestamp: datetime) -> int:
        """Extract time-based features"""
        return timestamp.hour * 60 + timestamp.minute
    
    def train(self, logs: List[LogEntry]):
        """Train the ML model and build behavioral baseline"""
        # Avoid truth-testing estimator objects from sklearn (they implement
        # __len__ which may access attributes not yet present across versions).
        if not ML_AVAILABLE or self.model is None:
            return
        
        logger.info("Training ML model and building behavioral baseline...")
        
        # Build behavioral baseline
        for log in logs:
            self.baseline.update_baseline(log)
        logger.info(f"Built baseline for {len(self.baseline.user_baselines)} users and {len(self.baseline.host_baselines)} hosts")
        
        # Extract features
        features = self.extract_features(logs)
        
        if len(features) < self.settings.ml_config.training_samples:
            logger.warning(f"Not enough samples for training: {len(features)} < {self.settings.ml_config.training_samples}")
            return
        
        # Scale features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train model
        self.model.fit(features_scaled)
        self.is_trained = True
        
        # Save trained model
        try:
            self.models_dir.mkdir(parents=True, exist_ok=True)
            import joblib
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            logger.info(f"Saved trained model to {self.model_path}")
        except Exception as e:
            logger.warning(f"Failed to save model: {e}")
        
        # Save behavioral baseline
        try:
            self.baseline.save_baseline()
        except Exception as e:
            logger.warning(f"Failed to save baseline: {e}")
        
        logger.info("ML model trained successfully")
    
    def detect_anomalies(self, logs: List[LogEntry]) -> List[Alert]:
        """Detect anomalies using ML model"""
        # Use explicit None check to avoid invoking sklearn estimator __len__
        if not ML_AVAILABLE or self.model is None or not self.is_trained:
            return []
        
        alerts = []
        
        # Extract features
        features = self.extract_features(logs)
        features_scaled = self.scaler.transform(features)
        
        # Predict anomalies using public methods. Some sklearn versions expose
        # decision_function instead of score_samples; prefer score_samples and
        # fall back to negative decision_function values if needed.
        try:
            predictions = self.model.predict(features_scaled)
        except Exception as e:
            logger.error(f"ML predict failed: {e}")
            return []

        try:
            scores = self.model.score_samples(features_scaled)
        except AttributeError:
            # Older/newer versions may not have score_samples; fall back to decision_function
            try:
                df = self.model.decision_function(features_scaled)
                # decision_function: higher -> more normal; invert and scale
                scores = -df
            except Exception as e:
                logger.warning(f"ML scoring fallback failed: {e}")
                scores = [0.0] * len(predictions)
        except Exception as e:
            logger.warning(f"ML score_samples failed: {e}")
            scores = [0.0] * len(predictions)
        
        # Generate alerts for anomalies
        for i, (log, prediction, score) in enumerate(zip(logs, predictions, scores)):
            if prediction == -1:  # Anomaly detected
                confidence = abs(score)  # Convert to positive confidence score
                
                # Check behavioral baseline
                is_baseline_anomaly, anomaly_reason = self.baseline.is_anomalous(log)
                
                description = f"Anomalous behavior detected on {log.host}"
                if is_baseline_anomaly:
                    description += f" ({anomaly_reason})"
                    confidence = min(confidence * 1.2, 1.0)  # Increase confidence if baseline also flags it
                
                alert = Alert(
                    id=f"ml_anomaly_{log.host}_{log.timestamp.isoformat()}",
                    rule_name="ML Anomaly Detection",
                    severity="High" if is_baseline_anomaly else "Medium",
                    description=description,
                    host=log.host,
                    user=log.user,
                    ip=log.ip,
                    mitre_technique="T1055",  # Process Injection
                    confidence=min(confidence, 1.0),
                    tags=["ml_anomaly", "behavioral"] + (["baseline_anomaly"] if is_baseline_anomaly else []),
                    raw_events=[log]
                )
                alerts.append(alert)
        
        logger.info(f"ML detector generated {len(alerts)} anomaly alerts")
        return alerts
    
    async def detect(self, index_pattern: str = "filebeat-*", max_logs: int = 10000):
        """Query OpenSearch for logs and detect anomalies, write alerts back to OpenSearch"""
        if not self.opensearch_client:
            logger.warning("OpenSearch not available, skipping detection")
            return []
        
        try:
            # Query OpenSearch for recent logs
            # Handle @timestamp field gracefully - if it doesn't exist, query without it
            query = {
                "query": {
                    "match_all": {}
                },
                "size": max_logs
            }
            
            # Try to use @timestamp if available, but handle gracefully if it's not mapped
            try:
                # Test if @timestamp field exists by trying a small query
                test_query = {
                    "query": {"match_all": {}},
                    "size": 1,
                    "sort": [{"@timestamp": {"order": "desc"}}]
                }
                # Try the query - if it fails, @timestamp doesn't exist
                try:
                    self.opensearch_client.search(index=index_pattern, body=test_query)
                    # If successful, use @timestamp in the actual query
                    query["query"] = {
                        "range": {
                            "@timestamp": {
                                "gte": "now-1h",
                                "lte": "now"
                            }
                        }
                    }
                    query["sort"] = [{"@timestamp": {"order": "desc"}}]
                except Exception:
                    # @timestamp field doesn't exist or can't be sorted, use match_all
                    query["query"] = {"match_all": {}}
                    logger.info("No @timestamp field found in indices, querying all logs without timestamp filter")
            except Exception as e:
                # If checking fails, use safe query without timestamp
                query["query"] = {"match_all": {}}
                logger.warning(f"Could not check for @timestamp field: {e}. Using match_all query.")
            
            response = self.opensearch_client.search(
                index=index_pattern,
                body=query
            )
            
            # Convert OpenSearch hits to LogEntry objects
            from collectors.log_collector import LogEntry
            logs = []
            
            for hit in response['hits']['hits']:
                source = hit['_source']
                
                # Parse log entry
                log = LogEntry(
                    timestamp=datetime.fromisoformat(source.get('@timestamp', datetime.now(timezone.utc).isoformat()).replace('Z', '+00:00')),
                    host=source.get('host', {}).get('name', 'unknown') if isinstance(source.get('host'), dict) else source.get('host', 'unknown'),
                    user=source.get('user', 'unknown'),
                    event_id=source.get('event_id', 0),
                    ip=source.get('source', {}).get('ip', 'unknown') if isinstance(source.get('source'), dict) else source.get('ip', 'unknown'),
                    message=source.get('message', ''),
                    event_type=source.get('event_type', 'unknown'),
                    severity=source.get('severity', 'info'),
                    source=source.get('log_source', 'opensearch'),
                    raw_data=source
                )
                logs.append(log)
            
            logger.info(f"Retrieved {len(logs)} logs from OpenSearch")
            
            # Detect anomalies
            alerts = self.detect_anomalies(logs)
            
            # Write alerts to OpenSearch
            if alerts:
                await self._write_alerts_to_opensearch(alerts)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error querying OpenSearch: {e}")
            return []
    
    async def _write_alerts_to_opensearch(self, alerts: List[Alert]):
        """Write alerts to OpenSearch security-alerts index"""
        if not self.opensearch_client:
            return
        
        try:
            for alert in alerts:
                alert_dict = alert.to_dict()
                alert_dict['@timestamp'] = alert.timestamp.isoformat()
                alert_dict['_id'] = alert.id or str(uuid.uuid4())
                
                # Index the alert
                self.opensearch_client.index(
                    index='security-alerts',
                    id=alert_dict['_id'],
                    body=alert_dict,
                    refresh=True
                )
            
            logger.info(f"Wrote {len(alerts)} alerts to OpenSearch security-alerts index")
            
        except Exception as e:
            logger.error(f"Error writing alerts to OpenSearch: {e}")

class ThreatDetector:
    """Main threat detection engine"""
    
    def __init__(self, settings, opensearch_client=None):
        self.settings = settings
        self.rule_engine = RuleEngine(settings)
        self.ml_detector = MLDetector(settings, opensearch_client)
        self.opensearch_client = opensearch_client
        
    async def initialize(self):
        """Initialize threat detector"""
        logger.info("Initializing threat detector...")
        
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
                self.ml_detector.opensearch_client = self.opensearch_client
                # Verify connection by making a health check
                self.opensearch_client.info()
                logger.info("Connected to OpenSearch and verified")
            except Exception as e:
                logger.error(f"Failed to connect to OpenSearch: {e}")
                self.opensearch_client = None
        
        await self.ml_detector.initialize()
        
        logger.info("Threat detector initialized successfully")
    
    async def analyze_logs(self, logs: List[LogEntry]) -> List[Alert]:
        """Analyze logs and generate alerts"""
        logger.info(f"Analyzing {len(logs)} log entries...")
        
        all_alerts = []
        
        # Rule-based detection
        rule_alerts = self.rule_engine.evaluate_rules(logs)
        all_alerts.extend(rule_alerts)
        logger.info(f"Rule engine generated {len(rule_alerts)} alerts")
        
        # ML-based detection
        if self.settings.ml_config.enabled and len(logs) >= 100:
            # Train model if needed
            if not self.ml_detector.is_trained:
                self.ml_detector.train(logs)
            
            # Detect anomalies
            ml_alerts = self.ml_detector.detect_anomalies(logs)
            all_alerts.extend(ml_alerts)
            logger.info(f"ML detector generated {len(ml_alerts)} alerts")
        
        # Remove duplicates and sort by severity
        unique_alerts = self._deduplicate_alerts(all_alerts)
        unique_alerts.sort(key=lambda x: self._severity_score(x.severity), reverse=True)
        
        logger.info(f"Total unique alerts generated: {len(unique_alerts)}")
        return unique_alerts
    
    def _deduplicate_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """Remove duplicate alerts"""
        seen = set()
        unique_alerts = []
        
        for alert in alerts:
            # Create a key for deduplication
            key = f"{alert.rule_name}_{alert.host}_{alert.user}_{alert.ip}_{alert.timestamp.strftime('%Y%m%d%H%M')}"
            
            if key not in seen:
                seen.add(key)
                unique_alerts.append(alert)
        
        return unique_alerts
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity to numerical score for sorting"""
        severity_scores = {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Critical': 4
        }
        return severity_scores.get(severity, 0)
    
    async def save_alerts(self, alerts: List[Alert], filename: Optional[str] = None):
        """Save alerts to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"alerts_{timestamp}.json"
        
        file_path = Path(self.settings.alerts_dir) / filename
        
        with open(file_path, 'w') as f:
            for alert in alerts:
                f.write(json.dumps(alert.to_dict()) + '\n')
        
        logger.info(f"Saved {len(alerts)} alerts to {file_path}")
        return file_path
# ============================================================================
# SECTION 3: INTEL ENRICHER - Threat Intelligence APIs
# ============================================================================
# Threat Intelligence Enrichment Module for ThreatOps SOC

import asyncio
import aiohttp
import logging
import json
import hashlib
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import sqlite3
from urllib.parse import quote
from functools import wraps

# Alert is defined above in this same file

logger = logging.getLogger(__name__)

# OpenSearch client - optional import
try:
    from opensearchpy import OpenSearch
    OPENSEARCH_AVAILABLE = True
except ImportError:
    OPENSEARCH_AVAILABLE = False
    logger.warning("opensearch-py not available, OpenSearch integration disabled")

def retry_on_failure(max_retries: int = 3, delay: float = 1.0):
    """Decorator for retrying failed API calls"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except aiohttp.ClientError as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s: {e}")
                        await asyncio.sleep(wait_time)
                except Exception as e:
                    logger.error(f"Unexpected error in {func.__name__}: {e}")
                    return None
            
            logger.error(f"API call failed after {max_retries} attempts: {last_exception}")
            return None
        return wrapper
    return decorator

class ThreatIntelResult:
    """Threat intelligence enrichment result"""
    
    def __init__(self, **kwargs):
        self.ioc = kwargs.get('ioc', '')  # Indicator of Compromise
        self.ioc_type = kwargs.get('ioc_type', '')  # ip, domain, hash, url
        self.reputation = kwargs.get('reputation', 'unknown')  # clean, suspicious, malicious
        self.confidence = kwargs.get('confidence', 0.0)
        self.source = kwargs.get('source', '')
        self.details = kwargs.get('details', {})
        self.last_updated = kwargs.get('last_updated', datetime.now(timezone.utc))
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'ioc': self.ioc,
            'ioc_type': self.ioc_type,
            'reputation': self.reputation,
            'confidence': self.confidence,
            'source': self.source,
            'details': self.details,
            'last_updated': self.last_updated.isoformat()
        }

class LocalIntelDB:
    """Local threat intelligence database"""
    
    def __init__(self, db_path: str = "data/threat_intel.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                ioc TEXT PRIMARY KEY,
                ioc_type TEXT,
                reputation TEXT,
                confidence REAL,
                source TEXT,
                details TEXT,
                last_updated TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_cache (
                query TEXT PRIMARY KEY,
                response TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Load sample threat intelligence
        self._load_sample_intel()
    
    def _load_sample_intel(self):
        """Load sample threat intelligence data"""
        sample_iocs = [
            {
                'ioc': '192.168.1.100',
                'ioc_type': 'ip',
                'reputation': 'malicious',
                'confidence': 0.9,
                'source': 'sample_data',
                'details': {'reason': 'Known malicious IP from sample dataset'}
            },
            {
                'ioc': 'malicious-domain.com',
                'ioc_type': 'domain',
                'reputation': 'malicious',
                'confidence': 0.8,
                'source': 'sample_data',
                'details': {'reason': 'Known malicious domain from sample dataset'}
            },
            {
                'ioc': '5d41402abc4b2a76b9719d911017c592',
                'ioc_type': 'hash',
                'reputation': 'malicious',
                'confidence': 0.95,
                'source': 'sample_data',
                'details': {'reason': 'Known malicious file hash from sample dataset'}
            }
        ]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for ioc_data in sample_iocs:
            cursor.execute('''
                INSERT OR REPLACE INTO iocs 
                (ioc, ioc_type, reputation, confidence, source, details, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc_data['ioc'],
                ioc_data['ioc_type'],
                ioc_data['reputation'],
                ioc_data['confidence'],
                ioc_data['source'],
                json.dumps(ioc_data['details']),
                datetime.now(timezone.utc).isoformat()
            ))
        
        conn.commit()
        conn.close()
    
    def get_ioc_info(self, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Get IOC information from local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ioc, ioc_type, reputation, confidence, source, details, last_updated
            FROM iocs WHERE ioc = ? AND ioc_type = ?
        ''', (ioc, ioc_type))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return ThreatIntelResult(
                ioc=row[0],
                ioc_type=row[1],
                reputation=row[2],
                confidence=row[3],
                source=row[4],
                details=json.loads(row[5]) if row[5] else {},
                last_updated=datetime.fromisoformat(row[6])
            )
        
        return None
    
    def store_ioc_info(self, intel_result: ThreatIntelResult):
        """Store IOC information in local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO iocs 
            (ioc, ioc_type, reputation, confidence, source, details, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            intel_result.ioc,
            intel_result.ioc_type,
            intel_result.reputation,
            intel_result.confidence,
            intel_result.source,
            json.dumps(intel_result.details),
            intel_result.last_updated.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def cache_api_response(self, query: str, response: str):
        """Cache API response"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO api_cache (query, response)
            VALUES (?, ?)
        ''', (query, response))
        
        conn.commit()
        conn.close()
    
    def get_cached_response(self, query: str) -> Optional[str]:
        """Get cached API response"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT response FROM api_cache 
            WHERE query = ? AND timestamp > datetime('now', '-1 hour')
        ''', (query,))
        
        row = cursor.fetchone()
        conn.close()
        
        return row[0] if row else None

class VirusTotalAPI:
    """VirusTotal API integration"""
    
    def __init__(self, api_key: str, rate_limit: int = 4):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_request_time = 0
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP reputation with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"x-apikey": self.api_key}
                url = f"{self.base_url}/ip_addresses/{ip}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Parse response
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            reputation = 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean'
                            confidence = malicious / total if malicious > 0 else suspicious / total if suspicious > 0 else 0.1
                            
                            return ThreatIntelResult(
                                ioc=ip,
                                ioc_type='ip',
                                reputation=reputation,
                                confidence=confidence,
                                source='virustotal',
                                details={
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'total': total,
                                    'last_analysis': data.get('data', {}).get('attributes', {}).get('last_analysis_date')
                                }
                            )
                    
        except Exception as e:
            logger.error(f"VirusTotal API error for IP {ip}: {e}")
        
        return None
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Check domain reputation with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"x-apikey": self.api_key}
                url = f"{self.base_url}/domains/{domain}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            reputation = 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean'
                            confidence = malicious / total if malicious > 0 else suspicious / total if suspicious > 0 else 0.1
                            
                            return ThreatIntelResult(
                                ioc=domain,
                                ioc_type='domain',
                                reputation=reputation,
                                confidence=confidence,
                                source='virustotal',
                                details={
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'total': total
                                }
                            )
                    
        except Exception as e:
            logger.error(f"VirusTotal API error for domain {domain}: {e}")
        
        return None
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Check file hash with VirusTotal"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"x-apikey": self.api_key}
                url = f"{self.base_url}/files/{file_hash}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        total = sum(stats.values())
                        
                        if total > 0:
                            reputation = 'malicious' if malicious > 0 else 'suspicious' if suspicious > 0 else 'clean'
                            confidence = malicious / total if malicious > 0 else suspicious / total if suspicious > 0 else 0.1
                            
                            return ThreatIntelResult(
                                ioc=file_hash,
                                ioc_type='hash',
                                reputation=reputation,
                                confidence=confidence,
                                source='virustotal',
                                details={
                                    'malicious': malicious,
                                    'suspicious': suspicious,
                                    'total': total
                                }
                            )
                    
        except Exception as e:
            logger.error(f"VirusTotal API error for hash {file_hash}: {e}")
        
        return None
    
    async def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit):  # Convert to seconds per request
            await asyncio.sleep((60 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()

class AbuseIPDBAPI:
    """AbuseIPDB API integration"""
    
    def __init__(self, api_key: str, rate_limit: int = 1000):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.last_request_time = 0
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP reputation with AbuseIPDB"""
        if not self.api_key:
            logger.warning("AbuseIPDB API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"Key": self.api_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
                
                async with session.get(f"{self.base_url}/check", headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        abuse_confidence = data.get('data', {}).get('abuseConfidencePercentage', 0)
                        usage_type = data.get('data', {}).get('usageType', '')
                        country = data.get('data', {}).get('countryCode', '')
                        
                        reputation = 'malicious' if abuse_confidence > 75 else 'suspicious' if abuse_confidence > 25 else 'clean'
                        confidence = abuse_confidence / 100.0
                        
                        return ThreatIntelResult(
                            ioc=ip,
                            ioc_type='ip',
                            reputation=reputation,
                            confidence=confidence,
                            source='abuseipdb',
                            details={
                                'abuse_confidence': abuse_confidence,
                                'usage_type': usage_type,
                                'country': country,
                                'total_reports': data.get('data', {}).get('totalReports', 0)
                            }
                        )
                    
        except Exception as e:
            logger.error(f"AbuseIPDB API error for IP {ip}: {e}")
        
        return None
    
    async def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit):
            await asyncio.sleep((60 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()

class AlienVaultOTXAPI:
    """AlienVault OTX API integration"""
    
    def __init__(self, api_key: str, rate_limit: int = 100):
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.last_request_time = 0
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Check IP reputation with OTX"""
        if not self.api_key:
            logger.warning("AlienVault OTX API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"X-OTX-API-KEY": self.api_key}
                url = f"{self.base_url}/indicators/IPv4/{ip}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        pulses = data.get('pulse_info', {}).get('pulses', [])
                        
                        if pulse_count > 0:
                            # Calculate reputation based on pulse count and references
                            reputation = 'malicious' if pulse_count > 5 else 'suspicious' if pulse_count > 0 else 'clean'
                            confidence = min(pulse_count / 10.0, 1.0)
                            
                            # Extract pulse details
                            pulse_details = []
                            for pulse in pulses[:5]:  # Limit to first 5 pulses
                                pulse_details.append({
                                    'name': pulse.get('name', ''),
                                    'tags': pulse.get('tags', []),
                                    'references': pulse.get('references', [])
                                })
                            
                            return ThreatIntelResult(
                                ioc=ip,
                                ioc_type='ip',
                                reputation=reputation,
                                confidence=confidence,
                                source='otx',
                                details={
                                    'pulse_count': pulse_count,
                                    'pulses': pulse_details
                                }
                            )
                    
        except Exception as e:
            logger.error(f"OTX API error for IP {ip}: {e}")
        
        return None
    
    @retry_on_failure(max_retries=3, delay=1.0)
    async def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Check domain reputation with OTX"""
        if not self.api_key:
            logger.warning("AlienVault OTX API key not configured")
            return None
        
        await self._rate_limit()
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"X-OTX-API-KEY": self.api_key}
                url = f"{self.base_url}/indicators/domain/{domain}"
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        pulse_count = data.get('pulse_info', {}).get('count', 0)
                        
                        if pulse_count > 0:
                            reputation = 'malicious' if pulse_count > 5 else 'suspicious' if pulse_count > 0 else 'clean'
                            confidence = min(pulse_count / 10.0, 1.0)
                            
                            return ThreatIntelResult(
                                ioc=domain,
                                ioc_type='domain',
                                reputation=reputation,
                                confidence=confidence,
                                source='otx',
                                details={'pulse_count': pulse_count}
                            )
                    
        except Exception as e:
            logger.error(f"OTX API error for domain {domain}: {e}")
        
        return None
    
    async def _rate_limit(self):
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < (60 / self.rate_limit):
            await asyncio.sleep((60 / self.rate_limit) - time_since_last)
        
        self.last_request_time = time.time()

class IntelEnricher:
    """Main threat intelligence enrichment engine"""
    
    def __init__(self, settings, opensearch_client=None):
        self.settings = settings
        self.local_db = LocalIntelDB()
        self.apis = {}
        self.opensearch_client = opensearch_client
        
    async def initialize(self):
        """Initialize threat intelligence enricher"""
        logger.info("Initializing threat intelligence enricher...")
        
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
        
        # Initialize APIs
        for api_config in self.settings.get_enabled_apis():
            if api_config.name == "virustotal":
                self.apis['virustotal'] = VirusTotalAPI(api_config.api_key, api_config.rate_limit)
            elif api_config.name == "abuseipdb":
                self.apis['abuseipdb'] = AbuseIPDBAPI(api_config.api_key, api_config.rate_limit)
            elif api_config.name == "otx":
                self.apis['otx'] = AlienVaultOTXAPI(api_config.api_key, api_config.rate_limit)
        
        logger.info(f"Initialized {len(self.apis)} threat intelligence APIs")
    
    async def enrich_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """Enrich alerts with threat intelligence"""
        logger.info(f"Enriching {len(alerts)} alerts with threat intelligence...")
        
        enriched_alerts = []
        
        for alert in alerts:
            enriched_alert = await self._enrich_single_alert(alert)
            enriched_alerts.append(enriched_alert)
        
        logger.info(f"Enriched {len(enriched_alerts)} alerts")
        return enriched_alerts
    
    async def _enrich_single_alert(self, alert: Alert) -> Alert:
        """Enrich a single alert with threat intelligence"""
        intel_results = []
        
        # Extract IOCs from alert
        iocs = self._extract_iocs(alert)
        
        # Check each IOC
        for ioc, ioc_type in iocs:
            intel_result = await self._check_ioc(ioc, ioc_type)
            if intel_result:
                intel_results.append(intel_result)
        
        # Update alert with intelligence
        if intel_results:
            alert.tags.extend(['threat_intel_enriched'])
            
            # Determine overall reputation
            malicious_count = sum(1 for r in intel_results if r.reputation == 'malicious')
            suspicious_count = sum(1 for r in intel_results if r.reputation == 'suspicious')
            
            if malicious_count > 0:
                alert.tags.append('malicious_ioc')
                # Increase severity if malicious IOCs found
                if alert.severity == 'Low':
                    alert.severity = 'Medium'
                elif alert.severity == 'Medium':
                    alert.severity = 'High'
            elif suspicious_count > 0:
                alert.tags.append('suspicious_ioc')
            
            # Add intelligence details to raw_events
            for event in alert.raw_events:
                if hasattr(event, 'raw_data'):
                    event.raw_data['threat_intel'] = [r.to_dict() for r in intel_results]
        
        return alert
    
    def _extract_iocs(self, alert: Alert) -> List[Tuple[str, str]]:
        """Extract IOCs from alert"""
        iocs = []
        
        # Extract IP addresses
        if alert.ip and alert.ip != 'unknown':
            iocs.append((alert.ip, 'ip'))
        
        # Extract IOCs from raw events
        for event in alert.raw_events:
            if hasattr(event, 'raw_data'):
                raw_data = event.raw_data
                
                # Extract IPs from raw data
                for key, value in raw_data.items():
                    if 'ip' in key.lower() and isinstance(value, str) and value != 'unknown':
                        iocs.append((value, 'ip'))
                
                # Extract domains from command lines
                if 'command_line' in raw_data:
                    domains = self._extract_domains(raw_data['command_line'])
                    for domain in domains:
                        iocs.append((domain, 'domain'))
                
                # Extract file hashes
                if 'process_name' in raw_data:
                    # Simple hash extraction (in real implementation, use proper hash detection)
                    process_name = raw_data['process_name']
                    if len(process_name) == 32 and all(c in '0123456789abcdef' for c in process_name.lower()):
                        iocs.append((process_name, 'hash'))
        
        return list(set(iocs))  # Remove duplicates
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text"""
        import re
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        
        # Filter out common false positives
        filtered_domains = []
        for domain in domains:
            if not any(common in domain.lower() for common in ['localhost', '127.0.0.1', 'example.com']):
                filtered_domains.append(domain)
        
        return filtered_domains
    
    async def _check_ioc(self, ioc: str, ioc_type: str) -> Optional[ThreatIntelResult]:
        """Check IOC against all available sources"""
        # First check local database
        local_result = self.local_db.get_ioc_info(ioc, ioc_type)
        if local_result:
            return local_result
        
        # Check external APIs
        intel_result = None
        
        if ioc_type == 'ip':
            # Check IP with multiple APIs
            for api_name, api in self.apis.items():
                if hasattr(api, 'check_ip'):
                    try:
                        result = await api.check_ip(ioc)
                        if result:
                            intel_result = result
                            break
                    except Exception as e:
                        logger.error(f"Error checking IP {ioc} with {api_name}: {e}")
        
        elif ioc_type == 'domain':
            # Check domain with multiple APIs
            for api_name, api in self.apis.items():
                if hasattr(api, 'check_domain'):
                    try:
                        result = await api.check_domain(ioc)
                        if result:
                            intel_result = result
                            break
                    except Exception as e:
                        logger.error(f"Error checking domain {ioc} with {api_name}: {e}")
        
        elif ioc_type == 'hash':
            # Check hash with VirusTotal
            if 'virustotal' in self.apis:
                try:
                    result = await self.apis['virustotal'].check_hash(ioc)
                    if result:
                        intel_result = result
                except Exception as e:
                    logger.error(f"Error checking hash {ioc} with VirusTotal: {e}")
        
        # Store result in local database
        if intel_result:
            self.local_db.store_ioc_info(intel_result)
        
        return intel_result
    
    async def get_ioc_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        conn = sqlite3.connect(self.local_db.db_path)
        cursor = conn.cursor()
        
        # Get IOC counts by type
        cursor.execute('SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type')
        ioc_counts = dict(cursor.fetchall())
        
        # Get reputation distribution
        cursor.execute('SELECT reputation, COUNT(*) FROM iocs GROUP BY reputation')
        reputation_counts = dict(cursor.fetchall())
        
        # Get source distribution
        cursor.execute('SELECT source, COUNT(*) FROM iocs GROUP BY source')
        source_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_iocs': sum(ioc_counts.values()),
            'ioc_counts_by_type': ioc_counts,
            'reputation_distribution': reputation_counts,
            'source_distribution': source_counts
        }
    
    async def enrich_alerts_from_opensearch(self):
        """Query OpenSearch for alerts needing enrichment, enrich them, and update"""
        if not self.opensearch_client:
            logger.warning("OpenSearch not available, skipping alert enrichment")
            return []
        
        try:
            # Query for alerts that need enrichment (no threat_intel tag)
            query = {
                "query": {
                    "bool": {
                        "must_not": {
                            "term": {"tags": "threat_intel_enriched"}
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
            
            logger.info(f"Retrieved {len(alerts)} alerts needing enrichment from OpenSearch")
            
            # Enrich alerts
            enriched_alerts = await self.enrich_alerts(alerts)
            
            # Update alerts in OpenSearch
            if enriched_alerts:
                await self._update_alerts_in_opensearch(enriched_alerts)
            
            return enriched_alerts
            
        except Exception as e:
            logger.error(f"Error enriching alerts from OpenSearch: {e}")
            return []
    
    async def _update_alerts_in_opensearch(self, alerts: List[Alert]):
        """Update enriched alerts in OpenSearch"""
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
            
            logger.info(f"Updated {len(alerts)} enriched alerts in OpenSearch")
            
        except Exception as e:
            logger.error(f"Error updating alerts in OpenSearch: {e}")
# ============================================================================
# SECTION 4: RISK SCORER - MITRE ATT&CK Mapping & Risk Calculation
# ============================================================================
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

# Alert is defined above in this same file

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
