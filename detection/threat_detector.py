# Threat Detection Engine for ThreatOps SOC

import asyncio
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import json
import uuid

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

from collectors.log_collector import LogEntry

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
    
    def __init__(self):
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

class MLDetector:
    """Machine Learning-based anomaly detection"""
    
    def __init__(self, settings, opensearch_client=None):
        self.settings = settings
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.baseline = BehavioralBaseline()
        self.opensearch_client = opensearch_client
        
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
                    use_ssl=False
                )
                logger.info("Connected to OpenSearch")
            except Exception as e:
                logger.error(f"Failed to connect to OpenSearch: {e}")
                self.opensearch_client = None
        
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
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1h",
                            "lte": "now"
                        }
                    }
                },
                "size": max_logs,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
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
                    use_ssl=False
                )
                self.ml_detector.opensearch_client = self.opensearch_client
                logger.info("Connected to OpenSearch")
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
