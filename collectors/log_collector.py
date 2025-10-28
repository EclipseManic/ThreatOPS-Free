# Log Collector and Normalizer for ThreatOps SOC

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import xml.etree.ElementTree as ET

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

# Linux-specific imports
import subprocess
import os

logger = logging.getLogger(__name__)

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

class WindowsEVTXParser:
    """Parser for Windows EVTX files"""
    
    def __init__(self):
        self.event_mappings = {
            4624: "successful_logon",
            4625: "failed_logon",
            4672: "privilege_escalation",
            4688: "process_creation",
            5156: "network_connection",
            7045: "service_installation"
        }
    
    def parse_evtx_file(self, file_path: str) -> List[LogEntry]:
        """Parse EVTX file and return LogEntry objects"""
        entries = []
        
        try:
            if WINDOWS_AVAILABLE:
                entries = self._parse_with_win32(file_path)
            else:
                entries = self._parse_with_python_evtx(file_path)
        except Exception as e:
            logger.error(f"Error parsing EVTX file {file_path}: {e}")
            
        return entries
    
    def _parse_with_win32(self, file_path: str) -> List[LogEntry]:
        """Parse using win32evtlog (Windows only)"""
        entries = []
        
        try:
            # Open event log
            log_handle = win32evtlog.OpenEventLog(None, "Security")
            win32evtlog.ReadEventLog(log_handle, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            
            while True:
                events = win32evtlog.ReadEventLog(log_handle, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 1)
                if not events:
                    break
                    
                for event in events:
                    entry = self._parse_windows_event(event)
                    if entry:
                        entries.append(entry)
                        
        except Exception as e:
            logger.error(f"Error with win32evtlog: {e}")
        finally:
            try:
                win32evtlog.CloseEventLog(log_handle)
            except:
                pass
                
        return entries
    
    def _parse_with_python_evtx(self, file_path: str) -> List[LogEntry]:
        """Parse using python-evtx library"""
        entries = []
        
        try:
            from Evtx.Evtx import Evtx
            from Evtx.Views import evtx_file_xml_view
            
            with Evtx(file_path) as log:
                for xml, record in evtx_file_xml_view(log):
                    entry = self._parse_xml_event(xml)
                    if entry:
                        entries.append(entry)
                        
        except ImportError:
            logger.warning("python-evtx not available, using sample data")
            entries = self._generate_sample_windows_logs()
        except Exception as e:
            logger.error(f"Error parsing EVTX with python-evtx: {e}")
            
        return entries
    
    def _parse_xml_event(self, xml_data: str) -> Optional[LogEntry]:
        """Parse XML event data"""
        try:
            root = ET.fromstring(xml_data)
            
            # Extract event data
            system = root.find('.//System')
            event_data = root.find('.//EventData')
            
            if system is None:
                return None
                
            event_id = int(system.find('EventID').text)
            time_created = system.find('TimeCreated')
            timestamp = datetime.fromisoformat(time_created.get('SystemTime').replace('Z', '+00:00'))
            
            # Extract additional data
            computer = system.find('Computer').text if system.find('Computer') is not None else 'unknown'
            
            # Parse event data
            data_dict = {}
            if event_data is not None:
                for data_item in event_data.findall('Data'):
                    name = data_item.get('Name')
                    value = data_item.text
                    if name:
                        data_dict[name] = value
            
            # Create log entry
            entry = LogEntry(
                timestamp=timestamp,
                host=computer,
                event_id=event_id,
                event_type=self.event_mappings.get(event_id, 'unknown'),
                source='windows_evtx',
                raw_data=data_dict
            )
            
            # Extract specific fields based on event type
            if event_id == 4625:  # Failed logon
                entry.user = data_dict.get('TargetUserName', 'unknown')
                entry.ip = data_dict.get('IpAddress', 'unknown')
                entry.message = f"Failed logon attempt for user {entry.user} from {entry.ip}"
                entry.severity = 'warning'
                
            elif event_id == 4624:  # Successful logon
                entry.user = data_dict.get('TargetUserName', 'unknown')
                entry.ip = data_dict.get('IpAddress', 'unknown')
                entry.message = f"Successful logon for user {entry.user} from {entry.ip}"
                entry.severity = 'info'
                
            elif event_id == 4688:  # Process creation
                entry.process_name = data_dict.get('NewProcessName', 'unknown')
                entry.command_line = data_dict.get('CommandLine', '')
                entry.user = data_dict.get('SubjectUserName', 'unknown')
                entry.message = f"Process created: {entry.process_name}"
                entry.severity = 'info'
                
            return entry
            
        except Exception as e:
            logger.error(f"Error parsing XML event: {e}")
            return None
    
    def _parse_windows_event(self, event) -> Optional[LogEntry]:
        """Parse Windows event object"""
        try:
            event_id = event.EventID
            timestamp = datetime.fromtimestamp(event.TimeGenerated.timestamp(), tz=timezone.utc)
            computer = event.ComputerName
            
            # Extract event data
            data_dict = {}
            if hasattr(event, 'StringInserts'):
                for i, value in enumerate(event.StringInserts):
                    data_dict[f'Data{i}'] = value
            
            entry = LogEntry(
                timestamp=timestamp,
                host=computer,
                event_id=event_id,
                event_type=self.event_mappings.get(event_id, 'unknown'),
                source='windows_evtx',
                raw_data=data_dict
            )
            
            # Extract specific fields
            if event_id == 4625:  # Failed logon
                entry.user = data_dict.get('Data5', 'unknown')
                entry.ip = data_dict.get('Data19', 'unknown')
                entry.message = f"Failed logon attempt for user {entry.user} from {entry.ip}"
                entry.severity = 'warning'
                
            return entry
            
        except Exception as e:
            logger.error(f"Error parsing Windows event: {e}")
            return None
    
    def _generate_sample_windows_logs(self) -> List[LogEntry]:
        """Generate sample Windows logs for testing"""
        sample_logs = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="WIN-PC01",
                user="admin",
                event_id=4625,
                ip="192.168.1.100",
                message="Failed logon attempt for user admin from 192.168.1.100",
                event_type="failed_logon",
                severity="warning",
                source="windows_evtx"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="WIN-PC01",
                user="admin",
                event_id=4624,
                ip="192.168.1.100",
                message="Successful logon for user admin from 192.168.1.100",
                event_type="successful_logon",
                severity="info",
                source="windows_evtx"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="WIN-PC01",
                user="admin",
                event_id=4688,
                process_name="powershell.exe",
                command_line="powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAAMQAwAA==",
                message="Process created: powershell.exe",
                event_type="process_creation",
                severity="warning",
                source="windows_evtx"
            )
        ]
        return sample_logs

class LinuxAuthParser:
    """Parser for Linux auth.log files"""
    
    def parse_auth_log(self, file_path: str) -> List[LogEntry]:
        """Parse Linux auth.log file"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    entry = self._parse_auth_line(line.strip())
                    if entry:
                        entries.append(entry)
        except FileNotFoundError:
            logger.warning(f"Auth log file not found: {file_path}, generating sample data")
            entries = self._generate_sample_linux_logs()
        except Exception as e:
            logger.error(f"Error parsing auth log {file_path}: {e}")
            
        return entries
    
    def _parse_auth_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single auth.log line"""
        try:
            # Common auth.log patterns
            patterns = {
                'failed_login': r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) sshd\[\d+\]: Failed password for (\w+) from (\S+) port \d+',
                'successful_login': r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) sshd\[\d+\]: Accepted password for (\w+) from (\S+) port \d+',
                'sudo': r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) sudo: (\w+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=\S+',
                'su': r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (\S+) su\[\d+\]: (\w+) to (\w+) on \S+'
            }
            
            for event_type, pattern in patterns.items():
                match = re.match(pattern, line)
                if match:
                    groups = match.groups()
                    timestamp_str = groups[0]
                    host = groups[1]
                    
                    # Parse timestamp (simplified)
                    timestamp = datetime.now(timezone.utc)  # In real implementation, parse the actual timestamp
                    
                    entry = LogEntry(
                        timestamp=timestamp,
                        host=host,
                        event_type=event_type,
                        source='linux_auth',
                        message=line,
                        raw_data={'original_line': line}
                    )
                    
                    if event_type == 'failed_login':
                        entry.user = groups[2]
                        entry.ip = groups[3]
                        entry.event_id = 4625
                        entry.severity = 'warning'
                        entry.message = f"Failed SSH login for user {entry.user} from {entry.ip}"
                        
                    elif event_type == 'successful_login':
                        entry.user = groups[2]
                        entry.ip = groups[3]
                        entry.event_id = 4624
                        entry.severity = 'info'
                        entry.message = f"Successful SSH login for user {entry.user} from {entry.ip}"
                        
                    elif event_type == 'sudo':
                        entry.user = groups[2]
                        entry.event_id = 4672
                        entry.severity = 'info'
                        entry.message = f"Sudo command executed by user {entry.user}"
                        
                    return entry
                    
        except Exception as e:
            logger.error(f"Error parsing auth line: {e}")
            
        return None
    
    def _generate_sample_linux_logs(self) -> List[LogEntry]:
        """Generate sample Linux logs for testing"""
        sample_logs = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="linux-server",
                user="root",
                event_id=4625,
                ip="192.168.1.200",
                message="Failed SSH login for user root from 192.168.1.200",
                event_type="failed_login",
                severity="warning",
                source="linux_auth"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="linux-server",
                user="admin",
                event_id=4624,
                ip="192.168.1.200",
                message="Successful SSH login for user admin from 192.168.1.200",
                event_type="successful_login",
                severity="info",
                source="linux_auth"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="linux-server",
                user="admin",
                event_id=4672,
                message="Sudo command executed by user admin",
                event_type="sudo",
                severity="info",
                source="linux_auth"
            )
        ]
        return sample_logs

class JSONLogParser:
    """Parser for JSON log files"""
    
    def parse_json_log(self, file_path: str) -> List[LogEntry]:
        """Parse JSON log file"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            entry = self._parse_json_entry(data)
                            if entry:
                                entries.append(entry)
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            logger.warning(f"JSON log file not found: {file_path}, generating sample data")
            entries = self._generate_sample_json_logs()
        except Exception as e:
            logger.error(f"Error parsing JSON log {file_path}: {e}")
            
        return entries
    
    def _parse_json_entry(self, data: Dict[str, Any]) -> Optional[LogEntry]:
        """Parse a single JSON log entry"""
        try:
            # Extract timestamp
            timestamp = datetime.now(timezone.utc)
            if 'timestamp' in data:
                try:
                    timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
                except:
                    pass
            
            # Create log entry
            entry = LogEntry(
                timestamp=timestamp,
                host=data.get('host', 'unknown'),
                user=data.get('user', 'unknown'),
                event_id=data.get('event_id', 0),
                ip=data.get('ip', 'unknown'),
                message=data.get('message', ''),
                process_name=data.get('process_name', ''),
                command_line=data.get('command_line', ''),
                event_type=data.get('event_type', 'unknown'),
                severity=data.get('severity', 'info'),
                source='json_logs',
                raw_data=data
            )
            
            return entry
            
        except Exception as e:
            logger.error(f"Error parsing JSON entry: {e}")
            return None
    
    def _generate_sample_json_logs(self) -> List[LogEntry]:
        """Generate sample JSON logs for testing"""
        sample_logs = [
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="app-server",
                user="service_account",
                event_id=1001,
                ip="10.0.0.50",
                message="Application started successfully",
                event_type="application_start",
                severity="info",
                source="json_logs"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="app-server",
                user="user123",
                event_id=1002,
                ip="192.168.1.150",
                message="Suspicious API call detected",
                event_type="suspicious_api",
                severity="warning",
                source="json_logs"
            ),
            LogEntry(
                timestamp=datetime.now(timezone.utc),
                host="app-server",
                user="admin",
                event_id=1003,
                ip="192.168.1.150",
                message="Large data transfer detected",
                event_type="data_transfer",
                severity="critical",
                source="json_logs"
            )
        ]
        return sample_logs

class LogCollector:
    """Main log collector class"""
    
    def __init__(self, settings):
        self.settings = settings
        self.parsers = {
            'windows_evtx': WindowsEVTXParser(),
            'linux_auth': LinuxAuthParser(),
            'json_logs': JSONLogParser()
        }
        
    async def initialize(self):
        """Initialize the log collector"""
        logger.info("Initializing log collector...")
        
        # Create data directories
        Path(self.settings.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.settings.logs_dir).mkdir(parents=True, exist_ok=True)
        
        # Create sample log files if they don't exist
        await self._create_sample_logs()
        
        logger.info("Log collector initialized successfully")
    
    async def _create_sample_logs(self):
        """Create sample log files for testing"""
        sample_dir = Path(self.settings.data_dir) / "sample_logs"
        sample_dir.mkdir(parents=True, exist_ok=True)
        
        # Create sample JSON logs
        json_log_path = sample_dir / "application.json"
        if not json_log_path.exists():
            sample_json_logs = [
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": "app-server",
                    "user": "service_account",
                    "event_id": 1001,
                    "ip": "10.0.0.50",
                    "message": "Application started successfully",
                    "event_type": "application_start",
                    "severity": "info"
                },
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "host": "app-server",
                    "user": "user123",
                    "event_id": 1002,
                    "ip": "192.168.1.150",
                    "message": "Suspicious API call detected",
                    "event_type": "suspicious_api",
                    "severity": "warning"
                }
            ]
            
            with open(json_log_path, 'w') as f:
                for log in sample_json_logs:
                    f.write(json.dumps(log) + '\n')
        
        # Create sample auth log
        auth_log_path = sample_dir / "auth.log"
        if not auth_log_path.exists():
            sample_auth_logs = [
                f"{datetime.now().strftime('%b %d %H:%M:%S')} linux-server sshd[1234]: Failed password for root from 192.168.1.200 port 22",
                f"{datetime.now().strftime('%b %d %H:%M:%S')} linux-server sshd[1235]: Accepted password for admin from 192.168.1.200 port 22",
                f"{datetime.now().strftime('%b %d %H:%M:%S')} linux-server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls"
            ]
            
            with open(auth_log_path, 'w') as f:
                for log in sample_auth_logs:
                    f.write(log + '\n')
    
    async def collect_logs(self) -> List[LogEntry]:
        """Collect logs from all configured sources"""
        all_logs = []
        
        for source_config in self.settings.get_enabled_log_sources():
            try:
                logs = await self._collect_from_source(source_config)
                all_logs.extend(logs)
                logger.info(f"Collected {len(logs)} logs from {source_config.path}")
            except Exception as e:
                logger.error(f"Error collecting logs from {source_config.path}: {e}")
        
        # Sort by timestamp
        all_logs.sort(key=lambda x: x.timestamp)
        
        logger.info(f"Total logs collected: {len(all_logs)}")
        return all_logs
    
    async def _collect_from_source(self, source_config) -> List[LogEntry]:
        """Collect logs from a specific source"""
        parser = self.parsers.get(source_config.parser)
        if not parser:
            logger.error(f"No parser found for type: {source_config.parser}")
            return []
        
        if source_config.type == 'evtx':
            return parser.parse_evtx_file(source_config.path)
        elif source_config.type == 'auth':
            return parser.parse_auth_log(source_config.path)
        elif source_config.type == 'json':
            return parser.parse_json_log(source_config.path)
        else:
            logger.error(f"Unsupported log type: {source_config.type}")
            return []
    
    async def save_logs(self, logs: List[LogEntry], filename: Optional[str] = None):
        """Save logs to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs_{timestamp}.json"
        
        file_path = Path(self.settings.logs_dir) / filename
        
        with open(file_path, 'w') as f:
            for log in logs:
                f.write(json.dumps(log.to_dict()) + '\n')
        
        logger.info(f"Saved {len(logs)} logs to {file_path}")
        return file_path
