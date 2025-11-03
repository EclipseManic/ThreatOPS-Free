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

