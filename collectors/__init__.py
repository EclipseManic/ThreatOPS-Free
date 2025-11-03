# ThreatOps SOC Simulator - Collectors Package
# Note: Log collection is now handled by Filebeat
# This module only provides the LogEntry class for compatibility

from .log_collector import LogEntry

__all__ = [
    'LogEntry'
]
