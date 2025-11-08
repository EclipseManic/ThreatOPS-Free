"""
Pytest configuration and fixtures for ThreatOps SIEM tests
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path for all tests
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def test_data_dir():
    """Fixture providing path to test data directory"""
    return Path(__file__).parent / "test_data"


@pytest.fixture(scope="session")
def sample_log_entry():
    """Fixture providing a sample log entry"""
    from datetime import datetime, timezone
    from core_detection import LogEntry
    
    return LogEntry(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.100",
        dest_ip="10.0.0.1",
        event_type="test_event",
        severity="medium",
        message="Sample test log entry"
    )


@pytest.fixture(scope="session")
def sample_alert():
    """Fixture providing a sample alert"""
    from datetime import datetime, timezone
    from core_detection import Alert
    
    return Alert(
        timestamp=datetime.now(timezone.utc),
        alert_type="test_alert",
        severity="high",
        source_ip="192.168.1.100",
        description="Sample test alert"
    )


@pytest.fixture(scope="function")
def log_collector():
    """Fixture providing a LogCollector instance"""
    from core_detection import LogCollector
    return LogCollector()


@pytest.fixture(scope="function")
def threat_detector():
    """Fixture providing a ThreatDetector instance"""
    from core_detection import ThreatDetector
    return ThreatDetector()


@pytest.fixture(scope="function")
def intel_enricher():
    """Fixture providing an IntelEnricher instance"""
    from core_detection import IntelEnricher
    return IntelEnricher()


@pytest.fixture(scope="function")
def risk_scorer():
    """Fixture providing a RiskScorer instance"""
    from core_detection import RiskScorer
    return RiskScorer()


@pytest.fixture(scope="function")
def attack_simulator():
    """Fixture providing an AttackSimulator instance"""
    from simulation import AttackSimulator
    return AttackSimulator()


@pytest.fixture(scope="function")
def report_generator():
    """Fixture providing a ReportGenerator instance"""
    from reporting import ReportGenerator
    return ReportGenerator()


# Test markers
def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "requires_opensearch: mark test as requiring OpenSearch connection"
    )

