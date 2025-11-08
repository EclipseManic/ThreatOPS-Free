"""
Test Suite for core_detection.py
Tests log collection, threat detection, enrichment, and scoring
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core_detection import (
    LogEntry,
    LogCollector,
    ThreatDetector,
    Alert,
    IntelEnricher,
    RiskScorer,
    MITREMapper
)


class TestLogEntry:
    """Test LogEntry data model"""
    
    def test_log_entry_creation(self):
        """Test creating a log entry"""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            event_type="login",
            severity="high",
            message="Failed login attempt"
        )
        assert log.source_ip == "192.168.1.100"
        assert log.event_type == "login"
        assert log.severity == "high"
    
    def test_log_entry_to_dict(self):
        """Test converting log entry to dictionary"""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            event_type="login",
            severity="high",
            message="Test message"
        )
        log_dict = log.to_dict()
        assert isinstance(log_dict, dict)
        assert log_dict["source_ip"] == "192.168.1.100"


class TestLogCollector:
    """Test LogCollector functionality"""
    
    def test_log_collector_initialization(self):
        """Test log collector can be initialized"""
        collector = LogCollector()
        assert collector is not None
    
    def test_standardize_log(self):
        """Test log standardization"""
        collector = LogCollector()
        raw_log = {
            "timestamp": "2024-01-01T00:00:00Z",
            "source.ip": "192.168.1.100",
            "destination.ip": "10.0.0.1",
            "event.action": "login",
            "message": "Test"
        }
        
        standardized = collector.standardize_log(raw_log)
        assert standardized is not None
        if standardized:
            assert standardized.source_ip == "192.168.1.100"


class TestThreatDetector:
    """Test ThreatDetector functionality"""
    
    def test_threat_detector_initialization(self):
        """Test threat detector can be initialized"""
        detector = ThreatDetector()
        assert detector is not None
    
    def test_detect_threats_with_sample_log(self):
        """Test threat detection with a sample suspicious log"""
        detector = ThreatDetector()
        
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            event_type="failed_login",
            severity="high",
            message="Multiple failed login attempts detected",
            user="admin"
        )
        
        alerts = detector.detect_threats([log])
        assert isinstance(alerts, list)


class TestAlert:
    """Test Alert data model"""
    
    def test_alert_creation(self):
        """Test creating an alert"""
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="brute_force",
            severity="high",
            source_ip="192.168.1.100",
            description="Brute force attack detected"
        )
        assert alert.alert_type == "brute_force"
        assert alert.severity == "high"
        assert alert.source_ip == "192.168.1.100"
    
    def test_alert_to_dict(self):
        """Test converting alert to dictionary"""
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="malware",
            severity="critical",
            source_ip="10.0.0.50",
            description="Malware detected"
        )
        alert_dict = alert.to_dict()
        assert isinstance(alert_dict, dict)
        assert alert_dict["alert_type"] == "malware"


class TestIntelEnricher:
    """Test IntelEnricher functionality"""
    
    def test_enricher_initialization(self):
        """Test intel enricher can be initialized"""
        enricher = IntelEnricher()
        assert enricher is not None
    
    def test_check_reputation(self):
        """Test IP reputation check"""
        enricher = IntelEnricher()
        
        # Test with a known malicious IP pattern
        result = enricher.check_reputation("192.168.1.100")
        assert isinstance(result, dict)
        assert "reputation" in result or result == {}


class TestRiskScorer:
    """Test RiskScorer functionality"""
    
    def test_risk_scorer_initialization(self):
        """Test risk scorer can be initialized"""
        scorer = RiskScorer()
        assert scorer is not None
    
    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        scorer = RiskScorer()
        
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="brute_force",
            severity="high",
            source_ip="192.168.1.100",
            description="Test alert"
        )
        
        scored_alert = scorer.calculate_risk(alert)
        assert scored_alert is not None
        assert hasattr(scored_alert, 'risk_score')


class TestMITREMapper:
    """Test MITRE ATT&CK mapping"""
    
    def test_mitre_mapper_initialization(self):
        """Test MITRE mapper can be initialized"""
        mapper = MITREMapper()
        assert mapper is not None
    
    def test_map_to_mitre(self):
        """Test mapping alert to MITRE techniques"""
        mapper = MITREMapper()
        
        result = mapper.map_alert_to_mitre("brute_force")
        assert isinstance(result, dict)
        assert "technique_id" in result or "tactic" in result


class TestIntegration:
    """Integration tests for the full pipeline"""
    
    def test_full_detection_pipeline(self):
        """Test complete detection pipeline"""
        # Create components
        collector = LogCollector()
        detector = ThreatDetector()
        enricher = IntelEnricher()
        scorer = RiskScorer()
        
        # Create test log
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            event_type="failed_login",
            severity="high",
            message="Test suspicious activity",
            user="admin"
        )
        
        # Run through pipeline
        alerts = detector.detect_threats([log])
        assert isinstance(alerts, list)
        
        if alerts:
            # Enrich first alert
            enriched = enricher.enrich_alert(alerts[0])
            assert enriched is not None
            
            # Score the alert
            scored = scorer.calculate_risk(enriched)
            assert scored is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

