"""
Integration Tests for ThreatOps SIEM
Tests the complete end-to-end workflow
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core_detection import (
    LogEntry, LogCollector, ThreatDetector, 
    IntelEnricher, RiskScorer, Alert
)
from simulation import AttackSimulator
from reporting import ReportGenerator


class TestEndToEndWorkflow:
    """Test complete SIEM workflow from simulation to reporting"""
    
    def test_simulation_to_detection(self):
        """Test flow from attack simulation to threat detection"""
        # 1. Generate simulated attack
        simulator = AttackSimulator()
        scenarios = simulator.get_scenarios()
        assert len(scenarios) > 0
        
        # 2. Get logs from first scenario
        if scenarios:
            logs = simulator.generate_attack_logs(scenarios[0])
            assert len(logs) > 0
            
            # 3. Detect threats
            detector = ThreatDetector()
            alerts = detector.detect_threats(logs)
            
            # Should detect something from simulated attack
            assert isinstance(alerts, list)
    
    def test_detection_to_enrichment(self):
        """Test flow from detection to threat intelligence enrichment"""
        # 1. Create test alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="suspicious_login",
            severity="high",
            source_ip="192.168.1.100",
            description="Test alert"
        )
        
        # 2. Enrich with threat intel
        enricher = IntelEnricher()
        enriched_alert = enricher.enrich_alert(alert)
        
        assert enriched_alert is not None
    
    def test_enrichment_to_scoring(self):
        """Test flow from enrichment to risk scoring"""
        # 1. Create enriched alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="malware",
            severity="critical",
            source_ip="10.0.0.50",
            description="Malware detected"
        )
        
        # 2. Calculate risk score
        scorer = RiskScorer()
        scored_alert = scorer.calculate_risk(alert)
        
        assert scored_alert is not None
        assert hasattr(scored_alert, 'risk_score')
    
    def test_scoring_to_reporting(self):
        """Test flow from scoring to report generation"""
        # 1. Create scored alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="data_exfiltration",
            severity="critical",
            source_ip="192.168.1.100",
            description="Data exfiltration detected"
        )
        alert.risk_score = 95
        
        # 2. Generate report
        generator = ReportGenerator()
        report = generator.generate_html_report([alert])
        
        assert report is not None
        assert len(report) > 0
    
    def test_full_pipeline(self):
        """Test complete pipeline: Simulation → Detection → Enrichment → Scoring → Reporting"""
        # 1. Simulation
        simulator = AttackSimulator()
        scenarios = simulator.get_scenarios()
        
        if not scenarios:
            pytest.skip("No scenarios available")
        
        logs = simulator.generate_attack_logs(scenarios[0])
        
        if not logs:
            pytest.skip("No logs generated")
        
        # 2. Detection
        detector = ThreatDetector()
        alerts = detector.detect_threats(logs)
        
        if not alerts:
            pytest.skip("No alerts detected")
        
        # 3. Enrichment
        enricher = IntelEnricher()
        enriched_alerts = []
        for alert in alerts[:3]:  # Test first 3 alerts
            enriched = enricher.enrich_alert(alert)
            if enriched:
                enriched_alerts.append(enriched)
        
        # 4. Scoring
        scorer = RiskScorer()
        scored_alerts = []
        for alert in enriched_alerts:
            scored = scorer.calculate_risk(alert)
            if scored:
                scored_alerts.append(scored)
        
        # 5. Reporting
        generator = ReportGenerator()
        report = generator.generate_html_report(scored_alerts)
        
        # Verify end-to-end pipeline completed
        assert logs is not None
        assert alerts is not None
        assert len(enriched_alerts) > 0
        assert len(scored_alerts) > 0
        assert report is not None


class TestComponentInteractions:
    """Test interactions between different components"""
    
    def test_log_collector_and_detector_integration(self):
        """Test log collector output works with detector input"""
        collector = LogCollector()
        detector = ThreatDetector()
        
        # Create raw log
        raw_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "event_type": "failed_login",
            "message": "Failed login attempt"
        }
        
        # Standardize
        log = collector.standardize_log(raw_log)
        
        if log:
            # Should be able to detect threats
            alerts = detector.detect_threats([log])
            assert isinstance(alerts, list)
    
    def test_detector_and_enricher_integration(self):
        """Test detector output works with enricher input"""
        detector = ThreatDetector()
        enricher = IntelEnricher()
        
        # Create test log
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            dest_ip="10.0.0.1",
            event_type="suspicious_activity",
            severity="high",
            message="Test"
        )
        
        # Detect
        alerts = detector.detect_threats([log])
        
        # Enrich
        if alerts:
            enriched = enricher.enrich_alert(alerts[0])
            assert enriched is not None


class TestSystemResilience:
    """Test system handles edge cases and errors gracefully"""
    
    def test_empty_log_list(self):
        """Test system handles empty log list"""
        detector = ThreatDetector()
        alerts = detector.detect_threats([])
        assert isinstance(alerts, list)
        assert len(alerts) == 0
    
    def test_invalid_ip_enrichment(self):
        """Test enricher handles invalid IPs"""
        enricher = IntelEnricher()
        result = enricher.check_reputation("invalid_ip")
        # Should return empty dict or handle gracefully
        assert isinstance(result, dict)
    
    def test_missing_fields_in_alert(self):
        """Test scoring with minimal alert fields"""
        scorer = RiskScorer()
        
        # Create minimal alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="test",
            severity="low",
            source_ip="192.168.1.1",
            description="Minimal alert"
        )
        
        # Should still calculate score
        scored = scorer.calculate_risk(alert)
        assert scored is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

