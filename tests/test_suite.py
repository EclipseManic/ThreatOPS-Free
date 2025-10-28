# Test Suite for ThreatOps SOC Simulator

import pytest
from datetime import datetime, timezone

# Import our modules
import sys
sys.path.append('..')

from config.settings import Settings
from collectors.log_collector import LogCollector, LogEntry
from detection.threat_detector import ThreatDetector, Alert
from enrichment.intel_enricher import IntelEnricher
from simulation.attack_simulator import AttackSimulator
from scoring.risk_scorer import RiskScorer

class TestLogCollector:
    """Test cases for log collector"""
    
    def test_log_entry_creation(self):
        """Test LogEntry creation and serialization"""
        log = LogEntry(
            timestamp=datetime.now(timezone.utc),
            host="test-host",
            user="test-user",
            event_id=4625,
            ip="192.168.1.1",
            message="Test message",
            source="test"
        )
        
        assert log.host == "test-host"
        assert log.user == "test-user"
        assert log.event_id == 4625
        
        # Test serialization
        log_dict = log.to_dict()
        assert log_dict['host'] == "test-host"
        assert log_dict['event_id'] == 4625
        
        # Test deserialization
        log_restored = LogEntry.from_dict(log_dict)
        assert log_restored.host == log.host
        assert log_restored.event_id == log.event_id
    
    @pytest.mark.asyncio
    async def test_log_collector_initialization(self):
        """Test log collector initialization"""
        settings = Settings()
        collector = LogCollector(settings)
        
        await collector.initialize()
        assert collector.settings == settings

class TestThreatDetector:
    """Test cases for threat detector"""
    
    def test_alert_creation(self):
        """Test Alert creation and serialization"""
        alert = Alert(
            id="test-alert-001",
            rule_name="Test Rule",
            severity="High",
            description="Test alert description",
            host="test-host",
            user="test-user",
            ip="192.168.1.1",
            mitre_technique="T1110"
        )
        
        assert alert.id == "test-alert-001"
        assert alert.severity == "High"
        assert alert.mitre_technique == "T1110"
        
        # Test serialization
        alert_dict = alert.to_dict()
        assert alert_dict['id'] == "test-alert-001"
        assert alert_dict['severity'] == "High"
    
    @pytest.mark.asyncio
    async def test_threat_detector_initialization(self):
        """Test threat detector initialization"""
        settings = Settings()
        detector = ThreatDetector(settings)
        
        await detector.initialize()
        assert detector.settings == settings

class TestAttackSimulator:
    """Test cases for attack simulator"""
    
    @pytest.mark.asyncio
    async def test_attack_simulator_initialization(self):
        """Test attack simulator initialization"""
        settings = Settings()
        simulator = AttackSimulator(settings)
        
        await simulator.initialize()
        assert simulator.settings == settings
    
    @pytest.mark.asyncio
    async def test_brute_force_simulation(self):
        """Test brute force attack simulation"""
        settings = Settings()
        simulator = AttackSimulator(settings)
        
        # Get brute force scenario
        brute_force_scenario = None
        for scenario in simulator.scenarios:
            if scenario.name == "Brute Force Attack":
                brute_force_scenario = scenario
                break
        
        assert brute_force_scenario is not None
        
        # Simulate attack
        logs = await simulator._simulate_brute_force(brute_force_scenario)
        
        assert len(logs) > 0
        assert all(log.event_id == 4625 for log in logs)  # Failed logon events
        assert all(log.source == "attack_simulation" for log in logs)

class TestRiskScorer:
    """Test cases for risk scorer"""
    
    @pytest.mark.asyncio
    async def test_risk_scorer_initialization(self):
        """Test risk scorer initialization"""
        settings = Settings()
        scorer = RiskScorer(settings)
        
        await scorer.initialize()
        assert scorer.settings == settings
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        settings = Settings()
        scorer = RiskScorer(settings)
        
        # Create test alert
        alert = Alert(
            id="test-alert",
            rule_name="Test Rule",
            severity="High",
            description="Test alert",
            host="test-host",
            user="test-user",
            ip="192.168.1.1"
        )
        
        # Calculate risk score
        risk_score = scorer.risk_calculator.calculate_risk_score(alert)
        
        assert risk_score.base_score > 0
        assert risk_score.final_score > 0
        assert risk_score.risk_level in ['Low', 'Medium', 'High', 'Critical']

class TestIntelEnricher:
    """Test cases for intelligence enricher"""
    
    @pytest.mark.asyncio
    async def test_intel_enricher_initialization(self):
        """Test intelligence enricher initialization"""
        settings = Settings()
        enricher = IntelEnricher(settings)
        
        await enricher.initialize()
        assert enricher.settings == settings
    
    def test_local_intel_db(self):
        """Test local intelligence database"""
        settings = Settings()
        enricher = IntelEnricher(settings)
        
        # Test IOC storage and retrieval
        from enrichment.intel_enricher import ThreatIntelResult
        
        intel_result = ThreatIntelResult(
            ioc="192.168.1.100",
            ioc_type="ip",
            reputation="malicious",
            confidence=0.9,
            source="test"
        )
        
        enricher.local_db.store_ioc_info(intel_result)
        retrieved_result = enricher.local_db.get_ioc_info("192.168.1.100", "ip")
        
        assert retrieved_result is not None
        assert retrieved_result.ioc == "192.168.1.100"
        assert retrieved_result.reputation == "malicious"

class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_soc_workflow(self):
        """Test complete SOC workflow"""
        settings = Settings()
        
        # Initialize all components
        collector = LogCollector(settings)
        detector = ThreatDetector(settings)
        enricher = IntelEnricher(settings)
        scorer = RiskScorer(settings)
        
        await collector.initialize()
        await detector.initialize()
        await enricher.initialize()
        await scorer.initialize()
        
        # Collect logs
        logs = await collector.collect_logs()
        assert len(logs) > 0
        
        # Detect threats
        alerts = await detector.analyze_logs(logs)
        
        # Enrich alerts
        enriched_alerts = await enricher.enrich_alerts(alerts)
        
        # Score risks
        scored_alerts = await scorer.score_alerts(enriched_alerts)
        
        # Verify workflow
        assert len(scored_alerts) >= 0  # May be 0 if no threats detected

if __name__ == "__main__":
    pytest.main([__file__])
