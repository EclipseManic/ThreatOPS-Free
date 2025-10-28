# Simple System Test for ThreatOps SOC Simulator (moved to tests/)

import sys
import asyncio
import pytest
from pathlib import Path

# Ensure project root is on path (parent of tests/)
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

def test_imports():
    """Test that all modules can be imported"""
    print("Testing imports...")
    
    try:
        from config.settings import Settings
        print("✅ Config module imported successfully")
        
        from collectors.log_collector import LogCollector, LogEntry
        print("✅ Collectors module imported successfully")
        
        from detection.threat_detector import ThreatDetector, Alert
        print("✅ Detection module imported successfully")
        
        from enrichment.intel_enricher import IntelEnricher
        print("✅ Enrichment module imported successfully")
        
        from simulation.attack_simulator import AttackSimulator
        print("✅ Simulation module imported successfully")
        
        from scoring.risk_scorer import RiskScorer
        print("✅ Scoring module imported successfully")
        
        from dashboard.app import SOCDashboard
        print("✅ Dashboard module imported successfully")
        
        from reporting.report_generator import ReportGenerator
        print("✅ Reporting module imported successfully")
        
        # If imports succeeded, assert True
        assert True

    except ImportError as e:
        pytest.fail(f"Import error: {e}")

def test_basic_functionality():
    """Test basic functionality of core classes"""
    print("\nTesting basic functionality...")
    
    try:
        # Test Settings
        from config.settings import Settings
        settings = Settings.load_from_file()
        print("✅ Settings loaded successfully")
        
        # Test LogEntry
        from collectors.log_collector import LogEntry
        log = LogEntry(
            timestamp="2024-01-01T10:00:00Z",
            host="test-host",
            user="test-user",
            event_id=4625,
            ip="192.168.1.1",
            message="Test message",
            source="test"
        )
        print("✅ LogEntry created successfully")
        
        # Test Alert
        from detection.threat_detector import Alert
        alert = Alert(
            id="test-alert",
            rule_name="Test Rule",
            severity="High",
            description="Test alert",
            host="test-host",
            user="test-user",
            ip="192.168.1.1"
        )
        print("✅ Alert created successfully")
        
        # Test MITREMapper
        from scoring.risk_scorer import MITREMapper
        mapper = MITREMapper()
        technique = mapper.get_technique("T1110")
        assert technique is not None, "MITREMapper technique T1110 not found"

    except Exception as e:
        pytest.fail(f"Functionality test error: {e}")

def test_async_functionality():
    """Test async functionality by running the coroutine via asyncio.run"""
    print("\nTesting async functionality...")

    async def _run_async_checks():
        from config.settings import Settings
        from collectors.log_collector import LogCollector

        settings = Settings()
        collector = LogCollector(settings)

        # Test initialization
        await collector.initialize()
        print("LogCollector initialized successfully")

        # Test log collection
        logs = await collector.collect_logs()
        print(f"Collected {len(logs)} logs successfully")

        return True

    try:
        result = asyncio.run(_run_async_checks())
        assert result is True
    except Exception as e:
        pytest.fail(f"Async test error: {e}")

def main():
    """Main test function"""
    print("ThreatOps SOC Simulator - System Test")
    print("=" * 50)
    
    # Test imports
    import_success = test_imports()
    
    # Test basic functionality
    functionality_success = test_basic_functionality()
    
    # Test async functionality
    async_success = test_async_functionality()

    print("\n" + "=" * 50)
    print("Test Results:")
    print(f"   Imports: {'PASS' if import_success else 'FAIL'}")
    print(f"   Functionality: {'PASS' if functionality_success else 'FAIL'}")
    print(f"   Async Operations: {'PASS' if async_success else 'FAIL'}")

    # Optionally run the full simulation via setup.py wrappers
    try:
        from setup import run_simulation_sync
        print("\nRunning full simulation via setup.run_simulation_sync() ...")
        sim_result = run_simulation_sync()
        sim_success = sim_result is not None
        print(f"   {'PASS' if sim_success else 'FAIL'} Full simulation")
    except Exception as e:
        print(f"   Could not run full simulation: {e}")
        sim_success = False

    if import_success and functionality_success and async_success and sim_success:
        print("\nAll tests passed! System is ready to use.")
        return True
    else:
        print("\nSome tests failed. Check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
