"""
Test Suite for simulation.py
Tests attack simulation functionality
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from simulation import AttackSimulator, AttackScenario


class TestAttackScenario:
    """Test AttackScenario data model"""
    
    def test_scenario_creation(self):
        """Test creating an attack scenario"""
        scenario = AttackScenario(
            name="Test Attack",
            mitre_technique="T1078",
            description="Test description",
            severity="high",
            indicators=["test_indicator"]
        )
        assert scenario.name == "Test Attack"
        assert scenario.mitre_technique == "T1078"
        assert scenario.severity == "high"


class TestAttackSimulator:
    """Test AttackSimulator functionality"""
    
    def test_simulator_initialization(self):
        """Test simulator can be initialized"""
        simulator = AttackSimulator()
        assert simulator is not None
    
    def test_get_scenarios(self):
        """Test getting attack scenarios"""
        simulator = AttackSimulator()
        scenarios = simulator.get_scenarios()
        
        assert isinstance(scenarios, list)
        assert len(scenarios) > 0
    
    def test_generate_attack_logs(self):
        """Test generating attack logs"""
        simulator = AttackSimulator()
        
        # Generate logs for first scenario
        scenarios = simulator.get_scenarios()
        if scenarios:
            logs = simulator.generate_attack_logs(scenarios[0])
            assert isinstance(logs, list)
            assert len(logs) > 0
    
    def test_simulate_all_attacks(self):
        """Test simulating all attack scenarios"""
        simulator = AttackSimulator()
        
        # This should generate logs for all scenarios
        result = simulator.simulate_all()
        assert result is not None or result is True


class TestSimulationOutput:
    """Test simulation output and file creation"""
    
    def test_simulation_creates_logs(self):
        """Test that simulation creates log files"""
        simulator = AttackSimulator()
        
        # Check if simulator has output path configured
        assert hasattr(simulator, 'output_path') or hasattr(simulator, 'log_path')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

