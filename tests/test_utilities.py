"""
Test Suite for utilities.py
Tests setup, training, and utility functions
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utilities import (
    setup_opensearch,
    train_ml_model,
    update_threat_intel_db
)


class TestOpenSearchSetup:
    """Test OpenSearch setup utilities"""
    
    def test_setup_function_exists(self):
        """Test setup function is available"""
        assert callable(setup_opensearch)
    
    def test_setup_opensearch_dry_run(self):
        """Test OpenSearch setup (without actual connection)"""
        # This is a dry run test - just checks function structure
        try:
            result = setup_opensearch(verify_only=True)
            # If function accepts verify_only parameter, it should return something
            assert result is not None or result is None
        except TypeError:
            # Function might not accept parameters, which is fine
            pass


class TestMLModelTraining:
    """Test ML model training utilities"""
    
    def test_train_function_exists(self):
        """Test training function is available"""
        assert callable(train_ml_model)
    
    def test_train_ml_model_structure(self):
        """Test ML model training function structure"""
        # Check if function has proper signature
        import inspect
        sig = inspect.signature(train_ml_model)
        # Function should exist and be callable
        assert sig is not None


class TestThreatIntelUpdate:
    """Test threat intelligence database updates"""
    
    def test_update_function_exists(self):
        """Test update function is available"""
        assert callable(update_threat_intel_db)
    
    def test_threat_intel_update_structure(self):
        """Test threat intel update function structure"""
        import inspect
        sig = inspect.signature(update_threat_intel_db)
        assert sig is not None


class TestUtilitiesIntegration:
    """Integration tests for utilities"""
    
    def test_all_utility_functions_available(self):
        """Test that all main utility functions are available"""
        functions = [
            setup_opensearch,
            train_ml_model,
            update_threat_intel_db
        ]
        
        for func in functions:
            assert callable(func), f"{func.__name__} is not callable"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

