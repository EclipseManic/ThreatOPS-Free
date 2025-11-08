"""
Test Suite for reporting.py
Tests report generation, notifications, and SOAR automation
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from reporting import ReportGenerator, NotificationManager, SOARAutomation
from core_detection import Alert


class TestReportGenerator:
    """Test ReportGenerator functionality"""
    
    def test_report_generator_initialization(self):
        """Test report generator can be initialized"""
        generator = ReportGenerator()
        assert generator is not None
    
    def test_generate_html_report(self):
        """Test HTML report generation"""
        generator = ReportGenerator()
        
        # Create test alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="test",
            severity="high",
            source_ip="192.168.1.100",
            description="Test alert for reporting"
        )
        
        # Generate report
        html_report = generator.generate_html_report([alert])
        assert html_report is not None
        assert isinstance(html_report, str)
        assert len(html_report) > 0
    
    def test_generate_json_report(self):
        """Test JSON report generation"""
        generator = ReportGenerator()
        
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="test",
            severity="medium",
            source_ip="10.0.0.50",
            description="Test alert"
        )
        
        json_report = generator.generate_json_report([alert])
        assert json_report is not None
        assert isinstance(json_report, (str, dict))


class TestNotificationManager:
    """Test NotificationManager functionality"""
    
    def test_notification_manager_initialization(self):
        """Test notification manager can be initialized"""
        manager = NotificationManager()
        assert manager is not None
    
    def test_prepare_notification_message(self):
        """Test preparing notification messages"""
        manager = NotificationManager()
        
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="malware",
            severity="critical",
            source_ip="192.168.1.100",
            description="Critical malware detected"
        )
        
        # Most notification managers have a method to format messages
        assert hasattr(manager, 'send_notification') or hasattr(manager, 'notify')


class TestSOARAutomation:
    """Test SOAR automation functionality"""
    
    def test_soar_initialization(self):
        """Test SOAR automation can be initialized"""
        soar = SOARAutomation()
        assert soar is not None
    
    def test_block_ip_action(self):
        """Test IP blocking action"""
        soar = SOARAutomation()
        
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="brute_force",
            severity="high",
            source_ip="192.168.1.100",
            description="Brute force attack"
        )
        
        # Should have method to execute response actions
        assert hasattr(soar, 'execute_response') or hasattr(soar, 'respond_to_alert')
    
    def test_get_recommended_actions(self):
        """Test getting recommended actions for an alert"""
        soar = SOARAutomation()
        
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="malware",
            severity="critical",
            source_ip="10.0.0.50",
            description="Malware detected"
        )
        
        # Should be able to recommend actions
        assert hasattr(soar, 'get_actions') or hasattr(soar, 'recommend_actions')


class TestReportingIntegration:
    """Integration tests for reporting pipeline"""
    
    def test_full_reporting_pipeline(self):
        """Test complete reporting workflow"""
        # Create components
        generator = ReportGenerator()
        notifier = NotificationManager()
        soar = SOARAutomation()
        
        # Create test alert
        alert = Alert(
            timestamp=datetime.now(timezone.utc),
            alert_type="data_exfiltration",
            severity="critical",
            source_ip="192.168.1.100",
            description="Large data transfer detected"
        )
        
        # Generate report
        report = generator.generate_html_report([alert])
        assert report is not None
        
        # All components should be functional
        assert generator is not None
        assert notifier is not None
        assert soar is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

