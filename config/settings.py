# Configuration Management for ThreatOps SOC

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load .env file from project root (parent of config directory)
    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
        # Use ASCII-safe message for Windows compatibility
        try:
            print(f"[OK] Loaded environment variables from {env_path}")
        except UnicodeEncodeError:
            print(f"[OK] Loaded environment variables from .env file")
    else:
        # Try loading from current directory as fallback
        load_dotenv()
except ImportError:
    print("[WARNING] python-dotenv not installed. Environment variables must be set manually.")
except Exception as e:
    print(f"[WARNING] Error loading .env file: {e}")

class LogSourceConfig(BaseModel):
    """Configuration for log sources"""
    enabled: bool = True
    path: str
    type: str  # 'evtx', 'auth', 'json', 'syslog'
    parser: str
    frequency: int = 60  # seconds

class DetectionRuleConfig(BaseModel):
    """Configuration for detection rules"""
    name: str
    enabled: bool = True
    severity: str = "Medium"  # Low, Medium, High, Critical
    description: str
    conditions: List[Dict[str, Any]]
    mitre_technique: Optional[str] = None

class APIConfig(BaseModel):
    """Configuration for external APIs"""
    name: str
    enabled: bool = True
    api_key: Optional[str] = None
    rate_limit: int = 100  # requests per minute
    timeout: int = 30  # seconds

class MLConfig(BaseModel):
    """Configuration for ML models"""
    enabled: bool = True
    model_type: str = "isolation_forest"  # isolation_forest, one_class_svm
    contamination: float = 0.1
    training_samples: int = 100
    retrain_frequency: int = 24  # hours

class RiskScoringConfig(BaseModel):
    """Configuration for risk scoring"""
    base_score: int = 50
    severity_multipliers: Dict[str, float] = {
        "Low": 1.0,
        "Medium": 1.5,
        "High": 2.0,
        "Critical": 3.0
    }
    intel_multipliers: Dict[str, float] = {
        "clean": 0.5,
        "suspicious": 1.5,
        "malicious": 2.5
    }

class Settings(BaseModel):
    """Main settings configuration"""
    
    # General settings
    project_name: str = "ThreatOps Free"
    version: str = "1.0.0"
    debug: bool = False
    
    # Data storage
    data_dir: str = "data"
    logs_dir: str = "data/logs"
    alerts_dir: str = "data/alerts"
    reports_dir: str = "data/reports"
    
    # Log sources
    log_sources: List[LogSourceConfig] = Field(default_factory=lambda: [
        LogSourceConfig(
            path="data/sample_logs/windows.evtx",
            type="evtx",
            parser="windows_evtx"
        ),
        LogSourceConfig(
            path="data/sample_logs/auth.log",
            type="auth",
            parser="linux_auth"
        ),
        LogSourceConfig(
            path="data/sample_logs/application.json",
            type="json",
            parser="json_logs"
        )
    ])
    
    # Detection rules
    detection_rules: List[DetectionRuleConfig] = Field(default_factory=lambda: [
        DetectionRuleConfig(
            name="Brute Force Attack",
            severity="High",
            description="Multiple failed login attempts from same IP",
            conditions=[
                {"field": "event_id", "operator": "equals", "value": 4625},
                {"field": "count", "operator": "greater_than", "value": 5}
            ],
            mitre_technique="T1110"
        ),
        DetectionRuleConfig(
            name="Privilege Escalation",
            severity="Critical",
            description="Suspicious privilege escalation attempt",
            conditions=[
                {"field": "event_id", "operator": "equals", "value": 4672},
                {"field": "user", "operator": "not_in", "value": ["SYSTEM", "Administrator"]}
            ],
            mitre_technique="T1078"
        ),
        DetectionRuleConfig(
            name="Suspicious PowerShell",
            severity="Medium",
            description="PowerShell execution with suspicious parameters",
            conditions=[
                {"field": "process_name", "operator": "contains", "value": "powershell"},
                {"field": "command_line", "operator": "contains", "value": "-enc"}
            ],
            mitre_technique="T1059.001"
        )
    ])
    
    # API configurations
    apis: List[APIConfig] = Field(default_factory=lambda: [
        APIConfig(
            name="virustotal",
            enabled=True,
            api_key=os.getenv("VIRUSTOTAL_API_KEY")
        ),
        APIConfig(
            name="abuseipdb",
            enabled=True,
            api_key=os.getenv("ABUSEIPDB_API_KEY")
        ),
        APIConfig(
            name="otx",
            enabled=True,
            api_key=os.getenv("OTX_API_KEY")
        )
    ])
    
    # ML configuration
    ml_config: MLConfig = MLConfig()
    
    # Risk scoring
    risk_scoring: RiskScoringConfig = RiskScoringConfig()
    
    # Dashboard settings
    dashboard_port: int = 8501
    dashboard_host: str = "localhost"
    
    # Reporting
    report_frequency: int = 24  # hours
    report_formats: List[str] = ["html", "pdf"]
    
    @classmethod
    def load_from_file(cls, config_path: str = "config/settings.yaml") -> "Settings":
        """Load settings from YAML file"""
        config_file = Path(config_path)
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                config_data = yaml.safe_load(f)
            return cls(**config_data)
        else:
            # Create default config file
            settings = cls()
            settings.save_to_file(config_path)
            return settings
    
    def save_to_file(self, config_path: str = "config/settings.yaml"):
        """Save settings to YAML file"""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(self.dict(), f, default_flow_style=False, indent=2)
    
    def get_enabled_log_sources(self) -> List[LogSourceConfig]:
        """Get list of enabled log sources"""
        return [source for source in self.log_sources if source.enabled]
    
    def get_enabled_detection_rules(self) -> List[DetectionRuleConfig]:
        """Get list of enabled detection rules"""
        return [rule for rule in self.detection_rules if rule.enabled]
    
    def get_enabled_apis(self) -> List[APIConfig]:
        """Get list of enabled APIs"""
        return [api for api in self.apis if api.enabled and api.api_key]
    
    def get_api_config(self, api_name: str) -> Optional[APIConfig]:
        """Get configuration for specific API"""
        for api in self.apis:
            if api.name == api_name:
                return api
        return None
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate API keys and return status"""
        validation_results = {}
        for api in self.apis:
            if api.enabled:
                validation_results[api.name] = bool(api.api_key)
        return validation_results
    
    def get_missing_api_keys(self) -> List[str]:
        """Get list of enabled APIs with missing keys"""
        missing = []
        for api in self.apis:
            if api.enabled and not api.api_key:
                missing.append(api.name)
        return missing
    
    def validate_configuration(self) -> List[str]:
        """Validate configuration and return warnings"""
        warnings = []
        
        # Check API keys
        missing_keys = self.get_missing_api_keys()
        if missing_keys:
            warnings.append(f"⚠️  Missing API keys for: {', '.join(missing_keys)}")
            warnings.append("   Threat intelligence enrichment will be limited.")
        
        # Check data directories
        data_paths = [self.data_dir, self.logs_dir, self.alerts_dir, self.reports_dir]
        for path in data_paths:
            if not Path(path).exists():
                warnings.append(f"⚠️  Directory does not exist: {path}")
        
        # Check log sources
        for source in self.log_sources:
            if source.enabled and not Path(source.path).exists():
                warnings.append(f"⚠️  Log source file not found: {source.path}")
        
        return warnings
    
    def setup_wizard(self):
        """Interactive setup wizard for first-time configuration"""
        print("=" * 60)
        print("ThreatOps Free - Configuration Wizard")
        print("=" * 60)
        print()
        
        # Check for missing API keys
        missing_keys = self.get_missing_api_keys()
        if missing_keys:
            print("🔑 API Key Configuration")
            print("   The following APIs are enabled but missing keys:")
            for api_name in missing_keys:
                print(f"   - {api_name}")
            print()
            print("   To enable threat intelligence enrichment:")
            print("   1. Get free API keys from:")
            print("      - VirusTotal: https://www.virustotal.com/gui/join-us")
            print("      - AbuseIPDB: https://www.abuseipdb.com/register")
            print("      - AlienVault OTX: https://otx.alienvault.com/")
            print()
            print("   2. Create a .env file with:")
            print("      VIRUSTOTAL_API_KEY=your_key_here")
            print("      ABUSEIPDB_API_KEY=your_key_here")
            print("      OTX_API_KEY=your_key_here")
            print()
        
        # Check directories
        print("📁 Data Directories")
        for path in [self.data_dir, self.logs_dir, self.alerts_dir, self.reports_dir]:
            if not Path(path).exists():
                print(f"   Creating: {path}")
                Path(path).mkdir(parents=True, exist_ok=True)
            else:
                print(f"   ✓ {path}")
        print()
        
        # Save configuration
        self.save_to_file()
        print("✅ Configuration saved to config/settings.yaml")
        print()
        
        # Display warnings
        warnings = self.validate_configuration()
        if warnings:
            print("⚠️  Warnings:")
            for warning in warnings:
                print(f"   {warning}")
        else:
            print("✅ All checks passed! Your system is ready.")
        print()
        print("=" * 60)
