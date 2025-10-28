#!/usr/bin/env python3
"""
ML Model Training Script for ThreatOps SOC
This script trains the anomaly detection model on known-good (benign) log data.
Run this once to create the model, then the detector will load the pre-trained model.

This follows the correct ML workflow:
1. Train on known-good data (baseline behavior)
2. Use trained model to detect anomalous/bad data in production
"""

import asyncio
import logging
import sys
import json
import joblib
import numpy as np
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from config.settings import Settings
from collectors.log_collector import LogEntry

# Check if ML libraries are available
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("ERROR: scikit-learn not installed. Install with: pip install scikit-learn")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ModelTrainer:
    """Train ML models for anomaly detection"""
    
    def __init__(self, settings):
        self.settings = settings
        self.model = None
        self.scaler = None
        self.feature_names = []
        
    def load_training_data(self, data_path: Path) -> List[LogEntry]:
        """Load training data from log files"""
        logger.info(f"Loading training data from {data_path}...")
        
        training_logs = []
        
        # Load from JSON log files (known-good data)
        if data_path.is_file():
            # Single file
            files = [data_path]
        else:
            # Directory
            files = list(data_path.glob("*.json")) + list(data_path.glob("*.log"))
        
        for log_file in files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                log_data = json.loads(line.strip())
                                log_entry = self._dict_to_log_entry(log_data)
                                training_logs.append(log_entry)
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                logger.error(f"Error loading {log_file}: {e}")
        
        logger.info(f"Loaded {len(training_logs)} log entries for training")
        return training_logs
    
    def _dict_to_log_entry(self, data: Dict[str, Any]) -> LogEntry:
        """Convert dictionary to LogEntry object"""
        timestamp = data.get('timestamp', datetime.now(timezone.utc).isoformat())
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now(timezone.utc)
        
        return LogEntry(
            timestamp=timestamp,
            host=data.get('host', 'unknown'),
            user=data.get('user', 'unknown'),
            event_id=data.get('event_id', 0),
            ip=data.get('ip', 'unknown'),
            message=data.get('message', ''),
            process_name=data.get('process_name', ''),
            command_line=data.get('command_line', ''),
            event_type=data.get('event_type', 'unknown'),
            severity=data.get('severity', 'info'),
            source=data.get('source', 'training_data'),
            raw_data=data.get('raw_data', {})
        )
    
    def extract_features(self, logs: List[LogEntry]) -> np.ndarray:
        """Extract numerical features from logs"""
        logger.info("Extracting features from logs...")
        
        features = []
        self.feature_names = [
            'event_id',
            'host_length',
            'user_length',
            'message_length',
            'command_line_length',
            'is_failed_logon',
            'is_successful_logon',
            'is_process_creation',
            'is_network_connection',
            'is_warning',
            'is_critical',
            'ip_numeric',
            'time_of_day_minutes'
        ]
        
        for log in logs:
            feature_vector = [
                log.event_id,
                len(log.host),
                len(log.user),
                len(log.message),
                len(log.command_line),
                1 if log.event_type == 'failed_logon' else 0,
                1 if log.event_type == 'successful_logon' else 0,
                1 if log.event_type == 'process_creation' else 0,
                1 if log.event_type == 'network_connection' else 0,
                1 if log.severity == 'warning' else 0,
                1 if log.severity == 'critical' else 0,
                self._extract_ip_features(log.ip),
                self._extract_time_features(log.timestamp)
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def _extract_ip_features(self, ip: str) -> int:
        """Extract features from IP address"""
        if not ip or ip == 'unknown':
            return 0
        
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                # Convert to integer representation
                return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])
        except:
            pass
        
        return 0
    
    def _extract_time_features(self, timestamp: datetime) -> int:
        """Extract time-based features"""
        return timestamp.hour * 60 + timestamp.minute
    
    def train_model(self, logs: List[LogEntry], output_path: Path):
        """Train the anomaly detection model"""
        logger.info("=" * 60)
        logger.info("ThreatOps ML Model Training")
        logger.info("=" * 60)
        
        if len(logs) < self.settings.ml_config.training_samples:
            logger.error(f"Not enough training data: {len(logs)} < {self.settings.ml_config.training_samples}")
            logger.error("Please provide more benign log samples for training")
            return False
        
        # Extract features
        logger.info("Extracting features...")
        features = self.extract_features(logs)
        
        # Scale features
        logger.info("Scaling features...")
        self.scaler = StandardScaler()
        features_scaled = self.scaler.fit_transform(features)
        
        # Train model
        logger.info(f"Training {self.settings.ml_config.model_type} model...")
        self.model = IsolationForest(
            contamination=self.settings.ml_config.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            verbose=1
        )
        
        self.model.fit(features_scaled)
        
        # Test model on training data
        predictions = self.model.predict(features_scaled)
        anomaly_count = np.sum(predictions == -1)
        anomaly_percent = (anomaly_count / len(predictions)) * 100
        
        logger.info(f"\nTraining Statistics:")
        logger.info(f"  Total samples: {len(logs)}")
        logger.info(f"  Features extracted: {features.shape[1]}")
        logger.info(f"  Anomalies detected in training data: {anomaly_count} ({anomaly_percent:.2f}%)")
        logger.info(f"  Expected contamination: {self.settings.ml_config.contamination * 100}%")
        
        # Save model
        output_path.parent.mkdir(parents=True, exist_ok=True)
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'training_date': datetime.now(timezone.utc).isoformat(),
            'training_samples': len(logs),
            'contamination': self.settings.ml_config.contamination,
            'model_type': self.settings.ml_config.model_type
        }
        
        joblib.dump(model_data, output_path)
        logger.info(f"\n✓ Model saved to: {output_path}")
        logger.info(f"  File size: {output_path.stat().st_size / 1024:.2f} KB")
        
        logger.info("\n" + "=" * 60)
        logger.info("Training completed successfully!")
        logger.info("The ThreatDetector will now load this pre-trained model.")
        logger.info("=" * 60)
        
        return True
    
    def generate_sample_training_data(self, output_path: Path, num_samples: int = 1000):
        """Generate sample benign training data"""
        logger.info(f"Generating {num_samples} sample benign log entries...")
        
        sample_logs = []
        base_time = datetime.now(timezone.utc) - timedelta(days=7)
        
        for i in range(num_samples):
            # Simulate benign activity
            log_data = {
                'timestamp': (base_time + timedelta(minutes=i)).isoformat(),
                'host': f'WORKSTATION-{(i % 10) + 1:02d}',
                'user': f'user{(i % 50) + 1}',
                'event_id': np.random.choice([4624, 4634, 4688, 5156]),  # Benign event IDs
                'ip': f'192.168.1.{(i % 250) + 1}',
                'message': 'Normal system activity',
                'process_name': np.random.choice(['explorer.exe', 'chrome.exe', 'outlook.exe', 'excel.exe']),
                'command_line': '',
                'event_type': np.random.choice(['successful_logon', 'logoff', 'process_creation']),
                'severity': 'info',
                'source': 'generated_training_data',
                'raw_data': {}
            }
            sample_logs.append(log_data)
        
        # Save to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            for log in sample_logs:
                f.write(json.dumps(log) + '\n')
        
        logger.info(f"✓ Generated training data saved to: {output_path}")
        return output_path

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train ML model for ThreatOps anomaly detection")
    parser.add_argument("--training-data", type=str, help="Path to training data (file or directory)")
    parser.add_argument("--generate-sample", action="store_true", help="Generate sample training data")
    parser.add_argument("--num-samples", type=int, default=1000, help="Number of sample logs to generate")
    parser.add_argument("--output", type=str, default="models/model.joblib", help="Output model file")
    
    args = parser.parse_args()
    
    settings = Settings.load_from_file()
    trainer = ModelTrainer(settings)
    
    # Generate sample data if requested
    if args.generate_sample:
        sample_data_path = Path("data/training_data/benign_logs.json")
        trainer.generate_sample_training_data(sample_data_path, args.num_samples)
        args.training_data = str(sample_data_path)
    
    # Load training data
    if not args.training_data:
        logger.error("ERROR: No training data specified!")
        logger.error("Options:")
        logger.error("  1. Generate sample data: --generate-sample")
        logger.error("  2. Provide your own: --training-data /path/to/benign_logs.json")
        sys.exit(1)
    
    training_data_path = Path(args.training_data)
    if not training_data_path.exists():
        logger.error(f"Training data not found: {training_data_path}")
        sys.exit(1)
    
    # Load and train
    logs = trainer.load_training_data(training_data_path)
    
    if not logs:
        logger.error("No logs loaded. Please check your training data.")
        sys.exit(1)
    
    # Train and save model
    output_path = Path(args.output)
    success = trainer.train_model(logs, output_path)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

