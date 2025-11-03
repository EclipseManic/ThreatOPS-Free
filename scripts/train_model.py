#!/usr/bin/env python3
"""
Machine Learning Model Training Script

Trains an Isolation Forest anomaly detection model on benign log data.
This is the CORRECT production workflow: train once, then use the saved model.

Usage:
    # Generate sample benign data and train
    python scripts/train_model.py --generate-sample --num-samples 5000
    
    # Train on your own benign logs
    python scripts/train_model.py --training-data /path/to/benign_logs.json
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime, timedelta
import random

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib
except ImportError:
    print("ERROR: Required ML libraries not found.")
    print("Install them with: pip install scikit-learn joblib numpy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Paths
ROOT = Path(__file__).parent.parent
MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "model.joblib"


def generate_benign_samples(num_samples: int = 5000) -> list:
    """Generate realistic benign log samples for training."""
    logger.info(f"Generating {num_samples} benign log samples...")
    
    benign_logs = []
    base_time = datetime.now() - timedelta(days=30)
    
    # Benign event IDs (Windows Security Events)
    benign_event_ids = [4624, 4672, 4688, 4689, 4690, 4698, 4700, 4702]
    
    # Benign hostnames
    hostnames = ["DESKTOP-PC1", "LAPTOP-USER2", "SERVER-DB1", "WORKSTATION-A", "DEV-MACHINE"]
    
    # Benign users
    users = ["john.doe", "jane.smith", "admin", "service_account", "backup_user"]
    
    # Benign processes
    processes = [
        "explorer.exe", "chrome.exe", "notepad.exe", "powershell.exe",
        "cmd.exe", "svchost.exe", "teams.exe", "outlook.exe"
    ]
    
    for i in range(num_samples):
        timestamp = base_time + timedelta(minutes=i)
        
        log_entry = {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_id": random.choice(benign_event_ids),
            "host": random.choice(hostnames),
            "user": random.choice(users),
            "process_name": random.choice(processes),
            "command_line": f"{random.choice(processes)} /normal /operation",
            "source_ip": f"192.168.1.{random.randint(100, 200)}",
            "message": "Normal system operation",
            "severity": random.choice(["info", "info", "info", "warning"]),
            "log_level": "INFO"
        }
        
        benign_logs.append(log_entry)
    
    logger.info(f"✓ Generated {len(benign_logs)} benign samples")
    return benign_logs


def extract_features(log_entry: dict) -> list:
    """Extract numerical features from a log entry."""
    features = [
        int(log_entry.get("event_id", 0)),
        len(log_entry.get("host", "")),
        len(log_entry.get("user", "")),
        len(log_entry.get("message", "")),
        len(log_entry.get("command_line", "")),
        1 if log_entry.get("event_id") == 4625 else 0,  # Failed logon
        1 if log_entry.get("event_id") == 4624 else 0,  # Successful logon
        1 if log_entry.get("event_id") == 4688 else 0,  # Process creation
        1 if "network" in log_entry.get("message", "").lower() else 0,
        1 if log_entry.get("severity") == "warning" else 0,
        1 if log_entry.get("severity") == "critical" else 0,
        hash(log_entry.get("source_ip", "")) % 10000,  # IP hash
        datetime.strptime(log_entry.get("timestamp", "2024-01-01 00:00:00"), "%Y-%m-%d %H:%M:%S").hour * 60
    ]
    
    return features


def train_model(training_data: list, contamination: float = 0.1) -> IsolationForest:
    """Train the Isolation Forest model."""
    logger.info(f"Training Isolation Forest model...")
    logger.info(f"  Training samples: {len(training_data)}")
    logger.info(f"  Expected contamination: {contamination*100:.1f}%")
    
    # Extract features
    X = np.array([extract_features(log) for log in training_data])
    
    logger.info(f"  Feature dimensions: {X.shape}")
    
    # Train model
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        verbose=0
    )
    
    model.fit(X)
    
    # Evaluate on training data
    predictions = model.predict(X)
    anomalies = np.sum(predictions == -1)
    
    logger.info(f"  Anomalies detected in training: {anomalies} ({anomalies/len(X)*100:.1f}%)")
    logger.info(f"✓ Model training complete")
    
    return model


def save_model(model: IsolationForest) -> None:
    """Save the trained model to disk."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    joblib.dump(model, MODEL_PATH)
    
    # Get file size
    size_kb = MODEL_PATH.stat().st_size / 1024
    
    logger.info(f"✓ Model saved to: {MODEL_PATH}")
    logger.info(f"  File size: {size_kb:.1f} KB")


def load_training_data(file_path: str) -> list:
    """Load training data from JSON file."""
    logger.info(f"Loading training data from: {file_path}")
    
    data = []
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue
    
    logger.info(f"✓ Loaded {len(data)} log entries")
    return data


def main(args):
    """Main function."""
    logger.info("="*60)
    logger.info("ThreatOps ML Model Training")
    logger.info("="*60)
    
    # Get training data
    if args.generate_sample:
        training_data = generate_benign_samples(args.num_samples)
    elif args.training_data:
        training_data = load_training_data(args.training_data)
    else:
        logger.error("ERROR: Must specify --generate-sample or --training-data")
        return 1
    
    if not training_data:
        logger.error("ERROR: No training data available")
        return 1
    
    # Train model
    model = train_model(training_data, contamination=args.contamination)
    
    # Save model
    save_model(model)
    
    logger.info("\n" + "="*60)
    logger.info("✓ Training completed successfully!")
    logger.info("="*60)
    logger.info("\nThe model is now ready to use for anomaly detection.")
    logger.info("It will be automatically loaded by the ThreatDetector.")
    logger.info("\nRecommended: Retrain monthly with updated benign logs")
    logger.info("  to adapt to environment changes.")
    logger.info("="*60 + "\n")
    
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train ML anomaly detection model")
    parser.add_argument("--generate-sample", action="store_true", 
                       help="Generate sample benign data")
    parser.add_argument("--num-samples", type=int, default=5000,
                       help="Number of samples to generate (default: 5000)")
    parser.add_argument("--training-data", type=str,
                       help="Path to training data JSON file")
    parser.add_argument("--contamination", type=float, default=0.1,
                       help="Expected contamination rate (default: 0.1)")
    args = parser.parse_args()
    
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        logger.info("\n\nTraining interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"\nFatal error during training: {e}")
        sys.exit(1)

