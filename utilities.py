"""
================================================================================
UTILITIES MODULE - ThreatOps SOC
================================================================================

This file consolidates all utility scripts and setup tools:
- OpenSearch Setup (indices, templates, pipelines)
- ML Model Training
- Threat Intelligence Database Updates

Created by merging:
- scripts/setup_opensearch.py
- scripts/train_model.py
- scripts/update_intel_db.py
================================================================================
"""

# ============================================================================
# SECTION 1: OPENSEARCH SETUP
# ============================================================================
"""
OpenSearch Setup Script for ThreatOps

This script initializes OpenSearch for ThreatOps by creating:
- Index templates
- Ingest pipelines
- Index lifecycle management (ISM) policies
- Initial indices
- Security mappings

Run this after starting OpenSearch but before starting Filebeat.

Usage:
    python scripts/setup_opensearch.py
"""

import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: 'requests' library not found.")
    print("Install it with: pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# OpenSearch connection settings
# OpenSearch security is currently disabled (requires SSL certificates when enabled)
OPENSEARCH_HOST = "http://localhost:9200"

# HTTP session without auth (OpenSearch security is disabled)
session = requests.Session()
session.verify = False  # For self-signed certificates


def check_connection() -> bool:
    """Test connection to OpenSearch cluster."""
    try:
        response = session.get(f"{OPENSEARCH_HOST}/")
        response.raise_for_status()
        cluster_info = response.json()
        logger.info(f"✓ Connected to OpenSearch cluster: {cluster_info.get('cluster_name')}")
        logger.info(f"  Version: {cluster_info.get('version', {}).get('number')}")
        return True
    except Exception as e:
        logger.error(f"✗ Failed to connect to OpenSearch: {e}")
        logger.error("  Make sure OpenSearch is running on http://localhost:9200")
        return False


def create_index_template() -> bool:
    """Create index template for threatops-* indices."""
    
    template = {
        "index_patterns": ["threatops-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.codec": "best_compression",
                "index.refresh_interval": "5s",
                "index.max_result_window": 100000
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "timestamp": {"type": "date"},
                    "event_id": {"type": "keyword"},
                    "host": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "user": {"type": "keyword"},
                    "username": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "ip": {"type": "ip"},
                    "port": {"type": "integer"},
                    "process_name": {"type": "keyword"},
                    "command_line": {"type": "text"},
                    "message": {"type": "text"},
                    "severity": {"type": "keyword"},
                    "log_level": {"type": "keyword"},
                    "log_type": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "rule_name": {"type": "keyword"},
                    "rule_id": {"type": "keyword"},
                    "mitre_technique": {"type": "keyword"},
                    "mitre_tactic": {"type": "keyword"},
                    "alert_id": {"type": "keyword"},
                    "risk_score": {"type": "float"},
                    "threat_intel": {
                        "type": "object",
                        "properties": {
                            "reputation": {"type": "keyword"},
                            "source": {"type": "keyword"},
                            "last_seen": {"type": "date"},
                            "confidence": {"type": "float"}
                        }
                    },
                    "ml_score": {"type": "float"},
                    "is_anomaly": {"type": "boolean"},
                    "environment": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "fields": {"type": "object", "enabled": False}
                }
            }
        },
        "priority": 500,
        "version": 1,
        "_meta": {
            "description": "Index template for ThreatOps security logs and alerts"
        }
    }
    
    try:
        response = session.put(
            f"{OPENSEARCH_HOST}/_index_template/threatops-template",
            json=template,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        logger.info("✓ Index template created successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Failed to create index template: {e}")
        return False


def create_ingest_pipeline() -> bool:
    """Create ingest pipeline for log enrichment."""
    
    pipeline = {
        "description": "ThreatOps log enrichment pipeline",
        "processors": [
            {
                "set": {
                    "field": "@timestamp",
                    "value": "{{_ingest.timestamp}}",
                    "if": "ctx.timestamp == null && ctx['@timestamp'] == null"
                }
            },
            {
                "rename": {
                    "field": "timestamp",
                    "target_field": "@timestamp",
                    "ignore_missing": True,
                    "if": "ctx.timestamp != null && ctx['@timestamp'] == null"
                }
            },
            {
                "date": {
                    "field": "@timestamp",
                    "target_field": "@timestamp",
                    "formats": [
                        "yyyy-MM-dd HH:mm:ss",
                        "yyyy-MM-dd'T'HH:mm:ss'Z'",
                        "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'",
                        "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'",
                        "ISO8601"
                    ],
                    "ignore_failure": True
                }
            },
            {
                "grok": {
                    "field": "message",
                    "patterns": [
                        "%{IP:source_ip}",
                        "%{HOSTNAME:hostname}"
                    ],
                    "ignore_failure": True
                }
            },
            {
                "convert": {
                    "field": "risk_score",
                    "type": "float",
                    "ignore_missing": True,
                    "ignore_failure": True
                }
            },
            {
                "lowercase": {
                    "field": "severity",
                    "ignore_missing": True,
                    "ignore_failure": True
                }
            },
            {
                "remove": {
                    "field": ["agent.ephemeral_id", "agent.id", "ecs.version"],
                    "ignore_missing": True
                }
            }
        ],
        "on_failure": [
            {
                "set": {
                    "field": "error.message",
                    "value": "{{ _ingest.on_failure_message }}"
                }
            }
        ]
    }
    
    try:
        response = session.put(
            f"{OPENSEARCH_HOST}/_ingest/pipeline/threatops-enrichment",
            json=pipeline,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        logger.info("✓ Ingest pipeline created successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Failed to create ingest pipeline: {e}")
        return False


def create_ism_policy() -> bool:
    """Create Index State Management (ISM) policy for log retention."""
    
    policy = {
        "policy": {
            "description": "ThreatOps log retention policy - delete after 30 days",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [],
                    "transitions": [
                        {
                            "state_name": "warm",
                            "conditions": {
                                "min_index_age": "7d"
                            }
                        }
                    ]
                },
                {
                    "name": "warm",
                    "actions": [
                        {
                            "read_only": {}
                        },
                        {
                            "force_merge": {
                                "max_num_segments": 1
                            }
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {
                                "min_index_age": "30d"
                            }
                        }
                    ]
                },
                {
                    "name": "delete",
                    "actions": [
                        {
                            "delete": {}
                        }
                    ],
                    "transitions": []
                }
            ],
            "ism_template": [
                {
                    "index_patterns": ["threatops-logs-*"],
                    "priority": 100
                }
            ]
        }
    }
    
    try:
        response = session.put(
            f"{OPENSEARCH_HOST}/_plugins/_ism/policies/threatops-retention",
            json=policy,
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        logger.info("✓ ISM policy created successfully (30-day retention)")
        return True
    except Exception as e:
        # ISM plugin might not be available in all installations
        logger.warning(f"⚠ ISM policy creation skipped: {e}")
        logger.warning("  This is optional - logs will still be stored")
        return True  # Don't fail the setup


def create_initial_index() -> bool:
    """Create the initial index for today's logs."""
    from datetime import datetime
    
    index_name = f"threatops-logs-{datetime.now().strftime('%Y.%m.%d')}"
    
    try:
        # Check if index already exists
        response = session.head(f"{OPENSEARCH_HOST}/{index_name}")
        if response.status_code == 200:
            logger.info(f"✓ Index {index_name} already exists")
            return True
        
        # Create index (template will apply settings automatically)
        response = session.put(
            f"{OPENSEARCH_HOST}/{index_name}",
            headers={"Content-Type": "application/json"}
        )
        response.raise_for_status()
        logger.info(f"✓ Initial index created: {index_name}")
        return True
    except Exception as e:
        logger.error(f"✗ Failed to create initial index: {e}")
        return False


def verify_setup() -> bool:
    """Verify that all components were created successfully."""
    
    checks = []
    
    # Check index template
    try:
        response = session.get(f"{OPENSEARCH_HOST}/_index_template/threatops-template")
        checks.append(("Index Template", response.status_code == 200))
    except:
        checks.append(("Index Template", False))
    
    # Check ingest pipeline
    try:
        response = session.get(f"{OPENSEARCH_HOST}/_ingest/pipeline/threatops-enrichment")
        checks.append(("Ingest Pipeline", response.status_code == 200))
    except:
        checks.append(("Ingest Pipeline", False))
    
    # Check indices
    try:
        response = session.get(f"{OPENSEARCH_HOST}/_cat/indices/threatops-*?format=json")
        indices = response.json()
        checks.append(("Indices", len(indices) > 0))
    except:
        checks.append(("Indices", False))
    
    logger.info("\n" + "="*60)
    logger.info("Setup Verification:")
    logger.info("="*60)
    
    all_passed = True
    for name, passed in checks:
        status = "✓ PASS" if passed else "✗ FAIL"
        logger.info(f"  {name:20s} {status}")
        if not passed:
            all_passed = False
    
    logger.info("="*60)
    
    return all_passed


def main():
    """Main setup function."""
    
    logger.info("="*60)
    logger.info("ThreatOps OpenSearch Setup")
    logger.info("="*60)
    
    # Step 1: Check connection
    logger.info("\n1. Checking OpenSearch connection...")
    if not check_connection():
        logger.error("\nSetup failed: Cannot connect to OpenSearch")
        logger.error("Please ensure OpenSearch is running and try again:")
        logger.error("  cd opensearch-3.3.1")
        logger.error("  .\\bin\\opensearch.bat")
        return 1
    
    # Step 2: Create index template
    logger.info("\n2. Creating index template...")
    if not create_index_template():
        logger.error("\nSetup failed: Could not create index template")
        return 1
    
    # Step 3: Create ingest pipeline
    logger.info("\n3. Creating ingest pipeline...")
    if not create_ingest_pipeline():
        logger.error("\nSetup failed: Could not create ingest pipeline")
        return 1
    
    # Step 4: Create ISM policy
    logger.info("\n4. Creating ISM policy...")
    create_ism_policy()  # Optional, don't fail on error
    
    # Step 5: Create initial index
    logger.info("\n5. Creating initial index...")
    if not create_initial_index():
        logger.error("\nSetup failed: Could not create initial index")
        return 1
    
    # Step 6: Verify setup
    logger.info("\n6. Verifying setup...")
    if not verify_setup():
        logger.warning("\nSetup completed with warnings")
        return 0  # Don't fail - warnings are acceptable
    
    logger.info("\n" + "="*60)
    logger.info("✓ OpenSearch setup completed successfully!")
    logger.info("="*60)
    logger.info("\nNext steps:")
    logger.info("  1. Start Filebeat to begin log ingestion")
    logger.info("  2. Run attack simulation: python run.py --mode simulation")
    logger.info("  3. View logs in OpenSearch Dashboards: http://localhost:5601")
    logger.info("  4. Create index pattern in Dashboards: threatops-*")
    logger.info("="*60)
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("\n\nSetup interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"\nFatal error during setup: {e}")
        sys.exit(1)

# ============================================================================
# SECTION 2: ML MODEL TRAINING
# ============================================================================
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

# ============================================================================
# SECTION 3: THREAT INTELLIGENCE DATABASE UPDATES
# ============================================================================
"""
Threat Intelligence Database Update Script

Downloads and updates the local threat intelligence database from multiple free sources:
- Abuse.ch SSL Blacklist
- URLhaus
- Emerging Threats
- Blocklist.de
- Feodo Tracker
- MalwareBazaar
- CINSSCORE
- Talos Intelligence

Usage:
    python scripts/update_intel_db.py
    python scripts/update_intel_db.py --stats-only
"""

import sys
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
import argparse

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library not found.")
    print("Install it with: pip install requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path
ROOT = Path(__file__).parent.parent
DB_PATH = ROOT / "data" / "threat_intel.db"

# Threat intelligence feeds (all free)
FEEDS = {
    "abuse_ssl": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "description": "SSL Blacklist - Malicious SSL certificates"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text/",
        "type": "domain",
        "description": "URLhaus - Malware distribution sites"
    },
    "feodo_tracker": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip",
        "description": "Feodo Tracker - Botnet C2 servers"
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "description": "Blocklist.de - Attack sources"
    },
    "cinsscore": {
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "description": "CINSSCORE - Bad actors"
    },
}


def init_database():
    """Initialize the threat intelligence database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reputation TEXT DEFAULT 'malicious',
            confidence REAL DEFAULT 0.8,
            description TEXT
        )
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_indicator ON threat_intel(indicator)
    """)
    
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_type ON threat_intel(type)
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS update_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name TEXT NOT NULL,
            update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            indicators_added INTEGER,
            status TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    
    logger.info(f"✓ Database initialized: {DB_PATH}")


def download_feed(feed_name: str, feed_config: Dict) -> Set[str]:
    """Download and parse a threat intelligence feed."""
    try:
        logger.info(f"Downloading {feed_name}...")
        response = requests.get(feed_config["url"], timeout=30)
        response.raise_for_status()
        
        indicators = set()
        for line in response.text.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Extract IP or domain
            if feed_config["type"] == "ip":
                # Remove CIDR notation if present
                indicator = line.split('/')[0].split()[0]
            elif feed_config["type"] == "domain":
                # Extract domain from URL
                indicator = line.replace('http://', '').replace('https://', '').split('/')[0]
            else:
                indicator = line
            
            if indicator:
                indicators.add(indicator)
        
        logger.info(f"  Downloaded {len(indicators)} indicators from {feed_name}")
        return indicators
        
    except Exception as e:
        logger.error(f"  Failed to download {feed_name}: {e}")
        return set()


def update_database(feed_name: str, indicators: Set[str], feed_type: str, description: str) -> int:
    """Update the database with new indicators."""
    if not indicators:
        return 0
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    added = 0
    for indicator in indicators:
        try:
            cursor.execute("""
                INSERT INTO threat_intel (indicator, type, source, description, reputation, confidence)
                VALUES (?, ?, ?, ?, 'malicious', 0.8)
                ON CONFLICT(indicator) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    source = source || ',' || ?
            """, (indicator, feed_type, feed_name, description, feed_name))
            
            if cursor.rowcount > 0:
                added += 1
                
        except Exception as e:
            logger.debug(f"Error inserting {indicator}: {e}")
            continue
    
    # Record update history
    cursor.execute("""
        INSERT INTO update_history (feed_name, indicators_added, status)
        VALUES (?, ?, 'success')
    """, (feed_name, added))
    
    conn.commit()
    conn.close()
    
    logger.info(f"  Added {added} new indicators to database")
    return added


def get_statistics() -> Dict:
    """Get database statistics."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Total indicators
    cursor.execute("SELECT COUNT(*) FROM threat_intel")
    total = cursor.fetchone()[0]
    
    # By type
    cursor.execute("""
        SELECT type, COUNT(*) 
        FROM threat_intel 
        GROUP BY type
    """)
    by_type = dict(cursor.fetchall())
    
    # By source
    cursor.execute("""
        SELECT source, COUNT(*)
        FROM threat_intel
        GROUP BY source
        ORDER BY COUNT(*) DESC
        LIMIT 10
    """)
    by_source = cursor.fetchall()
    
    # Last update
    cursor.execute("""
        SELECT MAX(update_time)
        FROM update_history
    """)
    last_update = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "total": total,
        "by_type": by_type,
        "by_source": by_source,
        "last_update": last_update
    }


def print_statistics():
    """Print database statistics."""
    stats = get_statistics()
    
    print("\n" + "="*60)
    print("Threat Intelligence Database Statistics")
    print("="*60)
    print(f"\nTotal Indicators: {stats['total']:,}")
    
    print("\nBy Type:")
    for ioc_type, count in stats['by_type'].items():
        print(f"  {ioc_type:15s}: {count:,}")
    
    print("\nTop Sources:")
    for source, count in stats['by_source']:
        source_name = source.split(',')[0]  # Get first source
        print(f"  {source_name:20s}: {count:,}")
    
    if stats['last_update']:
        print(f"\nLast Update: {stats['last_update']}")
    
    print("="*60 + "\n")


def main(args):
    """Main function."""
    logger.info("="*60)
    logger.info("ThreatOps Threat Intelligence Database Updater")
    logger.info("="*60)
    
    # Initialize database
    init_database()
    
    # If stats only, just print and exit
    if args.stats_only:
        print_statistics()
        return 0
    
    # Download and update from each feed
    total_added = 0
    
    for feed_name, feed_config in FEEDS.items():
        logger.info(f"\nProcessing feed: {feed_config['description']}")
        
        indicators = download_feed(feed_name, feed_config)
        
        if indicators:
            added = update_database(
                feed_name,
                indicators,
                feed_config["type"],
                feed_config["description"]
            )
            total_added += added
    
    # Print final statistics
    logger.info("\n" + "="*60)
    logger.info(f"✓ Update complete! Added {total_added:,} new indicators")
    logger.info("="*60)
    
    print_statistics()
    
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Update threat intelligence database")
    parser.add_argument("--stats-only", action="store_true", help="Only show statistics, don't update")
    args = parser.parse_args()
    
    try:
        sys.exit(main(args))
    except KeyboardInterrupt:
        logger.info("\n\nUpdate interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"\nFatal error during update: {e}")
        sys.exit(1)

