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
    from requests.auth import HTTPBasicAuth
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
OPENSEARCH_HOST = "http://localhost:9200"
OPENSEARCH_USER = "admin"
OPENSEARCH_PASSWORD = "admin"

# HTTP session with auth
session = requests.Session()
session.auth = HTTPBasicAuth(OPENSEARCH_USER, OPENSEARCH_PASSWORD)
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

