#!/usr/bin/env python3
"""
OpenSearch Setup Script for ThreatOps SOC
This script configures OpenSearch with the necessary indices, templates, and pipelines.
"""

import requests
import json
import sys
import logging
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OpenSearchSetup:
    """OpenSearch configuration manager"""
    
    def __init__(self, host="https://localhost:9200", username="admin", password="admin"):
        self.host = host
        self.auth = (username, password)
        self.headers = {'Content-Type': 'application/json'}
        
    def check_connection(self):
        """Check if OpenSearch is accessible"""
        try:
            response = requests.get(
                self.host,
                auth=self.auth,
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                info = response.json()
                logger.info(f"✓ Connected to OpenSearch cluster: {info.get('cluster_name')}")
                logger.info(f"  Version: {info.get('version', {}).get('number')}")
                return True
            else:
                logger.error(f"✗ Failed to connect: HTTP {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"✗ Connection failed: {e}")
            logger.error("  Make sure OpenSearch is running on https://localhost:9200")
            return False
    
    def create_index_template(self):
        """Create index template for ThreatOps logs"""
        logger.info("Creating index template...")
        
        template_path = Path(__file__).parent.parent / "config" / "opensearch_index_template.json"
        
        with open(template_path, 'r') as f:
            template = json.load(f)
        
        try:
            response = requests.put(
                f"{self.host}/_index_template/threatops-template",
                auth=self.auth,
                headers=self.headers,
                json=template,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                logger.info("✓ Index template created successfully")
                return True
            else:
                logger.error(f"✗ Failed to create template: {response.text}")
                return False
        except Exception as e:
            logger.error(f"✗ Error creating template: {e}")
            return False
    
    def create_ingest_pipeline(self):
        """Create ingest pipeline for log enrichment"""
        logger.info("Creating ingest pipeline...")
        
        pipeline_path = Path(__file__).parent.parent / "config" / "opensearch_pipelines.json"
        
        with open(pipeline_path, 'r') as f:
            pipeline = json.load(f)
        
        try:
            response = requests.put(
                f"{self.host}/_ingest/pipeline/threatops-enrichment",
                auth=self.auth,
                headers=self.headers,
                json=pipeline,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                logger.info("✓ Ingest pipeline created successfully")
                return True
            else:
                logger.error(f"✗ Failed to create pipeline: {response.text}")
                return False
        except Exception as e:
            logger.error(f"✗ Error creating pipeline: {e}")
            return False
    
    def create_ilm_policy(self):
        """Create Index Lifecycle Management policy"""
        logger.info("Creating ILM policy...")
        
        policy = {
            "policy": {
                "description": "ThreatOps log retention policy",
                "default_state": "hot",
                "states": [
                    {
                        "name": "hot",
                        "actions": [
                            {
                                "rollover": {
                                    "min_index_age": "1d",
                                    "min_primary_shard_size": "50gb"
                                }
                            }
                        ],
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
                        "actions": [],
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
                        ]
                    }
                ],
                "ism_template": {
                    "index_patterns": ["threatops-*"],
                    "priority": 100
                }
            }
        }
        
        try:
            response = requests.put(
                f"{self.host}/_plugins/_ism/policies/threatops-policy",
                auth=self.auth,
                headers=self.headers,
                json=policy,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                logger.info("✓ ILM policy created successfully")
                return True
            else:
                logger.error(f"✗ Failed to create ILM policy: {response.text}")
                return False
        except Exception as e:
            logger.error(f"✗ Error creating ILM policy: {e}")
            return False
    
    def create_initial_index(self):
        """Create initial index"""
        logger.info("Creating initial index...")
        
        from datetime import datetime
        index_name = f"threatops-logs-{datetime.now().strftime('%Y.%m.%d')}"
        
        try:
            response = requests.put(
                f"{self.host}/{index_name}",
                auth=self.auth,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                logger.info(f"✓ Initial index created: {index_name}")
                return True
            elif response.status_code == 400 and "resource_already_exists_exception" in response.text:
                logger.info(f"✓ Index already exists: {index_name}")
                return True
            else:
                logger.error(f"✗ Failed to create index: {response.text}")
                return False
        except Exception as e:
            logger.error(f"✗ Error creating index: {e}")
            return False
    
    def setup_all(self):
        """Run full setup"""
        logger.info("=" * 60)
        logger.info("ThreatOps OpenSearch Setup")
        logger.info("=" * 60)
        
        steps = [
            ("Checking connection", self.check_connection),
            ("Creating index template", self.create_index_template),
            ("Creating ingest pipeline", self.create_ingest_pipeline),
            ("Creating ILM policy", self.create_ilm_policy),
            ("Creating initial index", self.create_initial_index),
        ]
        
        results = []
        for step_name, step_func in steps:
            logger.info(f"\n[Step] {step_name}...")
            result = step_func()
            results.append(result)
            if not result and step_name == "Checking connection":
                logger.error("\n✗ Setup failed: Cannot connect to OpenSearch")
                logger.error("  Please ensure OpenSearch is running and accessible")
                return False
        
        logger.info("\n" + "=" * 60)
        if all(results):
            logger.info("✓ OpenSearch setup completed successfully!")
            logger.info("\nNext steps:")
            logger.info("  1. Start Filebeat: filebeat -c config/filebeat.yml")
            logger.info("  2. Run attack simulations: python run.py")
            logger.info("  3. View dashboards: http://localhost:5601")
        else:
            logger.warning("⚠ Setup completed with some errors")
            logger.info("  Check the logs above for details")
        logger.info("=" * 60)
        
        return all(results)

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Setup OpenSearch for ThreatOps SOC")
    parser.add_argument("--host", default="https://localhost:9200", help="OpenSearch host")
    parser.add_argument("--username", default="admin", help="OpenSearch username")
    parser.add_argument("--password", default="admin", help="OpenSearch password")
    
    args = parser.parse_args()
    
    setup = OpenSearchSetup(args.host, args.username, args.password)
    success = setup.setup_all()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

