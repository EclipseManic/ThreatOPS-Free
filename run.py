#!/usr/bin/env python3
"""
================================================================================
ThreatOps SOC - Unified Entry Point
================================================================================

Single command to run everything with flags:
  python run.py --all           # Start everything (OpenSearch + Pipeline + Dashboard)
  python run.py --simulate      # Generate attack logs
  python run.py --detect        # Run threat detection
  python run.py --enrich        # Enrich with threat intelligence
  python run.py --score         # Calculate risk scores
  python run.py --pipeline      # Run full pipeline (detect → enrich → score)
  python run.py --continuous    # Run pipeline continuously
  python run.py --dashboard     # Start dashboard only
  python run.py --setup         # Setup OpenSearch
  python run.py --train         # Train ML model
  python run.py --update-intel  # Update threat intelligence DB

================================================================================
"""

import sys
import os
import argparse
import asyncio
import logging
import time
import subprocess
import webbrowser
from pathlib import Path
from datetime import datetime

# Add current directory to path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

# Import from our modules
from application import Settings, _setup_logging, create_directories, check_opensearch_health
from simulation import AttackSimulator
from core_detection import ThreatDetector
from core_detection import IntelEnricher
from core_detection import RiskScorer

logger = None  # Will be initialized after logging setup


class ThreatOpsOrchestrator:
    """Main orchestrator for all ThreatOps operations"""
    
    def __init__(self):
        self.settings = Settings()
        self.attack_simulator = AttackSimulator(self.settings)
        self.threat_detector = ThreatDetector(self.settings)
        self.intel_enricher = IntelEnricher(self.settings)
        self.risk_scorer = RiskScorer(self.settings)
        
    async def initialize(self):
        """Initialize all components"""
        logger.info("Initializing ThreatOps components...")
        await self.attack_simulator.initialize()
        await self.threat_detector.initialize()
        await self.intel_enricher.initialize()
        await self.risk_scorer.initialize()
        logger.info("✓ All components initialized")
    
    async def simulate(self):
        """Generate simulated attack logs"""
        logger.info("=" * 70)
        logger.info("RUNNING: Attack Simulation")
        logger.info("=" * 70)
        
        sim_logs = await self.attack_simulator.generate_attack_logs()
        logger.info(f"Generated {len(sim_logs)} simulated attack logs")
        
        # Write logs for Filebeat to collect
        await self.attack_simulator.write_logs_for_filebeat(sim_logs)
        
        # Save to simulations directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        await self.attack_simulator.save_simulation_logs(sim_logs, f"all_scenarios_{timestamp}")
        
        logger.info("✓ Simulation complete - logs written to data/sim_attacks.log")
        return sim_logs
    
    async def detect(self):
        """Run threat detection"""
        logger.info("=" * 70)
        logger.info("RUNNING: Threat Detection")
        logger.info("=" * 70)
        
        alerts = await self.threat_detector.ml_detector.detect(
            index_pattern="filebeat-*",
            max_logs=10000
        )
        
        logger.info(f"✓ Detection complete - {len(alerts)} alerts generated")
        return alerts
    
    async def enrich(self):
        """Enrich alerts with threat intelligence"""
        logger.info("=" * 70)
        logger.info("RUNNING: Threat Intelligence Enrichment")
        logger.info("=" * 70)
        
        enriched_alerts = await self.intel_enricher.enrich_alerts_from_opensearch()
        
        logger.info(f"✓ Enrichment complete - {len(enriched_alerts)} alerts enriched")
        return enriched_alerts
    
    async def score(self):
        """Calculate risk scores"""
        logger.info("=" * 70)
        logger.info("RUNNING: Risk Scoring")
        logger.info("=" * 70)
        
        scored_alerts = await self.risk_scorer.score_alerts_from_opensearch()
        
        logger.info(f"✓ Scoring complete - {len(scored_alerts)} alerts scored")
        return scored_alerts
    
    async def run_pipeline(self):
        """Run full detection pipeline"""
        logger.info("=" * 70)
        logger.info("RUNNING: Full SIEM Pipeline")
        logger.info("=" * 70)
        
        # Step 1: Detection
        alerts = await self.detect()
        if not alerts:
            logger.warning("No alerts detected, skipping enrichment and scoring")
            return None
        
        await asyncio.sleep(2)  # Wait for OpenSearch indexing
        
        # Step 2: Enrichment
        enriched_alerts = await self.enrich()
        if not enriched_alerts:
            logger.warning("No alerts enriched, skipping scoring")
            return None
        
        await asyncio.sleep(2)  # Wait for OpenSearch indexing
        
        # Step 3: Scoring
        scored_alerts = await self.score()
        
        logger.info("=" * 70)
        logger.info(f"PIPELINE COMPLETE!")
        logger.info(f"  Detected:  {len(alerts)} alerts")
        logger.info(f"  Enriched:  {len(enriched_alerts)} alerts")
        logger.info(f"  Scored:    {len(scored_alerts)} alerts")
        logger.info("=" * 70)
        
        return scored_alerts
    
    async def run_continuous(self, interval=60):
        """Run pipeline continuously"""
        logger.info("=" * 70)
        logger.info(f"RUNNING: Continuous Mode (interval: {interval}s)")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 70)
        
        try:
            while True:
                try:
                    await self.run_pipeline()
                except Exception as e:
                    logger.error(f"Error in pipeline: {e}")
                
                logger.info(f"\nWaiting {interval} seconds before next run...\n")
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            logger.info("\n✓ Continuous mode stopped")


def start_services():
    """Start OpenSearch, Filebeat, and OpenSearch Dashboards"""
    logger.info("=" * 70)
    logger.info("STARTING: Backend Services")
    logger.info("=" * 70)
    
    # Paths (update these to match your installation)
    OPENSEARCH_BIN = Path(r"D:\Cusor AI\opensearch-3.3.1-windows-x64\opensearch-3.3.1\bin\opensearch.bat")
    FILEBEAT_EXE = Path(r"D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat-9.2.0-windows-x86_64\filebeat.exe")
    DASHBOARDS_BIN = Path(r"D:\Cusor AI\opensearch-dashboards-3.3.0\bin\opensearch-dashboards.bat")
    
    processes = []
    
    # Start OpenSearch
    logger.info("\n[1/3] Starting OpenSearch...")
    if OPENSEARCH_BIN.exists():
        try:
            proc = subprocess.Popen(
                [str(OPENSEARCH_BIN)],
                cwd=str(OPENSEARCH_BIN.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(('OpenSearch', proc))
            logger.info("✓ OpenSearch started")
            
            # Wait for OpenSearch to become healthy
            logger.info("  Waiting for OpenSearch to become ready...")
            if check_opensearch_health(timeout=5, max_retries=12, retry_interval=10):
                logger.info("✓ OpenSearch is ready and healthy")
            else:
                logger.error("✗ OpenSearch failed to become healthy")
        except Exception as e:
            logger.error(f"✗ Failed to start OpenSearch: {e}")
    else:
        logger.error(f"✗ OpenSearch not found at: {OPENSEARCH_BIN}")
    
    # Start Filebeat
    logger.info("\n[2/3] Starting Filebeat...")
    if FILEBEAT_EXE.exists():
        try:
            proc = subprocess.Popen(
                [str(FILEBEAT_EXE), "-e"],
                cwd=str(FILEBEAT_EXE.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(('Filebeat', proc))
            logger.info("✓ Filebeat started")
            logger.info("  Waiting 10 seconds for connection...")
            time.sleep(10)
        except Exception as e:
            logger.error(f"✗ Failed to start Filebeat: {e}")
    else:
        logger.error(f"✗ Filebeat not found at: {FILEBEAT_EXE}")
    
    # Start OpenSearch Dashboards
    logger.info("\n[3/3] Starting OpenSearch Dashboards...")
    if DASHBOARDS_BIN.exists():
        try:
            dashboards_root = DASHBOARDS_BIN.parent.parent
            node_exe = dashboards_root / "node" / "node.exe"
            cli_js = dashboards_root / "src" / "cli" / "dist.js"
            
            if node_exe.exists() and cli_js.exists():
                proc = subprocess.Popen(
                    [str(node_exe), str(cli_js)],
                    cwd=str(dashboards_root),
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                processes.append(('OpenSearch Dashboards', proc))
                logger.info("✓ OpenSearch Dashboards started")
                logger.info("  URL: http://localhost:5601")
            else:
                logger.error(f"✗ Node.js or CLI not found")
        except Exception as e:
            logger.error(f"✗ Failed to start OpenSearch Dashboards: {e}")
    else:
        logger.error(f"✗ OpenSearch Dashboards not found at: {DASHBOARDS_BIN}")
    
    logger.info("\n" + "=" * 70)
    logger.info("✓ All services started!")
    logger.info("=" * 70)
    
    return processes


def start_dashboard():
    """Start Streamlit dashboard"""
    logger.info("=" * 70)
    logger.info("STARTING: ThreatOps Dashboard")
    logger.info("=" * 70)
    
    dashboard_app = ROOT / "application.py"
    
    if not dashboard_app.exists():
        logger.error(f"✗ Dashboard app not found at: {dashboard_app}")
        return None
    
    try:
        venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
        python_exe = str(venv_python) if venv_python.exists() else "python"
        
        # Find the dashboard section in application.py and extract it
        # For now, we'll use streamlit run on application.py
        proc = subprocess.Popen(
            [python_exe, "-m", "streamlit", "run", str(dashboard_app), 
             "--server.headless", "true"],
            cwd=str(ROOT),
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        
        logger.info("✓ Dashboard starting...")
        logger.info("  URL: http://localhost:8501")
        time.sleep(5)
        
        return proc
    except Exception as e:
        logger.error(f"✗ Failed to start dashboard: {e}")
        return None


def open_dashboards():
    """Open all dashboards in browser"""
    logger.info("\n" + "=" * 70)
    logger.info("OPENING: Dashboards in Browser")
    logger.info("=" * 70)
    
    dashboards = [
        ("ThreatOps Dashboard", "http://localhost:8501"),
        ("OpenSearch Dashboards", "http://localhost:5601"),
        ("OpenSearch API", "http://localhost:9200")
    ]
    
    for name, url in dashboards:
        try:
            logger.info(f"Opening {name}...")
            webbrowser.open(url)
            time.sleep(1)
        except Exception as e:
            logger.warning(f"Could not open {name}: {e}")
    
    logger.info("✓ Dashboards opened!")


def run_setup():
    """Run OpenSearch setup"""
    logger.info("=" * 70)
    logger.info("RUNNING: OpenSearch Setup")
    logger.info("=" * 70)
    
    from utilities import main as setup_main
    setup_main()
    
    logger.info("✓ Setup complete")


def run_train():
    """Train ML model"""
    logger.info("=" * 70)
    logger.info("RUNNING: ML Model Training")
    logger.info("=" * 70)
    
    # Generate benign samples and train
    import argparse
    args = argparse.Namespace(
        generate_sample=True,
        num_samples=5000,
        training_data=None,
        contamination=0.1
    )
    
    from utilities import main as train_main
    train_main(args)
    
    logger.info("✓ Training complete")


def run_update_intel():
    """Update threat intelligence database"""
    logger.info("=" * 70)
    logger.info("RUNNING: Threat Intelligence Update")
    logger.info("=" * 70)
    
    import argparse
    args = argparse.Namespace(stats_only=False)
    
    from utilities import main as update_main
    update_main(args)
    
    logger.info("✓ Update complete")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="ThreatOps SOC - Unified Entry Point",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --all            # Start everything
  python run.py --simulate       # Generate attack logs
  python run.py --detect         # Run detection
  python run.py --pipeline       # Run full pipeline
  python run.py --continuous     # Run continuously
  python run.py --dashboard      # Start dashboard only
  python run.py --setup          # Setup OpenSearch
  python run.py --train          # Train ML model
  python run.py --update-intel   # Update threat intel DB
        """
    )
    
    parser.add_argument('--all', action='store_true',
                       help='Start everything (services + simulation + pipeline + dashboard)')
    parser.add_argument('--simulate', action='store_true',
                       help='Generate simulated attack logs')
    parser.add_argument('--detect', action='store_true',
                       help='Run threat detection')
    parser.add_argument('--enrich', action='store_true',
                       help='Enrich with threat intelligence')
    parser.add_argument('--score', action='store_true',
                       help='Calculate risk scores')
    parser.add_argument('--pipeline', action='store_true',
                       help='Run full pipeline (detect → enrich → score)')
    parser.add_argument('--continuous', action='store_true',
                       help='Run pipeline continuously')
    parser.add_argument('--dashboard', action='store_true',
                       help='Start dashboard only')
    parser.add_argument('--setup', action='store_true',
                       help='Setup OpenSearch')
    parser.add_argument('--train', action='store_true',
                       help='Train ML model')
    parser.add_argument('--update-intel', action='store_true',
                       help='Update threat intelligence database')
    parser.add_argument('--interval', type=int, default=60,
                       help='Interval for continuous mode (default: 60s)')
    
    args = parser.parse_args()
    
    # Setup logging
    _setup_logging()
    global logger
    logger = logging.getLogger("run")
    
    # Create directories
    create_directories()
    
    try:
        # Handle --all mode
        if args.all:
            logger.info("=" * 70)
            logger.info("THREATOPS SOC - COMPLETE STARTUP")
            logger.info("=" * 70)
            
            # Start all services
            start_services()
            
            # Initialize orchestrator
            orchestrator = ThreatOpsOrchestrator()
            asyncio.run(orchestrator.initialize())
            
            # Run simulation
            logger.info("\n")
            asyncio.run(orchestrator.simulate())
            
            # Wait for log indexing
            logger.info("\nWaiting 15 seconds for log indexing...")
            time.sleep(15)
            
            # Run pipeline
            logger.info("\n")
            asyncio.run(orchestrator.run_pipeline())
            
            # Start dashboard
            logger.info("\n")
            start_dashboard()
            
            # Wait for OpenSearch Dashboards
            logger.info("\nWaiting for OpenSearch Dashboards...")
            time.sleep(30)
            
            # Open dashboards
            open_dashboards()
            
            logger.info("\n" + "=" * 70)
            logger.info("COMPLETE! All systems operational!")
            logger.info("=" * 70)
            logger.info("\nServices running:")
            logger.info("  ThreatOps UI:    http://localhost:8501")
            logger.info("  OpenSearch DB:   http://localhost:5601")
            logger.info("  OpenSearch API:  http://localhost:9200")
            logger.info("\n" + "=" * 70)
            logger.info("\nPress Enter to EXIT and close all services")
            logger.info("=" * 70)
            
            input()
            logger.info("\nShutting down...")
            return 0
        
        # Handle individual modes
        if args.setup:
            run_setup()
            return 0
        
        if args.train:
            run_train()
            return 0
        
        if args.update_intel:
            run_update_intel()
            return 0
        
        if args.dashboard:
            start_dashboard()
            logger.info("\nDashboard running at http://localhost:8501")
            logger.info("Press Ctrl+C to stop")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("\nStopping dashboard...")
            return 0
        
        # Modes that need OpenSearch
        if any([args.simulate, args.detect, args.enrich, args.score, args.pipeline, args.continuous]):
            # Check OpenSearch health
            logger.info("Checking OpenSearch connection...")
            if not check_opensearch_health(timeout=5, max_retries=1, retry_interval=0):
                logger.error("✗ OpenSearch is not running!")
                logger.error("Please start OpenSearch first or use: python run.py --all")
                return 1
            
            # Initialize orchestrator
            orchestrator = ThreatOpsOrchestrator()
            asyncio.run(orchestrator.initialize())
            
            if args.simulate:
                asyncio.run(orchestrator.simulate())
            
            elif args.detect:
                asyncio.run(orchestrator.detect())
            
            elif args.enrich:
                asyncio.run(orchestrator.enrich())
            
            elif args.score:
                asyncio.run(orchestrator.score())
            
            elif args.pipeline:
                asyncio.run(orchestrator.run_pipeline())
            
            elif args.continuous:
                asyncio.run(orchestrator.run_continuous(args.interval))
            
            return 0
        
        # No flags provided - show help
        parser.print_help()
        return 0
    
    except KeyboardInterrupt:
        logger.info("\n\nInterrupted by user")
        return 130
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

