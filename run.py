#!/usr/bin/env python3
"""
ThreatOps SIEM Pipeline Orchestrator

This is the main entry point for running the OpenSearch-based SIEM pipeline.
It orchestrates the flow: Detection → Enrichment → Scoring

Prerequisites:
  - OpenSearch running on localhost:9200
  - Filebeat configured and running to collect logs
  
Usage examples:
  python run.py --mode simulate    # Run attack simulation (writes to data/sim_attacks.log)
  python run.py --mode detect      # Run detection pipeline
  python run.py --mode enrich      # Run enrichment pipeline  
  python run.py --mode score       # Run scoring pipeline
  python run.py --mode pipeline    # Run full pipeline (detect > enrich > score)
  python run.py --mode continuous  # Run continuously every 60 seconds
  python run.py --mode all         # START EVERYTHING (services + simulation + pipeline + dashboard)
  
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import io
import time
import subprocess
import webbrowser
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

# Project root
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def _setup_logging() -> None:
    """Configure a UTF-8-safe logger suitable for Windows consoles."""
    try:
        utf8_stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        utf8_stream = sys.stdout

    class SafeStreamHandler(logging.StreamHandler):
        def emit(self, record: logging.LogRecord) -> None:  # type: ignore[override]
            try:
                super().emit(record)
            except UnicodeEncodeError:
                try:
                    msg = self.format(record) + self.terminator
                    if hasattr(self.stream, "buffer"):
                        self.stream.buffer.write(msg.encode("utf-8", errors="replace"))
                        try:
                            self.stream.buffer.flush()
                        except Exception:
                            pass
                    else:
                        safe_msg = msg.encode("utf-8", errors="replace").decode("utf-8")
                        self.stream.write(safe_msg)
                except Exception:
                    pass

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(str(ROOT / "threat_ops.log")),
            SafeStreamHandler(utf8_stream),
        ],
    )


def create_directories() -> None:
    """Create common directories used by the project."""
    directories = [
        ROOT / "data",
        ROOT / "data" / "logs",
        ROOT / "data" / "alerts",
        ROOT / "data" / "reports",
        ROOT / "data" / "simulations",
        ROOT / "logs",
    ]

    for d in directories:
        d.mkdir(parents=True, exist_ok=True)


class ThreatOpsPipeline:
    """OpenSearch-based SIEM Pipeline Orchestrator"""

    def __init__(self):
        from config.settings import Settings
        from simulation.attack_simulator import AttackSimulator
        from detection.threat_detector import ThreatDetector
        from enrichment.intel_enricher import IntelEnricher
        from scoring.risk_scorer import RiskScorer

        self.settings = Settings()
        self.attack_simulator = AttackSimulator(self.settings)
        self.threat_detector = ThreatDetector(self.settings)
        self.intel_enricher = IntelEnricher(self.settings)
        self.risk_scorer = RiskScorer(self.settings)
        self.logger = logging.getLogger("run")

    async def initialize(self) -> None:
        """Initialize all pipeline components"""
        self.logger.info("Initializing ThreatOps SIEM Pipeline components...")
        
        await self.attack_simulator.initialize()
        await self.threat_detector.initialize()
        await self.intel_enricher.initialize()
        await self.risk_scorer.initialize()
        
        self.logger.info("Initialization complete")

    async def run_simulation(self):
        """Generate simulated attack logs and write to file for Filebeat to collect"""
        self.logger.info("=== Running Attack Simulation ===")
        
        # Generate attack logs
        sim_logs = await self.attack_simulator.generate_attack_logs()
        self.logger.info(f"Generated {len(sim_logs)} simulated attack log entries")
        
        # Write logs to file for Filebeat to collect
        await self.attack_simulator.write_logs_for_filebeat(sim_logs)
        
        # Also save to simulations directory for records
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        await self.attack_simulator.save_simulation_logs(sim_logs, f"all_scenarios_{timestamp}")
        
        self.logger.info("[SUCCESS] Simulation complete - logs written to data/sim_attacks.log for Filebeat")
        return sim_logs

    async def run_detection(self):
        """Query OpenSearch for logs and run threat detection"""
        self.logger.info("=== Running Threat Detection ===")
        
        # Use ML detector's detect method which queries OpenSearch
        alerts = await self.threat_detector.ml_detector.detect(
            index_pattern="filebeat-*",
            max_logs=10000
        )
        
        self.logger.info(f"[SUCCESS] Detection complete - generated {len(alerts)} alerts in OpenSearch")
        return alerts

    async def run_enrichment(self):
        """Query OpenSearch for alerts and enrich with threat intelligence"""
        self.logger.info("=== Running Threat Intelligence Enrichment ===")
        
        enriched_alerts = await self.intel_enricher.enrich_alerts_from_opensearch()
        
        self.logger.info(f"[SUCCESS] Enrichment complete - enriched {len(enriched_alerts)} alerts in OpenSearch")
        return enriched_alerts

    async def run_scoring(self):
        """Query OpenSearch for enriched alerts and calculate risk scores"""
        self.logger.info("=== Running Risk Scoring ===")
        
        scored_alerts = await self.risk_scorer.score_alerts_from_opensearch()
        
        self.logger.info(f"[SUCCESS] Scoring complete - scored {len(scored_alerts)} alerts in OpenSearch")
        return scored_alerts

    async def run_full_pipeline(self):
        """Run the complete pipeline: Detection → Enrichment → Scoring"""
        self.logger.info("========================================")
        self.logger.info("Running Full SIEM Pipeline")
        self.logger.info("========================================")
        
        # Step 1: Detection
        alerts = await self.run_detection()
        
        if not alerts:
            self.logger.warning("No alerts detected, skipping enrichment and scoring")
            return
        
        # Wait a bit for OpenSearch to index
        await asyncio.sleep(2)
        
        # Step 2: Enrichment
        enriched_alerts = await self.run_enrichment()
        
        if not enriched_alerts:
            self.logger.warning("No alerts enriched, skipping scoring")
            return
        
        # Wait a bit for OpenSearch to index
        await asyncio.sleep(2)
        
        # Step 3: Scoring
        scored_alerts = await self.run_scoring()
        
        # Lines 199-205: Pipeline completion summary
        # This logs the final results of the detection pipeline
        self.logger.info("========================================")
        self.logger.info(f"Pipeline Complete!")
        self.logger.info(f"  Detected: {len(alerts)} alerts")
        self.logger.info(f"  Enriched: {len(enriched_alerts)} alerts")
        self.logger.info(f"  Scored: {len(scored_alerts)} alerts")
        self.logger.info("========================================")
        
        return scored_alerts

    async def run_continuous(self, interval: int = 60):
        """Run the pipeline continuously at specified interval"""
        self.logger.info(f"Starting continuous mode (interval: {interval}s)")
        self.logger.info("Press Ctrl+C to stop")
        
        try:
            while True:
                try:
                    await self.run_full_pipeline()
                except Exception as e:
                    self.logger.error(f"Error in pipeline execution: {e}")
                
                self.logger.info(f"Waiting {interval} seconds before next run...")
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            self.logger.info("Continuous mode stopped by user")


def start_all_services(with_dashboards=True):
    """Start OpenSearch, Filebeat, and OpenSearch Dashboards"""
    logger = logging.getLogger("run")
    
    # Paths
    OPENSEARCH_BIN = Path(r"D:\Cusor AI\opensearch-3.3.1-windows-x64\opensearch-3.3.1\bin\opensearch.bat")
    FILEBEAT_EXE = Path(r"D:\Cusor AI\filebeat-9.2.0-windows-x86_64\filebeat-9.2.0-windows-x86_64\filebeat.exe")
    DASHBOARDS_BIN = Path(r"D:\Cusor AI\opensearch-dashboards-3.3.0\bin\opensearch-dashboards.bat")
    
    processes = []
    process_pids = []  # Store PIDs for cleanup
    total_services = 3 if with_dashboards else 2
    
    # Start OpenSearch
    logger.info("=" * 70)
    logger.info("[1/3] Starting OpenSearch...")
    logger.info("=" * 70)
    if OPENSEARCH_BIN.exists():
        try:
            proc = subprocess.Popen(
                [str(OPENSEARCH_BIN)],
                cwd=str(OPENSEARCH_BIN.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(('OpenSearch', proc))
            process_pids.append(proc.pid)
            logger.info("[OK] OpenSearch started")
            logger.info("  Waiting 30 seconds for initialization...")
            time.sleep(30)
            
            # Verify OpenSearch is running
            try:
                import requests
                response = requests.get("http://localhost:9200", timeout=5)
                logger.info(f"[OK] OpenSearch is responding (status: {response.status_code})")
            except Exception as e:
                logger.warning(f"OpenSearch may still be starting: {e}")
        except Exception as e:
            logger.error(f"[X] Failed to start OpenSearch: {e}")
    else:
        logger.error(f"[X] OpenSearch not found at: {OPENSEARCH_BIN}")
    
    # Start Filebeat
    logger.info("")
    logger.info("=" * 70)
    logger.info("[2/3] Starting Filebeat...")
    logger.info("=" * 70)
    if FILEBEAT_EXE.exists():
        try:
            proc = subprocess.Popen(
                [str(FILEBEAT_EXE), "-e"],
                cwd=str(FILEBEAT_EXE.parent),
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            processes.append(('Filebeat', proc))
            process_pids.append(proc.pid)
            logger.info("[OK] Filebeat started")
            logger.info("  Waiting 10 seconds for connection...")
            time.sleep(10)
        except Exception as e:
            logger.error(f"[X] Failed to start Filebeat: {e}")
    else:
        logger.error(f"[X] Filebeat not found at: {FILEBEAT_EXE}")
    
    # Start OpenSearch Dashboards
    if with_dashboards:
        logger.info("")
        logger.info("=" * 70)
        logger.info("[3/3] Starting OpenSearch Dashboards...")
        logger.info("=" * 70)
        if DASHBOARDS_BIN.exists():
            try:
                # Set working directory to OpenSearch Dashboards root (not bin folder)
                dashboards_root = DASHBOARDS_BIN.parent.parent
                node_exe = dashboards_root / "node" / "node.exe"
                cli_js = dashboards_root / "src" / "cli" / "dist.js"
                
                # Start Node.js directly (bypass bat file to avoid path issues)
                if node_exe.exists() and cli_js.exists():
                    proc = subprocess.Popen(
                        [str(node_exe), str(cli_js)],
                        cwd=str(dashboards_root),
                        creationflags=subprocess.CREATE_NEW_CONSOLE,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    processes.append(('OpenSearch Dashboards', proc))
                    process_pids.append(proc.pid)
                    logger.info("[OK] OpenSearch Dashboards started")
                    logger.info("  URL: http://localhost:5601")
                    logger.info("  (Wait 90-120 seconds for it to fully start)")
                else:
                    logger.error(f"[X] Node.js or CLI not found at {dashboards_root}")
            except Exception as e:
                logger.error(f"[X] Failed to start OpenSearch Dashboards: {e}")
        else:
            logger.error(f"[X] OpenSearch Dashboards not found at: {DASHBOARDS_BIN}")
    else:
        logger.info("")
        logger.info("=" * 70)
        logger.info("[3/3] OpenSearch Dashboards - SKIPPED")
        logger.info("=" * 70)
        logger.info("  ThreatOps Dashboard will provide security monitoring")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("[OK] All services started successfully!")
    logger.info("=" * 70)
    logger.info("")
    
    # Store process PIDs globally for cleanup
    start_all_services.process_pids = process_pids
    start_all_services.processes = processes
    
    return processes


def open_dashboard():
    """Open the Streamlit dashboard in browser"""
    logger = logging.getLogger("run")
    dashboard_app = ROOT / "dashboard" / "app.py"
    
    if not dashboard_app.exists():
        logger.error(f"[X] Dashboard app not found at: {dashboard_app}")
        return None
    
    try:
        # Start Streamlit
        venv_python = ROOT / ".venv" / "Scripts" / "python.exe"
        python_exe = str(venv_python) if venv_python.exists() else "python"
        
        proc = subprocess.Popen(
            [python_exe, "-m", "streamlit", "run", str(dashboard_app), "--server.headless", "true"],
            cwd=str(ROOT),
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
        
        # Store Streamlit PID for cleanup
        if not hasattr(open_dashboard, 'process_pids'):
            open_dashboard.process_pids = []
        open_dashboard.process_pids.append(proc.pid)
        
        logger.info("[OK] Dashboard starting...")
        logger.info("  Waiting 5 seconds for Streamlit to start...")
        time.sleep(5)
        
        return proc
    except Exception as e:
        logger.error(f"[X] Failed to open dashboard: {e}")
        return None


def open_all_dashboards():
    """Open ALL three dashboards in browser"""
    logger = logging.getLogger("run")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("Opening all dashboards in browser...")
    logger.info("=" * 70)
    
    dashboards = [
        ("ThreatOps Dashboard", "http://localhost:8501", "Main SIEM interface"),
        ("OpenSearch Dashboards", "http://localhost:5601", "Advanced analytics (no login required)"),
        ("OpenSearch API", "http://localhost:9200", "Backend API & cluster info")
    ]
    
    for name, url, desc in dashboards:
        try:
            logger.info(f"Opening {name}...")
            webbrowser.open(url)
            logger.info(f"  [OK] {url} - {desc}")
            time.sleep(1)  # Small delay between opens
        except Exception as e:
            logger.warning(f"  [!] Could not open {name}: {e}")
    
    logger.info("")
    logger.info("[OK] All dashboards opened!")
    logger.info("=" * 70)
    logger.info("")


def cleanup_all_processes():
    """Kill all background processes started by this script"""
    logger = logging.getLogger("run")
    
    logger.info("")
    logger.info("=" * 70)
    logger.info("Cleaning up all background processes...")
    logger.info("=" * 70)
    
    if psutil is None:
        logger.warning("[!] psutil not installed - using basic cleanup")
        logger.warning("Install with: pip install psutil")
        logger.info("Closing processes by name using Windows commands...")
        
        # Windows command-line cleanup
        import os
        cleanup_commands = [
            "taskkill /F /FI \"WINDOWTITLE eq OpenSearch*\" /T",
            "taskkill /F /FI \"WINDOWTITLE eq Filebeat*\" /T",
            "taskkill /F /FI \"WINDOWTITLE eq OpenSearch Dashboards*\" /T",
            "taskkill /F /FI \"WINDOWTITLE eq ThreatOps Dashboard*\" /T"
        ]
        
        for cmd in cleanup_commands:
            try:
                os.system(cmd + " >nul 2>&1")
            except:
                pass
        
        logger.info("[OK] Cleanup attempted")
        logger.info("=" * 70)
        logger.info("")
        return
    
    all_pids = []
    
    # Get PIDs from services
    if hasattr(start_all_services, 'process_pids'):
        all_pids.extend(start_all_services.process_pids)
    
    # Get Streamlit PID
    if hasattr(open_dashboard, 'process_pids'):
        all_pids.extend(open_dashboard.process_pids)
    
    # Also kill by process name (catch any we missed)
    process_names = ['opensearch', 'filebeat', 'node', 'streamlit', 'python']
    
    killed_count = 0
    for pid in all_pids:
        try:
            process = psutil.Process(pid)
            process.terminate()
            killed_count += 1
            logger.info(f"  [OK] Killed process PID {pid}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Kill by name
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name'].lower()
            if any(name in proc_name for name in process_names):
                # Check if it's from our project
                try:
                    cmdline = ' '.join(proc.cmdline()).lower()
                    if 'threat_ops' in cmdline or 'opensearch' in cmdline or 'filebeat' in cmdline or 'opensearch-dashboards' in cmdline:
                        proc.terminate()
                        killed_count += 1
                        logger.info(f"  [OK] Killed {proc_name} (PID {proc.info['pid']})")
                except:
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    logger.info(f"[OK] Cleaned up {killed_count} processes")
    logger.info("=" * 70)
    logger.info("")


def main(argv: Optional[list[str]] = None) -> int:
    _setup_logging()
    logger = logging.getLogger("run")

    parser = argparse.ArgumentParser(
        description="ThreatOps SIEM Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start everything (OpenSearch, Filebeat, OpenSearch Dashboards, simulation, pipeline, UI)
  python run.py --mode all
  
  # Simulate attacks (writes logs for Filebeat to collect)
  python run.py --mode simulate
  
  # Run detection on logs in OpenSearch
  python run.py --mode detect
  
  # Run full pipeline (detect > enrich > score)
  python run.py --mode pipeline
  
  # Run continuously every 60 seconds
  python run.py --mode continuous --interval 60
  
Note: --mode all now ALWAYS starts OpenSearch Dashboards (no login required)
        """
    )
    
    parser.add_argument(
        "--mode",
        choices=["all", "simulate", "detect", "enrich", "score", "pipeline", "continuous"],
        default="pipeline",
        help="Mode to run (default: pipeline)"
    )
    
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Interval in seconds for continuous mode (default: 60)"
    )
    
    parser.add_argument(
        "--skip-init",
        action="store_true",
        help="Skip initialization and directory creation"
    )
    
    parser.add_argument(
        "--with-dashboards",
        action="store_true",
        help="(Deprecated - OpenSearch Dashboards now starts automatically with --mode all)"
    )
    
    args = parser.parse_args(argv)

    if not args.skip_init:
        create_directories()

    # Create pipeline
    pipeline: Optional[ThreatOpsPipeline] = None

    try:
        # Handle --all mode (start everything)
        if args.mode == "all":
            logger.info("=" * 70)
            logger.info("THREATOPS SIEM - COMPLETE STARTUP")
            logger.info("=" * 70)
            logger.info("")
            
            # Start all services - ALWAYS include OpenSearch Dashboards with --all
            start_all_services(with_dashboards=True)
            
            # Initialize pipeline
            logger.info("")
            logger.info("=" * 70)
            logger.info("[4/7] Initializing ThreatOps Pipeline...")
            logger.info("=" * 70)
            pipeline = ThreatOpsPipeline()
            asyncio.run(pipeline.initialize())
            logger.info("[OK] Pipeline initialized")
            logger.info("")
            
            # Run simulation
            logger.info("")
            logger.info("=" * 70)
            logger.info("[5/7] Running Attack Simulation...")
            logger.info("=" * 70)
            asyncio.run(pipeline.run_simulation())
            logger.info("[OK] Simulation complete")
            logger.info("")
            
            # Wait for Filebeat to collect logs
            logger.info("  Waiting 15 seconds for log indexing...")
            time.sleep(15)
            
            # Run pipeline
            logger.info("")
            logger.info("=" * 70)
            logger.info("[6/7] Running Detection Pipeline...")
            logger.info("=" * 70)
            asyncio.run(pipeline.run_full_pipeline())
            logger.info("[OK] Pipeline complete")
            logger.info("")
            
            # Open Streamlit dashboard
            logger.info("")
            logger.info("=" * 70)
            logger.info("[7/7] Starting ThreatOps Dashboard...")
            logger.info("=" * 70)
            open_dashboard()
            
            # Wait and verify OpenSearch Dashboards is ready
            logger.info("")
            logger.info("Waiting for OpenSearch Dashboards to be ready...")
            logger.info("(This can take 90-120 seconds - checking every 10 seconds)")
            
            dashboards_ready = False
            for attempt in range(12):  # Check for up to 120 seconds (12 x 10s)
                try:
                    import requests
                    response = requests.get("http://localhost:5601", timeout=3, allow_redirects=False)
                    if response.status_code in [200, 302, 401]:  # 401 = needs login (but server is up)
                        dashboards_ready = True
                        logger.info(f"[OK] OpenSearch Dashboards is ready! (attempt {attempt + 1}/12)")
                        break
                except:
                    pass
                
                if attempt < 11:
                    logger.info(f"Waiting... ({attempt + 1}/12)")
                    time.sleep(10)
            
            if not dashboards_ready:
                logger.warning("[!] OpenSearch Dashboards may still be starting - will try to open anyway")
            
            # Open ALL dashboards
            open_all_dashboards()
            
            logger.info("")
            logger.info("=" * 70)
            logger.info("COMPLETE! All systems operational!")
            logger.info("=" * 70)
            logger.info("")
            logger.info("Services running:")
            logger.info("   ThreatOps UI:      http://localhost:8501  <- Your main SIEM dashboard")
            logger.info("   OpenSearch DB:     http://localhost:5601  <- Advanced analytics (no login required)")
            logger.info("   OpenSearch API:    http://localhost:9200  <- Backend (for developers)")
            logger.info("")
            logger.info("Log Sources Active:")
            logger.info("   [*] Simulated attacks (MITRE ATT&CK scenarios)")
            logger.info("   [*] Windows Security logs (real system events)")
            logger.info("   [*] Windows System logs (real system events)")
            logger.info("   [*] Windows Application logs (real system events)")
            logger.info("")
            logger.info("=" * 70)
            logger.info("")
            logger.info("[!] Press Enter to EXIT and close all background services")
            logger.info("=" * 70)
            
            try:
                input()
                # Cleanup all processes
                cleanup_all_processes()
                logger.info("All services stopped. Goodbye!")
            except KeyboardInterrupt:
                cleanup_all_processes()
                logger.info("All services stopped. Goodbye!")
            
            return 0
        
        # Standard modes
        logger.info("=" * 60)
        logger.info("ThreatOps SIEM Pipeline")
        logger.info("=" * 60)
        
        pipeline = ThreatOpsPipeline()
        asyncio.run(pipeline.initialize())
        
        if args.mode == "simulate":
            logger.info("Mode: Attack Simulation")
            asyncio.run(pipeline.run_simulation())
            
        elif args.mode == "detect":
            logger.info("Mode: Threat Detection")
            asyncio.run(pipeline.run_detection())
            
        elif args.mode == "enrich":
            logger.info("Mode: Threat Intelligence Enrichment")
            asyncio.run(pipeline.run_enrichment())
            
        elif args.mode == "score":
            logger.info("Mode: Risk Scoring")
            asyncio.run(pipeline.run_scoring())
            
        elif args.mode == "pipeline":
            logger.info("Mode: Full Pipeline")
            asyncio.run(pipeline.run_full_pipeline())
            
        elif args.mode == "continuous":
            logger.info(f"Mode: Continuous (interval: {args.interval}s)")
            asyncio.run(pipeline.run_continuous(args.interval))

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as exc:
        logger.exception(f"Fatal error: {exc}")
        return 2

    logger.info("=" * 60)
    logger.info("Run completed successfully")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
