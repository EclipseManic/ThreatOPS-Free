#!/usr/bin/env python3
"""
Canonical startup entrypoint for ThreatOps.

This is the single, non-minimal entrypoint the project should expose.
It sets up logging (UTF-8 safe on Windows), creates required directories,
offers optional dependency installation, and can run modes:
  - simulation: run the SOC simulation once
  - dashboard: start the Streamlit dashboard (blocking)
  - test: run the test suite (uses pytest if available)
  - all: run simulation, tests and dashboard (in that order)

The implementation avoids expensive imports at module import time and
performs lazy imports inside functions so the script is resilient when
running in partial setups.

Usage examples:
  python run.py --mode simulation
  python run.py --mode dashboard
  python run.py --mode test
  python run.py --install-deps --mode all

"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import io
import subprocess
import os
from pathlib import Path
from typing import Optional

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


class ThreatOpsSOC:
    """Programmatic SOC runner (constructs components from the package).

    This replicates the previous `main.py` assembled SOC but keeps the
    orchestration here so `run.py` is the single canonical entrypoint.
    """

    def __init__(self):
        # Lazy imports so running `run.py --mode test` or `--install-deps`
        # doesn't fail early if optional deps are missing.
        from config.settings import Settings
        from collectors.log_collector import LogCollector
        from detection.threat_detector import ThreatDetector
        from enrichment.intel_enricher import IntelEnricher
        from simulation.attack_simulator import AttackSimulator
        from scoring.risk_scorer import RiskScorer
        from dashboard.app import SOCDashboard
        from reporting.report_generator import ReportGenerator

        self.settings = Settings()
        self.log_collector = LogCollector(self.settings)
        self.threat_detector = ThreatDetector(self.settings)
        self.intel_enricher = IntelEnricher(self.settings)
        self.attack_simulator = AttackSimulator(self.settings)
        self.risk_scorer = RiskScorer(self.settings)
        self.dashboard_app = SOCDashboard()
        self.report_generator = ReportGenerator(self.settings)
        self.logger = logging.getLogger("run")

    async def initialize(self) -> None:
        self.logger.info("Initializing ThreatOps SOC components...")
        await self.log_collector.initialize()
        await self.threat_detector.initialize()
        await self.intel_enricher.initialize()
        await self.attack_simulator.initialize()
        await self.risk_scorer.initialize()
        await self.report_generator.initialize()
        self.logger.info("Initialization complete")

    async def run_collection_cycle(self):
        self.logger.info("Running collection cycle")
        
        # Collect logs from all sources
        logs = await self.log_collector.collect_logs()
        self.logger.info(f"Collected {len(logs)} log entries")
        
        if not logs:
            self.logger.warning("No logs collected. Make sure log files exist or run simulation mode.")
            return []
        
        # Save collected logs
        await self.log_collector.save_logs(logs, "collected_logs.json")
        
        # Detect threats
        alerts = await self.threat_detector.analyze_logs(logs)
        self.logger.info(f"Detected {len(alerts)} alerts")
        
        # Enrich with threat intelligence
        enriched = await self.intel_enricher.enrich_alerts(alerts)
        self.logger.info(f"Enriched {len(enriched)} alerts")
        
        # Score risks
        scored = await self.risk_scorer.score_alerts(enriched)
        self.logger.info(f"Scored {len(scored)} alerts")
        
        # Save alerts to disk
        if scored:
            from pathlib import Path
            import json
            from datetime import datetime
            
            alerts_dir = Path(self.settings.alerts_dir)
            alerts_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            alert_file = alerts_dir / f"alerts_{timestamp}.json"
            
            with open(alert_file, 'w') as f:
                for alert in scored:
                    f.write(json.dumps(alert.to_dict()) + '\n')
            
            self.logger.info(f"Saved {len(scored)} alerts to {alert_file}")
        
        return scored

    async def run_simulation(self):
        self.logger.info("Running attack simulation")
        sim_logs = await self.attack_simulator.generate_attack_logs()
        self.logger.info(f"Generated {len(sim_logs)} simulated log entries")
        
        # Save simulated logs to logs directory
        await self.log_collector.save_logs(sim_logs, "simulated_logs.json")
        
        # Save scenario-specific logs to simulations directory
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        await self.attack_simulator.save_simulation_logs(sim_logs, f"all_scenarios_{timestamp}")
        
        # Detect threats
        alerts = await self.threat_detector.analyze_logs(sim_logs)
        self.logger.info(f"Detected {len(alerts)} alerts")
        
        # Enrich with threat intelligence
        enriched = await self.intel_enricher.enrich_alerts(alerts)
        self.logger.info(f"Enriched {len(enriched)} alerts with threat intelligence")
        
        # Score risks
        scored = await self.risk_scorer.score_alerts(enriched)
        self.logger.info(f"Scored {len(scored)} alerts with risk scores")
        
        # Save alerts to disk
        if scored:
            from pathlib import Path
            import json
            from datetime import datetime
            
            alerts_dir = Path(self.settings.alerts_dir)
            alerts_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            alert_file = alerts_dir / f"alerts_{timestamp}.json"
            
            with open(alert_file, 'w') as f:
                for alert in scored:
                    f.write(json.dumps(alert.to_dict()) + '\n')
            
            self.logger.info(f"Saved {len(scored)} alerts to {alert_file}")
        
        return scored

    async def generate_report(self):
        self.logger.info("Generating report")
        path = await self.report_generator.generate_daily_report()
        return path

    def start_dashboard(self):
        self.logger.info("Starting dashboard (blocking)")
        # Dashboard run method is expected to block until stopped when executed
        # inside the Streamlit runtime. If this script was invoked with plain
        # `python run.py` we spawn the Streamlit runner which will start the
        # HTTP server and re-run this script under Streamlit (with the same
        # --mode argument). This avoids calling Streamlit UI functions in
        # bare mode (which emit "missing ScriptRunContext" warnings).

        # If we're executing inside a Streamlit server process, run the dashboard
        # directly. Otherwise, spawn a Streamlit process that runs a small
        # wrapper script which imports and runs the dashboard. Using a small
        # wrapper avoids re-running this whole entrypoint (and prevents spawn
        # loops).
        try:
            import streamlit as st  # type: ignore
            # If Streamlit provides a ScriptRunContext, we are already under
            # the Streamlit runner (safe to call st.* APIs).
            try:
                from streamlit.runtime.scriptrunner.script_run_context import get_script_run_ctx
                if get_script_run_ctx() is not None:
                    self.dashboard_app.run()
                    return 0
            except Exception:
                # If we can't introspect the runtime, fall through to spawning
                # the Streamlit CLI so the app is served correctly.
                pass
        except Exception:
            # streamlit not importable in this process — we'll spawn the CLI
            # which will import streamlit in the child process.
            pass

        wrapper = ROOT / "run_streamlit.py"
        cmd = [sys.executable, "-m", "streamlit", "run", str(wrapper), "--", "--mode", "dashboard"]
        self.logger.info("Spawning Streamlit to serve the dashboard: %s", " ".join(cmd))
        return subprocess.run(cmd).returncode


def _install_dependencies(requirements: Path = ROOT / "requirements.txt") -> int:
    """Install dependencies using pip and the current Python interpreter.

    Returns the pip exit code.
    """
    if not requirements.exists():
        print(f"Requirements file not found: {requirements}")
        return 1

    cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements)]
    return subprocess.run(cmd).returncode


def _run_pytest() -> int:
    """Run the test suite using the active Python interpreter and pytest (if available)."""
    # Prefer running pytest as a module so it's resolved from the active env
    cmd = [sys.executable, "-m", "pytest", "-q"]
    return subprocess.run(cmd).returncode


def main(argv: Optional[list[str]] = None) -> int:
    _setup_logging()
    logger = logging.getLogger("run")

    parser = argparse.ArgumentParser(description="ThreatOps single entrypoint")
    parser.add_argument("--mode", choices=["simulation", "dashboard", "test", "all"], default="all")
    parser.add_argument("--install-deps", action="store_true", help="Install dependencies from requirements.txt before running")
    parser.add_argument("--skip-checks", action="store_true", help="Skip pre-flight checks and directory creation")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests when mode includes test/all")
    args = parser.parse_args(argv)

    if not args.skip_checks:
        create_directories()

    if args.install_deps:
        logger.info("Installing dependencies from requirements.txt (this may take a while)")
        code = _install_dependencies()
        if code != 0:
            logger.error("Dependency installation failed")
            return code

    # Lazy create SOC only when needed
    soc: Optional[ThreatOpsSOC] = None

    try:
        if args.mode in ("simulation", "all"):
            logger.info("Mode: simulation")
            soc = ThreatOpsSOC()
            asyncio.run(soc.initialize())
            scored = asyncio.run(soc.run_simulation())
            logger.info(f"Simulation produced {len(scored)} scored alerts")
            
            # Generate a report after simulation
            if scored:
                logger.info("Generating report for simulated threats...")
                report_path = asyncio.run(soc.generate_report())
                logger.info(f"Report generated at: {report_path}")

        if args.mode in ("test", "all") and not args.skip_tests:
            logger.info("Mode: test — running pytest")
            rc = _run_pytest()
            if rc != 0:
                logger.error("Tests failed")
                return rc

        if args.mode in ("dashboard", "all"):
            logger.info("Mode: dashboard")
            if soc is None:
                soc = ThreatOpsSOC()
                # initialize only the non-blocking components
                asyncio.run(soc.initialize())
            # start dashboard (blocks until stopped)
            soc.start_dashboard()

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        return 130
    except Exception as exc:
        logger.exception(f"Fatal error while running: {exc}")
        return 2

    logger.info("Run completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
