"""System test moved into tests/ and simplified to call setup.run_simulation_sync()
"""

import sys
from pathlib import Path

# Ensure project root is on path (parent of tests/)
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from pathlib import Path as _Path

def main():
    print("ThreatOps - System Test (tests/test_system.py)")
    print("=" * 50)

    try:
        from setup import run_simulation_sync

        print("Running full SOC simulation via setup.run_simulation_sync()...")
        result = run_simulation_sync()
        if result is None:
            print("❌ Full simulation failed via setup.run_simulation_sync()")
            return 1

        alerts = result.get("alerts", [])
        simulated = result.get("simulated", [])
        report = result.get("report")

        print("\nTest Summary:")
        print(f"  • Alerts processed: {len(alerts)}")
        print(f"  • Simulation logs: {len(simulated)}")
        if report:
            print(f"  • Report generated: {_Path(report).name}")

        print("\n✅ Full simulation executed via setup successfully!")
        return 0

    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
