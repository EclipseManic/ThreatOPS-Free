#!/usr/bin/env python3
"""
ThreatOps SIEM - Test Runner
Run all tests or specific test suites
"""

import sys
import subprocess
from pathlib import Path


def run_all_tests():
    """Run all tests with coverage"""
    print("🧪 Running all ThreatOps SIEM tests...\n")
    
    cmd = [
        sys.executable, "-m", "pytest",
        "-v",  # Verbose
        "--tb=short",  # Short traceback format
        "--color=yes",  # Colored output
        str(Path(__file__).parent)  # Test directory
    ]
    
    return subprocess.call(cmd)


def run_unit_tests():
    """Run only unit tests"""
    print("🧪 Running unit tests...\n")
    
    cmd = [
        sys.executable, "-m", "pytest",
        "-v",
        "-m", "unit",
        str(Path(__file__).parent)
    ]
    
    return subprocess.call(cmd)


def run_integration_tests():
    """Run only integration tests"""
    print("🧪 Running integration tests...\n")
    
    cmd = [
        sys.executable, "-m", "pytest",
        "-v",
        "-m", "integration",
        str(Path(__file__).parent / "test_integration.py")
    ]
    
    return subprocess.call(cmd)


def run_specific_test(test_file):
    """Run a specific test file"""
    print(f"🧪 Running {test_file}...\n")
    
    cmd = [
        sys.executable, "-m", "pytest",
        "-v",
        str(Path(__file__).parent / test_file)
    ]
    
    return subprocess.call(cmd)


def run_with_coverage():
    """Run tests with coverage report"""
    print("🧪 Running tests with coverage analysis...\n")
    
    cmd = [
        sys.executable, "-m", "pytest",
        "-v",
        "--cov=../",  # Coverage for parent directory
        "--cov-report=term-missing",  # Show missing lines
        "--cov-report=html",  # Generate HTML report
        str(Path(__file__).parent)
    ]
    
    return subprocess.call(cmd)


def main():
    """Main test runner"""
    if len(sys.argv) < 2:
        # Default: run all tests
        return run_all_tests()
    
    command = sys.argv[1].lower()
    
    if command == "all":
        return run_all_tests()
    elif command == "unit":
        return run_unit_tests()
    elif command == "integration":
        return run_integration_tests()
    elif command == "coverage":
        return run_with_coverage()
    elif command.startswith("test_"):
        return run_specific_test(command + ".py" if not command.endswith(".py") else command)
    else:
        print(f"❌ Unknown command: {command}")
        print("\nUsage:")
        print("  python run_tests.py [all|unit|integration|coverage|test_file]")
        print("\nExamples:")
        print("  python run_tests.py                    # Run all tests")
        print("  python run_tests.py all                # Run all tests")
        print("  python run_tests.py unit               # Run unit tests only")
        print("  python run_tests.py integration        # Run integration tests")
        print("  python run_tests.py coverage           # Run with coverage")
        print("  python run_tests.py test_core_detection  # Run specific test file")
        return 1


if __name__ == "__main__":
    sys.exit(main())

