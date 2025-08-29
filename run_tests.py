#!/usr/bin/env python3
"""
Test runner for PY-Framework
Provides different test execution modes and reporting
"""

import sys
import subprocess
import argparse
import time
from pathlib import Path


def run_command(cmd, description):
    """Run a command and capture output"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print('='*60)
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            cwd=Path(__file__).parent
        )
        
        duration = time.time() - start_time
        
        print(f"Exit code: {result.returncode}")
        print(f"Duration: {duration:.2f}s")
        
        if result.stdout:
            print("\nSTDOUT:")
            print(result.stdout)
        
        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)
        
        return result.returncode == 0, duration
        
    except Exception as e:
        print(f"Error running command: {e}")
        return False, 0


def run_unit_tests():
    """Run unit tests only"""
    cmd = [
        "uv", "run", "pytest", 
        "tests/",
        "-v",
        "-m", "not slow and not integration and not performance",
        "--tb=short"
    ]
    return run_command(cmd, "Unit Tests")


def run_integration_tests():
    """Run integration tests"""
    cmd = [
        "uv", "run", "pytest", 
        "tests/test_integration_complete.py",
        "-v",
        "-m", "integration",
        "--tb=short"
    ]
    return run_command(cmd, "Integration Tests")


def run_security_tests():
    """Run security tests"""
    cmd = [
        "uv", "run", "pytest", 
        "tests/test_security_comprehensive.py",
        "-v",
        "-m", "security",
        "--tb=short"
    ]
    return run_command(cmd, "Security Tests")


def run_performance_tests():
    """Run performance tests"""
    cmd = [
        "uv", "run", "pytest", 
        "tests/test_performance.py",
        "-v",
        "-m", "performance",
        "--tb=short",
        "-s"  # Don't capture output for performance metrics
    ]
    return run_command(cmd, "Performance Tests")


def run_all_tests():
    """Run all tests"""
    cmd = [
        "uv", "run", "pytest", 
        "tests/",
        "-v",
        "--tb=short"
    ]
    return run_command(cmd, "All Tests")


def run_coverage_tests():
    """Run tests with coverage report"""
    # Try to run with coverage if plugin is available; otherwise fallback
    has_cov = subprocess.run(
        ["uv", "run", "python", "-c", "import pytest_cov"], capture_output=True
    ).returncode == 0

    if has_cov:
        cmd = [
            "uv", "run", "pytest",
            "tests/",
            "--cov=src/framework",
            "--cov-report=term-missing",
            "-v",
        ]
        return run_command(cmd, "Coverage Tests (with pytest-cov)")
    else:
        cmd = [
            "uv", "run", "pytest",
            "tests/",
            "-v",
        ]
        return run_command(cmd, "Tests (pytest-cov not available)")


def run_specific_test(test_pattern):
    """Run specific test by pattern"""
    cmd = [
        "uv", "run", "pytest", 
        "-v",
        "-k", test_pattern,
        "--tb=short"
    ]
    return run_command(cmd, f"Specific Tests (pattern: {test_pattern})")


def run_linting():
    """Run code linting"""
    print("\n" + "="*60)
    print("Running Code Quality Checks")
    print("="*60)
    
    success = True
    
    # Run black check
    black_cmd = ["uv", "run", "black", "--check", "src/", "tests/"]
    black_success, _ = run_command(black_cmd, "Black Code Formatting Check")
    success = success and black_success
    
    # Run ruff check
    ruff_cmd = ["uv", "run", "ruff", "check", "src/", "tests/"]
    ruff_success, _ = run_command(ruff_cmd, "Ruff Linting Check")
    success = success and ruff_success
    
    return success


def main():
    parser = argparse.ArgumentParser(description="PY-Framework Test Runner")
    parser.add_argument(
        "test_type", 
        choices=[
            "unit", "integration", "security", "performance", 
            "all", "coverage", "lint", "quick"
        ],
        help="Type of tests to run"
    )
    parser.add_argument(
        "-k", "--pattern", 
        help="Run specific tests matching pattern"
    )
    parser.add_argument(
        "--no-lint", 
        action="store_true",
        help="Skip linting when running 'all' tests"
    )
    
    args = parser.parse_args()
    
    print("PY-Framework Test Runner")
    print("=" * 50)
    print(f"Test type: {args.test_type}")
    if args.pattern:
        print(f"Pattern: {args.pattern}")
    print()
    
    total_start_time = time.time()
    
    if args.pattern:
        success, duration = run_specific_test(args.pattern)
    elif args.test_type == "unit":
        success, duration = run_unit_tests()
    elif args.test_type == "integration":
        success, duration = run_integration_tests()
    elif args.test_type == "security":
        success, duration = run_security_tests()
    elif args.test_type == "performance":
        success, duration = run_performance_tests()
    elif args.test_type == "coverage":
        success, duration = run_coverage_tests()
    elif args.test_type == "lint":
        success = run_linting()
        duration = 0
    elif args.test_type == "quick":
        # Run unit tests + linting
        unit_success, unit_duration = run_unit_tests()
        lint_success = run_linting() if not args.no_lint else True
        success = unit_success and lint_success
        duration = unit_duration
    elif args.test_type == "all":
        # Run all test types
        results = []
        
        # Unit tests
        unit_success, unit_duration = run_unit_tests()
        results.append(("Unit Tests", unit_success, unit_duration))
        
        # Integration tests
        int_success, int_duration = run_integration_tests()
        results.append(("Integration Tests", int_success, int_duration))
        
        # Security tests
        sec_success, sec_duration = run_security_tests()
        results.append(("Security Tests", sec_success, sec_duration))
        
        # Performance tests
        perf_success, perf_duration = run_performance_tests()
        results.append(("Performance Tests", perf_success, perf_duration))
        
        # Linting
        if not args.no_lint:
            lint_success = run_linting()
            results.append(("Linting", lint_success, 0))
        else:
            lint_success = True
        
        # Summary
        total_duration = time.time() - total_start_time
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        
        all_success = True
        for test_name, test_success, test_duration in results:
            status = "PASS" if test_success else "FAIL"
            print(f"{test_name:20} {status:>8} ({test_duration:.1f}s)")
            all_success = all_success and test_success
        
        print("-" * 60)
        print(f"{'Overall':20} {'PASS' if all_success else 'FAIL':>8} ({total_duration:.1f}s)")
        
        success = all_success
        duration = total_duration
    
    total_duration = time.time() - total_start_time
    
    print("\n" + "="*60)
    print("FINAL RESULT")
    print("="*60)
    print(f"Status: {'SUCCESS' if success else 'FAILURE'}")
    print(f"Total Duration: {total_duration:.2f}s")
    
    if not success:
        print("\nSome tests failed. Please review the output above.")
        sys.exit(1)
    else:
        print("\nAll tests passed successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
