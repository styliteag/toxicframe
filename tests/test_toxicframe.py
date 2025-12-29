#!/usr/bin/env python3
"""
Test script to find the minimal packet size that triggers the toxicframe bug.

Generates test files with the toxic pattern in varying sizes, uploads them
to the SG-2100, and tests each file 10 times to find:
- Smallest packet that triggers the bug
- Packets that sometimes get dropped (intermittent failures)
"""

import subprocess
import hashlib
import os
import sys
import time
import socket
import urllib.request
import urllib.error
import argparse
from pathlib import Path
from typing import List, Tuple, Dict
from dataclasses import dataclass
from datetime import datetime

# Import common modules
from test_config import (
    TOXIC_PATTERN, PATTERN_LEN,
    SCP_HOST, SCP_PORT, SCP_DEST, HTTP_BASE_URL,
    TEST_ITERATIONS, TEST_DIR
)


@dataclass
class TestResult:
    """Result of testing a single file."""
    filename: str
    size: int
    pattern_repeats: int
    hash: str
    successes: int
    failures: int
    success_rate: float
    is_toxic: bool  # True if always fails (0% success), False if always succeeds (100% success), None if intermittent


def generate_test_file(size_bytes: int, pattern_repeats: int, padding: bytes = b'\x00') -> bytes:
    """
    Generate a test file with the toxic pattern repeated.
    
    Args:
        size_bytes: Target size in bytes
        pattern_repeats: Number of times to repeat the pattern
        padding: Bytes to use for padding if size_bytes > pattern_repeats * PATTERN_LEN
    
    Returns:
        bytes: Generated test file content
    """
    content = TOXIC_PATTERN * pattern_repeats
    
    # Pad to exact size if needed
    if len(content) < size_bytes:
        content += padding * (size_bytes - len(content))
    elif len(content) > size_bytes:
        content = content[:size_bytes]
    
    return content


def calculate_file_hash(content: bytes) -> str:
    """Calculate SHA256 hash of file content."""
    return hashlib.sha256(content).hexdigest()[:16]  # Use first 16 chars for filename


# Import common test functions
from test_common import (
    upload_test_file,
    test_download_file
)

def upload_file(local_path: Path, remote_filename: str, scp_host: str = None, scp_port: int = None) -> bool:
    """
    Upload file to SG-2100 via SCP.
    
    Returns:
        bool: True if upload succeeded
    """
    data = local_path.read_bytes()
    return upload_test_file(data, remote_filename)

def test_download(filename: str, expected_size: int, http_url: str = None, timeout: int = 5) -> bool:
    """
    Test downloading the file via HTTP.
    
    Args:
        filename: Name of the file to download
        expected_size: Expected file size in bytes
        http_url: HTTP base URL
        timeout: Request timeout in seconds (default 5 - short timeout to quickly detect hangs)
    
    Returns:
        bool: True if download succeeded (got full file), False if failed
    """
    return test_download_file(filename, expected_size, http_url, timeout)


def test_file(filename: str, expected_size: int, http_url: str = None, iterations: int = None) -> Tuple[int, int]:
    """
    Test a file multiple times and return success/failure counts.
    
    Returns:
        Tuple[int, int]: (successes, failures)
    """
    http_url = http_url or HTTP_BASE_URL
    iterations = iterations or TEST_ITERATIONS
    
    successes = 0
    failures = 0
    
    print(f"    Testing {iterations} times...", end=" ", flush=True)
    
    for i in range(iterations):
        success = test_download(filename, expected_size, http_url)
        if success:
            successes += 1
            print("✓", end="", flush=True)
        else:
            failures += 1
            print("✗", end="", flush=True)
        time.sleep(0.5)  # Small delay between tests
    
    print(f" ({successes}/{iterations})")
    return successes, failures


def generate_initial_test_cases() -> List[Tuple[int, int]]:
    """
    Generate initial test cases: start with 39 repetitions, then decrease by 14 bytes.
    
    Returns:
        List of (size_bytes, pattern_repeats) tuples, sorted descending by size
    """
    test_cases = []
    
    # Start with 39 repetitions and work down by 14 bytes (one pattern) at a time
    for repeats in range(39, 0, -1):
        size = repeats * PATTERN_LEN
        test_cases.append((size, repeats))
    
    return test_cases


def generate_fine_grained_tests(boundary_size: int) -> List[Tuple[int, int]]:
    """
    Generate 1-byte step tests around a boundary.
    
    Args:
        boundary_size: Size where transition was detected
    
    Returns:
        List of (size_bytes, pattern_repeats) tuples for fine-grained testing
    """
    test_cases = []
    
    # Test 1-byte steps around the boundary (13 bytes before and after)
    for offset in range(-13, 14):
        test_size = boundary_size + offset
        if test_size > 0:
            # Calculate how many full patterns fit
            pattern_repeats = test_size // PATTERN_LEN
            test_cases.append((test_size, pattern_repeats))
    
    # Remove duplicates and sort
    test_cases = list(set(test_cases))
    test_cases.sort(key=lambda x: x[0], reverse=True)
    
    return test_cases


def run_tests(scp_host: str = None, scp_port: int = None, http_url: str = None, iterations: int = None) -> List[TestResult]:
    """Run all tests adaptively and return results."""
    # Use provided values or fall back to globals
    scp_host = scp_host or SCP_HOST
    scp_port = scp_port or SCP_PORT
    http_url = http_url or HTTP_BASE_URL
    iterations = iterations or TEST_ITERATIONS
    
    results = []
    
    # Track state to detect transitions
    last_result_toxic = None  # None = not tested yet, True = toxic, False = safe
    transition_detected = False  # Track if we've already done fine-grained testing
    
    print(f"Testing on {scp_host}:{scp_port}")
    print(f"HTTP base URL: {http_url}")
    print(f"Test iterations per file: {iterations}")
    print("Strategy: Start with 39 repetitions, decrease by 14 bytes, then 1-byte steps when transition detected")
    print("-" * 80)
    
    # Start with initial test cases (39, 38, 37, ... repetitions)
    test_cases = generate_initial_test_cases()
    test_queue = list(test_cases)  # Queue of tests to run
    tested_sizes = set()  # Track which sizes we've already tested
    
    test_idx = 0
    while test_queue:
        size_bytes, pattern_repeats = test_queue.pop(0)
        
        # Skip if already tested
        if size_bytes in tested_sizes:
            continue
        
        test_idx += 1
        print(f"\n[{test_idx}] Testing size={size_bytes} bytes, pattern_repeats={pattern_repeats}")
        
        # Generate test file
        content = generate_test_file(size_bytes, pattern_repeats)
        file_hash = calculate_file_hash(content)
        filename = f"toxic-{file_hash}"
        local_path = TEST_DIR / filename
        
        # Write local file
        local_path.write_bytes(content)
        
        # Upload to SG-2100
        print(f"  Uploading {filename} ({size_bytes} bytes)...", end=" ", flush=True)
        if not upload_file(local_path, filename, scp_host, scp_port):
            print("FAILED - skipping test")
            local_path.unlink()  # Clean up
            continue
        print("OK")
        
        # Wait a bit for file to be available
        time.sleep(1)
        
        # Test download
        successes, failures = test_file(filename, size_bytes, http_url, iterations)
        success_rate = successes / iterations if iterations > 0 else 0
        
        # Determine if toxic (always fails), safe (always succeeds), or intermittent
        is_toxic = None
        if success_rate == 0.0:
            is_toxic = True
        elif success_rate == 1.0:
            is_toxic = False
        
        result = TestResult(
            filename=filename,
            size=size_bytes,
            pattern_repeats=pattern_repeats,
            hash=file_hash,
            successes=successes,
            failures=failures,
            success_rate=success_rate,
            is_toxic=is_toxic
        )
        results.append(result)
        tested_sizes.add(size_bytes)
        
        # Detect transition: if result is toxic (fails) and previous was safe (succeeds)
        # or vice versa, add fine-grained tests around this boundary
        current_toxic = (success_rate == 0.0)  # True if always fails
        
        if last_result_toxic is not None and not transition_detected:
            if last_result_toxic != current_toxic:
                # Transition detected! Add fine-grained tests
                print(f"\n  🔍 Transition detected at {size_bytes} bytes!")
                print(f"     Previous: {'TOXIC' if last_result_toxic else 'SAFE'}, Current: {'TOXIC' if current_toxic else 'SAFE'}")
                print(f"     Adding 1-byte step tests around boundary...")
                
                fine_tests = generate_fine_grained_tests(size_bytes)
                # Add to front of queue (test larger sizes first)
                for test_case in reversed(fine_tests):
                    if test_case[0] not in tested_sizes:
                        test_queue.insert(0, test_case)
                
                transition_detected = True
        
        last_result_toxic = current_toxic
        
        # Clean up local file
        local_path.unlink()
        
        # Small delay between test cases
        time.sleep(0.5)
    
    return results


def generate_report(results: List[TestResult], iterations: int = None) -> str:
    """Generate a detailed test report."""
    iterations = iterations or TEST_ITERATIONS
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("TOXICFRAME TEST REPORT")
    report_lines.append("=" * 80)
    report_lines.append(f"Generated: {datetime.now().isoformat()}")
    report_lines.append(f"Total test cases: {len(results)}")
    report_lines.append(f"Test iterations per file: {iterations}")
    report_lines.append("")
    
    # Summary statistics
    always_fail = [r for r in results if r.success_rate == 0.0]
    always_succeed = [r for r in results if r.success_rate == 1.0]
    intermittent = [r for r in results if 0.0 < r.success_rate < 1.0]
    
    report_lines.append("SUMMARY")
    report_lines.append("-" * 80)
    report_lines.append(f"Always fail (toxic):     {len(always_fail):4d} files")
    report_lines.append(f"Always succeed (safe):  {len(always_succeed):4d} files")
    report_lines.append(f"Intermittent failures:  {len(intermittent):4d} files")
    report_lines.append("")
    
    # Smallest toxic packet
    if always_fail:
        smallest_toxic = min(always_fail, key=lambda x: x.size)
        report_lines.append("SMALLEST TOXIC PACKET")
        report_lines.append("-" * 80)
        report_lines.append(f"Size: {smallest_toxic.size} bytes")
        report_lines.append(f"Pattern repeats: {smallest_toxic.pattern_repeats}")
        report_lines.append(f"Filename: {smallest_toxic.filename}")
        report_lines.append(f"Success rate: {smallest_toxic.success_rate:.1%} ({smallest_toxic.successes}/{iterations})")
        report_lines.append("")
    
    # Intermittent failures
    if intermittent:
        report_lines.append("INTERMITTENT FAILURES (sometimes dropped)")
        report_lines.append("-" * 80)
        # Sort by success rate (lowest first)
        intermittent_sorted = sorted(intermittent, key=lambda x: (x.success_rate, x.size))
        for r in intermittent_sorted[:20]:  # Top 20
            report_lines.append(
                f"Size: {r.size:4d} bytes | Pattern: {r.pattern_repeats:2d} repeats | "
                f"Success: {r.success_rate:5.1%} ({r.successes:2d}/{iterations}) | "
                f"File: {r.filename}"
            )
        if len(intermittent) > 20:
            report_lines.append(f"... and {len(intermittent) - 20} more")
        report_lines.append("")
    
    # Detailed results table
    report_lines.append("DETAILED RESULTS")
    report_lines.append("-" * 80)
    report_lines.append(f"{'Size':>6} | {'Pattern':>7} | {'Success':>7} | {'Status':<12} | {'Filename'}")
    report_lines.append("-" * 80)
    
    # Sort by size
    results_sorted = sorted(results, key=lambda x: (x.size, x.pattern_repeats))
    for r in results_sorted:
        if r.success_rate == 0.0:
            status = "TOXIC"
        elif r.success_rate == 1.0:
            status = "SAFE"
        else:
            status = f"INTERMITTENT"
        
        report_lines.append(
            f"{r.size:6d} | {r.pattern_repeats:7d} | {r.success_rate:6.1%} | {status:<12} | {r.filename}"
        )
    
    report_lines.append("")
    report_lines.append("=" * 80)
    
    return "\n".join(report_lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test script to find minimal packet size that triggers toxicframe bug"
    )
    parser.add_argument(
        "--host", default=SCP_HOST.split("@")[1] if "@" in SCP_HOST else "10.25.0.1",
        help="SG-2100 hostname or IP (default: 10.25.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=SCP_PORT,
        help=f"SSH/SCP port (default: {SCP_PORT})"
    )
    parser.add_argument(
        "--user", default="root",
        help="SSH username (default: root)"
    )
    parser.add_argument(
        "--iterations", type=int, default=TEST_ITERATIONS,
        help=f"Number of test iterations per file (default: {TEST_ITERATIONS})"
    )
    parser.add_argument(
        "--http-url", default=None,
        help="HTTP base URL (default: http://<host>:8080)"
    )
    parser.add_argument(
        "--http-port", type=int, default=8080,
        help="HTTP port (default: 8080)"
    )
    
    args = parser.parse_args()
    
    # Prepare config
    scp_host = f"{args.user}@{args.host}"
    scp_port = args.port
    iterations = args.iterations
    http_url = args.http_url or f"http://{args.host}:{args.http_port}"
    
    print("Toxicframe Test Script")
    print("=" * 80)
    print(f"Target: {scp_host}:{scp_port}")
    print(f"HTTP URL: {http_url}")
    print(f"Iterations per file: {iterations}")
    print("=" * 80)
    
    try:
        results = run_tests(scp_host=scp_host, scp_port=scp_port, http_url=http_url, iterations=iterations)
        
        # Generate report
        report = generate_report(results, iterations=iterations)
        
        # Save report
        report_path = TEST_DIR / f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path.write_text(report)
        
        # Print report
        print("\n" + report)
        print(f"\nReport saved to: {report_path}")
        
        return 0
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

