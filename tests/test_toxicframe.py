#!/usr/bin/env python3
"""
Test script to find minimal packet size that triggers the toxicframe bug.
Uses raw Ethernet packets via packetgen API.
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import List

from config import TOXIC_PATTERN, PATTERN_LEN, TEST_ITERATIONS, TEST_DIR
from test_common import test_payload, classify_result, get_sender, get_receiver, cleanup


@dataclass
class TestResult:
    """Result of testing a single payload."""
    size: int
    pattern_repeats: int
    successes: int
    failures: int
    success_rate: float
    is_toxic: bool  # None if intermittent


def generate_test_file(size_bytes: int, pattern_repeats: int) -> bytes:
    """Generate test data with toxic pattern repeated."""
    content = TOXIC_PATTERN * pattern_repeats
    if len(content) < size_bytes:
        content += b'\x00' * (size_bytes - len(content))
    return content[:size_bytes]


def run_tests(iterations: int = TEST_ITERATIONS) -> List[TestResult]:
    """Run all tests adaptively."""
    results = []
    last_toxic = None
    transition_done = False
    
    # Initial test cases: 39 down to 1 repetitions
    test_queue = [(r * PATTERN_LEN, r) for r in range(39, 0, -1)]
    tested = set()
    
    print(f"Testing with {iterations} iterations per size")
    print("-" * 60)
    
    idx = 0
    while test_queue:
        size, repeats = test_queue.pop(0)
        if size in tested:
            continue
        
        idx += 1
        print(f"[{idx}] Size {size} ({repeats} repeats)...", end=" ", flush=True)
        
        data = generate_test_file(size, repeats)
        successes, failures = test_payload(data, iterations)
        rate = successes / iterations
        
        is_toxic = None
        if rate == 0:
            is_toxic = True
        elif rate == 1:
            is_toxic = False
        
        status = classify_result(successes, iterations)
        print(f"{status} ({successes}/{iterations})")
        
        results.append(TestResult(size, repeats, successes, failures, rate, is_toxic))
        tested.add(size)
        
        # Detect transition, add fine-grained tests
        current_toxic = (rate == 0)
        if last_toxic is not None and last_toxic != current_toxic and not transition_done:
            print(f"  Transition detected! Adding 1-byte tests...")
            for offset in range(-13, 14):
                test_size = size + offset
                if test_size > 0 and test_size not in tested:
                    test_queue.insert(0, (test_size, test_size // PATTERN_LEN))
            transition_done = True
        
        last_toxic = current_toxic
    
    return results


def generate_report(results: List[TestResult], iterations: int) -> str:
    """Generate test report."""
    lines = ["=" * 60, "TOXICFRAME TEST REPORT", "=" * 60]
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Total tests: {len(results)}, Iterations: {iterations}")
    lines.append("")
    
    toxic = [r for r in results if r.success_rate == 0]
    safe = [r for r in results if r.success_rate == 1]
    maybe = [r for r in results if 0 < r.success_rate < 1]
    
    lines.append("SUMMARY")
    lines.append(f"  Toxic: {len(toxic)}, Safe: {len(safe)}, Maybe: {len(maybe)}")
    
    if toxic:
        smallest = min(toxic, key=lambda x: x.size)
        lines.append(f"\nSMALLEST TOXIC: {smallest.size} bytes ({smallest.pattern_repeats} repeats)")
    
    if maybe:
        lines.append("\nINTERMITTENT:")
        for r in sorted(maybe, key=lambda x: x.success_rate)[:10]:
            lines.append(f"  {r.size} bytes: {r.success_rate:.0%}")
    
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Find minimal toxic packet size")
    parser.add_argument("--iterations", type=int, default=TEST_ITERATIONS, help="Iterations per test")
    args = parser.parse_args()
    
    print("Toxicframe Test Script")
    print("=" * 60)
    
    sender = get_sender()
    if not sender.health_check():
        print("ERROR: Cannot reach packetgen API")
        return 1
    print("Packetgen API: OK")
    
    try:
        get_receiver()
        print("BPF receiver: OK\n")
    except Exception as e:
        print(f"ERROR: BPF: {e}")
        return 1
    
    try:
        results = run_tests(args.iterations)
        report = generate_report(results, args.iterations)
        
        report_path = TEST_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path.write_text(report)
        
        print("\n" + report)
        print(f"\nSaved: {report_path}")
    finally:
        cleanup()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        cleanup()
        sys.exit(1)
