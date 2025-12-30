#!/usr/bin/env python3
"""
Test different lengths of 0x4a byte patterns and create histogram of success rates.

This script tests packets containing varying numbers of consecutive 0x4a bytes
to find the exact minimum toxic length and create detailed statistics.
"""

import sys
import sqlite3
from collections import defaultdict
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime

from config import TEST_ITERATIONS, DB_FILE
from test_common import test_payload, classify_result, get_sender, get_receiver, cleanup
from db_common import init_database, save_test_result, get_cached_result


@dataclass
class LengthTestResult:
    """Result of testing a specific length."""
    length: int
    successes: int
    failures: int
    success_rate: float
    is_toxic: bool
    classification: str


def generate_pattern(length: int, byte_value: int = 0x4a) -> bytes:
    """Generate a pattern of consecutive bytes."""
    return bytes([byte_value] * length)


def test_length_cached(conn: sqlite3.Connection, length: int, byte_value: int = 0x4a,
                      iterations: int = TEST_ITERATIONS) -> LengthTestResult:
    """Test a specific length, using cache if available."""
    # Generate the pattern
    data = generate_pattern(length, byte_value)

    # Check cache (we'll use a custom cache key)
    cache_key = f"length_test_{byte_value}_{length}"
    cursor = conn.cursor()
    cursor.execute("""
        SELECT successes, failures, data_hex
        FROM test_results
        WHERE test_type=? AND start_pos=? AND length=?
    """, (cache_key, 0, length))

    cached = cursor.fetchone()
    if cached:
        successes, failures, data_hex = cached
        success_rate = successes / iterations
        classification = classify_result(successes, iterations)
        is_toxic = (success_rate == 0)
        return LengthTestResult(length, successes, failures, success_rate, is_toxic, classification)

    # Test it
    print(f"  Testing {length} bytes of 0x{byte_value:02x}...", end=" ", flush=True)
    successes, failures = test_payload(data, iterations)
    success_rate = successes / iterations
    classification = classify_result(successes, iterations)
    is_toxic = (success_rate == 0)
    print(f"{classification} ({successes}/{iterations})")

    # Save to database (using custom test_type)
    total = successes + failures
    probability = successes / total if total > 0 else 0.0

    cursor.execute("""
        INSERT OR REPLACE INTO test_results
        (test_type, start_pos, end_pos, length, successes, failures, probability, classification, data_hex)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (cache_key, 0, length - 1, length, successes, failures, probability, classification, data.hex()))

    conn.commit()
    return LengthTestResult(length, successes, failures, success_rate, is_toxic, classification)


def run_length_tests(conn: sqlite3.Connection, start_length: int = 100, end_length: int = 130,
                    byte_value: int = 0x4a, iterations: int = TEST_ITERATIONS) -> List[LengthTestResult]:
    """Run tests for a range of lengths."""
    results = []

    print(f"Testing lengths {start_length}-{end_length} bytes of 0x{byte_value:02x}")
    print(f"Iterations per length: {iterations}")
    print("=" * 60)

    for length in range(start_length, end_length + 1):
        result = test_length_cached(conn, length, byte_value, iterations)
        results.append(result)

    return results


def show_length_histogram(conn: sqlite3.Connection, byte_value: int = 0x4a, iterations: int = None):
    """Show histogram of length test results."""
    cursor = conn.cursor()

    print("\n" + "=" * 80)
    print(f"LENGTH HISTOGRAM - 0x{byte_value:02x} PATTERNS")
    print("=" * 80)

    # Get all length test results
    cursor.execute("""
        SELECT start_pos, length, successes, failures, classification
        FROM test_results
        WHERE test_type LIKE ?
        ORDER BY length
    """, (f"length_test_{byte_value}_%",))

    results = cursor.fetchall()

    if not results:
        print("No test results found.")
        return

    # Group by classification
    classification_counts = defaultdict(int)
    length_results = {}

    for _, length, successes, failures, classification in results:
        classification_counts[classification] += 1
        length_results[length] = (successes, failures, classification)

    print("CLASSIFICATION SUMMARY:")
    for cls, count in classification_counts.items():
        print(f"  {cls}: {count} lengths")

    iterations_text = f" ({iterations} iterations each)" if iterations else ""
    print(f"\nDETAILED RESULTS ({len(results)} lengths tested){iterations_text}:")
    print("Length | Success Rate | Classification")
    print("-------|--------------|----------------")

    toxic_lengths = []
    safe_lengths = []
    maybe_lengths = []

    for length in sorted(length_results.keys()):
        successes, failures, classification = length_results[length]
        total = successes + failures
        success_rate = successes / total if total > 0 else 0

        if classification == "TOXIC":
            toxic_lengths.append(length)
        elif classification == "SAFE":
            safe_lengths.append(length)
        else:
            maybe_lengths.append(length)

        print(f"{length:4d}   | {success_rate:.3f}        | {classification}")

    # Show ranges
    if toxic_lengths:
        print(f"\nTOXIC LENGTHS: {min(toxic_lengths)}-{max(toxic_lengths)} bytes ({len(toxic_lengths)} lengths)")

    if safe_lengths:
        print(f"SAFE LENGTHS: {min(safe_lengths)}-{max(safe_lengths)} bytes ({len(safe_lengths)} lengths)")

    if maybe_lengths:
        print(f"INTERMITTENT LENGTHS: {min(maybe_lengths)}-{max(maybe_lengths)} bytes ({len(maybe_lengths)} lengths)")

    # Find transition points
    if toxic_lengths and safe_lengths:
        transition_start = max(safe_lengths) if safe_lengths else min(toxic_lengths) - 1
        transition_end = min(toxic_lengths) if toxic_lengths else max(safe_lengths) + 1
        print(f"\nTRANSITION ZONE: {transition_start}-{transition_end} bytes")

        # Show details for transition zone
        print("\nTRANSITION DETAILS:")
        for length in range(max(transition_start - 2, min(length_results.keys())),
                           min(transition_end + 3, max(length_results.keys()) + 1)):
            if length in length_results:
                successes, failures, classification = length_results[length]
                total = successes + failures
                success_rate = successes / total if total > 0 else 0
                print(f"{length:4d}   | {success_rate:.3f}        | {classification}")


def create_markdown_histogram(conn: sqlite3.Connection, byte_values: list = None, iterations: int = None):
    """Create a detailed Markdown histogram file."""
    if byte_values is None:
        byte_values = [0x4a, 0xb5]

    lines = ["# Toxic Frame Bug - Length Histograms\n"]
    lines.append("Detailed analysis of packet success rates by length for toxic byte patterns.\n")
    lines.append(f"Generated: {datetime.now().isoformat()}\n")

    if iterations:
        lines.append(f"**Test Parameters:** {iterations} iterations per length\n")

    for byte_value in byte_values:
        lines.append(f"## 0x{byte_value:02x} ({byte_value} decimal) Patterns\n")

        cursor = conn.cursor()
        cursor.execute("""
            SELECT length, successes, failures, classification
            FROM test_results
            WHERE test_type LIKE ?
            ORDER BY length
        """, (f"length_test_{byte_value}_%",))

        results = cursor.fetchall()

        if not results:
            lines.append("No test results found.\n")
            continue

        # Classification summary
        classification_counts = defaultdict(int)
        for length, successes, failures, classification in results:
            classification_counts[classification] += 1

        lines.append("### Classification Summary\n")
        for cls, count in classification_counts.items():
            lines.append(f"- **{cls}**: {count} lengths\n")
        lines.append("")

        # Detailed results table
        lines.append("### Detailed Results\n")
        lines.append("| Length | Success Rate | Success/Fail | Classification |")
        lines.append("|--------|--------------|--------------|----------------|")

        toxic_lengths = []
        safe_lengths = []
        maybe_lengths = []

        for length, successes, failures, classification in results:
            total = successes + failures
            success_rate = successes / total if total > 0 else 0

            if classification == "TOXIC":
                toxic_lengths.append(length)
            elif classification == "SAFE":
                safe_lengths.append(length)
            else:
                maybe_lengths.append(length)

            lines.append(f"| {length:3d} | {success_rate:5.1%} | {successes:3d}/{failures:3d} | {classification:8} |")

        lines.append("")

        # Range summaries
        if toxic_lengths:
            lines.append(f"**TOXIC LENGTHS:** {min(toxic_lengths)}-{max(toxic_lengths)} bytes ({len(toxic_lengths)} lengths)\n")

        if safe_lengths:
            lines.append(f"**SAFE LENGTHS:** {min(safe_lengths)}-{max(safe_lengths)} bytes ({len(safe_lengths)} lengths)\n")

        if maybe_lengths:
            lines.append(f"**INTERMITTENT LENGTHS:** {min(maybe_lengths)}-{max(maybe_lengths)} bytes ({len(maybe_lengths)} lengths)\n")

        # Transition zone
        if toxic_lengths and safe_lengths:
            transition_start = max(safe_lengths) if safe_lengths else min(toxic_lengths) - 1
            transition_end = min(toxic_lengths) if toxic_lengths else max(safe_lengths) + 1
            lines.append(f"**TRANSITION ZONE:** {transition_start}-{transition_end} bytes\n")

            lines.append("### Transition Zone Details\n")
            lines.append("| Length | Success Rate | Success/Fail | Classification |")
            lines.append("|--------|--------------|--------------|----------------|")

            for length in range(max(transition_start - 2, min(r[0] for r in results)),
                               min(transition_end + 3, max(r[0] for r in results) + 1)):
                for result_length, successes, failures, classification in results:
                    if result_length == length:
                        total = successes + failures
                        success_rate = successes / total if total > 0 else 0
                        lines.append(f"| {length:3d} | {success_rate:5.1%} | {successes:3d}/{failures:3d} | {classification:8} |")
                        break

            lines.append("")

        lines.append("---\n")

    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Test different lengths of byte patterns")
    parser.add_argument("--histogram", action="store_true", help="Show histogram only")
    parser.add_argument("--markdown", action="store_true", help="Create HISTOGRAM.md file")
    parser.add_argument("--start", type=int, default=100, help="Start length")
    parser.add_argument("--end", type=int, default=130, help="End length")
    parser.add_argument("--byte", type=lambda x: int(x, 0), default=0x4a, help="Byte value (hex)")
    parser.add_argument("--iterations", type=int, default=TEST_ITERATIONS, help="Iterations per test")
    parser.add_argument("--both", action="store_true", help="Test both 0x4a and 0xb5")
    args = parser.parse_args()

    conn = init_database()

    if args.histogram:
        if args.both:
            for byte_val in [0x4a, 0xb5]:
                show_length_histogram(conn, byte_val, args.iterations)
        else:
            show_length_histogram(conn, args.byte, args.iterations)
        conn.close()
        return 0

    if args.markdown:
        markdown_content = create_markdown_histogram(conn, [0x4a, 0xb5] if args.both else [args.byte], args.iterations)
        with open("HISTOGRAM.md", "w") as f:
            f.write(markdown_content)
        print("Created HISTOGRAM.md")
        conn.close()
        return 0

    # Check API
    sender = get_sender()
    if not sender.health_check():
        print("ERROR: Cannot reach packetgen API")
        from config import PACKETGEN_API_PORT
        print(f"Start it: python3.11 /root/packetgen.py {PACKETGEN_API_PORT}")
        return 1
    print("Packetgen API: OK")

    try:
        get_receiver()
        print("BPF receiver: OK\n")
    except Exception as e:
        print(f"ERROR: BPF: {e}")
        print("Try running with sudo")
        return 1

    try:
        byte_values = [0x4a, 0xb5] if args.both else [args.byte]

        for byte_val in byte_values:
            print(f"\n{'='*60}")
            print(f"Testing 0x{byte_val:02x} ({byte_val}) patterns")
            print(f"{'='*60}")
            results = run_length_tests(conn, args.start, args.end, byte_val, args.iterations)
            show_length_histogram(conn, byte_val, args.iterations)
            print(f"\nCompleted 0x{byte_val:02x}: {len(results)} lengths with {args.iterations} iterations each")

        # Create markdown histogram
        if args.both:
            print("\nCreating HISTOGRAM.md...")
            markdown_content = create_markdown_histogram(conn, [0x4a, 0xb5], args.iterations)
            with open("HISTOGRAM.md", "w") as f:
                f.write(markdown_content)
            print("Created HISTOGRAM.md")

    finally:
        cleanup()
        conn.close()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
        cleanup()
        sys.exit(1)
