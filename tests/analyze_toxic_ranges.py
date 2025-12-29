#!/usr/bin/env python3
"""
Comprehensive analysis of toxic ranges in toxic.bin.

Tests all possible byte ranges, stores results in SQLite, and generates histograms.
"""

import sys
import time
import sqlite3
from pathlib import Path
from typing import Tuple, Optional
from collections import defaultdict

# Import common modules
from test_config import TEST_ITERATIONS, DB_FILE
from test_common import (
    upload_test_file,
    test_download_file,
    extract_range,
    get_toxic_bin_data,
    classify_result
)
from db_common import (
    init_toxic_analysis_db,
    save_test_result
)


def get_file_size() -> int:
    """Get the size of toxic.bin."""
    return len(get_toxic_bin_data())


def test_range_multiple(start: int, end: int) -> Tuple[int, int, bytes]:
    """
    Test a range multiple times and return success/failure counts and the data.
    
    Returns:
        Tuple[int, int, bytes]: (successes, failures, range_data)
    """
    range_data = extract_range(start, end)
    if len(range_data) != (end - start + 1):
        return (0, TEST_ITERATIONS, range_data)  # Failed to extract
    
    # Create filename from hash
    import hashlib
    file_hash = hashlib.sha256(range_data).hexdigest()[:16]
    filename = f"test-{file_hash}"
    
    # Upload once
    if not upload_test_file(range_data, filename):
        return (0, TEST_ITERATIONS, range_data)  # Upload failed
    
    time.sleep(0.3)  # Wait for file to be available
    
    # Test multiple times
    successes = 0
    failures = 0
    
    for _ in range(TEST_ITERATIONS):
        if test_download_file(filename, len(range_data)):
            successes += 1
        else:
            failures += 1
        time.sleep(0.1)  # Small delay between tests
    
    return (successes, failures, range_data)


def test_range_cached(conn, start: int, end: int) -> Optional[Tuple[int, int, bytes]]:
    """Test a range, using cache if available."""
    from db_common import get_cached_result
    
    length = end - start + 1
    
    # Check cache
    cached = get_cached_result(conn, start, length, "toxic_analysis")
    
    if cached:
        successes, failures, data_hex = cached
        data = bytes.fromhex(data_hex)
        return (successes, failures, data)
    
    # Not cached, test it
    print(f"  Testing range {start}-{end} (length {length})...", end=" ", flush=True)
    successes, failures, data = test_range_multiple(start, end)
    probability = successes / TEST_ITERATIONS
    classification = classify_result(successes, TEST_ITERATIONS)
    
    print(f"{classification} ({successes}/{TEST_ITERATIONS}, {probability:.1%})")
    
    save_test_result(conn, start, end, successes, failures, data)
    time.sleep(0.1)  # Small delay
    
    return (successes, failures, data)


def binary_search_toxic_ranges(conn):
    """Binary search to find toxic ranges efficiently, using the same logic as binary_search_toxic.py."""
    file_size = get_file_size()
    
    print("Binary search for toxic ranges (starting from largest)")
    print("=" * 80)
    print(f"File size: {file_size} bytes")
    print("-" * 80)
    
    # First, check if the full file is toxic
    print(f"Testing full file (0-{file_size-1})...", end=" ", flush=True)
    result = test_range_cached(conn, 0, file_size - 1)
    if not result:
        print("ERROR")
        return
    
    successes, failures, _ = result
    full_file_toxic = (successes == 0)
    
    if not full_file_toxic:
        print(f"SAFE ({successes}/{TEST_ITERATIONS})")
        print("\nSAFE - full file is not toxic!")
        return
    
    print(f"TOXIC ({successes}/{TEST_ITERATIONS})")
    
    # Binary search for smallest toxic range starting from position 0
    print("\nBinary search for smallest toxic range starting from byte 0:")
    print("-" * 80)
    
    left = 0
    right = file_size - 1
    smallest_toxic_end = right
    
    while left <= right:
        mid = (left + right) // 2
        test_end = mid
        
        result = test_range_cached(conn, 0, test_end)
        if not result:
            break
        
        successes, failures, _ = result
        toxic = (successes == 0)
        
        if toxic:
            smallest_toxic_end = test_end
            right = mid - 1  # Try smaller
        else:
            left = mid + 1  # Try larger
    
    print(f"\nSmallest toxic range from start: 0-{smallest_toxic_end} ({smallest_toxic_end + 1} bytes)")
    
    # Now try to find if we can start later and still be toxic
    print("\nBinary search for latest start position that is still toxic:")
    print("-" * 80)
    
    # We know 0 to smallest_toxic_end is toxic, now find latest start
    left_start = 0
    right_start = smallest_toxic_end
    
    latest_toxic_start = 0
    
    while left_start <= right_start:
        mid_start = (left_start + right_start) // 2
        test_start = mid_start
        test_end = smallest_toxic_end
        
        result = test_range_cached(conn, test_start, test_end)
        if not result:
            break
        
        successes, failures, _ = result
        toxic = (successes == 0)
        
        if toxic:
            latest_toxic_start = test_start
            left_start = mid_start + 1  # Try starting later
        else:
            right_start = mid_start - 1  # Try starting earlier
    
    # Now find smallest end from this start
    print(f"\nBinary search for smallest end from start {latest_toxic_start}:")
    print("-" * 80)
    
    left_end = latest_toxic_start
    right_end = file_size - 1
    smallest_end = right_end
    
    while left_end <= right_end:
        mid_end = (left_end + right_end) // 2
        test_end = mid_end
        
        result = test_range_cached(conn, latest_toxic_start, test_end)
        if not result:
            break
        
        successes, failures, _ = result
        toxic = (successes == 0)
        
        if toxic:
            smallest_end = test_end
            right_end = mid_end - 1  # Try smaller
        else:
            left_end = mid_end + 1  # Try larger
    
    result_range = (latest_toxic_start, smallest_end)
    size = smallest_end - latest_toxic_start + 1
    print(f"\n{'='*80}")
    print(f"SMALLEST TOXIC RANGE: {latest_toxic_start}-{smallest_end} ({size} bytes)")
    print(f"{'='*80}")
    
    # Test surrounding ranges to find boundaries
    print(f"\nTesting surrounding ranges to find exact boundaries:")
    print("-" * 80)
    
    # Test ranges around the found toxic range
    for offset in [-2, -1, 0, 1, 2]:
        test_start = max(0, latest_toxic_start + offset)
        test_end = test_start + size - 1
        if test_end < file_size:
            test_range_cached(conn, test_start, test_end)
    
    # Test different lengths from the same start
    for length_offset in [-2, -1, 0, 1, 2]:
        test_length = max(1, size + length_offset)
        test_end = latest_toxic_start + test_length - 1
        if test_end < file_size:
            test_range_cached(conn, latest_toxic_start, test_end)


def test_all_ranges(max_size: Optional[int] = None, step: int = 1):
    """Test all possible ranges systematically."""
    file_size = get_file_size()
    max_size = max_size or file_size
    
    print(f"Testing all ranges in toxic.bin ({file_size} bytes)")
    print(f"Max range size: {max_size} bytes")
    print(f"Step size: {step}")
    from test_config import TIMEOUT
    print(f"Timeout: {TIMEOUT}s, Iterations: {TEST_ITERATIONS}")
    print("=" * 80)
    
    conn = init_toxic_analysis_db()
    
    total_tests = 0
    for length in range(1, min(max_size + 1, file_size + 1), step):
        for start in range(0, file_size - length + 1, step):
            end = start + length - 1
            
            # Check if already tested
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM test_results WHERE start_pos = ? AND length = ?", 
                          (start, length))
            if cursor.fetchone():
                continue  # Already tested
            
            total_tests += 1
            print(f"[{total_tests}] Testing range {start}-{end} (length {length})...", 
                  end=" ", flush=True)
            
            successes, failures, data = test_range_multiple(start, end)
            probability = successes / TEST_ITERATIONS
            classification = classify_result(successes, TEST_ITERATIONS)
            
            print(f"{classification} ({successes}/{TEST_ITERATIONS}, {probability:.1%})")
            
            save_test_result(conn, start, end, successes, failures, data)
            
            time.sleep(0.2)  # Small delay between ranges
    
    conn.close()
    print(f"\nCompleted {total_tests} tests")
    print(f"Database: {DB_FILE}")


def format_hex_with_patterns(data_hex: str, max_length: int = 60) -> str:
    """
    Format hex data, detecting and compressing repeating patterns.
    
    Returns hex string with repeating patterns shown as (pattern ...)
    """
    if not data_hex:
        return ""
    
    # Convert hex string to bytes for pattern detection
    try:
        data = bytes.fromhex(data_hex)
    except:
        return data_hex[:max_length]
    
    if len(data) == 0:
        return ""
    
    # Try to detect repeating pattern (14 bytes: the toxic pattern)
    pattern_len = 14
    if len(data) >= pattern_len * 2:
        pattern = data[:pattern_len]
        # Check if pattern repeats
        repeats = 1
        for i in range(pattern_len, len(data), pattern_len):
            if i + pattern_len <= len(data) and data[i:i+pattern_len] == pattern:
                repeats += 1
            else:
                break
        
        # If pattern repeats at least 2 times, show it compressed
        if repeats >= 2:
            pattern_hex = pattern.hex()
            pattern_formatted = " ".join(pattern_hex[i:i+2] for i in range(0, len(pattern_hex), 2))
            remaining = len(data) - (repeats * pattern_len)
            
            if remaining == 0:
                return f"({pattern_formatted} ×{repeats})"
            else:
                remaining_hex = data[repeats * pattern_len:].hex()
                remaining_formatted = " ".join(remaining_hex[i:i+2] for i in range(0, min(len(remaining_hex), max_length - len(pattern_formatted) - 20), 2))
                return f"({pattern_formatted} ×{repeats}) {remaining_formatted}"
    
    # No repeating pattern detected, format normally
    hex_display = data_hex[:max_length]
    if len(data_hex) > max_length:
        hex_display += "..."
    # Add spaces every 2 chars for readability
    return " ".join(hex_display[i:i+2] for i in range(0, len(hex_display), 2))


def generate_histogram():
    """Generate histogram analysis from database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Get all results with hex data
    cursor.execute("""
        SELECT start_pos, length, successes, classification, data_hex
        FROM test_results
        ORDER BY start_pos, length
    """)
    
    results = cursor.fetchall()
    
    if not results:
        print("No results in database!")
        conn.close()
        return
    
    # Group by start position
    by_start = defaultdict(list)
    for start, length, successes, classification, data_hex in results:
        by_start[start].append((length, successes, classification, data_hex))
    
    # Generate histogram
    print("\n" + "=" * 80)
    print("HISTOGRAM: Success rate by start position and length")
    print("=" * 80)
    
    # For each start position, show distribution
    for start in sorted(by_start.keys()):
        ranges = by_start[start]
        print(f"\nStart position {start}:")
        print(f"  {'Length':<8} {'Successes':<12} {'Classification':<12} {'Hex Data'}")
        print(f"  {'-'*8} {'-'*12} {'-'*12} {'-'*60}")
        
        for length, successes, classification, data_hex in sorted(ranges):
            prob_str = f"{successes}/{TEST_ITERATIONS}"
            hex_formatted = format_hex_with_patterns(data_hex, max_length=60)
            print(f"  {length:<8} {prob_str:<12} {classification:<12} {hex_formatted}")
    
    # Summary statistics
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    
    cursor.execute("""
        SELECT classification, COUNT(*) as count
        FROM test_results
        GROUP BY classification
    """)
    
    for classification, count in cursor.fetchall():
        print(f"{classification}: {count} ranges")
    
    # Find patterns
    print("\n" + "=" * 80)
    print("TOXIC RANGES (0/10 successes)")
    print("=" * 80)
    cursor.execute("""
        SELECT start_pos, length, end_pos, data_hex
        FROM test_results
        WHERE classification = 'TOXIC'
        ORDER BY length, start_pos
        LIMIT 50
    """)
    
    toxic_ranges = cursor.fetchall()
    if toxic_ranges:
        print(f"{'Start':<8} {'Length':<8} {'End':<8} {'Hex Data'}")
        print("-" * 100)
        for start, length, end, data_hex in toxic_ranges:
            hex_formatted = format_hex_with_patterns(data_hex, max_length=60)
            print(f"{start:<8} {length:<8} {end:<8} {hex_formatted}")
        if len(toxic_ranges) == 50:
            print(f"... (showing first 50, query for more)")
    else:
        print("No toxic ranges found")
    
    # MAYBE ranges (intermittent)
    print("\n" + "=" * 80)
    print("MAYBE RANGES (intermittent failures)")
    print("=" * 80)
    cursor.execute("""
        SELECT start_pos, length, end_pos, successes, probability, data_hex
        FROM test_results
        WHERE classification = 'MAYBE'
        ORDER BY probability, length, start_pos
        LIMIT 50
    """)
    
    maybe_ranges = cursor.fetchall()
    if maybe_ranges:
        print(f"{'Start':<8} {'Length':<8} {'End':<8} {'Successes':<12} {'Probability':<12} {'Hex Data'}")
        print("-" * 120)
        for start, length, end, successes, prob, data_hex in maybe_ranges:
            hex_formatted = format_hex_with_patterns(data_hex, max_length=40)
            print(f"{start:<8} {length:<8} {end:<8} {successes}/{TEST_ITERATIONS:<8} {prob:.1%} {hex_formatted}")
        if len(maybe_ranges) == 50:
            print(f"... (showing first 50, query for more)")
    else:
        print("No intermittent ranges found")
    
    conn.close()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze toxic ranges in toxic.bin"
    )
    parser.add_argument(
        "--max-size", type=int, default=None,
        help="Maximum range size to test (default: file size)"
    )
    parser.add_argument(
        "--step", type=int, default=1,
        help="Step size for testing (default: 1)"
    )
    parser.add_argument(
        "--histogram", action="store_true",
        help="Generate histogram from existing database"
    )
    parser.add_argument(
        "--query", type=str, default=None,
        help="SQL query to run on database"
    )
    parser.add_argument(
        "--binary-search", action="store_true",
        help="Use binary search instead of testing all ranges (much faster)"
    )
    
    args = parser.parse_args()
    
    if args.histogram:
        generate_histogram()
        return 0
    
    if args.query:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute(args.query)
        results = cursor.fetchall()
        for row in results:
            print(row)
        conn.close()
        return 0
    
    # Run tests
    conn = init_toxic_analysis_db()
    
    if args.binary_search:
        binary_search_toxic_ranges(conn)
    else:
        test_all_ranges(max_size=args.max_size, step=args.step)
    
    conn.close()
    
    # Generate histogram
    generate_histogram()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

