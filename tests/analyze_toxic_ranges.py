#!/usr/bin/env python3
"""
Analyze toxic ranges in toxic.bin using raw Ethernet packets.
"""

import sys
import sqlite3
from collections import defaultdict
from typing import Optional, Tuple

from config import TEST_ITERATIONS, DB_FILE, TOXIC_BIN_PATH
from test_common import (
    test_payload, classify_result, get_toxic_bin_data,
    get_sender, get_receiver, cleanup
)
from db_common import init_database, save_test_result, get_cached_result


def test_range_cached(conn: sqlite3.Connection, start: int, end: int) -> Optional[Tuple[int, int, bytes]]:
    """Test a range, using cache if available."""
    length = end - start + 1
    toxic_data = get_toxic_bin_data()
    
    if end >= len(toxic_data):
        return None
    
    data = toxic_data[start:end + 1]
    
    # Check cache
    cached = get_cached_result(conn, start, length)
    if cached:
        successes, failures, data_hex = cached
        return successes, failures, bytes.fromhex(data_hex)
    
    # Test it
    print(f"  Testing {start}-{end} ({length} bytes)...", end=" ", flush=True)
    successes, failures = test_payload(data)
    classification = classify_result(successes, TEST_ITERATIONS)
    print(f"{classification} ({successes}/{TEST_ITERATIONS})")
    
    save_test_result(conn, start, end, successes, failures, data)
    return successes, failures, data


def binary_search_toxic(conn: sqlite3.Connection):
    """Binary search for smallest toxic range."""
    toxic_data = get_toxic_bin_data()
    file_size = len(toxic_data)
    
    print(f"Binary search for toxic ranges")
    print(f"File size: {file_size} bytes")
    print("=" * 60)
    
    # Test full file
    print(f"\nTesting full file (0-{file_size-1})...")
    result = test_range_cached(conn, 0, file_size - 1)
    if not result:
        print("ERROR")
        return
    
    successes, _, _ = result
    if successes > 0:
        print("Full file is SAFE!")
        return
    
    # Binary search for smallest end from start 0
    print("\nFinding smallest toxic range from byte 0:")
    print("-" * 60)
    
    left, right = 0, file_size - 1
    smallest_end = right
    
    while left <= right:
        mid = (left + right) // 2
        result = test_range_cached(conn, 0, mid)
        if not result:
            break
        successes, _, _ = result
        if successes == 0:
            smallest_end = mid
            right = mid - 1
        else:
            left = mid + 1
    
    print(f"\nSmallest from start: 0-{smallest_end} ({smallest_end + 1} bytes)")
    
    # Find latest start
    print("\nFinding latest toxic start:")
    print("-" * 60)
    
    left, right = 0, smallest_end
    latest_start = 0
    
    while left <= right:
        mid = (left + right) // 2
        result = test_range_cached(conn, mid, smallest_end)
        if not result:
            break
        successes, _, _ = result
        if successes == 0:
            latest_start = mid
            left = mid + 1
        else:
            right = mid - 1
    
    # Find smallest end from latest_start
    print(f"\nFinding smallest end from start {latest_start}:")
    print("-" * 60)
    
    left, right = latest_start, file_size - 1
    final_end = right
    
    while left <= right:
        mid = (left + right) // 2
        result = test_range_cached(conn, latest_start, mid)
        if not result:
            break
        successes, _, _ = result
        if successes == 0:
            final_end = mid
            right = mid - 1
        else:
            left = mid + 1
    
    size = final_end - latest_start + 1
    print(f"\n{'=' * 60}")
    print(f"SMALLEST TOXIC: {latest_start}-{final_end} ({size} bytes)")
    print(f"{'=' * 60}")
    
    data = toxic_data[latest_start:final_end + 1]
    print(f"\nToxic data (hex): {data.hex()}")


def show_histogram(conn: sqlite3.Connection):
    """Show results histogram."""
    cursor = conn.cursor()
    
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    
    cursor.execute("SELECT classification, COUNT(*) FROM test_results WHERE test_type='range_test' GROUP BY classification")
    for cls, count in cursor.fetchall():
        print(f"  {cls}: {count}")
    
    print("\nTOXIC RANGES:")
    cursor.execute("""
        SELECT start_pos, end_pos, length 
        FROM test_results WHERE test_type='range_test' AND classification='TOXIC'
        ORDER BY length LIMIT 10
    """)
    for start, end, length in cursor.fetchall():
        print(f"  {start}-{end} ({length} bytes)")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyze toxic ranges")
    parser.add_argument("--histogram", action="store_true", help="Show histogram only")
    args = parser.parse_args()
    
    conn = init_database()
    
    if args.histogram:
        show_histogram(conn)
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
        binary_search_toxic(conn)
        show_histogram(conn)
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
