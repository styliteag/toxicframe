#!/usr/bin/env python3
"""
Search for variations of the toxic pattern that still trigger the bug.
Uses raw Ethernet packets via packetgen API.
"""

import sys
import sqlite3

from config import TOXIC_PATTERN, PATTERN_LEN, TEST_ITERATIONS
from test_common import (
    test_payload,
    classify_result,
    get_sender,
    get_receiver,
    cleanup
)
from db_common import init_pattern_variations_db, save_pattern_variation


def search_smaller_patterns(conn, repetitions: int = 30, force: bool = False):
    """Search for smaller patterns that are still toxic."""
    print("=" * 60)
    print("SEARCH: Smaller Patterns")
    print("=" * 60)
    print(f"Original: {TOXIC_PATTERN.hex()}")
    print("-" * 60)
    
    # Test full pattern repeated
    print(f"Full pattern (×{repetitions})...", end=" ", flush=True)
    full_data = TOXIC_PATTERN * repetitions
    successes, failures = test_payload(full_data)
    classification = classify_result(successes, TEST_ITERATIONS)
    print(f"{classification} ({successes}/{TEST_ITERATIONS})")
    save_pattern_variation(conn, "smaller", full_data, f"Full ×{repetitions}", successes, failures)
    
    if classification != "TOXIC":
        print(f"WARNING: Full pattern is {classification}, not TOXIC")
    
    # Test sub-patterns
    print("\nSub-patterns:")
    for start in range(PATTERN_LEN):
        for length in range(1, PATTERN_LEN - start + 1):
            if start == 0 and length == PATTERN_LEN:
                continue
            
            sub = TOXIC_PATTERN[start:start + length]
            data = sub * repetitions
            
            # Check cache (skip if force)
            if not force:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM test_results WHERE test_type='pattern_variation' AND pattern_hex=?",
                    (data.hex(),)
                )
                if cursor.fetchone():
                    continue
            
            print(f"  Bytes {start}-{start+length-1} (×{repetitions})...", end=" ", flush=True)
            successes, failures = test_payload(data)
            classification = classify_result(successes, TEST_ITERATIONS)
            print(f"{classification} ({successes}/{TEST_ITERATIONS})")
            save_pattern_variation(conn, "smaller", data, f"Bytes {start}-{start+length-1} ×{repetitions}", successes, failures)


def flip_bit(byte_val: int, bit_pos: int) -> int:
    """Flip a single bit."""
    return byte_val ^ (1 << bit_pos)


def search_bit_flips(conn, force: bool = False):
    """Search for bit-flipped variations."""
    print("=" * 60)
    print("SEARCH: Bit Flips")
    print("=" * 60)
    
    total = PATTERN_LEN * 8
    tested = 0
    
    for byte_idx in range(PATTERN_LEN):
        for bit_idx in range(8):
            modified = bytearray(TOXIC_PATTERN)
            modified[byte_idx] = flip_bit(modified[byte_idx], bit_idx)
            modified = bytes(modified)
            
            # Check cache (skip if force)
            if not force:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id FROM test_results WHERE test_type='pattern_variation' AND pattern_hex=?",
                    (modified.hex(),)
                )
                if cursor.fetchone():
                    continue
            
            tested += 1
            desc = f"Byte {byte_idx}, bit {bit_idx}"
            print(f"[{tested}/{total}] {desc}...", end=" ", flush=True)
            
            successes, failures = test_payload(modified)
            classification = classify_result(successes, TEST_ITERATIONS)
            print(f"{classification} ({successes}/{TEST_ITERATIONS})")
            save_pattern_variation(conn, "bitflip", modified, desc, successes, failures)


def generate_report(conn: sqlite3.Connection):
    """Generate report from database."""
    cursor = conn.cursor()
    
    print("\n" + "=" * 60)
    print("REPORT")
    print("=" * 60)
    
    cursor.execute("""
        SELECT pattern_type, classification, COUNT(*) 
        FROM test_results WHERE test_type='pattern_variation'
        GROUP BY pattern_type, classification
    """)
    
    print("\nSummary:")
    for ptype, cls, count in cursor.fetchall():
        print(f"  {ptype} {cls}: {count}")
    
    print("\nToxic patterns:")
    cursor.execute("""
        SELECT pattern_type, pattern_desc, pattern_hex 
        FROM test_results 
        WHERE test_type='pattern_variation' AND classification='TOXIC'
        ORDER BY LENGTH(pattern_hex)
        LIMIT 20
    """)
    for ptype, desc, hex_data in cursor.fetchall():
        print(f"  [{ptype}] {desc}: {hex_data[:40]}...")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Search toxic pattern variations")
    parser.add_argument("--smaller", action="store_true", help="Test smaller patterns")
    parser.add_argument("--bitflip", action="store_true", help="Test bit flips")
    parser.add_argument("--report", action="store_true", help="Show report only")
    parser.add_argument("--repetitions", type=int, default=30, help="Repetitions for smaller")
    parser.add_argument("--force", action="store_true", help="Force re-test even if results exist in database")
    args = parser.parse_args()
    
    conn = init_pattern_variations_db()
    
    if args.report:
        generate_report(conn)
        conn.close()
        return 0
    
    # Check API
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
    
    if not args.smaller and not args.bitflip:
        args.smaller = args.bitflip = True
    
    try:
        if args.smaller:
            search_smaller_patterns(conn, args.repetitions, force=args.force)
        if args.bitflip:
            search_bit_flips(conn, force=args.force)
        generate_report(conn)
    finally:
        cleanup()
        conn.close()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        cleanup()
        sys.exit(1)
