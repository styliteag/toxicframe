#!/usr/bin/env python3
"""
Search for variations of the toxic pattern that still trigger the bug.

Two search methods:
1. Smaller patterns - test if parts of the 14-byte pattern are toxic
2. Bit flips - flip individual bits in the pattern and test if still toxic
"""

import sys
import time
from pathlib import Path
from typing import Tuple, Optional, List

# Import common modules
from test_config import TOXIC_PATTERN, PATTERN_LEN, TEST_ITERATIONS
from test_common import (
    test_pattern_multiple,
    classify_result
)
from db_common import (
    init_pattern_variations_db,
    save_pattern_variation
)


def search_smaller_patterns(conn, repetitions: int = 30):
    """Search for smaller patterns that are still toxic."""
    print("=" * 80)
    print("SEARCH METHOD 1: Smaller Patterns")
    print("=" * 80)
    print(f"Testing if parts of the {PATTERN_LEN}-byte pattern are toxic")
    print(f"Each pattern will be repeated {repetitions} times before testing")
    print(f"Original pattern: {' '.join(f'{b:02x}' for b in TOXIC_PATTERN)}")
    print("-" * 80)
    
    # First, test the full pattern repeated to confirm it's toxic
    # But note: the original toxic.bin is 1024 bytes, not just the repeated pattern
    # So we should test with the actual toxic.bin first, or test larger sizes
    print(f"Step 1: Testing full {PATTERN_LEN}-byte pattern repeated {repetitions} times...", end=" ", flush=True)
    full_repeated = TOXIC_PATTERN * repetitions
    pattern_desc = f"Full {PATTERN_LEN}-byte pattern (×{repetitions})"
    
    # Always test the base pattern, don't skip
    successes, failures = test_pattern_multiple(full_repeated)
    probability = successes / TEST_ITERATIONS
    classification = classify_result(successes, TEST_ITERATIONS)
    
    print(f"{classification} ({successes}/{TEST_ITERATIONS}, {probability:.1%})")
    
    save_pattern_variation(conn, "smaller", full_repeated, pattern_desc, successes, failures)
    time.sleep(0.2)
    
    if classification != "TOXIC":
        print(f"\n⚠️  WARNING: Full pattern repeated {repetitions}x is {classification}, not TOXIC!")
        print(f"Note: Original toxic.bin is 1024 bytes (39×14 + 478 extra bytes)")
        print("The toxicity might require the full file size or additional data.")
        print("Continuing with smaller patterns anyway...")
    else:
        print(f"✓ Base pattern confirmed TOXIC - continuing with smaller patterns...")
    
    print("\nStep 2: Testing smaller sub-patterns...")
    print("-" * 80)
    
    # Test all possible sub-patterns
    for start in range(PATTERN_LEN):
        for length in range(1, PATTERN_LEN - start + 1):
            # Skip the full pattern (already tested)
            if start == 0 and length == PATTERN_LEN:
                continue
            
            sub_pattern = TOXIC_PATTERN[start:start+length]
            # Repeat the pattern
            repeated_pattern = sub_pattern * repetitions
            pattern_desc = f"Bytes {start}-{start+length-1} of original pattern (×{repetitions})"
            
            # Check if already tested
            cursor = conn.cursor()
            pattern_hex = repeated_pattern.hex()
            cursor.execute("SELECT id FROM test_results WHERE test_type = 'pattern_variation' AND pattern_type = 'smaller' AND pattern_hex = ?", 
                          (pattern_hex,))
            if cursor.fetchone():
                continue  # Already tested
            
            print(f"Testing {pattern_desc} ({length} bytes × {repetitions} = {len(repeated_pattern)} bytes)...", end=" ", flush=True)
            
            successes, failures = test_pattern_multiple(repeated_pattern)
            probability = successes / TEST_ITERATIONS
            classification = classify_result(successes, TEST_ITERATIONS)
            
            print(f"{classification} ({successes}/{TEST_ITERATIONS}, {probability:.1%})")
            
            save_pattern_variation(conn, "smaller", repeated_pattern, pattern_desc, successes, failures)
            time.sleep(0.2)


def flip_bit(byte_val: int, bit_pos: int) -> int:
    """Flip a single bit in a byte."""
    return byte_val ^ (1 << bit_pos)


def search_bit_flips(conn):
    """Search for bit-flipped variations that are still toxic."""
    print("=" * 80)
    print("SEARCH METHOD 2: Bit Flips")
    print("=" * 80)
    print(f"Testing if flipping individual bits in the {PATTERN_LEN}-byte pattern still triggers the bug")
    print(f"Original pattern: {' '.join(f'{b:02x}' for b in TOXIC_PATTERN)}")
    print("-" * 80)
    
    total_variations = PATTERN_LEN * 8  # 14 bytes * 8 bits = 112 variations
    tested = 0
    
    # Test each bit flip
    for byte_idx in range(PATTERN_LEN):
        for bit_idx in range(8):
            # Create pattern with one bit flipped
            modified_pattern = bytearray(TOXIC_PATTERN)
            modified_pattern[byte_idx] = flip_bit(modified_pattern[byte_idx], bit_idx)
            modified_pattern = bytes(modified_pattern)
            
            pattern_desc = f"Byte {byte_idx}, bit {bit_idx} flipped"
            
            # Check if already tested
            cursor = conn.cursor()
            pattern_hex = modified_pattern.hex()
            cursor.execute("SELECT id FROM test_results WHERE test_type = 'pattern_variation' AND pattern_type = 'bitflip' AND pattern_hex = ?", 
                          (pattern_hex,))
            if cursor.fetchone():
                continue  # Already tested
            
            tested += 1
            print(f"[{tested}/{total_variations}] Testing {pattern_desc}...", end=" ", flush=True)
            
            successes, failures = test_pattern_multiple(modified_pattern, filename_prefix="pattern")
            probability = successes / TEST_ITERATIONS
            classification = classify_result(successes, TEST_ITERATIONS)
            
            print(f"{classification} ({successes}/{TEST_ITERATIONS}, {probability:.1%})")
            
            save_pattern_variation(conn, "bitflip", modified_pattern, pattern_desc, successes, failures)
            time.sleep(0.1)


def generate_report(conn: sqlite3.Connection):
    """Generate report from database."""
    cursor = conn.cursor()
    
    print("\n" + "=" * 80)
    print("REPORT: Pattern Variations")
    print("=" * 80)
    
    # Summary by type
    cursor.execute("""
        SELECT pattern_type, classification, COUNT(*) as count
        FROM test_results
        WHERE test_type = 'pattern_variation'
        GROUP BY pattern_type, classification
        ORDER BY pattern_type, classification
    """)
    
    print("\nSummary by type:")
    print("-" * 80)
    for pattern_type, classification, count in cursor.fetchall():
        print(f"{pattern_type:12} {classification:12}: {count:4} patterns")
    
    # Toxic smaller patterns
    print("\n" + "=" * 80)
    print("TOXIC SMALLER PATTERNS")
    print("=" * 80)
    cursor.execute("""
        SELECT pattern_desc, pattern_hex, successes, probability
        FROM test_results
        WHERE test_type = 'pattern_variation' AND pattern_type = 'smaller' AND classification = 'TOXIC'
        ORDER BY LENGTH(pattern_hex), pattern_hex
    """)
    
    toxic_smaller = cursor.fetchall()
    if toxic_smaller:
        print(f"{'Description':<40} {'Hex Pattern':<60} {'Successes':<12} {'Probability'}")
        print("-" * 130)
        for desc, pattern_hex, successes, prob in toxic_smaller:
            hex_formatted = " ".join(pattern_hex[i:i+2] for i in range(0, len(pattern_hex), 2))
            print(f"{desc:<40} {hex_formatted:<60} {successes}/{TEST_ITERATIONS:<8} {prob:.1%}")
    else:
        print("No toxic smaller patterns found")
    
    # Toxic bit-flipped patterns
    print("\n" + "=" * 80)
    print("TOXIC BIT-FLIPPED PATTERNS")
    print("=" * 80)
    cursor.execute("""
        SELECT pattern_desc, pattern_hex, successes, probability
        FROM test_results
        WHERE test_type = 'pattern_variation' AND pattern_type = 'bitflip' AND classification = 'TOXIC'
        ORDER BY pattern_desc
    """)
    
    toxic_bitflips = cursor.fetchall()
    if toxic_bitflips:
        print(f"{'Description':<40} {'Hex Pattern':<60} {'Successes':<12} {'Probability'}")
        print("-" * 130)
        for desc, pattern_hex, successes, prob in toxic_bitflips:
            hex_formatted = " ".join(pattern_hex[i:i+2] for i in range(0, len(pattern_hex), 2))
            print(f"{desc:<40} {hex_formatted:<60} {successes}/{TEST_ITERATIONS:<8} {prob:.1%}")
    else:
        print("No toxic bit-flipped patterns found")
    
    # MAYBE patterns (intermittent)
    print("\n" + "=" * 80)
    print("MAYBE PATTERNS (intermittent)")
    print("=" * 80)
    cursor.execute("""
        SELECT pattern_type, pattern_desc, pattern_hex, successes, probability
        FROM test_results
        WHERE test_type = 'pattern_variation' AND classification = 'MAYBE'
        ORDER BY pattern_type, probability, pattern_desc
        LIMIT 20
    """)
    
    maybe_patterns = cursor.fetchall()
    if maybe_patterns:
        print(f"{'Type':<12} {'Description':<40} {'Hex Pattern':<40} {'Successes':<12} {'Probability'}")
        print("-" * 120)
        for ptype, desc, pattern_hex, successes, prob in maybe_patterns:
            hex_formatted = " ".join(pattern_hex[i:i+2] for i in range(0, min(len(pattern_hex), 40), 2))
            if len(pattern_hex) > 40:
                hex_formatted += "..."
            print(f"{ptype:<12} {desc:<40} {hex_formatted:<40} {successes}/{TEST_ITERATIONS:<8} {prob:.1%}")
    else:
        print("No intermittent patterns found")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Search for variations of the toxic pattern"
    )
    parser.add_argument(
        "--smaller", action="store_true",
        help="Search for smaller patterns (parts of the 14-byte pattern)"
    )
    parser.add_argument(
        "--bitflip", action="store_true",
        help="Search for bit-flipped variations"
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Generate report from existing database"
    )
    parser.add_argument(
        "--repetitions", type=int, default=30,
        help="Number of repetitions for smaller patterns (default: 30)"
    )
    
    args = parser.parse_args()
    
    conn = init_pattern_variations_db()
    
    if args.report:
        generate_report(conn)
        conn.close()
        return 0
    
    if not args.smaller and not args.bitflip:
        # Default: run both
        args.smaller = True
        args.bitflip = True
    
    if args.smaller:
        search_smaller_patterns(conn, repetitions=args.repetitions)
    
    if args.bitflip:
        search_bit_flips(conn)
    
    # Generate report
    generate_report(conn)
    
    conn.close()
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

