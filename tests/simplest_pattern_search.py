#!/usr/bin/env python3
"""
Search for the simplest toxic pattern.

Starts from known simple patterns (high repetition) and tries to simplify further:
- Reduce to single repeating byte
- Find minimum length with single byte
- Try different byte values
"""

import sys
import sqlite3
from typing import List, Tuple, Optional

from config import (
    BRUTE_FORCE_TIMEOUT, BRUTE_FORCE_ITERATIONS,
    TOXIC_SMALLEST_BIN_PATH, DB_FILE
)
from test_common import (
    test_payload_fast, test_payloads_batch,
    get_sender, get_receiver, cleanup
)
from db_common import init_pattern_variations_db, save_pattern_variation
from pattern_cache import get_cache


def get_simplest_toxic_pattern() -> Optional[bytes]:
    """Get the simplest toxic pattern from database (most repeating)."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Get pattern with most repetition (simplest structure)
    cursor.execute('''
        SELECT pattern_hex, LENGTH(pattern_hex)/2 as length_bytes
        FROM test_results 
        WHERE test_type = "pattern_variation" 
        AND classification = "TOXIC"
        ORDER BY LENGTH(pattern_hex) DESC
        LIMIT 1
    ''')
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        hex_data, length = result
        return bytes.fromhex(hex_data)
    return None


def search_single_byte_patterns(target_length: int, use_cache: bool = True) -> List[Tuple[int, bytes]]:
    """
    Search for toxic patterns made of a single repeating byte.
    Tests all 256 byte values at different lengths.
    """
    print("=" * 60)
    print("SEARCH: Single Byte Patterns")
    print("=" * 60)
    print(f"Testing all 256 byte values at length {target_length}")
    print("-" * 60)
    
    toxic_patterns = []
    
    # Test all 256 byte values
    batch = []
    byte_values = list(range(256))
    
    for byte_val in byte_values:
        pattern = bytes([byte_val]) * target_length
        batch.append(pattern)
    
    print(f"Testing {len(batch)} single-byte patterns...", end=" ", flush=True)
    results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                  timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
    
    for (payload, successes, failures), byte_val in zip(results, byte_values):
        if successes == 0:  # TOXIC
            toxic_patterns.append((byte_val, payload))
            print(f"\n    ⚠️  TOXIC: 0x{byte_val:02x} × {target_length} = {payload.hex()[:60]}...")
    
    print(f"\nFound {len(toxic_patterns)} toxic single-byte patterns")
    return toxic_patterns


def search_minimal_single_byte(byte_val: int, max_length: int, use_cache: bool = True) -> Optional[int]:
    """
    Binary search for minimum length of single-byte pattern that's toxic.
    """
    print(f"\nBinary search for minimum length of 0x{byte_val:02x} pattern...")
    
    min_len = 1
    max_len = max_length
    shortest = None
    
    while min_len <= max_len:
        test_len = (min_len + max_len) // 2
        pattern = bytes([byte_val]) * test_len
        
        print(f"  Testing length {test_len}...", end=" ", flush=True)
        is_toxic = not test_payload_fast(pattern, timeout=BRUTE_FORCE_TIMEOUT)
        
        if is_toxic:
            shortest = test_len
            max_len = test_len - 1
            print("TOXIC ✓")
        else:
            min_len = test_len + 1
            print("SAFE")
    
    if shortest:
        print(f"  Minimum length: {shortest} bytes")
    return shortest


def simplify_pattern(pattern: bytes, use_cache: bool = True) -> bytes:
    """
    Try to simplify a pattern by reducing unique bytes.
    Uses hill climbing: try replacing bytes with most common byte.
    """
    print("=" * 60)
    print("SIMPLIFY: Pattern Simplification")
    print("=" * 60)
    print(f"Original: {len(pattern)} bytes, {len(set(pattern))} unique bytes")
    print("-" * 60)
    
    from collections import Counter
    
    current = pattern
    tested = {current}
    
    # Verify current is toxic
    print("Testing original pattern...", end=" ", flush=True)
    if not test_packet(current, use_cache):
        print("NOT TOXIC - cannot simplify")
        return current
    print("TOXIC ✓")
    
    # Try replacing bytes with most common byte
    for iteration in range(20):
        counts = Counter(current)
        most_common_byte = counts.most_common(1)[0][0]
        
        # Try replacing each unique byte with most common
        simplified = False
        for byte_val in set(current):
            if byte_val == most_common_byte:
                continue
            
            # Replace all occurrences of this byte
            new_pattern = current.replace(bytes([byte_val]), bytes([most_common_byte]))
            
            if new_pattern not in tested and new_pattern != current:
                tested.add(new_pattern)
                print(f"  Iter {iteration+1}: Replacing 0x{byte_val:02x} with 0x{most_common_byte:02x}...", end=" ", flush=True)
                
                is_toxic = test_packet(new_pattern, use_cache)
                if is_toxic:
                    current = new_pattern
                    simplified = True
                    unique = len(set(current))
                    print(f"TOXIC ✓ ({unique} unique bytes)")
                    break
                else:
                    print("SAFE")
        
        if not simplified:
            break
    
    print(f"\nSimplified to: {len(current)} bytes, {len(set(current))} unique bytes")
    return current


def test_packet(packet: bytes, use_cache: bool = True) -> bool:
    """Test if packet is toxic. Returns True if toxic."""
    cache = get_cache() if use_cache else None
    if cache and cache.is_cached(packet):
        return False  # Cached as SAFE
    
    return not test_payload_fast(packet, timeout=BRUTE_FORCE_TIMEOUT)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Search for simplest toxic pattern")
    parser.add_argument("--single-byte", type=int, default=None,
                       help="Test single-byte patterns at specified length")
    parser.add_argument("--minimal", type=int, default=None,
                       help="Find minimal length for single byte (specify byte value as hex, e.g. 0x22)")
    parser.add_argument("--simplify", action="store_true",
                       help="Simplify existing toxic pattern")
    parser.add_argument("--all", action="store_true",
                       help="Run all simplification strategies")
    parser.add_argument("--no-cache", action="store_true",
                       help="Disable pattern cache")
    parser.add_argument("--no-db", action="store_true",
                       help="Don't save to database")
    args = parser.parse_args()
    
    print("Simplest Pattern Search")
    print("=" * 60)
    
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
        print("Try running with sudo")
        return 1
    
    use_cache = not args.no_cache
    save_to_db = not args.no_db
    conn = init_pattern_variations_db() if save_to_db else None
    
    all_toxic = []
    
    try:
        # Get simplest known pattern
        simplest = get_simplest_toxic_pattern()
        if simplest:
            print(f"Starting from simplest known pattern: {len(simplest)} bytes")
            print(f"  Hex: {simplest.hex()[:80]}...")
            from collections import Counter
            counts = Counter(simplest)
            print(f"  Unique bytes: {len(counts)}")
            print(f"  Most common: 0x{counts.most_common(1)[0][0]:02x} × {counts.most_common(1)[0][1]}")
            print()
        
        if args.all or args.single_byte:
            target_length = args.single_byte or (len(simplest) if simplest else 794)
            toxic = search_single_byte_patterns(target_length, use_cache)
            for byte_val, payload in toxic:
                all_toxic.append(("single_byte", payload))
                if save_to_db:
                    save_pattern_variation(conn, "simplest", payload,
                                         f"Single byte 0x{byte_val:02x} × {len(payload)}",
                                         0, 1)
                    
                    # Also find minimal length for this byte
                    if args.all:
                        min_len = search_minimal_single_byte(byte_val, target_length, use_cache)
                        if min_len:
                            min_pattern = bytes([byte_val]) * min_len
                            all_toxic.append(("single_byte_minimal", min_pattern))
                            if save_to_db:
                                save_pattern_variation(conn, "simplest", min_pattern,
                                                     f"Minimal single byte 0x{byte_val:02x} × {min_len}",
                                                     0, 1)
        
        if args.all or args.minimal is not None:
            byte_val = args.minimal if args.minimal is not None else 0x22
            max_length = len(simplest) if simplest else 800
            min_len = search_minimal_single_byte(byte_val, max_length, use_cache)
            if min_len:
                min_pattern = bytes([byte_val]) * min_len
                all_toxic.append(("single_byte_minimal", min_pattern))
                if save_to_db:
                    save_pattern_variation(conn, "simplest", min_pattern,
                                         f"Minimal single byte 0x{byte_val:02x} × {min_len}",
                                         0, 1)
        
        if args.all or args.simplify:
            if simplest:
                simplified = simplify_pattern(simplest, use_cache)
                if simplified != simplest:
                    all_toxic.append(("simplified", simplified))
                    if save_to_db:
                        save_pattern_variation(conn, "simplest", simplified,
                                             f"Simplified from {len(simplest)} bytes",
                                             0, 1)
            else:
                print("No pattern to simplify - run other searches first")
        
        # Summary
        print("\n" + "=" * 60)
        if all_toxic:
            print(f"⚠️  FOUND {len(all_toxic)} SIMPLIFIED PATTERNS")
            print("=" * 60)
            for search_type, payload in all_toxic:
                from collections import Counter
                counts = Counter(payload)
                unique = len(counts)
                most_common = counts.most_common(1)[0] if counts else (0, 0)
                print(f"  [{search_type}] {len(payload)} bytes, {unique} unique bytes")
                print(f"    Most common: 0x{most_common[0]:02x} × {most_common[1]} ({most_common[1]/len(payload)*100:.1f}%)")
        else:
            print("✓ No simpler patterns found")
            print("=" * 60)
    finally:
        cleanup()
        if conn:
            conn.close()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted")
        cleanup()
        sys.exit(1)

