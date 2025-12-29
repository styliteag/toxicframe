#!/usr/bin/env python3
"""
Ultra-fast brute force search for toxic patterns.

Tests patterns in parallel batches for maximum speed.
"""

import sys
import itertools
from typing import List, Tuple

from config import (
    PATTERN_LEN, BRUTE_FORCE_TIMEOUT, BRUTE_FORCE_ITERATIONS, BRUTE_FORCE_BATCH_SIZE
)
from test_common import (
    test_payloads_batch, test_payload_fast,
    get_sender, get_receiver, cleanup, classify_result
)
from db_common import init_pattern_variations_db, save_pattern_variation
from pattern_cache import get_cache


def generate_all_patterns(length: int) -> List[bytes]:
    """Generate all possible byte patterns of given length."""
    patterns = []
    for combo in itertools.product(range(256), repeat=length):
        patterns.append(bytes(combo))
    return patterns


def generate_pattern_variations(base: bytes, max_changes: int = 1) -> List[bytes]:
    """Generate patterns with up to max_changes bytes modified."""
    patterns = [base]
    
    for num_changes in range(1, max_changes + 1):
        # Generate all combinations of positions to change
        for positions in itertools.combinations(range(len(base)), num_changes):
            # For each position, try all 255 possible byte values
            for byte_vals in itertools.product(range(256), repeat=num_changes):
                new_pattern = bytearray(base)
                for pos, val in zip(positions, byte_vals):
                    if new_pattern[pos] != val:  # Skip if unchanged
                        new_pattern[pos] = val
                        patterns.append(bytes(new_pattern))
    
    return patterns


def brute_force_small_patterns(max_length: int = 4, batch_size: int = None, 
                                save_to_db: bool = True, use_cache: bool = True):
    """Brute force search for small toxic patterns."""
    batch_size = batch_size or BRUTE_FORCE_BATCH_SIZE
    print(f"Brute force search for patterns up to {max_length} bytes")
    print(f"Batch size: {batch_size}, Timeout: {BRUTE_FORCE_TIMEOUT}s")
    if save_to_db:
        print("Saving TOXIC patterns to database")
    
    cache = get_cache()
    stats = cache.get_stats()
    print(f"Cache: {stats['total_cached']:,} SAFE patterns cached")
    print("=" * 60)
    
    toxic_patterns = []
    total_tested = 0
    total_skipped = 0
    conn = init_pattern_variations_db() if save_to_db else None
    
    for length in range(1, max_length + 1):
        print(f"\nTesting {length}-byte patterns...")
        total_for_length = 256 ** length
        print(f"Total: {total_for_length:,} patterns")
        
        # Generate in batches
        batch = []
        batch_num = 0
        
        for combo in itertools.product(range(256), repeat=length):
            batch.append(bytes(combo))
            
            if len(batch) >= batch_size:
                batch_num += 1
                print(f"  Batch {batch_num} ({len(batch)} patterns)...", end=" ", flush=True)
                
                results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                             timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
                # Count actual tests (some may have been cached)
                actual_tested = len([r for r in results if r[1] > 0 or r[2] > 0])
                total_tested += actual_tested
                total_skipped += len(batch) - actual_tested
                
                # Check for toxic patterns (only save TOXIC to DB)
                for payload, successes, failures in results:
                    if successes == 0:  # TOXIC
                        toxic_patterns.append((length, payload))
                        hex_str = payload.hex()
                        print(f"\n    ⚠️  TOXIC FOUND: {hex_str} ({length} bytes)")
                        print(f"       Pattern: {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}")
                        if conn:
                            save_pattern_variation(conn, "bruteforce", payload,
                                                  f"Brute force {length}-byte pattern",
                                                  successes, failures)
                            print(f"       ✓ Saved to database")
                
                print(f"({total_tested:,}/{total_for_length:,})")
                batch = []
        
        # Test remaining
        if batch:
            print(f"  Final batch ({len(batch)} patterns)...", end=" ", flush=True)
            results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                         timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
            actual_tested = len([r for r in results if r[1] > 0 or r[2] > 0])
            total_tested += actual_tested
            total_skipped += len(batch) - actual_tested
            
            for payload, successes, failures in results:
                if successes == 0:
                    toxic_patterns.append((length, payload))
                    hex_str = payload.hex()
                    print(f"\n    ⚠️  TOXIC FOUND: {hex_str} ({length} bytes)")
                    print(f"       Pattern: {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}")
                    if conn:
                        save_pattern_variation(conn, "bruteforce", payload,
                                              f"Brute force {length}-byte pattern",
                                              successes, failures)
                        print(f"       ✓ Saved to database")
            
            print(f"({total_tested:,} tested, {total_skipped:,} cached/{total_for_length:,})")
    
    if conn:
        conn.close()
    
    # Show final cache stats
    final_stats = cache.get_stats()
    print(f"\nCache stats: {final_stats['total_cached']:,} SAFE patterns cached")
    
    return toxic_patterns


def brute_force_variations(base_pattern: bytes, max_changes: int = 2, 
                           batch_size: int = None, save_to_db: bool = True, use_cache: bool = True):
    """Brute force search around a base pattern."""
    batch_size = batch_size or BRUTE_FORCE_BATCH_SIZE
    print(f"Brute force variations of base pattern")
    print(f"Base: {base_pattern.hex()}")
    print(f"Max changes: {max_changes}, Batch size: {batch_size}, Timeout: {BRUTE_FORCE_TIMEOUT}s")
    if save_to_db:
        print("Saving TOXIC patterns to database")
    
    cache = get_cache()
    stats = cache.get_stats()
    print(f"Cache: {stats['total_cached']:,} SAFE patterns cached")
    print("=" * 60)
    
    toxic_patterns = []
    total_tested = 0
    total_skipped = 0
    conn = init_pattern_variations_db() if save_to_db else None
    
    # Generate variations in batches
    batch = []
    batch_num = 0
    
    for num_changes in range(1, max_changes + 1):
        print(f"\nTesting {num_changes}-byte variations...")
        
        for positions in itertools.combinations(range(len(base_pattern)), num_changes):
            for byte_vals in itertools.product(range(256), repeat=num_changes):
                new_pattern = bytearray(base_pattern)
                changed = False
                for pos, val in zip(positions, byte_vals):
                    if new_pattern[pos] != val:
                        new_pattern[pos] = val
                        changed = True
                
                if changed:
                    batch.append(bytes(new_pattern))
                
                if len(batch) >= batch_size:
                    batch_num += 1
                    print(f"  Batch {batch_num}...", end=" ", flush=True)
                    
                    results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                                 timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
                    
                    actual_tested = len([r for r in results if r[1] > 0 or r[2] > 0])
                    total_tested += actual_tested
                    total_skipped += len(batch) - actual_tested
                    
                    for payload, successes, failures in results:
                        if successes == 0:
                            toxic_patterns.append(payload)
                            hex_str = payload.hex()
                            print(f"\n    ⚠️  TOXIC FOUND: {hex_str}")
                            print(f"       Pattern: {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}")
                            if conn:
                                save_pattern_variation(conn, "bruteforce", payload,
                                                      f"Variation of {base_pattern.hex()}",
                                                      successes, failures)
                                print(f"       ✓ Saved to database")
                    
                    print(f"({len(toxic_patterns)} toxic, {total_tested} tested, {total_skipped} cached)")
                    batch = []
        
        # Test remaining
        if batch:
            print(f"  Final batch...", end=" ", flush=True)
            results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                         timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
            
            actual_tested = len([r for r in results if r[1] > 0 or r[2] > 0])
            total_tested += actual_tested
            total_skipped += len(batch) - actual_tested
            
            for payload, successes, failures in results:
                if successes == 0:
                    toxic_patterns.append(payload)
                    hex_str = payload.hex()
                    print(f"\n    ⚠️  TOXIC FOUND: {hex_str}")
                    print(f"       Pattern: {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}")
                    if conn:
                        save_pattern_variation(conn, "bruteforce", payload,
                                              f"Variation of {base_pattern.hex()}",
                                              successes, failures)
                        print(f"       ✓ Saved to database")
            
            print(f"({len(toxic_patterns)} toxic, {total_tested} tested, {total_skipped} cached)")
            batch = []
    
    if conn:
        conn.close()
    
    # Show final cache stats
    final_stats = cache.get_stats()
    print(f"\nCache stats: {final_stats['total_cached']:,} SAFE patterns cached")
    
    return toxic_patterns


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Brute force search for toxic patterns")
    parser.add_argument("--max-length", type=int, default=3, 
                       help="Maximum pattern length to test (default: 3)")
    parser.add_argument("--batch-size", type=int, default=None,
                       help=f"Batch size for parallel testing (default: {BRUTE_FORCE_BATCH_SIZE})")
    parser.add_argument("--variations", type=str, default=None,
                       help="Base pattern hex for variation search")
    parser.add_argument("--max-changes", type=int, default=2,
                       help="Max bytes to change in variation search")
    parser.add_argument("--no-db", action="store_true",
                       help="Don't save results to database")
    parser.add_argument("--no-cache", action="store_true",
                       help="Don't use pattern cache (test all patterns)")
    parser.add_argument("--clear-cache", action="store_true",
                       help="Clear pattern cache before starting")
    args = parser.parse_args()
    
    print("Ultra-Fast Brute Force Pattern Search")
    print("=" * 60)
    
    # Check API
    sender = get_sender()
    if not sender.health_check():
        print("ERROR: Cannot reach packetgen API")
        return 1
    print("Packetgen API: OK")
    
    try:
        get_receiver()
        print("BPF receiver: OK")
    except Exception as e:
        print(f"ERROR: BPF: {e}")
        print("Try running with sudo")
        return 1
    
    # Handle cache
    use_cache = not args.no_cache
    if args.clear_cache:
        from pattern_cache import clear_cache
        clear_cache()
        print("Cache cleared")
    if not use_cache:
        print("Cache disabled")
    print()
    
    try:
        save_to_db = not args.no_db
        use_cache = not args.no_cache
        
        if args.variations:
            base = bytes.fromhex(args.variations)
            toxic = brute_force_variations(base, args.max_changes, args.batch_size, save_to_db, use_cache)
        else:
            toxic = brute_force_small_patterns(args.max_length, args.batch_size, save_to_db, use_cache)
        
        print("\n" + "=" * 60)
        if toxic:
            print(f"⚠️  FOUND {len(toxic)} TOXIC PATTERN(S)")
            print("=" * 60)
            for item in toxic:
                if isinstance(item, tuple):
                    length, pattern = item
                    hex_str = pattern.hex()
                    print(f"  {length} bytes: {hex_str}")
                    print(f"    {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}")
                else:
                    hex_str = item.hex()
                    print(f"  {hex_str}")
                    print(f"    {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}")
        else:
            print("✓ No toxic patterns found")
            print("=" * 60)
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

