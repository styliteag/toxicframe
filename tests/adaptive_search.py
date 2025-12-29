#!/usr/bin/env python3
"""
Adaptive intelligent search for toxic patterns using feedback-guided exploration.

Uses test results to guide search direction:
- Hill climbing: Keep toxic variations, discard safe ones
- Binary search for optimal lengths
- Pattern mutation guided by results
"""

import sys
import random
import itertools
from typing import List, Tuple, Optional, Set
from pathlib import Path

from config import (
    BRUTE_FORCE_TIMEOUT, BRUTE_FORCE_ITERATIONS, BRUTE_FORCE_BATCH_SIZE,
    TOXIC_SMALLEST_BIN_PATH
)
from test_common import (
    test_payload_fast, test_payloads_batch,
    get_sender, get_receiver, cleanup
)
from db_common import init_pattern_variations_db, save_pattern_variation
from pattern_cache import get_cache


def analyze_toxic_smallest() -> Tuple[bytes, int, bytes]:
    """Analyze toxic_smallest.bin to extract pattern and suffix."""
    if not TOXIC_SMALLEST_BIN_PATH.exists():
        raise FileNotFoundError(f"toxic_smallest.bin not found at {TOXIC_SMALLEST_BIN_PATH}")
    
    data = TOXIC_SMALLEST_BIN_PATH.read_bytes()
    
    # Find repeating 14-byte pattern
    pattern = data[:14]
    repeats = 0
    for i in range(0, len(data), 14):
        if i + 14 <= len(data) and data[i:i+14] == pattern:
            repeats += 1
        else:
            break
    
    suffix = data[repeats * 14:]
    
    return pattern, repeats, suffix


def test_packet(packet: bytes, use_cache: bool = True) -> bool:
    """Test if packet is toxic. Returns True if toxic (not received)."""
    cache = get_cache() if use_cache else None
    if cache and cache.is_cached(packet):
        return False  # Cached as SAFE, so not toxic
    
    return not test_payload_fast(packet, timeout=BRUTE_FORCE_TIMEOUT)


def adaptive_suffix_length_search(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                                 use_cache: bool = True) -> Tuple[int, List[bytes]]:
    """
    Adaptive search for shortest suffix using binary search + feedback.
    Returns (shortest_length, list_of_toxic_suffixes_at_that_length)
    """
    print("=" * 60)
    print("ADAPTIVE: Suffix Length Search")
    print("=" * 60)
    print(f"Pattern: {base_pattern.hex()} × {base_repeats}")
    print(f"Base suffix: {len(base_suffix)} bytes")
    print("-" * 60)
    
    # Verify base is toxic
    full_base = base_pattern * base_repeats + base_suffix
    print("Testing base (full suffix)...", end=" ", flush=True)
    if not test_packet(full_base, use_cache):
        print("SAFE - base is not toxic!")
        return len(base_suffix), []
    print("TOXIC ✓")
    
    # Binary search for shortest length
    print("\nBinary search for shortest suffix length...")
    min_len = 1
    max_len = len(base_suffix)
    shortest_len = max_len
    toxic_suffixes = []
    
    while min_len <= max_len:
        test_len = (min_len + max_len) // 2
        test_suffix = base_suffix[:test_len]
        test_packet_bytes = base_pattern * base_repeats + test_suffix
        
        suffix_hex = test_suffix.hex()
        suffix_display = ' '.join(suffix_hex[i:i+2] for i in range(0, min(len(suffix_hex), 40), 2))
        if len(suffix_hex) > 40:
            suffix_display += "..."
        
        print(f"  Length {test_len}: {suffix_display}...", end=" ", flush=True)
        
        is_toxic = test_packet(test_packet_bytes, use_cache)
        
        if is_toxic:
            shortest_len = test_len
            max_len = test_len - 1
            toxic_suffixes.append(test_suffix)
            print("TOXIC ✓")
        else:
            min_len = test_len + 1
            print("SAFE")
    
    print(f"\nShortest toxic suffix length: {shortest_len} bytes")
    return shortest_len, toxic_suffixes


def adaptive_suffix_content_search(base_pattern: bytes, base_repeats: int, 
                                  target_length: int, known_toxic: bytes,
                                  use_cache: bool = True, max_iterations: int = 50) -> List[bytes]:
    """
    Adaptive search for suffix content variations using hill climbing.
    Starts from known toxic suffix and explores variations.
    """
    print("=" * 60)
    print("ADAPTIVE: Suffix Content Search")
    print("=" * 60)
    print(f"Target length: {target_length} bytes")
    print(f"Starting from: {known_toxic.hex()[:40]}...")
    print("-" * 60)
    
    toxic_suffixes = [known_toxic[:target_length]]
    tested: Set[bytes] = {known_toxic[:target_length]}
    
    # Hill climbing: try mutations of known toxic suffixes
    for iteration in range(max_iterations):
        if not toxic_suffixes:
            break
        
        # Pick a random toxic suffix to mutate
        current = random.choice(toxic_suffixes)
        mutations = []
        
        # Generate mutations: single byte changes
        for pos in range(len(current)):
            for byte_val in random.sample(range(256), min(10, 256)):  # Try 10 random values per position
                new_suffix = bytearray(current)
                new_suffix[pos] = byte_val
                new_suffix_bytes = bytes(new_suffix)
                
                if new_suffix_bytes not in tested:
                    tested.add(new_suffix_bytes)
                    mutations.append(new_suffix_bytes)
        
        if not mutations:
            continue
        
        # Test mutations in batch
        batch = [base_pattern * base_repeats + mut for mut in mutations]
        results = test_payloads_batch(batch, iterations=1, timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        new_toxic = []
        for (payload, successes, failures), mut in zip(results, mutations):
            if successes == 0:  # TOXIC
                if mut not in [s for s in toxic_suffixes]:
                    toxic_suffixes.append(mut)
                    new_toxic.append(mut)
                    suffix_hex = mut.hex()
                    suffix_display = ' '.join(suffix_hex[i:i+2] for i in range(0, min(len(suffix_hex), 40), 2))
                    print(f"  Iter {iteration+1}: Found toxic suffix: {suffix_display}...")
        
        if iteration % 10 == 0:
            print(f"  Iteration {iteration+1}: {len(toxic_suffixes)} toxic suffixes found")
    
    print(f"\nFound {len(toxic_suffixes)} toxic suffix variations")
    return toxic_suffixes


def adaptive_pattern_length_search(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                                   use_cache: bool = True) -> Tuple[int, List[bytes]]:
    """
    Adaptive search for shortest pattern length using binary search.
    """
    print("=" * 60)
    print("ADAPTIVE: Pattern Length Search")
    print("=" * 60)
    print(f"Base pattern: {base_pattern.hex()} ({len(base_pattern)} bytes)")
    print(f"Base repeats: {base_repeats}")
    print("-" * 60)
    
    # Verify base is toxic
    full_base = base_pattern * base_repeats + base_suffix
    print("Testing base pattern...", end=" ", flush=True)
    if not test_packet(full_base, use_cache):
        print("SAFE - base is not toxic!")
        return len(base_pattern), []
    print("TOXIC ✓")
    
    # Binary search for shortest pattern length
    print("\nBinary search for shortest pattern length...")
    min_len = 1
    max_len = len(base_pattern)
    shortest_len = max_len
    toxic_patterns = []
    
    while min_len <= max_len:
        test_len = (min_len + max_len) // 2
        test_pattern = base_pattern[:test_len]
        
        # Adjust repeats to keep similar total size
        target_size = len(base_pattern) * base_repeats + len(base_suffix)
        test_repeats = max(1, target_size // test_len)
        test_packet_bytes = test_pattern * test_repeats + base_suffix
        
        pattern_hex = test_pattern.hex()
        pattern_display = ' '.join(pattern_hex[i:i+2] for i in range(0, min(len(pattern_hex), 40), 2))
        if len(pattern_hex) > 40:
            pattern_display += "..."
        
        print(f"  Length {test_len} (×{test_repeats}): {pattern_display}...", end=" ", flush=True)
        
        is_toxic = test_packet(test_packet_bytes, use_cache)
        
        if is_toxic:
            shortest_len = test_len
            max_len = test_len - 1
            toxic_patterns.append(test_pattern)
            print("TOXIC ✓")
        else:
            min_len = test_len + 1
            print("SAFE")
    
    print(f"\nShortest toxic pattern length: {shortest_len} bytes")
    return shortest_len, toxic_patterns


def adaptive_pattern_content_search(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                                    target_length: int, use_cache: bool = True,
                                    max_iterations: int = 50) -> List[bytes]:
    """
    Adaptive search for pattern content variations using hill climbing.
    """
    print("=" * 60)
    print("ADAPTIVE: Pattern Content Search")
    print("=" * 60)
    print(f"Target length: {target_length} bytes")
    print(f"Starting from: {base_pattern[:target_length].hex()}")
    print("-" * 60)
    
    start_pattern = base_pattern[:target_length]
    toxic_patterns = [start_pattern]
    tested: Set[bytes] = {start_pattern}
    
    # Hill climbing
    for iteration in range(max_iterations):
        if not toxic_patterns:
            break
        
        current = random.choice(toxic_patterns)
        mutations = []
        
        # Generate mutations: single byte changes
        for pos in range(len(current)):
            for byte_val in random.sample(range(256), min(10, 256)):
                new_pattern = bytearray(current)
                new_pattern[pos] = byte_val
                new_pattern_bytes = bytes(new_pattern)
                
                if new_pattern_bytes not in tested:
                    tested.add(new_pattern_bytes)
                    mutations.append(new_pattern_bytes)
        
        if not mutations:
            continue
        
        # Test mutations
        batch = [mut * base_repeats + base_suffix for mut in mutations]
        results = test_payloads_batch(batch, iterations=1, timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        for (payload, successes, failures), mut in zip(results, mutations):
            if successes == 0:  # TOXIC
                if mut not in [p for p in toxic_patterns]:
                    toxic_patterns.append(mut)
                    pattern_hex = mut.hex()
                    pattern_display = ' '.join(pattern_hex[i:i+2] for i in range(0, min(len(pattern_hex), 40), 2))
                    print(f"  Iter {iteration+1}: Found toxic pattern: {pattern_display}...")
        
        if iteration % 10 == 0:
            print(f"  Iteration {iteration+1}: {len(toxic_patterns)} toxic patterns found")
    
    print(f"\nFound {len(toxic_patterns)} toxic pattern variations")
    return toxic_patterns


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Adaptive intelligent search for toxic patterns")
    parser.add_argument("--suffix-length", action="store_true",
                       help="Search for shortest suffix length")
    parser.add_argument("--suffix-content", action="store_true",
                       help="Search for suffix content variations")
    parser.add_argument("--pattern-length", action="store_true",
                       help="Search for shortest pattern length")
    parser.add_argument("--pattern-content", action="store_true",
                       help="Search for pattern content variations")
    parser.add_argument("--all", action="store_true",
                       help="Run all adaptive searches")
    parser.add_argument("--iterations", type=int, default=50,
                       help="Max iterations for content search (default: 50)")
    parser.add_argument("--no-cache", action="store_true",
                       help="Disable pattern cache")
    parser.add_argument("--no-db", action="store_true",
                       help="Don't save to database")
    args = parser.parse_args()
    
    print("Adaptive Intelligent Toxic Pattern Search")
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
    
    # Analyze base
    pattern, repeats, suffix = analyze_toxic_smallest()
    
    # Verify base is toxic
    full_base = pattern * repeats + suffix
    print("Verifying base pattern is toxic...", end=" ", flush=True)
    base_toxic = test_packet(full_base, use_cache=not args.no_cache)
    if not base_toxic:
        print("NOT TOXIC - cannot proceed")
        return 1
    print("TOXIC ✓\n")
    
    use_cache = not args.no_cache
    save_to_db = not args.no_db
    conn = init_pattern_variations_db() if save_to_db else None
    
    all_toxic = []
    
    try:
        if args.all or args.suffix_length:
            shortest_len, toxic_suffixes = adaptive_suffix_length_search(
                pattern, repeats, suffix, use_cache
            )
            for tox_suffix in toxic_suffixes:
                full_packet = pattern * repeats + tox_suffix
                all_toxic.append(("adaptive_suffix_length", full_packet))
                if save_to_db:
                    save_pattern_variation(conn, "adaptive", full_packet,
                                         f"Shortest suffix ({len(tox_suffix)} bytes)",
                                         0, 1)
        
        if args.all or args.suffix_content:
            if args.all or args.suffix_length:
                # Use shortest length found
                shortest_len, _ = adaptive_suffix_length_search(
                    pattern, repeats, suffix, use_cache
                )
                known_toxic = suffix[:shortest_len]
            else:
                shortest_len = len(suffix)
                known_toxic = suffix
            
            toxic_suffixes = adaptive_suffix_content_search(
                pattern, repeats, shortest_len, known_toxic, use_cache, args.iterations
            )
            for tox_suffix in toxic_suffixes:
                full_packet = pattern * repeats + tox_suffix
                all_toxic.append(("adaptive_suffix_content", full_packet))
                if save_to_db:
                    save_pattern_variation(conn, "adaptive", full_packet,
                                         f"Suffix content variation ({len(tox_suffix)} bytes)",
                                         0, 1)
        
        if args.all or args.pattern_length:
            shortest_len, toxic_patterns = adaptive_pattern_length_search(
                pattern, repeats, suffix, use_cache
            )
            for tox_pattern in toxic_patterns:
                # Adjust repeats
                target_size = len(pattern) * repeats + len(suffix)
                test_repeats = max(1, target_size // len(tox_pattern))
                full_packet = tox_pattern * test_repeats + suffix
                all_toxic.append(("adaptive_pattern_length", full_packet))
                if save_to_db:
                    save_pattern_variation(conn, "adaptive", full_packet,
                                         f"Shortest pattern ({len(tox_pattern)} bytes)",
                                         0, 1)
        
        if args.all or args.pattern_content:
            if args.all or args.pattern_length:
                shortest_len, _ = adaptive_pattern_length_search(
                    pattern, repeats, suffix, use_cache
                )
            else:
                shortest_len = len(pattern)
            
            toxic_patterns = adaptive_pattern_content_search(
                pattern, repeats, suffix, shortest_len, use_cache, args.iterations
            )
            for tox_pattern in toxic_patterns:
                full_packet = tox_pattern * repeats + suffix
                all_toxic.append(("adaptive_pattern_content", full_packet))
                if save_to_db:
                    save_pattern_variation(conn, "adaptive", full_packet,
                                         f"Pattern content variation ({len(tox_pattern)} bytes)",
                                         0, 1)
        
        # Summary
        print("\n" + "=" * 60)
        if all_toxic:
            print(f"⚠️  FOUND {len(all_toxic)} TOXIC PATTERNS")
            print("=" * 60)
            for search_type, payload in all_toxic:
                print(f"  [{search_type}] {len(payload)} bytes")
        else:
            print("✓ No additional toxic patterns found")
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

