#!/usr/bin/env python3
"""
Intelligent search for toxic patterns starting from toxic_smallest.bin.

Systematically explores variations of the known toxic pattern:
- Pattern byte mutations
- Suffix variations
- Repetition count changes
- Pattern length changes
"""

import sys
import itertools
import random
from pathlib import Path
from typing import List, Tuple, Optional

from config import (
    BRUTE_FORCE_TIMEOUT, BRUTE_FORCE_ITERATIONS, BRUTE_FORCE_BATCH_SIZE,
    TOXIC_SMALLEST_BIN_PATH
)
from test_common import (
    test_payloads_batch, test_payload_fast, get_sender, get_receiver, cleanup, get_toxic_bin_data
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
    
    print(f"Analyzed toxic_smallest.bin:")
    print(f"  Total size: {len(data)} bytes")
    print(f"  Pattern: {pattern.hex()} ({len(pattern)} bytes)")
    print(f"  Repeats: {repeats} times")
    print(f"  Suffix: {suffix.hex()[:40]}... ({len(suffix)} bytes)")
    print()
    
    return pattern, repeats, suffix


def search_pattern_mutations(base_pattern: bytes, max_mutations: int = 2,
                            batch_size: int = None, use_cache: bool = True):
    """Search by mutating pattern bytes."""
    batch_size = batch_size or BRUTE_FORCE_BATCH_SIZE
    print("=" * 60)
    print("SEARCH: Pattern Byte Mutations")
    print("=" * 60)
    print(f"Base pattern: {base_pattern.hex()}")
    print(f"Max mutations: {max_mutations}, Batch size: {batch_size}")
    print("-" * 60)
    
    toxic_patterns = []
    cache = get_cache() if use_cache else None
    
    for num_mutations in range(1, max_mutations + 1):
        print(f"\nTesting {num_mutations}-byte mutations...")
        batch = []
        batch_num = 0
        
        # Generate all combinations of positions to mutate
        for positions in itertools.combinations(range(len(base_pattern)), num_mutations):
            # Try all byte values for each position
            for byte_vals in itertools.product(range(256), repeat=num_mutations):
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
                    
                    for payload, successes, failures in results:
                        if successes == 0:  # TOXIC
                            toxic_patterns.append(("pattern_mutation", payload))
                            hex_str = payload.hex()
                            print(f"\n    ⚠️  TOXIC: {hex_str}")
                    
                    print(f"({len(toxic_patterns)} toxic)")
                    batch = []
        
        # Test remaining
        if batch:
            print(f"  Final batch...", end=" ", flush=True)
            results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                         timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
            for payload, successes, failures in results:
                if successes == 0:
                    toxic_patterns.append(("pattern_mutation", payload))
            print(f"({len(toxic_patterns)} toxic)")
    
    return toxic_patterns


def search_suffix_variations(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                            max_suffix_changes: int = 3, batch_size: int = None,
                            use_cache: bool = True):
    """Search by varying suffix bytes."""
    batch_size = batch_size or BRUTE_FORCE_BATCH_SIZE
    print("=" * 60)
    print("SEARCH: Suffix Variations")
    print("=" * 60)
    print(f"Pattern: {base_pattern.hex()} × {base_repeats}")
    print(f"Base suffix: {base_suffix.hex()[:40]}... ({len(base_suffix)} bytes)")
    print(f"Max suffix changes: {max_suffix_changes}")
    print("-" * 60)
    
    toxic_patterns = []
    cache = get_cache() if use_cache else None
    
    # Limit suffix search to first N bytes (suffix can be long)
    suffix_search_len = min(len(base_suffix), 20)  # Search first 20 bytes of suffix
    
    for num_changes in range(1, min(max_suffix_changes + 1, suffix_search_len + 1)):
        print(f"\nTesting {num_changes}-byte suffix mutations...")
        batch = []
        batch_num = 0
        
        # Generate mutations in first suffix_search_len bytes
        for positions in itertools.combinations(range(suffix_search_len), num_changes):
            for byte_vals in itertools.product(range(256), repeat=num_changes):
                new_suffix = bytearray(base_suffix)
                changed = False
                for pos, val in zip(positions, byte_vals):
                    if new_suffix[pos] != val:
                        new_suffix[pos] = val
                        changed = True
                
                if changed:
                    # Reconstruct full packet
                    full_packet = base_pattern * base_repeats + bytes(new_suffix)
                    batch.append(full_packet)
                
                if len(batch) >= batch_size:
                    batch_num += 1
                    print(f"  Batch {batch_num}...", end=" ", flush=True)
                    
                    results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                               timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
                    
                    for payload, successes, failures in results:
                        if successes == 0:
                            toxic_patterns.append(("suffix_mutation", payload))
                            print(f"\n    ⚠️  TOXIC: {payload.hex()[:60]}...")
                    
                    print(f"({len(toxic_patterns)} toxic)")
                    batch = []
        
        # Test remaining
        if batch:
            print(f"  Final batch...", end=" ", flush=True)
            results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                         timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
            for payload, successes, failures in results:
                if successes == 0:
                    toxic_patterns.append(("suffix_mutation", payload))
            print(f"({len(toxic_patterns)} toxic)")
    
    return toxic_patterns


def search_repetition_variations(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                                repeat_range: Tuple[int, int] = None, use_cache: bool = True):
    """Search by varying repetition count."""
    if repeat_range is None:
        repeat_range = (max(1, base_repeats - 5), base_repeats + 5)
    
    print("=" * 60)
    print("SEARCH: Repetition Count Variations")
    print("=" * 60)
    print(f"Pattern: {base_pattern.hex()}")
    print(f"Base repeats: {base_repeats}, Testing: {repeat_range[0]}-{repeat_range[1]}")
    print("-" * 60)
    
    toxic_patterns = []
    batch = []
    
    for repeats in range(repeat_range[0], repeat_range[1] + 1):
        if repeats == base_repeats:
            continue  # Skip base case
        
        full_packet = base_pattern * repeats + base_suffix
        batch.append(full_packet)
    
    if batch:
        print(f"Testing {len(batch)} repetition variations...", end=" ", flush=True)
        results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                    timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        for payload, successes, failures in results:
            if successes == 0:
                toxic_patterns.append(("repetition_variation", payload))
                print(f"\n    ⚠️  TOXIC: {len(payload)} bytes")
        
        print(f"({len(toxic_patterns)} toxic)")
    
    return toxic_patterns


def search_pattern_length_variations(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                                    use_cache: bool = True):
    """Search by varying pattern length (try sub-patterns)."""
    print("=" * 60)
    print("SEARCH: Pattern Length Variations")
    print("=" * 60)
    print(f"Base pattern: {base_pattern.hex()} ({len(base_pattern)} bytes)")
    print("-" * 60)
    
    toxic_patterns = []
    batch = []
    
    # Try shorter patterns (1 to len-1 bytes)
    for length in range(1, len(base_pattern)):
        sub_pattern = base_pattern[:length]
        # Try different repetition counts to keep similar total size
        target_size = len(base_pattern) * base_repeats + len(base_suffix)
        repeats = max(1, target_size // length)
        
        full_packet = sub_pattern * repeats + base_suffix
        if len(full_packet) <= target_size + 50:  # Don't make too large
            batch.append(full_packet)
    
    if batch:
        print(f"Testing {len(batch)} pattern length variations...", end=" ", flush=True)
        results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                    timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        for payload, successes, failures in results:
            if successes == 0:
                toxic_patterns.append(("pattern_length", payload))
                print(f"\n    ⚠️  TOXIC: {len(payload)} bytes")
        
        print(f"({len(toxic_patterns)} toxic)")
    
    return toxic_patterns


def search_shortest_suffix(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                          use_cache: bool = True, try_random: bool = True):
    """Search for the shortest suffix that still triggers toxicity."""
    print("=" * 60)
    print("SEARCH: Shortest Suffix")
    print("=" * 60)
    print(f"Pattern: {base_pattern.hex()} × {base_repeats}")
    print(f"Base suffix: {base_suffix.hex()[:40]}... ({len(base_suffix)} bytes)")
    print("-" * 60)
    
    toxic_patterns = []
    
    # First, verify base is toxic
    full_base = base_pattern * base_repeats + base_suffix
    print("Testing base (full suffix)...", end=" ", flush=True)
    base_result = test_payload_fast(full_base, timeout=BRUTE_FORCE_TIMEOUT)
    if base_result:
        print("SAFE - base is not toxic!")
        return toxic_patterns
    print("TOXIC ✓")
    
    # Binary search for shortest suffix length
    print("\nBinary search for shortest suffix length...")
    min_length = 1
    max_length = len(base_suffix)
    shortest_length = max_length
    
    while min_length <= max_length:
        test_length = (min_length + max_length) // 2
        # Use first test_length bytes of base suffix
        test_suffix = base_suffix[:test_length]
        test_packet = base_pattern * base_repeats + test_suffix
        
        suffix_hex = test_suffix.hex()
        suffix_display = ' '.join(suffix_hex[i:i+2] for i in range(0, min(len(suffix_hex), 40), 2))
        if len(suffix_hex) > 40:
            suffix_display += "..."
        
        print(f"  Testing suffix length {test_length}: {suffix_display}...", end=" ", flush=True)
        is_toxic = not test_payload_fast(test_packet, timeout=BRUTE_FORCE_TIMEOUT)
        
        if is_toxic:
            shortest_length = test_length
            max_length = test_length - 1
            print("TOXIC ✓")
        else:
            min_length = test_length + 1
            print("SAFE")
    
    print(f"\nShortest suffix length: {shortest_length} bytes")
    
    # Now test different byte values at that length
    print(f"\nTesting different {shortest_length}-byte suffix values...")
    
    # Strategy 1: Try original suffix bytes
    original_suffix = base_suffix[:shortest_length]
    test_packet = base_pattern * base_repeats + original_suffix
    suffix_hex = original_suffix.hex()
    suffix_display = ' '.join(suffix_hex[i:i+2] for i in range(0, len(suffix_hex), 2))
    print(f"  Original bytes ({shortest_length}): {suffix_display}...", end=" ", flush=True)
    if not test_payload_fast(test_packet, timeout=BRUTE_FORCE_TIMEOUT):
        toxic_patterns.append(("shortest_suffix", test_packet))
        print("TOXIC ✓")
    else:
        print("SAFE")
    
    # Strategy 2: Try all zeros
    zero_suffix = b'\x00' * shortest_length
    test_packet = base_pattern * base_repeats + zero_suffix
    suffix_display = ' '.join(['00'] * min(shortest_length, 20))
    if shortest_length > 20:
        suffix_display += f" ... ({shortest_length} bytes)"
    print(f"  All zeros ({shortest_length}): {suffix_display}...", end=" ", flush=True)
    if not test_payload_fast(test_packet, timeout=BRUTE_FORCE_TIMEOUT):
        toxic_patterns.append(("shortest_suffix", test_packet))
        print("TOXIC ✓")
    else:
        print("SAFE")
    
    # Strategy 3: Try all 0xFF
    ff_suffix = b'\xff' * shortest_length
    test_packet = base_pattern * base_repeats + ff_suffix
    suffix_display = ' '.join(['ff'] * min(shortest_length, 20))
    if shortest_length > 20:
        suffix_display += f" ... ({shortest_length} bytes)"
    print(f"  All 0xFF ({shortest_length}): {suffix_display}...", end=" ", flush=True)
    if not test_payload_fast(test_packet, timeout=BRUTE_FORCE_TIMEOUT):
        toxic_patterns.append(("shortest_suffix", test_packet))
        print("TOXIC ✓")
    else:
        print("SAFE")
    
    # Strategy 4: Try pattern bytes repeated
    if shortest_length >= len(base_pattern):
        pattern_suffix = (base_pattern * ((shortest_length // len(base_pattern)) + 1))[:shortest_length]
        test_packet = base_pattern * base_repeats + pattern_suffix
        suffix_hex = pattern_suffix.hex()
        suffix_display = ' '.join(suffix_hex[i:i+2] for i in range(0, min(len(suffix_hex), 40), 2))
        if len(suffix_hex) > 40:
            suffix_display += "..."
        print(f"  Pattern repeated ({shortest_length}): {suffix_display}...", end=" ", flush=True)
        if not test_payload_fast(test_packet, timeout=BRUTE_FORCE_TIMEOUT):
            toxic_patterns.append(("shortest_suffix", test_packet))
            print("TOXIC ✓")
        else:
            print("SAFE")
    
    # Strategy 5: Try random bytes (if enabled)
    if try_random:
        print(f"\nTesting random {shortest_length}-byte suffixes...")
        batch = []
        for i in range(100):  # Test 100 random suffixes
            random_suffix = bytes([random.randint(0, 255) for _ in range(shortest_length)])
            test_packet = base_pattern * base_repeats + random_suffix
            batch.append(test_packet)
        
        results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                    timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        for payload, successes, failures in results:
            if successes == 0:  # TOXIC
                toxic_patterns.append(("shortest_suffix_random", payload))
                suffix = payload[base_repeats * len(base_pattern):]
                suffix_hex = suffix.hex()
                suffix_display = ' '.join(suffix_hex[i:i+2] for i in range(0, len(suffix_hex), 2))
                print(f"    ⚠️  TOXIC random suffix ({len(suffix)}): {suffix_display}")
        
        print(f"  Found {len([p for t, p in toxic_patterns if t == 'shortest_suffix_random'])} toxic random suffixes")
    
    # Strategy 6: Try single-byte variations (if length is 1)
    if shortest_length == 1:
        print(f"\nTesting all 256 single-byte values...")
        batch = []
        for byte_val in range(256):
            test_packet = base_pattern * base_repeats + bytes([byte_val])
            batch.append(test_packet)
        
        results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                    timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        toxic_bytes = []
        for payload, successes, failures in results:
            if successes == 0:  # TOXIC
                toxic_patterns.append(("shortest_suffix", payload))
                suffix_byte = payload[base_repeats * len(base_pattern)]
                toxic_bytes.append(suffix_byte)
        
        if toxic_bytes:
            unique_toxic = sorted(set(toxic_bytes))
            print(f"  Found {len(toxic_bytes)} toxic byte values ({len(unique_toxic)} unique):")
            # Show in groups of 16 for readability
            for i in range(0, len(unique_toxic), 16):
                group = unique_toxic[i:i+16]
                hex_vals = [hex(b) for b in group]
                print(f"    {', '.join(hex_vals)}")
        else:
            print("  No toxic single-byte values found")
    
    return toxic_patterns


def search_bit_flips(base_pattern: bytes, base_repeats: int, base_suffix: bytes,
                    max_flips: int = 1, use_cache: bool = True):
    """Search by flipping bits in pattern."""
    print("=" * 60)
    print("SEARCH: Bit Flips in Pattern")
    print("=" * 60)
    print(f"Base pattern: {base_pattern.hex()}")
    print("-" * 60)
    
    toxic_patterns = []
    batch = []
    
    for byte_idx in range(len(base_pattern)):
        for bit_idx in range(8):
            new_pattern = bytearray(base_pattern)
            new_pattern[byte_idx] ^= (1 << bit_idx)
            
            full_packet = bytes(new_pattern) * base_repeats + base_suffix
            batch.append(full_packet)
    
    if batch:
        print(f"Testing {len(batch)} bit-flipped patterns...", end=" ", flush=True)
        results = test_payloads_batch(batch, iterations=BRUTE_FORCE_ITERATIONS,
                                    timeout=BRUTE_FORCE_TIMEOUT, use_cache=use_cache)
        
        for payload, successes, failures in results:
            if successes == 0:
                toxic_patterns.append(("bit_flip", payload))
                print(f"\n    ⚠️  TOXIC: {payload.hex()[:60]}...")
        
        print(f"({len(toxic_patterns)} toxic)")
    
    return toxic_patterns


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Intelligent search for toxic patterns")
    parser.add_argument("--pattern-mutations", type=int, default=0,
                       help="Max pattern byte mutations (0 = disabled)")
    parser.add_argument("--suffix-mutations", type=int, default=0,
                       help="Max suffix byte mutations (0 = disabled)")
    parser.add_argument("--repetitions", action="store_true",
                       help="Test repetition count variations")
    parser.add_argument("--pattern-length", action="store_true",
                       help="Test pattern length variations")
    parser.add_argument("--bit-flips", action="store_true",
                       help="Test bit flips")
    parser.add_argument("--shortest-suffix", action="store_true",
                       help="Find shortest suffix that triggers toxicity")
    parser.add_argument("--no-random", action="store_true",
                       help="Don't test random suffix bytes (for --shortest-suffix)")
    parser.add_argument("--all", action="store_true",
                       help="Run all search strategies")
    parser.add_argument("--no-cache", action="store_true",
                       help="Disable pattern cache")
    parser.add_argument("--no-db", action="store_true",
                       help="Don't save to database")
    args = parser.parse_args()
    
    print("Intelligent Toxic Pattern Search")
    print("=" * 60)
    
    # Check API first
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
    
    # Analyze base pattern
    pattern, repeats, suffix = analyze_toxic_smallest()
    
    # Verify base pattern is toxic
    print("Verifying base pattern is toxic...", end=" ", flush=True)
    full_packet = pattern * repeats + suffix
    
    # Test multiple times to be sure
    test_results = []
    for i in range(5):
        arrived = test_payload_fast(full_packet, timeout=BRUTE_FORCE_TIMEOUT)
        test_results.append(arrived)
    
    successes = sum(test_results)
    failures = len(test_results) - successes
    
    if successes == 0:
        print(f"✓ TOXIC confirmed ({failures}/{len(test_results)} failed)")
        print()
    elif successes == len(test_results):
        print(f"✗ NOT TOXIC ({successes}/{len(test_results)} succeeded)")
        print("ERROR: Base pattern is not toxic! Something is wrong.")
        print("Cannot proceed with intelligent search.")
        return 1
    else:
        print(f"⚠ MAYBE ({successes}/{len(test_results)} succeeded)")
        print("WARNING: Base pattern shows intermittent behavior.")
        print("Proceeding with search anyway...")
        print()
    
    use_cache = not args.no_cache
    save_to_db = not args.no_db
    conn = init_pattern_variations_db() if save_to_db else None
    
    all_toxic = []
    
    # If no specific strategy selected, default to pattern mutations only
    if not (args.all or args.pattern_mutations > 0 or args.suffix_mutations > 0 or 
            args.repetitions or args.pattern_length or args.bit_flips or args.shortest_suffix):
        args.pattern_mutations = 1  # Default to 1-byte pattern mutations
    
    try:
        if args.all or args.pattern_mutations > 0:
            toxic = search_pattern_mutations(pattern, args.pattern_mutations, use_cache=use_cache)
            all_toxic.extend(toxic)
            if save_to_db:
                for search_type, payload in toxic:
                    save_pattern_variation(conn, "intelligent", payload,
                                         f"{search_type}: {payload.hex()[:40]}...",
                                         0, 1)
        
        if args.all or args.suffix_mutations > 0:
            toxic = search_suffix_variations(pattern, repeats, suffix, args.suffix_mutations, use_cache=use_cache)
            all_toxic.extend(toxic)
            if save_to_db:
                for search_type, payload in toxic:
                    save_pattern_variation(conn, "intelligent", payload,
                                         f"{search_type}: {payload.hex()[:40]}...",
                                         0, 1)
        
        if args.all or args.repetitions:
            toxic = search_repetition_variations(pattern, repeats, suffix, use_cache=use_cache)
            all_toxic.extend(toxic)
            if save_to_db:
                for search_type, payload in toxic:
                    save_pattern_variation(conn, "intelligent", payload,
                                         f"{search_type}: {len(payload)} bytes",
                                         0, 1)
        
        if args.all or args.pattern_length:
            toxic = search_pattern_length_variations(pattern, repeats, suffix, use_cache=use_cache)
            all_toxic.extend(toxic)
            if save_to_db:
                for search_type, payload in toxic:
                    save_pattern_variation(conn, "intelligent", payload,
                                         f"{search_type}: {len(payload)} bytes",
                                         0, 1)
        
        if args.all or args.bit_flips:
            toxic = search_bit_flips(pattern, repeats, suffix, use_cache=use_cache)
            all_toxic.extend(toxic)
            if save_to_db:
                for search_type, payload in toxic:
                    save_pattern_variation(conn, "intelligent", payload,
                                         f"{search_type}: {payload.hex()[:40]}...",
                                         0, 1)
        
        if args.all or args.shortest_suffix:
            toxic = search_shortest_suffix(pattern, repeats, suffix, use_cache=use_cache,
                                         try_random=not args.no_random)
            all_toxic.extend(toxic)
            if save_to_db:
                for search_type, payload in toxic:
                    save_pattern_variation(conn, "intelligent", payload,
                                         f"{search_type}: {len(payload)} bytes",
                                         0, 1)
        
        # Summary
        print("\n" + "=" * 60)
        if all_toxic:
            print(f"⚠️  FOUND {len(all_toxic)} TOXIC PATTERNS")
            print("=" * 60)
            for search_type, payload in all_toxic:
                hex_str = payload.hex()
                print(f"  [{search_type}] {len(payload)} bytes: {hex_str[:60]}...")
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

