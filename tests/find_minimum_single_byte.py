#!/usr/bin/env python3
"""
Find minimum length for single-byte toxic patterns.

1. Test random single-byte patterns at 794 bytes
2. Find which bytes are toxic
3. Binary search for minimum length
"""

import sys
import random
import argparse
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).parent))

from test_common import test_payload_fast, get_sender, get_receiver, cleanup
from config import BRUTE_FORCE_TIMEOUT, TEST_ITERATIONS
from db_common import init_database, save_test_result


def test_single_byte_pattern(byte_val: int, length: int, iterations: int = TEST_ITERATIONS) -> Tuple[int, int]:
    """Test a single-byte pattern at given length."""
    payload = bytes([byte_val]) * length
    successes, failures = 0, 0
    
    for _ in range(iterations):
        if test_payload_fast(payload, timeout=BRUTE_FORCE_TIMEOUT):
            successes += 1
        else:
            failures += 1
    
    return successes, failures


def find_toxic_bytes_at_length(length: int, num_samples: int = 50) -> List[int]:
    """Test random single-byte patterns to find which bytes are toxic."""
    print(f"Testing {num_samples} random single-byte patterns at {length} bytes...")
    print("=" * 80)
    
    toxic_bytes = []
    tested_bytes = set()
    
    # Always test known toxic bytes first
    known_toxic = [0x4a, 0xb5]
    for byte_val in known_toxic:
        if byte_val not in tested_bytes:
            print(f"Testing 0x{byte_val:02x}...", end=" ", flush=True)
            successes, failures = test_single_byte_pattern(byte_val, length, iterations=TEST_ITERATIONS)
            tested_bytes.add(byte_val)
            
            if successes == 0:
                print(f"✓ TOXIC ({failures}/{TEST_ITERATIONS})")
                toxic_bytes.append(byte_val)
            else:
                print(f"SAFE ({successes}/{TEST_ITERATIONS})")
    
    # Test random bytes
    random_bytes = random.sample([b for b in range(256) if b not in tested_bytes], 
                                 min(num_samples - len(tested_bytes), 256 - len(tested_bytes)))
    
    for byte_val in random_bytes:
        print(f"Testing 0x{byte_val:02x}...", end=" ", flush=True)
        successes, failures = test_single_byte_pattern(byte_val, length, iterations=TEST_ITERATIONS)
        tested_bytes.add(byte_val)
        
        if successes == 0:
            print(f"✓ TOXIC ({failures}/{TEST_ITERATIONS})")
            toxic_bytes.append(byte_val)
        elif successes == TEST_ITERATIONS:
            print(f"SAFE ({successes}/{TEST_ITERATIONS})")
        else:
            print(f"INTERMITTENT ({successes}/{TEST_ITERATIONS})")
    
    return toxic_bytes


def binary_search_minimum_length(byte_val: int, start_length: int = 794) -> int:
    """Binary search for minimum toxic length for a single-byte pattern."""
    print(f"\nBinary search for minimum length (byte 0x{byte_val:02x})...")
    print("=" * 80)
    
    # First verify start_length is toxic
    print(f"Verifying {start_length} bytes is toxic...", end=" ", flush=True)
    successes, failures = test_single_byte_pattern(byte_val, start_length, iterations=TEST_ITERATIONS)
    if successes > 0:
        print(f"SAFE - {start_length} bytes is not toxic!")
        return -1
    print(f"✓ TOXIC")
    
    # Binary search
    min_length = 1
    max_length = start_length
    minimum_toxic = start_length
    
    while min_length <= max_length:
        test_length = (min_length + max_length) // 2
        print(f"Testing {test_length} bytes...", end=" ", flush=True)
        
        successes, failures = test_single_byte_pattern(byte_val, test_length, iterations=TEST_ITERATIONS)
        
        if successes == 0:  # Toxic
            minimum_toxic = test_length
            max_length = test_length - 1
            print(f"✓ TOXIC (min so far: {minimum_toxic})")
        else:  # Safe
            min_length = test_length + 1
            print(f"SAFE ({successes}/{TEST_ITERATIONS})")
    
    return minimum_toxic


def main():
    parser = argparse.ArgumentParser(description="Find minimum length for single-byte toxic patterns")
    parser.add_argument("--length", type=int, default=794, help="Length to test random bytes at (default: 794)")
    parser.add_argument("--samples", type=int, default=50, help="Number of random bytes to test (default: 50)")
    parser.add_argument("--byte", type=str, help="Test specific byte (hex, e.g., 4a)")
    parser.add_argument("--min-only", action="store_true", help="Only find minimum length, skip random testing")
    args = parser.parse_args()
    
    # Initialize
    sender = get_sender()
    if not sender.health_check():
        print("ERROR: Cannot reach packetgen API")
        sys.exit(1)
    
    get_receiver()
    init_database()
    
    try:
        if args.byte:
            # Test specific byte
            byte_val = int(args.byte, 16)
            print(f"Testing byte 0x{byte_val:02x} at {args.length} bytes...")
            successes, failures = test_single_byte_pattern(byte_val, args.length, iterations=TEST_ITERATIONS)
            print(f"Result: {successes} successes, {failures} failures")
            
            if successes == 0:
                min_length = binary_search_minimum_length(byte_val, args.length)
                print(f"\n{'='*80}")
                print(f"Minimum toxic length for 0x{byte_val:02x}: {min_length} bytes")
            else:
                print(f"Byte 0x{byte_val:02x} is not toxic at {args.length} bytes")
        
        elif args.min_only:
            # Just find minimum for known toxic bytes
            known_toxic = [0x4a, 0xb5]
            results = []
            
            for byte_val in known_toxic:
                min_length = binary_search_minimum_length(byte_val, args.length)
                if min_length > 0:
                    results.append((byte_val, min_length))
            
            print(f"\n{'='*80}")
            print("MINIMUM TOXIC LENGTHS:")
            print("=" * 80)
            for byte_val, min_len in results:
                print(f"  0x{byte_val:02x}: {min_len} bytes")
        
        else:
            # Find toxic bytes, then find minimum length
            toxic_bytes = find_toxic_bytes_at_length(args.length, args.samples)
            
            if not toxic_bytes:
                print("\nNo toxic bytes found!")
                return
            
            print(f"\n{'='*80}")
            print(f"Found {len(toxic_bytes)} toxic bytes: {[hex(b) for b in toxic_bytes]}")
            print("=" * 80)
            
            # Find minimum length for each toxic byte
            results = []
            for byte_val in toxic_bytes:
                min_length = binary_search_minimum_length(byte_val, args.length)
                if min_length > 0:
                    results.append((byte_val, min_length))
            
            print(f"\n{'='*80}")
            print("MINIMUM TOXIC LENGTHS:")
            print("=" * 80)
            for byte_val, min_len in results:
                print(f"  0x{byte_val:02x}: {min_len} bytes")
                # Save to binary file
                output_file = Path(f"../binarys/minimum_0x{byte_val:02x}.bin")
                output_file.write_bytes(bytes([byte_val]) * min_len)
                print(f"    Saved: {output_file}")
    
    finally:
        cleanup()


if __name__ == "__main__":
    main()

