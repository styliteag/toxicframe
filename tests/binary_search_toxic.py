#!/usr/bin/env python3
"""
Binary search to find the smallest toxic packet in toxic.bin.
Uses raw Ethernet packets via packetgen API.
"""

import sys
from typing import Tuple, Optional

from config import BINARY_SEARCH_ITERATIONS as TEST_ITERATIONS
from test_common import (
    test_payload,
    get_toxic_bin_data,
    classify_result,
    get_sender,
    get_receiver,
    cleanup
)

# Fewer iterations for binary search speed
SEARCH_ITERATIONS = 3


def test_range(start: int, end: int, debug: bool = False) -> Tuple[int, int]:
    """Test a byte range. Returns (successes, failures)."""
    data = get_toxic_bin_data()
    if end >= len(data):
        return (0, SEARCH_ITERATIONS)
    
    range_data = data[start:end + 1]
    return test_payload(range_data, SEARCH_ITERATIONS)


def is_toxic_range(start: int, end: int, debug: bool = False) -> bool:
    """Check if a byte range is toxic (always fails)."""
    successes, failures = test_range(start, end, debug)
    is_toxic = successes == 0
    status = "TOXIC" if is_toxic else "SAFE" if successes == SEARCH_ITERATIONS else "MAYBE"
    print(f"{status} ({successes}/{SEARCH_ITERATIONS})", flush=True)
    return is_toxic


def get_file_size() -> int:
    """Get the size of toxic.bin."""
    return len(get_toxic_bin_data())


def binary_search_smallest_toxic() -> Optional[Tuple[int, int]]:
    """Binary search to find the smallest toxic range."""
    file_size = get_file_size()
    print(f"File size: {file_size} bytes")
    print("-" * 60)
    
    # Test full file
    print(f"Testing full file (0-{file_size-1})...", end=" ", flush=True)
    if not is_toxic_range(0, file_size - 1):
        print("\nFull file is SAFE!")
        return None
    
    # Binary search for smallest end from start 0
    print("\nBinary search for smallest toxic range from byte 0:")
    print("-" * 60)
    
    left, right = 0, file_size - 1
    smallest_end = right
    
    while left <= right:
        mid = (left + right) // 2
        print(f"  Testing 0-{mid} ({mid + 1} bytes)...", end=" ", flush=True)
        
        if is_toxic_range(0, mid):
            smallest_end = mid
            right = mid - 1
        else:
            left = mid + 1
    
    print(f"\nSmallest from start: 0-{smallest_end} ({smallest_end + 1} bytes)")
    
    # Find latest start
    print("\nBinary search for latest toxic start:")
    print("-" * 60)
    
    left, right = 0, smallest_end
    latest_start = 0
    
    while left <= right:
        mid = (left + right) // 2
        print(f"  Testing {mid}-{smallest_end} ({smallest_end - mid + 1} bytes)...", end=" ", flush=True)
        
        if is_toxic_range(mid, smallest_end):
            latest_start = mid
            left = mid + 1
        else:
            right = mid - 1
    
    # Find smallest end from latest_start
    print(f"\nBinary search for smallest end from start {latest_start}:")
    print("-" * 60)
    
    left, right = latest_start, file_size - 1
    final_end = right
    
    while left <= right:
        mid = (left + right) // 2
        print(f"  Testing {latest_start}-{mid} ({mid - latest_start + 1} bytes)...", end=" ", flush=True)
        
        if is_toxic_range(latest_start, mid):
            final_end = mid
            right = mid - 1
        else:
            left = mid + 1
    
    size = final_end - latest_start + 1
    print(f"\n{'=' * 60}")
    print(f"SMALLEST TOXIC: {latest_start}-{final_end} ({size} bytes)")
    print(f"{'=' * 60}")
    
    return (latest_start, final_end)


def main():
    """Main entry point."""
    print("Binary Search for Smallest Toxic Packet")
    print("=" * 60)
    
    # Check API
    sender = get_sender()
    if not sender.health_check():
        print(f"ERROR: Cannot reach packetgen API")
        from config import PACKETGEN_API_PORT
        print(f"Start it: python3.11 /root/packetgen.py {PACKETGEN_API_PORT}")
        return 1
    print("Packetgen API: OK")
    
    # Initialize receiver
    try:
        receiver = get_receiver()
        print("BPF receiver: OK")
    except Exception as e:
        print(f"ERROR: Cannot open BPF: {e}")
        print("Try running with sudo")
        return 1
    
    try:
        result = binary_search_smallest_toxic()
        if result:
            start, end = result
            data = get_toxic_bin_data()[start:end + 1]
            print(f"\nToxic data (hex): {data.hex()}")
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
