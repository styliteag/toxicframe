#!/usr/bin/env python3
"""
Binary search to find the smallest toxic packet in toxic.bin.

Tests different byte ranges to find the minimal size that triggers the bug.
Also tests if HTTP range requests trigger the bug.
"""

import urllib.request
import urllib.error
import socket
import sys
import time
import hashlib
from typing import Tuple, Optional

# Import common modules
from test_config import HTTP_BASE_URL, TOXIC_FILE, TIMEOUT, TEST_DIR
from test_common import (
    upload_test_file,
    test_download_file,
    extract_range,
    get_toxic_bin_data
)

# Fewer iterations for binary search speed
TEST_ITERATIONS = 3


def test_range_via_range_request(start: int, end: int) -> bool:
    """Test a byte range using HTTP Range request."""
    from test_config import HTTP_BASE_URL, TOXIC_FILE, TIMEOUT
    url = f"{HTTP_BASE_URL}/{TOXIC_FILE}"
    try:
        req = urllib.request.Request(url)
        req.add_header("Range", f"bytes={start}-{end}")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            data = response.read()
            expected_size = end - start + 1
            return len(data) >= expected_size * 0.9
    except (urllib.error.HTTPError, urllib.error.URLError, 
            ConnectionResetError, ConnectionAbortedError, OSError, 
            socket.timeout, Exception):
        return False


def test_download_range(start: int, end: int, use_range_request: bool = False, debug: bool = False) -> bool:
    """
    Test downloading a byte range from toxic.bin.
    
    Args:
        start: Start byte position
        end: End byte position (inclusive)
        use_range_request: If True, use HTTP Range header; if False, extract range and test as separate file
        debug: If True, print debug information
    
    Returns:
        bool: True if download succeeded, False if failed (toxic)
    """
    if use_range_request:
        # Test if the range request itself triggers the bug
        return test_range_via_range_request(start, end)
    else:
        # Extract the range, upload it as a separate file, and test that file
        range_data = extract_range(start, end)
        if len(range_data) != (end - start + 1):
            if debug:
                print(f"    [DEBUG] Couldn't extract range: got {len(range_data)} bytes, expected {end - start + 1}")
            return False  # Couldn't extract range
        
        # Create filename from hash
        file_hash = hashlib.sha256(range_data).hexdigest()[:16]
        filename = f"test-{file_hash}"
        
        if debug:
            print(f"    [DEBUG] Extracted {len(range_data)} bytes, uploading as {filename}")
        
        # Upload and test
        if not upload_test_file(range_data, filename):
            if debug:
                print(f"    [DEBUG] Upload failed for {filename}")
            return False
        
        time.sleep(0.2)  # Wait for file to be available
        
        # Test the uploaded file
        result = test_download_file(filename, len(range_data))
        if debug:
            print(f"    [DEBUG] Test result for {filename}: {'SUCCESS' if result else 'FAILED'}")
        return result


def test_range_multiple(start: int, end: int, use_range_request: bool = False, debug: bool = False) -> Tuple[int, int]:
    """
    Test a range multiple times and return success/failure counts.
    
    Returns:
        Tuple[int, int]: (successes, failures)
    """
    successes = 0
    failures = 0
    
    for i in range(TEST_ITERATIONS):
        if test_download_range(start, end, use_range_request, debug=(debug and i == 0)):
            successes += 1
        else:
            failures += 1
        time.sleep(0.2)  # Small delay
    
    return successes, failures


def is_toxic_range(start: int, end: int, use_range_request: bool = False, debug: bool = False) -> bool:
    """
    Check if a byte range is toxic (always fails).
    
    Returns:
        bool: True if toxic (always fails), False if safe (succeeds at least once)
    """
    successes, failures = test_range_multiple(start, end, use_range_request, debug=debug)
    is_toxic = successes == 0  # Toxic if it never succeeds
    # Debug output
    status = "TOXIC" if is_toxic else "SAFE"
    print(f"{status} ({successes}/{TEST_ITERATIONS} successes)", flush=True)
    return is_toxic


def get_file_size() -> int:
    """Get the size of toxic.bin."""
    return len(get_toxic_bin_data())


def binary_search_smallest_toxic(use_range_request: bool = False) -> Optional[Tuple[int, int]]:
    """
    Binary search to find the smallest toxic range.
    
    Strategy:
    - Start with the full file (0 to size-1)
    - If toxic, try smaller ranges
    - Find the smallest range that is still toxic
    
    Returns:
        Optional[Tuple[int, int]]: (start, end) of smallest toxic range, or None if not found
    """
    file_size = get_file_size()
    print(f"File size: {file_size} bytes")
    print(f"Using {'HTTP Range requests' if use_range_request else 'full file downloads'}")
    print("-" * 80)
    
    # First, check if the full file is toxic
    print(f"Testing full file (0-{file_size-1})...", end=" ", flush=True)
    full_file_toxic = is_toxic_range(0, file_size - 1, use_range_request)
    if not full_file_toxic:
        print("\nSAFE - full file is not toxic!")
        return None
    print("")
    
    # Binary search for smallest toxic range starting from position 0
    print("\nBinary search for smallest toxic range starting from byte 0:")
    print("-" * 80)
    
    left = 0
    right = file_size - 1
    smallest_toxic_end = right
    
    while left <= right:
        mid = (left + right) // 2
        test_end = mid
        
        print(f"  Testing range 0-{test_end} ({test_end + 1} bytes)...", end=" ", flush=True)
        toxic = is_toxic_range(0, test_end, use_range_request)
        
        if toxic:
            smallest_toxic_end = test_end
            right = mid - 1  # Try smaller
        else:
            left = mid + 1  # Try larger
        
        time.sleep(0.1)
    
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
        
        print(f"  Testing range {test_start}-{test_end} ({test_end - test_start + 1} bytes)...", end=" ", flush=True)
        toxic = is_toxic_range(test_start, test_end, use_range_request)
        
        if toxic:
            latest_toxic_start = test_start
            left_start = mid_start + 1  # Try starting later
        else:
            right_start = mid_start - 1  # Try starting earlier
        
        time.sleep(0.1)
    
    # Now find smallest end from this start
    print(f"\nBinary search for smallest end from start {latest_toxic_start}:")
    print("-" * 80)
    
    left_end = latest_toxic_start
    right_end = file_size - 1
    smallest_end = right_end
    
    while left_end <= right_end:
        mid_end = (left_end + right_end) // 2
        test_end = mid_end
        
        print(f"  Testing range {latest_toxic_start}-{test_end} ({test_end - latest_toxic_start + 1} bytes)...", end=" ", flush=True)
        toxic = is_toxic_range(latest_toxic_start, test_end, use_range_request)
        
        if toxic:
            smallest_end = test_end
            right_end = mid_end - 1  # Try smaller
        else:
            left_end = mid_end + 1  # Try larger
        
        time.sleep(0.1)
    
    result = (latest_toxic_start, smallest_end)
    size = smallest_end - latest_toxic_start + 1
    print(f"\n{'='*80}")
    print(f"SMALLEST TOXIC RANGE: {latest_toxic_start}-{smallest_end} ({size} bytes)")
    print(f"{'='*80}")
    
    return result


def main():
    """Main entry point."""
    print("Binary Search for Smallest Toxic Packet")
    print("=" * 80)
    
    # Test 1: Full file downloads (current method)
    print("\n[TEST 1] Using full file downloads:")
    result1 = binary_search_smallest_toxic(use_range_request=False)
    
    if result1:
        start1, end1 = result1
        size1 = end1 - start1 + 1
        print(f"\nResult: Range {start1}-{end1} ({size1} bytes) is the smallest toxic packet")
    else:
        print("\nResult: No toxic range found with full file downloads")
    
    print("\n" + "=" * 80)
    print("\n[TEST 2] Using HTTP Range requests:")
    result2 = binary_search_smallest_toxic(use_range_request=True)
    
    if result2:
        start2, end2 = result2
        size2 = end2 - start2 + 1
        print(f"\nResult: Range {start2}-{end2} ({size2} bytes) is the smallest toxic packet")
        
        # Compare results
        if result1:
            if size2 < size1:
                print(f"\n⚠️  Range requests find a SMALLER toxic packet! ({size2} < {size1} bytes)")
            elif size2 > size1:
                print(f"\n⚠️  Range requests find a LARGER toxic packet ({size2} > {size1} bytes)")
            else:
                print(f"\n✓ Both methods find the same size ({size1} bytes)")
    else:
        print("\nResult: No toxic range found with HTTP Range requests")
        if result1:
            print("⚠️  Range requests do NOT trigger the bug, but full downloads do!")
    
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

