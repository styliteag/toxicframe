#!/usr/bin/env python3
"""
Brute force search for toxic 2-byte patterns.

Tests all 65536 possible 2-byte patterns (0x0000 to 0xffff) in 200-byte packets.
Each pattern is repeated 100 times to create a 200-byte packet.
"""

import sys
import sqlite3
from typing import List, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass

from config import DB_FILE
from test_common import test_payload, classify_result, get_sender, get_receiver, cleanup
from db_common import init_database


@dataclass
class TwoBytePatternResult:
    """Result of testing a 2-byte pattern."""
    pattern: int  # 0x0000 to 0xffff
    byte1: int
    byte2: int
    successes: int
    failures: int
    success_rate: float
    classification: str


def generate_2byte_pattern(pattern: int, packet_size: int = 200) -> bytes:
    """Generate a packet with repeating 2-byte pattern.
    
    Args:
        pattern: 16-bit pattern (0x0000 to 0xffff)
        packet_size: Total packet size in bytes (default 200)
    
    Returns:
        bytes: Packet data with pattern repeated
    """
    byte1 = (pattern >> 8) & 0xff
    byte2 = pattern & 0xff
    pattern_bytes = bytes([byte1, byte2])
    
    # Repeat pattern to fill packet_size bytes
    repetitions = packet_size // 2
    data = pattern_bytes * repetitions
    
    # Add remaining bytes if packet_size is odd
    if packet_size % 2 == 1:
        data += bytes([byte1])
    
    return data


def test_2byte_pattern_cached(conn: sqlite3.Connection, pattern: int,
                               packet_size: int = 200,
                               iterations: int = 1) -> TwoBytePatternResult:
    """Test a 2-byte pattern, using cache if available."""
    byte1 = (pattern >> 8) & 0xff
    byte2 = pattern & 0xff
    
    # Generate the pattern
    data = generate_2byte_pattern(pattern, packet_size)
    
    # Check cache
    cache_key = f"2byte_pattern_{packet_size}"
    pattern_hex = f"{pattern:04x}"
    cursor = conn.cursor()
    cursor.execute("""
        SELECT successes, failures, classification
        FROM test_results
        WHERE test_type=? AND pattern_hex=? AND length=?
    """, (cache_key, pattern_hex, packet_size))
    
    cached = cursor.fetchone()
    if cached:
        successes, failures, classification = cached
        total = successes + failures
        success_rate = successes / total if total > 0 else 0.0
        return TwoBytePatternResult(
            pattern, byte1, byte2, successes, failures, success_rate, classification
        )
    
    # Test it (silent - will be logged by caller if needed)
    successes, failures = test_payload(data, iterations)
    total = successes + failures
    success_rate = successes / total if total > 0 else 0.0
    classification = classify_result(successes, total)
    
    # Save to database
    probability = success_rate
    
    cursor.execute("""
        INSERT OR REPLACE INTO test_results
        (test_type, pattern_type, pattern_hex, pattern_desc, length, successes, failures, probability, classification, data_hex)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        cache_key,
        "2byte",
        pattern_hex,
        f"0x{byte1:02x} 0x{byte2:02x}",
        packet_size,
        successes,
        failures,
        probability,
        classification,
        data.hex()
    ))
    
    conn.commit()
    return TwoBytePatternResult(
        pattern, byte1, byte2, successes, failures, success_rate, classification
    )


def run_brute_force_search(conn: sqlite3.Connection, start_pattern: int = 0x0000,
                          end_pattern: int = 0xffff, packet_size: int = 200,
                          iterations: int = 1,
                          progress_interval: int = 100) -> List[TwoBytePatternResult]:
    """Run brute force search for all 2-byte patterns.
    
    Args:
        conn: Database connection
        start_pattern: Starting pattern (default 0x0000)
        end_pattern: Ending pattern (default 0xffff)
        packet_size: Packet size in bytes (default 200)
        iterations: Test iterations per pattern
        progress_interval: Print progress every N patterns
    
    Returns:
        List of test results
    """
    results = []
    total_patterns = end_pattern - start_pattern + 1
    
    print(f"Brute force search for 2-byte toxic patterns")
    print(f"Pattern range: 0x{start_pattern:04x} to 0x{end_pattern:04x} ({total_patterns} patterns)")
    print(f"Packet size: {packet_size} bytes ({packet_size // 2} repetitions per pattern)")
    print(f"Iterations per pattern: {iterations}")
    print("=" * 80)
    
    toxic_count = 0
    safe_count = 0
    maybe_count = 0
    last_first_byte = None
    
    for i, pattern in enumerate(range(start_pattern, end_pattern + 1), 1):
        result = test_2byte_pattern_cached(conn, pattern, packet_size, iterations)
        results.append(result)
        
        # Only print when first byte changes
        current_first_byte = result.byte1
        if current_first_byte != last_first_byte:
            if last_first_byte is not None:
                print()  # New line after previous first byte group
            print(f"Testing 0x{current_first_byte:02x}...", end="", flush=True)
            last_first_byte = current_first_byte
        
        if result.classification == "TOXIC":
            toxic_count += 1
            print(f" TOXIC:0x{pattern:04x}", end="", flush=True)
        elif result.classification == "SAFE":
            safe_count += 1
            # Silent for safe patterns
        else:
            maybe_count += 1
            print(f" MAYBE:0x{pattern:04x}", end="", flush=True)
        
        # Progress update
        if i % progress_interval == 0 or i == total_patterns:
            if last_first_byte is not None:
                print()  # New line after first byte indicator
            print(f"Progress: {i}/{total_patterns} ({100*i/total_patterns:.1f}%)")
            print(f"  TOXIC: {toxic_count}, SAFE: {safe_count}, MAYBE: {maybe_count}")
            print()
    
    return results


def show_summary(conn: sqlite3.Connection, packet_size: int = 200):
    """Show summary of 2-byte pattern test results."""
    cursor = conn.cursor()
    
    print("\n" + "=" * 80)
    print("2-BYTE PATTERN TEST SUMMARY")
    print("=" * 80)
    
    cache_key = f"2byte_pattern_{packet_size}"
    cursor.execute("""
        SELECT pattern_hex, pattern_desc, successes, failures, classification
        FROM test_results
        WHERE test_type=? AND length=?
        ORDER BY pattern_hex
    """, (cache_key, packet_size))
    
    results = cursor.fetchall()
    
    if not results:
        print("No test results found.")
        return
    
    # Classification counts
    toxic_patterns = []
    safe_patterns = []
    maybe_patterns = []
    
    for pattern_hex, pattern_desc, successes, failures, classification in results:
        pattern = int(pattern_hex, 16)
        if classification == "TOXIC":
            toxic_patterns.append((pattern, pattern_desc, successes, failures))
        elif classification == "SAFE":
            safe_patterns.append((pattern, pattern_desc, successes, failures))
        else:
            maybe_patterns.append((pattern, pattern_desc, successes, failures))
    
    print(f"\nTotal patterns tested: {len(results)}")
    print(f"  TOXIC: {len(toxic_patterns)}")
    print(f"  SAFE: {len(safe_patterns)}")
    print(f"  MAYBE: {len(maybe_patterns)}")
    
    if toxic_patterns:
        print(f"\n{'='*80}")
        print("TOXIC PATTERNS (2-byte patterns that trigger the bug):")
        print(f"{'='*80}")
        print("Pattern  | Bytes      | Success/Fail | Classification")
        print("---------|------------|--------------|----------------")
        for pattern, pattern_desc, successes, failures in sorted(toxic_patterns):
            print(f"0x{pattern:04x}  | {pattern_desc:10s} | {successes:3d}/{failures:3d}        | TOXIC")
    
    if maybe_patterns:
        print(f"\n{'='*80}")
        print(f"INTERMITTENT PATTERNS ({len(maybe_patterns)} patterns):")
        print(f"{'='*80}")
        print("Pattern  | Bytes      | Success/Fail | Classification")
        print("---------|------------|--------------|----------------")
        for pattern, pattern_desc, successes, failures in sorted(maybe_patterns):
            print(f"0x{pattern:04x}  | {pattern_desc:10s} | {successes:3d}/{failures:3d}        | MAYBE")


def export_toxic_patterns(conn: sqlite3.Connection, packet_size: int = 200,
                          filename: str = "toxic_2byte_patterns.txt"):
    """Export toxic 2-byte patterns to a file."""
    cursor = conn.cursor()
    
    cache_key = f"2byte_pattern_{packet_size}"
    cursor.execute("""
        SELECT pattern_hex, pattern_desc, successes, failures
        FROM test_results
        WHERE test_type=? AND length=? AND classification='TOXIC'
        ORDER BY pattern_hex
    """, (cache_key, packet_size))
    
    results = cursor.fetchall()
    
    with open(filename, "w") as f:
        f.write("# Toxic 2-byte Patterns\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Packet size: {packet_size} bytes\n")
        f.write(f"# Total toxic patterns: {len(results)}\n\n")
        
        f.write("Pattern  | Bytes      | Success/Fail\n")
        f.write("---------|------------|--------------\n")
        
        for pattern_hex, pattern_desc, successes, failures in results:
            pattern = int(pattern_hex, 16)
            f.write(f"0x{pattern:04x}  | {pattern_desc:10s} | {successes:3d}/{failures:3d}\n")
    
    print(f"Exported {len(results)} toxic patterns to {filename}")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Brute force search for toxic 2-byte patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test all patterns (0x0000 to 0xffff)
  sudo python3 test_2byte_patterns.py

  # Test specific range
  sudo python3 test_2byte_patterns.py --start 0x4a00 --end 0x4aff

  # Show summary only
  python3 test_2byte_patterns.py --summary

  # Export toxic patterns
  python3 test_2byte_patterns.py --export
        """
    )
    parser.add_argument("--start", type=lambda x: int(x, 0), default=0x0000,
                       help="Starting pattern (default: 0x0000)")
    parser.add_argument("--end", type=lambda x: int(x, 0), default=0xffff,
                       help="Ending pattern (default: 0xffff)")
    parser.add_argument("--packet-size", type=int, default=200,
                       help="Packet size in bytes (default: 200)")
    parser.add_argument("--iterations", type=int, default=1,
                       help="Iterations per test (default: 1)")
    parser.add_argument("--progress", type=int, default=100,
                       help="Progress update interval (default: 100)")
    parser.add_argument("--summary", action="store_true",
                       help="Show summary only (no testing)")
    parser.add_argument("--export", type=str, nargs="?",
                       const="toxic_2byte_patterns.txt",
                       help="Export toxic patterns to file")
    args = parser.parse_args()
    
    conn = init_database()
    
    if args.summary:
        show_summary(conn, args.packet_size)
        conn.close()
        return 0
    
    if args.export:
        export_toxic_patterns(conn, args.packet_size, args.export)
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
        results = run_brute_force_search(
            conn,
            args.start,
            args.end,
            args.packet_size,
            args.iterations,
            args.progress
        )
        
        print("\n" + "=" * 80)
        print("TESTING COMPLETE")
        print("=" * 80)
        show_summary(conn, args.packet_size)
        
        # Auto-export if toxic patterns found
        toxic_count = sum(1 for r in results if r.classification == "TOXIC")
        if toxic_count > 0:
            export_filename = f"toxic_2byte_patterns_{args.packet_size}bytes.txt"
            export_toxic_patterns(conn, args.packet_size, export_filename)
    
    finally:
        cleanup()
        conn.close()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        print("Progress saved to database. Resume with:")
        print(f"  python3 test_2byte_patterns.py --start <last_pattern>")
        cleanup()
        sys.exit(1)

