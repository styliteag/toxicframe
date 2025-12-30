#!/usr/bin/env python3
"""
Test script to check if the 120-byte toxic pattern (0x4a) triggers the bug
when embedded at different positions within larger packets.

This tests whether the toxic pattern needs to be at the start of a packet
or can trigger the bug from anywhere within the packet.
"""

import sys
import argparse
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass
from typing import List

from config import TEST_ITERATIONS, BINARY_DIR
from test_common import test_payload, classify_result, get_sender, get_receiver, cleanup


@dataclass
class EmbeddedTestResult:
    """Result of testing toxic pattern at a specific offset."""
    packet_size: int
    toxic_offset: int
    successes: int
    failures: int
    success_rate: float
    is_toxic: bool


def load_minimum_toxic() -> bytes:
    """Load the minimum toxic pattern (120 bytes of 0x4a)."""
    toxic_path = BINARY_DIR / "minimum_0x4a.bin"
    if not toxic_path.exists():
        raise FileNotFoundError(f"minimum_0x4a.bin not found at {toxic_path}")
    data = toxic_path.read_bytes()
    if len(data) != 120:
        raise ValueError(f"Expected 120 bytes, got {len(data)}")
    return data


def create_embedded_packet(total_size: int, toxic_data: bytes, offset: int) -> bytes:
    """
    Create a packet with toxic data embedded at a specific offset.

    Args:
        total_size: Total packet size in bytes
        toxic_data: The toxic pattern (120 bytes)
        offset: Where to place the toxic pattern in the packet

    Returns:
        Packet data with toxic pattern embedded
    """
    toxic_len = len(toxic_data)

    # Validate offset
    if offset + toxic_len > total_size:
        raise ValueError(f"Offset {offset} + toxic length {toxic_len} exceeds packet size {total_size}")

    # Create packet: prefix + toxic data + suffix
    prefix = b'\x22' * offset  # Fill prefix with safe byte (0x22)
    suffix_len = total_size - offset - toxic_len
    suffix = b'\x22' * suffix_len  # Fill suffix with safe byte (0x22)

    return prefix + toxic_data + suffix


def run_embedded_tests(iterations: int = TEST_ITERATIONS) -> List[EmbeddedTestResult]:
    """Run tests with toxic pattern embedded at different offsets."""
    results = []

    # Load the minimum toxic pattern
    toxic_data = load_minimum_toxic()
    toxic_len = len(toxic_data)
    print(f"Loaded toxic pattern: {toxic_len} bytes of 0x4a")

    # Test packet sizes
    packet_sizes = [200, 300, 500, 794]  # Different packet sizes to test

    # For each packet size, test different offsets
    for packet_size in packet_sizes:
        print(f"\nTesting packet size: {packet_size} bytes")
        print("-" * 50)

        # Calculate possible offsets (every 10 bytes, plus some edge cases)
        max_offset = packet_size - toxic_len
        offsets_to_test = []

        # Add some specific offsets
        for offset in range(0, min(max_offset + 1, 101), 10):  # 0, 10, 20, ..., 100
            offsets_to_test.append(offset)

        # Add some edge cases near the end
        for offset in [max_offset - 20, max_offset - 10, max_offset]:
            if offset >= 0 and offset not in offsets_to_test:
                offsets_to_test.append(offset)

        offsets_to_test.sort()

        for offset in offsets_to_test:
            print(f"  Offset {offset:3d}/{max_offset}...", end=" ", flush=True)

            try:
                # Create packet with toxic data embedded
                packet_data = create_embedded_packet(packet_size, toxic_data, offset)

                # Test the packet
                successes, failures = test_payload(packet_data, iterations)
                success_rate = successes / iterations

                is_toxic = (success_rate == 0)

                status = classify_result(successes, iterations)
                print(f"{status} ({successes}/{iterations})")

                results.append(EmbeddedTestResult(
                    packet_size=packet_size,
                    toxic_offset=offset,
                    successes=successes,
                    failures=failures,
                    success_rate=success_rate,
                    is_toxic=is_toxic
                ))

            except ValueError as e:
                print(f"SKIP ({e})")
                continue

    return results


def generate_report(results: List[EmbeddedTestResult], iterations: int) -> str:
    """Generate test report."""
    lines = ["=" * 70, "EMBEDDED TOXIC PATTERN TEST REPORT", "=" * 70]
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Total tests: {len(results)}, Iterations: {iterations}")
    lines.append("")

    # Group results by packet size
    packet_sizes = sorted(set(r.packet_size for r in results))

    for packet_size in packet_sizes:
        size_results = [r for r in results if r.packet_size == packet_size]
        toxic_results = [r for r in size_results if r.is_toxic]
        safe_results = [r for r in size_results if not r.is_toxic]

        lines.append(f"PACKET SIZE: {packet_size} bytes")
        lines.append(f"  Total tests: {len(size_results)}")
        lines.append(f"  Toxic positions: {len(toxic_results)}")
        lines.append(f"  Safe positions: {len(safe_results)}")

        if toxic_results:
            lines.append("  TOXIC OFFSETS:")
            for r in toxic_results:
                lines.append(f"    Offset {r.toxic_offset:3d}: {r.successes}/{iterations} received")

        if safe_results:
            lines.append("  SAFE OFFSETS:")
            safe_offsets = [r.toxic_offset for r in safe_results[:10]]  # Show first 10
            lines.append(f"    Offsets: {', '.join(f'{o:3d}' for o in safe_offsets)}")
            if len(safe_results) > 10:
                lines.append(f"    ... and {len(safe_results) - 10} more")

        lines.append("")

    # Summary
    all_toxic = [r for r in results if r.is_toxic]
    lines.append("SUMMARY")
    lines.append(f"  Total toxic positions found: {len(all_toxic)}")

    if all_toxic:
        lines.append("  PACKET SIZE BREAKDOWN:")
        for packet_size in packet_sizes:
            size_toxic = [r for r in all_toxic if r.packet_size == packet_size]
            if size_toxic:
                min_offset = min(r.toxic_offset for r in size_toxic)
                max_offset = max(r.toxic_offset for r in size_toxic)
                lines.append(f"    {packet_size} bytes: {len(size_toxic)} toxic positions (offsets {min_offset}-{max_offset})")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Test embedded toxic patterns at different offsets")
    parser.add_argument("--iterations", type=int, default=TEST_ITERATIONS, help="Iterations per test")
    args = parser.parse_args()

    print("Embedded Toxic Pattern Test Script")
    print("=" * 70)

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

    try:
        results = run_embedded_tests(args.iterations)
        report = generate_report(results, args.iterations)

        # Save report
        report_path = Path(f"embedded_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        report_path.write_text(report)

        print("\n" + report)
        print(f"\nSaved: {report_path}")
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
