#!/usr/bin/env python3
"""
Toxic range analysis using raw Ethernet broadcast packets.

Sends packets via packetgen API on pfSense, receives via BPF locally.
Uses sequence numbers to verify packet arrival.
"""

import os
import sys
import fcntl
import struct
import threading
import time
import sqlite3
import json
import urllib.request
from pathlib import Path
from collections import defaultdict
from typing import Optional, Tuple

# Config
PACKETGEN_API = "http://10.25.0.1:8088"
LOCAL_IFACE = b"en7"  # Interface on 10.25.0.x network
ETHERTYPE = b"\x27\xfa"
ETHERTYPE_INT = 0x27fa

# From macOS/FreeBSD <net/bpf.h>
BIOCSETIF = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCSETF = 0x80104267
BIOCGBLEN = 0x40044266

# Test config
TEST_ITERATIONS = 10
RECV_TIMEOUT = 0.1  # 100ms should be plenty for local network
DB_FILE = Path(__file__).parent / "toxicframe_tests.db"
TOXIC_BIN_PATH = Path(__file__).parent.parent / "binarys" / "toxic.bin"


class BPFReceiver:
    """BPF-based packet receiver for macOS."""
    
    def __init__(self, ifname: bytes = LOCAL_IFACE):
        self.ifname = ifname
        self.fd = None
        self.buf_len = 0
        self.running = False
        self.received: dict[int, float] = {}  # seq -> timestamp
        self._lock = threading.Lock()
        self._thread = None
    
    def open(self):
        """Open BPF device and bind to interface."""
        # Find available BPF device
        for i in range(256):
            try:
                self.fd = os.open(f"/dev/bpf{i}", os.O_RDONLY)
                break
            except OSError:
                continue
        else:
            raise RuntimeError("No available BPF device")
        
        # Get buffer length
        buf = struct.pack("I", 0)
        buf = fcntl.ioctl(self.fd, BIOCGBLEN, buf)
        self.buf_len = struct.unpack("I", buf)[0]
        
        # Set immediate mode
        fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("I", 1))
        
        # Bind to interface
        ifreq = struct.pack("16sH14s", self.ifname, 0, b"\x00" * 14)
        fcntl.ioctl(self.fd, BIOCSETIF, ifreq)
        
        # Set BPF filter: ethertype == 0x27fa
        # BPF program: ldh [12], jeq #0x27fa, ret #65535, ret #0
        bpf_insns = struct.pack(
            "HBBI" * 4,
            0x28, 0, 0, 12,       # ldh [12] - load ethertype
            0x15, 0, 1, ETHERTYPE_INT,  # jeq #0x27fa, skip 0, else skip 1
            0x06, 0, 0, 65535,    # ret #65535 - accept
            0x06, 0, 0, 0         # ret #0 - reject
        )
        bpf_prog = struct.pack("HxxxxP", 4, id(bpf_insns))  # This won't work on macOS
        # Skip filter for now, we'll filter in userspace
    
    def start(self):
        """Start receiver thread."""
        self.running = True
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()
    
    def stop(self):
        """Stop receiver thread."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=1.0)
        if self.fd:
            os.close(self.fd)
            self.fd = None
    
    def _recv_loop(self):
        """Receive loop - parse BPF packets."""
        import select
        buf = bytearray(self.buf_len)
        
        while self.running:
            # Wait for data with timeout
            try:
                rlist, _, _ = select.select([self.fd], [], [], 0.01)
                if not rlist:
                    continue
            except:
                continue
            
            try:
                n = os.read(self.fd, self.buf_len)
                if not n:
                    continue
                data = bytes(n) if isinstance(n, int) else n
            except:
                continue
            
            # Parse BPF header(s) and extract packets
            self._parse_bpf_buffer(data)
    
    def _parse_bpf_buffer(self, data: bytes):
        """Parse BPF buffer containing one or more packets."""
        offset = 0
        while offset + 18 < len(data):  # BPF header is 18 bytes on macOS
            # BPF header: struct timeval (16), caplen (4), datalen (4), hdrlen (2)
            # Actually on macOS it's different - let's use a simpler approach
            # Try to find ethernet frames directly
            
            # Look for our ethertype in the buffer
            pos = data.find(ETHERTYPE, offset)
            if pos < 0 or pos < 12:
                break
            
            # Extract frame starting 12 bytes before ethertype
            frame_start = pos - 12
            if frame_start < offset:
                offset = pos + 2
                continue
            
            # Check ethertype is at correct position
            if data[frame_start + 12:frame_start + 14] == ETHERTYPE:
                # Extract sequence number (first 4 bytes of payload)
                payload_start = frame_start + 14
                if payload_start + 4 <= len(data):
                    seq = struct.unpack(">I", data[payload_start:payload_start + 4])[0]
                    with self._lock:
                        if seq not in self.received:
                            self.received[seq] = time.time()
            
            offset = pos + 2
    
    def clear(self):
        """Clear received packets."""
        with self._lock:
            self.received.clear()
    
    def wait_for_seq(self, seq: int, timeout: float = RECV_TIMEOUT) -> bool:
        """Wait for a specific sequence number."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if seq in self.received:
                    return True
            time.sleep(0.001)  # 1ms poll
        return False
    
    def got_seq(self, seq: int) -> bool:
        """Check if sequence was received."""
        with self._lock:
            return seq in self.received


class PacketSender:
    """Send packets via packetgen HTTP API."""
    
    def __init__(self, api_url: str = PACKETGEN_API):
        self.api_url = api_url
        self._seq = 0
        self._lock = threading.Lock()
    
    def _next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq
    
    def _post(self, endpoint: str, data: dict) -> dict:
        """POST JSON to API."""
        url = f"{self.api_url}{endpoint}"
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read())
        except Exception as e:
            return {"error": str(e)}
    
    def send_payload(self, payload: bytes, count: int = 1) -> Tuple[int, dict]:
        """
        Send payload with sequence number prepended.
        Returns (seq, api_response).
        """
        seq = self._next_seq()
        # Prepend 4-byte sequence number
        full_payload = struct.pack(">I", seq) + payload
        result = self._post("/send/raw", {"hex": full_payload.hex(), "count": count})
        return seq, result
    
    def health_check(self) -> bool:
        """Check if API is healthy."""
        try:
            url = f"{self.api_url}/health"
            with urllib.request.urlopen(url, timeout=2) as resp:
                data = json.loads(resp.read())
                return data.get("status") == "ok"
        except:
            return False


def init_db() -> sqlite3.Connection:
    """Initialize SQLite database."""
    conn = sqlite3.connect(str(DB_FILE))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS packet_tests (
            id INTEGER PRIMARY KEY,
            start_pos INTEGER,
            length INTEGER,
            end_pos INTEGER,
            successes INTEGER,
            failures INTEGER,
            probability REAL,
            classification TEXT,
            data_hex TEXT,
            timestamp REAL,
            UNIQUE(start_pos, length)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_start_len ON packet_tests(start_pos, length)")
    conn.commit()
    return conn


def get_toxic_bin_data() -> bytes:
    """Load toxic.bin data."""
    if TOXIC_BIN_PATH.exists():
        return TOXIC_BIN_PATH.read_bytes()
    raise FileNotFoundError(f"toxic.bin not found at {TOXIC_BIN_PATH}")


def classify_result(successes: int, total: int) -> str:
    """Classify result as TOXIC/SAFE/MAYBE."""
    if successes == 0:
        return "TOXIC"
    elif successes == total:
        return "SAFE"
    return "MAYBE"


def test_range(receiver: BPFReceiver, sender: PacketSender, 
               data: bytes, iterations: int = TEST_ITERATIONS) -> Tuple[int, int]:
    """
    Test a payload multiple times.
    Returns (successes, failures).
    """
    successes = 0
    failures = 0
    
    for _ in range(iterations):
        receiver.clear()
        seq, result = sender.send_payload(data)
        
        if "error" in result:
            failures += 1
            continue
        
        # Wait for packet
        if receiver.wait_for_seq(seq, RECV_TIMEOUT):
            successes += 1
        else:
            failures += 1
    
    return successes, failures


def get_cached_result(conn: sqlite3.Connection, start: int, length: int) -> Optional[Tuple[int, int, str]]:
    """Get cached result from DB."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT successes, failures, data_hex FROM packet_tests WHERE start_pos = ? AND length = ?",
        (start, length)
    )
    return cursor.fetchone()


def save_result(conn: sqlite3.Connection, start: int, end: int, 
                successes: int, failures: int, data: bytes):
    """Save test result to DB."""
    length = end - start + 1
    total = successes + failures
    probability = successes / total if total > 0 else 0
    classification = classify_result(successes, total)
    
    conn.execute("""
        INSERT OR REPLACE INTO packet_tests 
        (start_pos, length, end_pos, successes, failures, probability, classification, data_hex, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (start, length, end, successes, failures, probability, classification, data.hex(), time.time()))
    conn.commit()


def test_range_cached(conn: sqlite3.Connection, receiver: BPFReceiver, sender: PacketSender,
                      start: int, end: int) -> Optional[Tuple[int, int, bytes]]:
    """Test a range, using cache if available."""
    length = end - start + 1
    toxic_data = get_toxic_bin_data()
    
    if end >= len(toxic_data):
        return None
    
    data = toxic_data[start:end + 1]
    
    # Check cache
    cached = get_cached_result(conn, start, length)
    if cached:
        successes, failures, data_hex = cached
        return successes, failures, bytes.fromhex(data_hex)
    
    # Test it
    print(f"  Testing {start}-{end} ({length} bytes)...", end=" ", flush=True)
    successes, failures = test_range(receiver, sender, data)
    probability = successes / TEST_ITERATIONS
    classification = classify_result(successes, TEST_ITERATIONS)
    print(f"{classification} ({successes}/{TEST_ITERATIONS}, {probability:.0%})")
    
    save_result(conn, start, end, successes, failures, data)
    return successes, failures, data


def binary_search_toxic(conn: sqlite3.Connection, receiver: BPFReceiver, sender: PacketSender):
    """Binary search for smallest toxic range."""
    toxic_data = get_toxic_bin_data()
    file_size = len(toxic_data)
    
    print(f"Binary search for toxic ranges")
    print(f"File size: {file_size} bytes")
    print("=" * 60)
    
    # Test full file
    print(f"\nTesting full file (0-{file_size-1})...")
    result = test_range_cached(conn, receiver, sender, 0, file_size - 1)
    if not result:
        print("ERROR")
        return
    
    successes, _, _ = result
    if successes > 0:
        print("Full file is SAFE - not toxic!")
        return
    
    # Binary search for smallest toxic end from start 0
    print("\nFinding smallest toxic range from byte 0:")
    print("-" * 60)
    
    left, right = 0, file_size - 1
    smallest_end = right
    
    while left <= right:
        mid = (left + right) // 2
        result = test_range_cached(conn, receiver, sender, 0, mid)
        if not result:
            break
        
        successes, _, _ = result
        if successes == 0:  # Toxic
            smallest_end = mid
            right = mid - 1
        else:
            left = mid + 1
    
    print(f"\nSmallest toxic from start: 0-{smallest_end} ({smallest_end + 1} bytes)")
    
    # Find latest start that's still toxic
    print("\nFinding latest toxic start:")
    print("-" * 60)
    
    left, right = 0, smallest_end
    latest_start = 0
    
    while left <= right:
        mid = (left + right) // 2
        result = test_range_cached(conn, receiver, sender, mid, smallest_end)
        if not result:
            break
        
        successes, _, _ = result
        if successes == 0:  # Toxic
            latest_start = mid
            left = mid + 1
        else:
            right = mid - 1
    
    # Find smallest end from latest_start
    print(f"\nFinding smallest end from start {latest_start}:")
    print("-" * 60)
    
    left, right = latest_start, file_size - 1
    final_end = right
    
    while left <= right:
        mid = (left + right) // 2
        result = test_range_cached(conn, receiver, sender, latest_start, mid)
        if not result:
            break
        
        successes, _, _ = result
        if successes == 0:
            final_end = mid
            right = mid - 1
        else:
            left = mid + 1
    
    size = final_end - latest_start + 1
    print(f"\n{'=' * 60}")
    print(f"SMALLEST TOXIC: {latest_start}-{final_end} ({size} bytes)")
    print(f"{'=' * 60}")
    
    # Show the toxic data
    data = toxic_data[latest_start:final_end + 1]
    print(f"\nToxic data (hex): {data.hex()}")


def show_histogram(conn: sqlite3.Connection):
    """Show histogram of results."""
    cursor = conn.cursor()
    
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    
    cursor.execute("""
        SELECT classification, COUNT(*) FROM packet_tests GROUP BY classification
    """)
    for cls, count in cursor.fetchall():
        print(f"  {cls}: {count}")
    
    print("\n" + "-" * 60)
    print("TOXIC RANGES:")
    cursor.execute("""
        SELECT start_pos, end_pos, length, data_hex 
        FROM packet_tests WHERE classification = 'TOXIC'
        ORDER BY length, start_pos LIMIT 20
    """)
    for start, end, length, data_hex in cursor.fetchall():
        hex_short = data_hex[:40] + "..." if len(data_hex) > 40 else data_hex
        print(f"  {start}-{end} ({length}b): {hex_short}")
    
    print("\nMAYBE RANGES:")
    cursor.execute("""
        SELECT start_pos, end_pos, length, successes, probability
        FROM packet_tests WHERE classification = 'MAYBE'
        ORDER BY probability, length LIMIT 20
    """)
    for start, end, length, succ, prob in cursor.fetchall():
        print(f"  {start}-{end} ({length}b): {succ}/{TEST_ITERATIONS} ({prob:.0%})")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Analyze toxic ranges via packet broadcast")
    parser.add_argument("--histogram", action="store_true", help="Show results histogram")
    parser.add_argument("--max-size", type=int, help="Max range size to test")
    parser.add_argument("--step", type=int, default=1, help="Step size")
    args = parser.parse_args()
    
    conn = init_db()
    
    if args.histogram:
        show_histogram(conn)
        conn.close()
        return 0
    
    # Initialize sender and receiver
    print("Initializing...")
    sender = PacketSender()
    
    if not sender.health_check():
        print(f"ERROR: Cannot reach packetgen API at {PACKETGEN_API}")
        print("Start it on pfSense: python3.11 /root/packetgen.py 8088")
        return 1
    print(f"  Packetgen API: OK")
    
    receiver = BPFReceiver()
    try:
        receiver.open()
        receiver.start()
        print(f"  BPF receiver on {LOCAL_IFACE.decode()}: OK")
    except Exception as e:
        print(f"ERROR: Cannot open BPF receiver: {e}")
        print("Try running with sudo")
        return 1
    
    # Quick connectivity test
    print("\nConnectivity test...")
    receiver.clear()
    seq, result = sender.send_payload(b"TEST")
    if "error" in result:
        print(f"  Send failed: {result['error']}")
    elif receiver.wait_for_seq(seq, RECV_TIMEOUT):
        print(f"  Packet {seq} received OK")
    else:
        print(f"  WARNING: Packet {seq} not received (may be normal if filtered)")
    
    try:
        binary_search_toxic(conn, receiver, sender)
        show_histogram(conn)
    finally:
        receiver.stop()
    conn.close()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(1)
