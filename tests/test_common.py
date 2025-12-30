"""
Common testing functions using raw Ethernet packets.

Sends packets via packetgen API on pfSense, receives via BPF locally.
"""

import os
import fcntl
import struct
import threading
import time
import json
import urllib.request
from typing import Tuple, Optional

from config import (
    PACKETGEN_API, LOCAL_IFACE, ETHERTYPE, ETHERTYPE_INT,
    TEST_ITERATIONS, RECV_TIMEOUT, TOXIC_BIN_PATH
)

# macOS/FreeBSD BPF ioctls
BIOCSETIF = 0x8020426c
BIOCIMMEDIATE = 0x80044270
BIOCGBLEN = 0x40044266


class BPFReceiver:
    """BPF-based packet receiver."""
    
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
        for i in range(256):
            try:
                self.fd = os.open(f"/dev/bpf{i}", os.O_RDONLY)
                break
            except OSError:
                continue
        else:
            raise RuntimeError("No available BPF device")
        
        buf = struct.pack("I", 0)
        buf = fcntl.ioctl(self.fd, BIOCGBLEN, buf)
        self.buf_len = struct.unpack("I", buf)[0]
        
        fcntl.ioctl(self.fd, BIOCIMMEDIATE, struct.pack("I", 1))
        
        ifreq = struct.pack("16sH14s", self.ifname, 0, b"\x00" * 14)
        fcntl.ioctl(self.fd, BIOCSETIF, ifreq)
    
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
        """Receive loop."""
        import select
        while self.running:
            try:
                rlist, _, _ = select.select([self.fd], [], [], 0.01)
                if not rlist:
                    continue
                data = os.read(self.fd, self.buf_len)
                if data:
                    self._parse_buffer(data)
            except:
                continue
    
    def _parse_buffer(self, data: bytes):
        """Parse BPF buffer for our ethertype."""
        offset = 0
        while offset + 14 < len(data):
            pos = data.find(ETHERTYPE, offset)
            if pos < 12:
                break
            
            frame_start = pos - 12
            if frame_start >= offset and data[frame_start + 12:frame_start + 14] == ETHERTYPE:
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
            time.sleep(0.001)
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
        """Send payload with sequence number prepended."""
        seq = self._next_seq()
        full_payload = struct.pack(">I", seq) + payload
        result = self._post("/send/raw", {"hex": full_payload.hex(), "count": count})
        return seq, result
    
    def health_check(self) -> bool:
        """Check if API is healthy."""
        try:
            url = f"{self.api_url}/health"
            with urllib.request.urlopen(url, timeout=2) as resp:
                return json.loads(resp.read()).get("status") == "ok"
        except:
            return False


# Global instances (lazily initialized)
_receiver: Optional[BPFReceiver] = None
_sender: Optional[PacketSender] = None


def get_receiver() -> BPFReceiver:
    """Get or create global BPF receiver."""
    global _receiver
    if _receiver is None:
        _receiver = BPFReceiver()
        _receiver.open()
        _receiver.start()
    return _receiver


def get_sender() -> PacketSender:
    """Get or create global packet sender."""
    global _sender
    if _sender is None:
        _sender = PacketSender()
    return _sender


def cleanup():
    """Cleanup global instances."""
    global _receiver, _sender
    if _receiver:
        _receiver.stop()
        _receiver = None
    _sender = None


def test_payload(payload: bytes, iterations: int = TEST_ITERATIONS) -> Tuple[int, int]:
    """
    Test a payload multiple times.
    Returns (successes, failures).
    """
    receiver = get_receiver()
    sender = get_sender()
    
    successes = 0
    failures = 0
    
    for _ in range(iterations):
        receiver.clear()
        seq, result = sender.send_payload(payload)
        
        if "error" in result:
            failures += 1
            continue
        
        if receiver.wait_for_seq(seq, RECV_TIMEOUT):
            successes += 1
        else:
            failures += 1
    
    return successes, failures


def classify_result(successes: int, total: int) -> str:
    """Classify result as TOXIC/SAFE/MAYBE."""
    if successes == 0:
        return "TOXIC"
    elif successes == total:
        return "SAFE"
    return "MAYBE"


def get_toxic_bin_data() -> bytes:
    """Load toxic.bin data."""
    if not hasattr(get_toxic_bin_data, '_cached'):
        if TOXIC_BIN_PATH.exists():
            get_toxic_bin_data._cached = TOXIC_BIN_PATH.read_bytes()
        else:
            raise FileNotFoundError(f"toxic.bin not found at {TOXIC_BIN_PATH}")
    return get_toxic_bin_data._cached


def extract_range(start: int, end: int) -> bytes:
    """Extract a byte range from toxic.bin."""
    data = get_toxic_bin_data()
    if end >= len(data):
        return b''
    return data[start:end + 1]


def test_pattern_multiple(pattern_data: bytes, iterations: int = None, 
                         filename_prefix: str = "test") -> Tuple[int, int]:
    """Test a pattern multiple times. Returns (successes, failures)."""
    iterations = iterations or TEST_ITERATIONS
    return test_payload(pattern_data, iterations)
