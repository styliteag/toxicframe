"""
Centralized configuration for toxicframe tests.

All IPs, ports, interfaces, and test parameters are defined here.
"""

from pathlib import Path

# ============================================================================
# Network Configuration
# ============================================================================

# pfSense/FreeBSD box
PFSENSE_IP = "10.25.0.1"
PFSENSE_SSH_PORT = 9922
PFSENSE_SSH_USER = "root"
PFSENSE_SSH_HOST = f"{PFSENSE_SSH_USER}@{PFSENSE_IP}"

# Packet generator API (running on pfSense)
PACKETGEN_API_PORT = 8088
PACKETGEN_API = f"http://{PFSENSE_IP}:{PACKETGEN_API_PORT}"

# pfSense interface for packet sending
PFSENSE_IFACE = b"mvneta1"

# Local interface for packet receiving (BPF)
LOCAL_IFACE = b"en7"

# ============================================================================
# Ethernet Frame Configuration
# ============================================================================

# Ethertype for toxic frames (custom, not assigned by IEEE)
ETHERTYPE = b"\x27\xfa"
ETHERTYPE_INT = 0x27fa

# Default destination MAC (broadcast)
DEFAULT_DST_MAC = b"\xff" * 6

# ============================================================================
# Test Parameters
# ============================================================================

# Number of iterations per test
TEST_ITERATIONS = 10

# Binary search uses fewer iterations for speed
BINARY_SEARCH_ITERATIONS = 3

# Packet receive timeout (seconds)
RECV_TIMEOUT = 0.1  # 100ms

# ============================================================================
# File Paths
# ============================================================================

# Test directory (where this config.py lives)
TEST_DIR = Path(__file__).parent

# Database file
DB_FILE = TEST_DIR / "toxicframe_tests.db"

# Binary files directory
BINARY_DIR = TEST_DIR.parent / "binarys"
TOXIC_BIN_PATH = BINARY_DIR / "toxic.bin"
TOXIC_SMALLEST_BIN_PATH = BINARY_DIR / "toxic_smallest.bin"
MAYBE_SMALLEST_BIN_PATH = BINARY_DIR / "maybe_smallest.bin"

# ============================================================================
# Toxic Pattern
# ============================================================================

# The 14-byte toxic pattern that triggers the bug
TOXIC_PATTERN = bytes([
    0x44, 0x24, 0x12, 0x91, 0x48, 0x44, 0x22, 0x12,
    0x89, 0x48, 0x24, 0x22, 0x91, 0x89
])
PATTERN_LEN = len(TOXIC_PATTERN)  # 14 bytes

# ============================================================================
# Packet Generator Configuration (for packetgen.py on pfSense)
# ============================================================================

# Default API port (can be overridden via command line)
PACKETGEN_DEFAULT_PORT = 8080

# Number of worker threads for parallel sending
PACKETGEN_NUM_WORKERS = 4

