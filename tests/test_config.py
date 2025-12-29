"""
Common configuration for toxicframe tests.
"""

from pathlib import Path

# Network configuration
HTTP_BASE_URL = "http://10.25.0.1:8080"
SCP_HOST = "root@10.25.0.1"
SCP_PORT = 9922
SCP_DEST = "/usr/local/www"
TOXIC_FILE = "toxic.bin"

# Test configuration
TIMEOUT = 0.5
TEST_ITERATIONS = 10
TEST_DIR = Path(__file__).parent

# Toxic pattern: 44 24 12 91 48 44 22 12 89 48 24 22 91 89 (14 bytes)
TOXIC_PATTERN = bytes([0x44, 0x24, 0x12, 0x91, 0x48, 0x44, 0x22, 0x12, 0x89, 0x48, 0x24, 0x22, 0x91, 0x89])
PATTERN_LEN = len(TOXIC_PATTERN)  # 14 bytes

# Database file (unified)
DB_FILE = TEST_DIR / "toxicframe_tests.db"

# Paths
TOXIC_BIN_PATH = Path(__file__).parent.parent / "binarys" / "toxic.bin"

