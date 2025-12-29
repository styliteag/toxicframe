"""
Common testing functions for toxicframe tests.
"""

import urllib.request
import urllib.error
import socket
import subprocess
import hashlib
import time
from pathlib import Path
from typing import Tuple

from test_config import (
    HTTP_BASE_URL, SCP_HOST, SCP_PORT, SCP_DEST,
    TIMEOUT, TEST_ITERATIONS, TEST_DIR
)


def upload_test_file(data: bytes, filename: str, test_dir: Path = None) -> bool:
    """
    Upload a test file to the server.
    
    Args:
        data: File content as bytes
        filename: Remote filename
        test_dir: Directory for temporary file (default: TEST_DIR)
    
    Returns:
        bool: True if upload succeeded
    """
    test_dir = test_dir or TEST_DIR
    local_path = test_dir / filename
    try:
        local_path.write_bytes(data)
        cmd = [
            "scp", "-P", str(SCP_PORT),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            str(local_path),
            f"{SCP_HOST}:{SCP_DEST}/{filename}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        local_path.unlink()  # Clean up
        return result.returncode == 0
    except Exception:
        if local_path.exists():
            local_path.unlink()
        return False


def test_download_file(filename: str, expected_size: int, http_url: str = None, timeout: float = None) -> bool:
    """
    Test downloading a file.
    
    Args:
        filename: Name of the file to download
        expected_size: Expected file size in bytes
        http_url: HTTP base URL (default: HTTP_BASE_URL)
        timeout: Request timeout in seconds (default: TIMEOUT)
    
    Returns:
        bool: True if download succeeded (got expected size), False if failed
    """
    http_url = http_url or HTTP_BASE_URL
    timeout = timeout or TIMEOUT
    url = f"{http_url}/{filename}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read()
            return len(data) >= expected_size * 0.9
    except (urllib.error.HTTPError, urllib.error.URLError, 
            ConnectionResetError, ConnectionAbortedError, OSError, 
            socket.timeout, Exception):
        return False


def test_pattern_multiple(pattern_data: bytes, iterations: int = None, 
                         http_url: str = None, timeout: float = None,
                         filename_prefix: str = "test") -> Tuple[int, int]:
    """
    Test a pattern multiple times and return success/failure counts.
    
    Args:
        pattern_data: Pattern data to test
        iterations: Number of test iterations (default: TEST_ITERATIONS)
        http_url: HTTP base URL (default: HTTP_BASE_URL)
        timeout: Request timeout (default: TIMEOUT)
        filename_prefix: Prefix for generated filename
    
    Returns:
        Tuple[int, int]: (successes, failures)
    """
    iterations = iterations or TEST_ITERATIONS
    http_url = http_url or HTTP_BASE_URL
    timeout = timeout or TIMEOUT
    
    # Create filename from hash
    file_hash = hashlib.sha256(pattern_data).hexdigest()[:16]
    filename = f"{filename_prefix}-{file_hash}"
    
    # Upload once
    if not upload_test_file(pattern_data, filename):
        return (0, iterations)  # Upload failed
    
    time.sleep(0.3)  # Wait for file to be available
    
    # Test multiple times
    successes = 0
    failures = 0
    
    for _ in range(iterations):
        if test_download_file(filename, len(pattern_data), http_url, timeout):
            successes += 1
        else:
            failures += 1
        time.sleep(0.1)  # Small delay between tests
    
    return (successes, failures)


def classify_result(successes: int, total: int) -> str:
    """
    Classify test result.
    
    Args:
        successes: Number of successful tests
        total: Total number of tests
    
    Returns:
        str: "TOXIC", "SAFE", or "MAYBE"
    """
    if successes == 0:
        return "TOXIC"
    elif successes == total:
        return "SAFE"
    else:
        return "MAYBE"


def get_toxic_bin_data() -> bytes:
    """Get toxic.bin data from local file (cached)."""
    if not hasattr(get_toxic_bin_data, '_cached_data'):
        from test_config import TOXIC_BIN_PATH
        if TOXIC_BIN_PATH.exists():
            get_toxic_bin_data._cached_data = TOXIC_BIN_PATH.read_bytes()
        else:
            raise FileNotFoundError(f"toxic.bin not found at {TOXIC_BIN_PATH}")
    return get_toxic_bin_data._cached_data


def extract_range(start: int, end: int) -> bytes:
    """
    Extract a byte range from toxic.bin.
    
    Args:
        start: Start byte position
        end: End byte position (inclusive)
    
    Returns:
        bytes: Extracted range
    """
    toxic_data = get_toxic_bin_data()
    if len(toxic_data) < end + 1:
        return b''
    return toxic_data[start:end+1]


