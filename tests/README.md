# Toxicframe Test Suite

This directory contains test scripts to find the minimal packet size that triggers the toxicframe bug on the Netgate SG-2100.

## Overview

The test script generates files of varying sizes containing the toxic pattern:
- **Pattern**: `44 24 12 91 48 44 22 12 89 48 24 22 91 89` (14 bytes)
- **Original**: 1 KB file with pattern repeated 39 times

## Usage

### Prerequisites

- Python 3.6+
- SSH/SCP access to the SG-2100
- Network access to the SG-2100 HTTP server

### Configuration

All configuration is centralized in `config.py`. Edit this file to change:

- **Network settings**: pfSense IP, SSH port, packetgen API port
- **Interface names**: Local BPF interface, pfSense interface
- **Test parameters**: Iterations, timeouts
- **Paths**: Database, binary files

Key settings:
```python
PFSENSE_IP = "10.25.0.1"
PFSENSE_SSH_PORT = 9922
PACKETGEN_API_PORT = 8088
LOCAL_IFACE = b"en7"  # Your local interface
PFSENSE_IFACE = b"mvneta1"  # pfSense interface
TEST_ITERATIONS = 10
```

### Running the Tests

```bash
cd test
python3 test_toxicframe.py
```

Or make it executable and run directly:

```bash
chmod +x test_toxicframe.py
./test_toxicframe.py
```

## What It Does

1. **Generates test files** with the toxic pattern in various sizes:
   - Exact pattern repeats (14, 28, 42, ... bytes)
   - Partial patterns (1-13 bytes)
   - Pattern with padding to specific sizes
   - Sizes between pattern boundaries

2. **Uploads each file** to the SG-2100 via SCP:
   - Files are named `toxic-{hash}` where hash is SHA256 (first 16 chars)
   - Uploaded to `/usr/local/www/` on the SG-2100

3. **Tests each file 10 times** via HTTP download:
   - Attempts to download the file
   - Records success/failure for each attempt
   - Calculates success rate

4. **Generates a report** with:
   - Summary statistics (toxic, safe, intermittent)
   - Smallest toxic packet found
   - Intermittent failures (packets that sometimes get dropped)
   - Detailed results table

## Output

The script generates a timestamped report file:
- `test_report_YYYYMMDD_HHMMSS.txt`

The report includes:
- **Summary**: Count of toxic, safe, and intermittent files
- **Smallest Toxic Packet**: The smallest file that always fails
- **Intermittent Failures**: Files that sometimes succeed, sometimes fail
- **Detailed Results**: Complete table of all test results

## Understanding Results

- **TOXIC** (0% success): File always fails - triggers the bug
- **SAFE** (100% success): File always succeeds - doesn't trigger the bug
- **INTERMITTENT** (0-100% success): File sometimes fails - may indicate timing or edge cases

## Notes

- The script uses standard library modules only (no external dependencies)
- Files are cleaned up locally after testing
- Remote files remain on the SG-2100 (you may want to clean them up manually)
- There's a small delay between tests to avoid overwhelming the system


