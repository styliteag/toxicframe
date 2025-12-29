# Toxicframe Test Suite

This directory contains test scripts to find the minimal packet size that triggers the toxicframe bug on the Netgate SG-2100/pfSense.

## Overview

The test suite uses **raw Ethernet packets** to test toxic patterns:
- **Pattern**: `44 24 12 91 48 44 22 12 89 48 24 22 91 89` (14 bytes)
- **Method**: Sends packets via packetgen API on pfSense, receives via BPF locally
- **Ethertype**: `0x27fa` (custom, not assigned by IEEE)

## Architecture

1. **packetgen.py** - Runs on pfSense, sends raw Ethernet frames via BPF
2. **Test scripts** - Run locally, send packets via HTTP API, receive via BPF
3. **BPF receiver** - Captures packets on local interface to verify delivery

## Prerequisites

### On pfSense/FreeBSD box:
- Python 3.11+ (`/usr/local/bin/python3.11`)
- Root access for BPF (`/dev/bpf*`)
- Network interface for sending (default: `mvneta1`)

### On local machine (macOS/Linux):
- Python 3.6+
- Root access for BPF (to receive packets)
- Network interface on same subnet as pfSense

## Setup

### 1. Upload packetgen.py to pfSense

```bash
scp -P 9922 tests/netgate/packetgen.py root@10.25.0.1:/root/
```

### 2. Start packetgen API on pfSense

```bash
ssh -p 9922 root@10.25.0.1
python3.11 /root/packetgen.py 8088
```

The API will listen on port 8088 (configurable in `config.py`).

### 3. Configure local settings

Edit `config.py` to match your setup:

```python
# pfSense/FreeBSD box
PFSENSE_IP = "10.25.0.1"
PFSENSE_SSH_PORT = 9922
PACKETGEN_API_PORT = 8088

# Interfaces
LOCAL_IFACE = b"en7"      # Your local interface (check with ifconfig)
PFSENSE_IFACE = b"mvneta1"  # pfSense interface (check on pfSense)

# Test parameters
TEST_ITERATIONS = 10
RECV_TIMEOUT = 0.1  # 100ms
```

## Running Tests

### Binary Search (Fastest)

Finds the smallest toxic range using binary search:

```bash
sudo python3 binary_search_toxic.py
```

### Full Range Analysis

Tests all ranges systematically (slower, more thorough):

```bash
sudo python3 analyze_toxic_ranges.py
```

### Pattern Variations

Tests variations of the toxic pattern:

```bash
sudo python3 search_pattern_variations.py
```

### Basic Test

Adaptive testing with automatic fine-grained boundary detection:

```bash
sudo python3 test_toxicframe.py
```

**Note**: All scripts require `sudo` for BPF access.

## How It Works

1. **Send**: Test script sends HTTP POST to packetgen API with payload hex
2. **Transmit**: packetgen.py sends raw Ethernet frame via BPF on pfSense
3. **Receive**: Local BPF receiver captures frame on local interface
4. **Verify**: Sequence numbers track which packets arrived
5. **Classify**: Results classified as TOXIC (0% success), SAFE (100%), or MAYBE (intermittent)

## Packet Format

```
[Ethernet Header]
  DST MAC: ff:ff:ff:ff:ff:ff (broadcast)
  SRC MAC: <pfSense interface MAC>
  Ethertype: 0x27fa
[Payload]
  4 bytes: Sequence number (big-endian)
  N bytes: Test data (toxic pattern or range from toxic.bin)
```

## API Endpoints

The packetgen API provides:

- `GET /health` - Health check
- `GET /payloads` - List loaded payloads
- `POST /payload` - Load payload `{"name": "foo", "hex": "deadbeef"}`
- `POST /send` - Send packets `{"payload": "name", "count": 100}`
- `POST /send/raw` - Send raw hex `{"hex": "deadbeef", "count": 1}`

## Understanding Results

- **TOXIC** (0% success): Packet always blocked - triggers the bug
- **SAFE** (100% success): Packet always arrives - doesn't trigger the bug
- **MAYBE** (0-100% success): Intermittent - may indicate timing or edge cases

## Database

Test results are stored in SQLite database:
- `toxicframe_tests.db` - All test results with caching

View results:
```bash
python3 analyze_toxic_ranges.py --histogram
```

## Troubleshooting

### "Cannot reach packetgen API"
- Check packetgen is running: `ssh -p 9922 root@10.25.0.1 "ps aux | grep packetgen"`
- Check firewall allows port 8088
- Verify `PACKETGEN_API` in `config.py` matches running port

### "Cannot open BPF device"
- Run with `sudo`
- Check interface name in `config.py` matches your system
- Verify interface is up: `ifconfig en7`

### "Packet not received"
- Check both machines are on same subnet
- Verify interface names are correct
- Check for firewall rules blocking broadcast packets
- May be normal if packet is filtered/dropped (that's what we're testing!)

## Files

- `config.py` - Centralized configuration
- `test_common.py` - Shared BPF receiver and packet sender
- `packetgen.py` - Packet generator API (runs on pfSense)
- `binary_search_toxic.py` - Fast binary search
- `analyze_toxic_ranges.py` - Comprehensive range analysis
- `search_pattern_variations.py` - Pattern variation testing
- `test_toxicframe.py` - Adaptive testing
- `db_common.py` - Database utilities
