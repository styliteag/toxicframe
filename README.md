# Toxic Frame Bug on Netgate SG-2100

**#toxicframe** – A deterministic hardware bug in the Netgate SG-2100's integrated Marvell 6000 switch that causes file transfers to stop at specific byte patterns.

## TL;DR

A **Toxic Frame** on the Netgate SG-2100 stops file transfers over SMB/HTTP. The problem lies in the hardware of the integrated Marvell 6000 Switch and occurs when the LAN port of the SG-2100 is involved – regardless of VLAN configuration, routing, or firewall rules. The specific data pattern triggers the bug deterministically. **No workaround is currently known.**

## The Problem

File transfers stop at an exact, reproducible point when transferring files containing specific byte patterns. This is not random, not load-dependent – it's deterministic. The behavior is reproducible over both **SMB** and **HTTP**.

### Symptoms

- File transfer stops at an exact percentage (e.g., 49% for the original test file)
- No timeout, no error – just silent stop
- Reproducible with specific byte patterns
- Protocol-independent (SMB, HTTP, etc.)

### Root Cause

The tests point to a drop in the **Switch/SoC path** of the SG-2100 (Marvell platform). Regardless of the protocol, the flow stops as soon as the "toxic" sector/packet pattern is encountered. The packet is sent by the CPU but never reaches the client – it gets dropped somewhere between CPU and Switch.

## 🚨 Breaking News: Simplest Toxic Patterns Discovered

Through systematic testing and adaptive search algorithms, we've discovered that **the bug can be triggered by extremely simple patterns** – even a single byte repeated just 120-121 times!

### Critical Discovery: Byte-Specific Bug

**The bug is byte-value specific, not just length-based!** After testing 100+ random single-byte patterns at 794 bytes, **only two byte values trigger the bug:**
- `0x4a` (byte value 074) = `01001010` in binary
- `0xb5` (byte value 181) = `10110101` in binary

**Note:** These two byte values are bitwise inverses of each other (`~0x4a = 0xb5`).

All other tested bytes (including `0x00`, `0xff`, `0x22`, etc.) are **safe** at 794 bytes.

### Minimum Toxic Lengths

| Byte Value | Minimum Toxic Length | File |
|------------|---------------------|------|
| `0x4a` | **121 bytes** | `minimum_0x4a.bin` |
| `0xb5` | **121 bytes** | `minimum_0xb5.bin` |

**Note:** Final results from comprehensive testing with 100 iterations per length. Previous estimates of 119 bytes were due to insufficient statistical sampling.

These are the **smallest confirmed toxic patterns** – just 120-121 bytes of a single repeated byte value!

### The 3 Simplest Toxic Patterns (at 794 bytes)

| File | Size | Pattern | Verification |
|------|------|---------|--------------|
| `simplest_1.bin` | 794 bytes | Single byte `0x4a` repeated 794 times | ✅ **Confirmed TOXIC** (0/10 packets received) |
| `simplest_2.bin` | 794 bytes | Single byte `0xb5` repeated 794 times | ✅ **Confirmed TOXIC** (0/10 packets received) |
| `simplest_3.bin` | 794 bytes | Mostly `0x22` (84.9%) with 2 unique bytes | ⚠️ Intermittent (1/10 packets received) |

### Hexdump of Simplest Patterns

**simplest_1.bin** (794 bytes - 100% `0x4a`):
```
00000000: 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a  JJJJJJJJJJJJJJJJ
00000010: 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a  JJJJJJJJJJJJJJJJ
...
(0x4a repeated 794 times)
```

**simplest_2.bin** (794 bytes - 100% `0xb5`):
```
00000000: b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5  ................
00000010: b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5  ................
...
(0xb5 repeated 794 times)
```

**simplest_3.bin** (794 bytes - 84.9% `0x22`):
```
00000000: 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22  """"""""""""""""
00000010: 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22 22  """"""""""""""""
...
(0x22 × 674, plus other bytes)
```

### Implications

This discovery reveals that:
- **The bug is byte-value specific** – only `0x4a` and `0xb5` trigger it, not all byte values
- **The minimum toxic length is 119 bytes** for these specific byte values (not 794 bytes)
- **The original 14-byte pattern is not special** – it was just the first pattern discovered
- **The bug appears to be related to specific byte values** interacting with the switch's packet processing at certain lengths

This suggests the Marvell switch has a hardware bug in its packet processing that fails when encountering **specific byte values** (`0x4a` or `0xb5`) repeated at least 119 bytes. The bug is **not** a general length threshold for any byte value.

### Detailed Length Analysis: Success Rate Histograms

Through systematic testing of different packet lengths containing consecutive `0x4a` bytes, we created detailed success rate histograms that reveal the exact transition point where packets become toxic:

| Length (bytes) | Success Rate | Classification |
|----------------|--------------|----------------|
| 100-105        | 100%         | SAFE           |
| 106-120        | 5-99%        | MAYBE          |
| 121-130        | 0%           | TOXIC          |

**Updated Results (100 iterations per length):**
- **0x4a (74 decimal):** Minimum toxic length = **121 bytes**
- **0xb5 (181 decimal):** Minimum toxic length = **121 bytes**
- **Statistical significance:** Results based on 100 iterations per length across 31 lengths (6200 total tests)

**Key Findings:**
- **Minimum toxic length: 119 bytes** (not 120 as previously estimated)
- **Transition zone: 110-118 bytes** shows intermittent behavior
- **Sharp threshold: 119+ bytes** = consistently dropped (toxic)
- **Statistical significance:** Results based on 5-10 iterations per length

The transition zone (110-118 bytes) shows probabilistic dropping behavior, suggesting the bug may be related to internal buffer sizes or packet processing thresholds in the Marvell 6000 switch.

### 🚨 CRITICAL DISCOVERY: Position-Independent Bug

**The toxic pattern triggers the bug regardless of its position in the packet!**

Testing with the minimum toxic pattern (120 bytes of `0x4a`) embedded at different offsets within larger packets revealed that:

- **All 51 test positions across 4 packet sizes (200, 300, 500, 794 bytes) were TOXIC**
- The pattern triggers the bug whether it appears at the **beginning**, **middle**, or **end** of packets
- **Every tested packet containing the 120-byte `0x4a` sequence was blocked** (0/3 packets received)

This makes the bug **significantly more dangerous** than previously understood. The toxic pattern can appear anywhere within packet payloads and will still trigger the hardware bug, potentially affecting any file transfer or network communication that happens to contain these byte sequences.

### Hexdump of Minimum Toxic Patterns

**minimum_0x4a.bin** (120 bytes - 100% `0x4a`):
```
00000000: 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a  JJJJJJJJJJJJJJJJ
00000010: 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a 4a  JJJJJJJJJJJJJJJJ
...
(0x4a repeated 120 times - MINIMUM TOXIC LENGTH)
```

**minimum_0xb5.bin** (121 bytes - 100% `0xb5`):
```
00000000: b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5  ................
00000010: b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5 b5  ................
...
(0xb5 repeated 121 times - MINIMUM TOXIC LENGTH)
```

## The Toxic Pattern

The bug is triggered by a specific **14-byte pattern**:

```
44 24 12 91 48 44 22 12 89 48 24 22 91 89
```

In the original `toxic.bin` (1 KB), this pattern is repeated 39 times.

**Note:** This was the first pattern discovered, but we now know much simpler patterns (single bytes) also trigger the bug at 794 bytes.

## Repository Structure

```
├── binarys/                    # Binary test files
│   ├── toxic.bin               # Original 1KB toxic file
│   ├── toxic_smallest.bin      # Smallest confirmed toxic file
│   ├── maybe_smallest.bin      # Candidate for even smaller
│   ├── simplest_1.bin          # Simplest: 0x4a × 794 (confirmed toxic)
│   ├── simplest_2.bin          # Simplest: 0xb5 × 794 (confirmed toxic)
│   ├── simplest_3.bin          # Mostly 0x22 × 794 (intermittent)
│   ├── minimum_0x4a.bin        # MINIMUM: 0x4a × 120 (smallest toxic)
│   └── minimum_0xb5.bin        # MINIMUM: 0xb5 × 121 (smallest toxic)
├── tests/                      # Test suite
│   ├── test_toxicframe.py      # Main test script
│   ├── test_embedded_toxic.py  # Test embedded toxic patterns at different offsets
│   ├── test_length_histogram.py # Test different lengths and create success rate histograms
│   ├── HISTOGRAM.md            # Detailed length histogram results (100 iterations)
│   ├── binary_search_toxic.py  # Find smallest toxic packet
│   ├── analyze_toxic_ranges.py # Analyze toxic byte ranges
│   └── ...                     # More test utilities
└── presentation/               # 39C3 Lightning Talk
    ├── toxicframe.md           # Marp slides
    ├── toxicframe.pdf          # Exported PDF
    └── speaker_notes.md        # Speaker notes
```

## Hardware Affected

| Component | Value |
|-----------|-------|
| **Device** | Netgate SG-2100 |
| **CPU** | Marvell Armada 3720 (ARM64 Cortex-A53) |
| **Switch** | Marvell 6000 (88E6141) |
| **Uplink** | CPU ↔ Switch with **2.5 GbE** |
| **Affected Interface** | mvneta1 |
| **pfSense Version** | Tested on 25.07.x |

### Interestingly NOT Affected

- **GL-iNet Brume (GL-MV1000)** with same Marvell 88E6141 switch chip but only 1GbE uplink – bug not reproducible with OpenWRT

## Test Files

| File | Description | SHA256 |
|------|-------------|--------|
| `toxic.bin` | Contains the toxic byte pattern – triggers the bug | `c53442b8ebc2631d4326fb70cdcc62a5c452674ed306d31120235fc180cfd499` |

## Running the Test Suite

### Prerequisites

- Python 3.6+
- SSH/SCP access to the SG-2100
- Network access to the SG-2100 HTTP server

### Configuration

Edit `tests/test_config.py`:

```python
HTTP_BASE_URL = "http://10.25.0.1:8080"
SCP_HOST = "root@10.25.0.1"
SCP_PORT = 9922
SCP_DEST = "/usr/local/www"
```

### Running Tests

```bash
cd tests
python3 test_toxicframe.py
```

## What Was Ruled Out

- ✗ MTU/fragmentation issues
- ✗ Bandwidth/rate limiting
- ✗ DPI blocking
- ✗ VLAN configuration (problem occurs with and without VLANs)
- ✗ IPsec tunnel overhead
- ✗ Firewall rules
- ✗ Routing configuration
- ✗ Hardware offloading (checksum, TSO, LSO)

## Timeline

| Date | Event |
|------|-------|
| ~2020 | First reports on Reddit ("Weirdest Issue Ever?") |
| Nov 2025 | Bug reported to Netgate |
| Nov 2025 | Netgate confirms and reproduces the bug |
| Dec 2025 | 39C3 Lightning Talk |

## Possible Workaround

**Do not use the integrated switch!**
- Use only the WAN port
- Implement VLANs with an external switch

## Resources

- [Blog Post (German)](https://blog.stylite.de/blog/toxicframe-netgate-sg-2100/) – Detailed analysis with PCAP files and video demonstrations

## Contributing

If you have experienced this issue or have additional information, please open an issue or submit a PR with your findings.

**Especially interested in:**
- Can the Switch-ASIC registers be read to see if/why the packet is dropped?
- Can OpenWRT or similar be installed on the SG-2100 for further testing?
- Tests on other hardware with Marvell 6000 series switches

## License

MIT

---

*This repository documents a hardware bug for the benefit of the community and to assist affected users.*

**#toxicframe** – *Wim Bonis · Stylite AG*
