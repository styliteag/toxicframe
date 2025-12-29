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

## The Toxic Pattern

The bug is triggered by a specific **14-byte pattern**:

```
44 24 12 91 48 44 22 12 89 48 24 22 91 89
```

In the original `toxic.bin` (1 KB), this pattern is repeated 39 times.

## Repository Structure

```
├── binarys/                    # Binary test files
│   ├── toxic.bin               # Original 1KB toxic file
│   ├── toxic_smallest.bin      # Smallest confirmed toxic file
│   └── maybe_smallest.bin      # Candidate for even smaller
├── tests/                      # Test suite
│   ├── test_toxicframe.py      # Main test script
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
