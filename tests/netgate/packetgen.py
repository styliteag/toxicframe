#!/usr/bin/env python3
import os
import sys
import fcntl
import struct

# From FreeBSD <net/bpf.h>
BIOCSETIF      = 0x8020426c
BIOCSHDRCMPLT  = 0x80044275

IFNAME = b"mvneta1"  # your interface name


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <payloadfile>")
        sys.exit(1)

    payload_file = sys.argv[1]

    with open(payload_file, "rb") as fp:
        toxic = fp.read()

    # Open BPF (cloning device on FreeBSD)
    bpf_fd = os.open("/dev/bpf", os.O_WRONLY)

    try:
        # Tell BPF that we provide a complete Ethernet header
        hdr_complete = struct.pack("I", 1)
        fcntl.ioctl(bpf_fd, BIOCSHDRCMPLT, hdr_complete)

        # Bind to interface "lan0"
        # struct ifreq { char ifr_name[16]; short ifr_ifru; ... }
        ifreq = struct.pack("16sH14s", IFNAME, 0, b"\x00" * 14)
        fcntl.ioctl(bpf_fd, BIOCSETIF, ifreq)

        # Build frame: dst(6) + src(6) + ethertype(2) + payload
        frame  = b"\xff" * 6                          # ff:ff:ff:ff:ff:ff
        frame += bytes.fromhex("90ec773a15b0")        # 9c:bf:0d:00:3e:ff
        frame += b"\x27\xfa"                          # EtherType 0x27fa
        frame += toxic

        os.write(bpf_fd, frame)

    finally:
        os.close(bpf_fd)


if __name__ == "__main__":
    main()