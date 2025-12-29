#!/usr/bin/env python3
"""
Fast packet generator with HTTP API.
Uses BPF on FreeBSD to send raw Ethernet frames.
"""
import os
import sys
import fcntl
import struct
import threading
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

# From FreeBSD <net/bpf.h>
BIOCSETIF = 0x8020426c
BIOCSHDRCMPLT = 0x80044275

# Config - matches config.py in tests/
# Note: This runs on pfSense, so values are defined here
IFNAME = b"mvneta1"  # pfSense interface (update in config.py: PFSENSE_IFACE)
DEFAULT_DST_MAC = b"\xff" * 6  # broadcast
DEFAULT_ETHERTYPE = b"\x27\xfa"  # matches config.py: ETHERTYPE


def get_interface_mac(ifname: str | bytes) -> bytes:
    """Read MAC address from interface using ifconfig."""
    if isinstance(ifname, bytes):
        ifname = ifname.decode()
    out = subprocess.check_output(["ifconfig", ifname], text=True)
    match = re.search(r"ether\s+([0-9a-f:]{17})", out, re.I)
    if not match:
        raise RuntimeError(f"Could not find MAC for {ifname}")
    return bytes.fromhex(match.group(1).replace(":", ""))
NUM_WORKERS = 4  # matches config.py: PACKETGEN_NUM_WORKERS
API_PORT = 8080  # default, can override via command line (config.py: PACKETGEN_API_PORT = 8088)


class BPFSender:
    """Thread-safe BPF packet sender."""
    
    def __init__(self, ifname: bytes = IFNAME, src_mac: bytes = None):
        self.ifname = ifname
        self.src_mac = src_mac or get_interface_mac(ifname)
        self._local = threading.local()
        self._lock = threading.Lock()
    
    def _get_fd(self) -> int:
        """Get thread-local BPF file descriptor."""
        if not hasattr(self._local, 'fd'):
            fd = os.open("/dev/bpf", os.O_WRONLY)
            fcntl.ioctl(fd, BIOCSHDRCMPLT, struct.pack("I", 1))
            ifreq = struct.pack("16sH14s", self.ifname, 0, b"\x00" * 14)
            fcntl.ioctl(fd, BIOCSETIF, ifreq)
            self._local.fd = fd
        return self._local.fd
    
    def send(self, payload: bytes, dst: bytes = DEFAULT_DST_MAC, 
             src: bytes = None, ethertype: bytes = DEFAULT_ETHERTYPE) -> None:
        """Send single frame."""
        frame = dst + (src or self.src_mac) + ethertype + payload
        os.write(self._get_fd(), frame)
    
    def send_burst(self, payload: bytes, count: int, dst: bytes = DEFAULT_DST_MAC,
                   src: bytes = None, ethertype: bytes = DEFAULT_ETHERTYPE) -> int:
        """Send multiple frames as fast as possible. Returns actual sent count."""
        frame = dst + (src or self.src_mac) + ethertype + payload
        fd = self._get_fd()
        for i in range(count):
            os.write(fd, frame)
        return count


class PacketWorker:
    """Worker pool for parallel packet sending."""
    
    def __init__(self, sender: BPFSender, num_workers: int = NUM_WORKERS):
        self.sender = sender
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        self.payloads: dict[str, bytes] = {}  # name -> payload
        self._lock = threading.Lock()
    
    def load_payload(self, name: str, data: bytes) -> None:
        with self._lock:
            self.payloads[name] = data
    
    def load_payload_file(self, name: str, path: str) -> None:
        with open(path, "rb") as f:
            self.load_payload(name, f.read())
    
    def get_payload(self, name: str) -> bytes | None:
        with self._lock:
            return self.payloads.get(name)
    
    def send_async(self, payload_name: str, count: int = 1):
        """Queue async send job."""
        payload = self.get_payload(payload_name)
        if payload is None:
            raise ValueError(f"Unknown payload: {payload_name}")
        return self.executor.submit(self.sender.send_burst, payload, count)
    
    def send_parallel(self, payload_name: str, total_count: int, num_tasks: int = None):
        """Send packets in parallel across workers."""
        num_tasks = num_tasks or NUM_WORKERS
        payload = self.get_payload(payload_name)
        if payload is None:
            raise ValueError(f"Unknown payload: {payload_name}")
        
        per_task = total_count // num_tasks
        remainder = total_count % num_tasks
        
        futures = []
        for i in range(num_tasks):
            cnt = per_task + (1 if i < remainder else 0)
            if cnt > 0:
                futures.append(self.executor.submit(self.sender.send_burst, payload, cnt))
        
        return sum(f.result() for f in futures)


# Global state
sender = None
worker = None


class APIHandler(BaseHTTPRequestHandler):
    """Simple HTTP API handler."""
    
    def log_message(self, format, *args):
        pass  # quiet
    
    def _json_response(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""
    
    def do_GET(self):
        if self.path == "/payloads":
            with worker._lock:
                names = list(worker.payloads.keys())
            self._json_response({"payloads": names})
        elif self.path == "/health":
            self._json_response({"status": "ok"})
        else:
            self._json_response({"error": "not found"}, 404)
    
    def do_POST(self):
        try:
            if self.path == "/payload":
                # Load payload: {"name": "foo", "hex": "deadbeef"} or {"name": "foo", "file": "/path"}
                data = json.loads(self._read_body())
                name = data["name"]
                if "hex" in data:
                    worker.load_payload(name, bytes.fromhex(data["hex"]))
                elif "file" in data:
                    worker.load_payload_file(name, data["file"])
                elif "base64" in data:
                    import base64
                    worker.load_payload(name, base64.b64decode(data["base64"]))
                else:
                    return self._json_response({"error": "need hex, file, or base64"}, 400)
                self._json_response({"ok": True, "name": name})
            
            elif self.path == "/send":
                # Send packets: {"payload": "name", "count": 1000, "parallel": true}
                data = json.loads(self._read_body())
                name = data["payload"]
                count = data.get("count", 1)
                parallel = data.get("parallel", count > 100)
                
                if parallel:
                    sent = worker.send_parallel(name, count)
                else:
                    payload = worker.get_payload(name)
                    if payload is None:
                        return self._json_response({"error": f"unknown payload: {name}"}, 400)
                    sent = sender.send_burst(payload, count)
                
                self._json_response({"sent": sent})
            
            elif self.path == "/send/raw":
                # Send raw hex payload: {"hex": "...", "count": 1}
                data = json.loads(self._read_body())
                payload = bytes.fromhex(data["hex"])
                count = data.get("count", 1)
                sent = sender.send_burst(payload, count)
                self._json_response({"sent": sent})
            
            else:
                self._json_response({"error": "not found"}, 404)
        except Exception as e:
            self._json_response({"error": str(e)}, 500)


class ThreadedHTTPServer(HTTPServer):
    """Handle each request in a new thread."""
    def process_request(self, request, client_address):
        t = threading.Thread(target=self.process_request_thread, args=(request, client_address))
        t.daemon = True
        t.start()
    
    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


def main():
    global sender, worker
    
    port = int(sys.argv[1]) if len(sys.argv) > 1 else API_PORT
    
    sender = BPFSender()
    print(f"Interface {IFNAME.decode()} MAC: {sender.src_mac.hex(':')}")
    worker = PacketWorker(sender, NUM_WORKERS)
    
    # Preload any payload files from args
    for i, arg in enumerate(sys.argv[2:], 1):
        if os.path.isfile(arg):
            name = os.path.basename(arg).replace(".", "_")
            worker.load_payload_file(name, arg)
            print(f"Loaded payload '{name}' from {arg}")
    
    server = ThreadedHTTPServer(("0.0.0.0", port), APIHandler)
    print(f"Packet generator API on port {port}")
    print("Endpoints:")
    print("  GET  /health          - health check")
    print("  GET  /payloads        - list loaded payloads")
    print("  POST /payload         - load payload {name, hex|file|base64}")
    print("  POST /send            - send packets {payload, count, parallel}")
    print("  POST /send/raw        - send raw {hex, count}")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
