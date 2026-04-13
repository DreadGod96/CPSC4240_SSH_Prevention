"""
sentinel_daemon.py - The Python User-Space Controller
"""

from bcc import BPF
import time
import os
import re
import socket
import struct

# --- CONTRACT CONFIG ---
INTERFACE = "eth0"  # Verify with 'ip link'
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5       # Max failures before ban
WINDOW = 300        # Seconds to track failures

# 1. Load the Kernel Contract
b = BPF(src_file="sentinel_kern.c")
fn = b.load_func("xdp_sentinel", BPF.XDP)
b.attach_xdp(INTERFACE, fn, 0)

# 2. Access the Shared Map
blacklist = b.get_table("blacklist")
failed_attempts = {}

def ban_attacker(ip_str):
    """Updates the kernel-space map with a new blacklisted IP."""
    # Convert dotted-string IP to Network Byte Order integer
    ip_int = struct.unpack("I", socket.inet_aton(ip_str))[0]
    
    # Push to Kernel (Key: IP integer, Value: Timestamp)
    blacklist[struct.pack("I", ip_int)] = b.u64(int(time.time()))
    
    print(f"[!] SENTINEL: Host {ip_str} neutralized at NIC level.")
    with open("/var/log/sentinel_bans.log", "a") as f:
        f.write(f"{time.ctime()}: {ip_str} BANNED\n")

def run_sentinel():
    print(f"Sentinel-XDP Operational on {INTERFACE}. Monitoring {LOG_FILE}...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                now = time.time()
                failed_attempts.setdefault(ip, [])
                failed_attempts[ip].append(now)
                
                # Filter old attempts
                failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t < WINDOW]

                if len(failed_attempts[ip]) >= THRESHOLD:
                    ban_attacker(ip)

if __name__ == "__main__":
    try:
        run_sentinel()
    except KeyboardInterrupt:
        print("\nDetaching from NIC and shutting down...")
    finally:
        b.remove_xdp(INTERFACE, 0)
