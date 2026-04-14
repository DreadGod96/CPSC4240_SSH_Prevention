#BPF tool access (BPF Compiler Collection) - push data to the kernel
from bcc import BPF
#timestamps
import time
#opens the auth log
import os
#regex - find failed passwd
import re
# convert ip to binary
import socket
#c conversions
import struct

INTERFACE = "wlp2s0"
LOG_FILE = "/var/log/auth.log"
THRESHOLD = 5
WINDOW = 300

#compile NIC_Guard into bytecode
try:
    b = BPF(src_file="NIC_Guard.c")
    fn = b.load_func("xdp_sentinel", BPF.XDP)

#try to attach to the wifi driver
    try: 
        b.attach_xdp(INTERFACE, fn, 0)
    except:
        print(f"XDP not supported on {INTERFACE}. Moving to generic mode...")
        b.attach_xdp(INTERFACE, fn, BPF.XDP_FLAGS_SKB_MODE)

#exit if program wont load
except Exception as e:
    print(f"Failed to load BPF program: {e}")
    exit(1)

#access the blacklist
blacklist = b.get_table("blacklist")
#initialize a dictionary to track attempts
failed_attempts = {}

#Update hash map with blacklisted IP and log the action
def blacklist_attacker(ip_string):
    try:
        #convert IP to 32 bit unsigned integer(BE), grab 1st item
        ip_convert = struct.unpack("I", socket.inet_aton(ip_string))[0]

        #push to kernel (key(IP converted), val(timestamp))
        blacklist[struct.pack("I", ip_convert)] = b.u64(int(time.time()))
        print(f"Sentinel: Host {ip_string} stopped at the NIC.")

        #append to designated log for attempt blocking
        with open("/var/log/NIC_Guard_Bans.log", "a") as block_log:
            #timestamp: address
            block_log.write(f"{time.ctime()}: {ip_string} BLACKLISTED!!!\n"
    except Exception as e:
        print(f"Error blacklisting {ip_string}: {e}")

def run_ssh_guard():
    print(f"SSH Guard Operational on {INTERFACE}")
    print(f"Monitoring {LOG_FILE} for any brute force attempts..."

    #Look in the auth log
    with open(LOG_FILE, "r") as read_log:
        #check end of log
        read_log.seek(0, os.SEEK_END)
        
        #persistent polling the log
        while True:
            line = read_log.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            #look for passwd failures
            pass_match = re.search(r"Failed password for .* from (\d+\d+\.\d+\.\d+)", line
            if match:
                ip = match.group(1)
                timestamp = time.time()

                #set up and update failure history
                failed_attempts.setdefault(ip, [])
                failed_attempts[ip].append(timestamp)

                #filter out attempts past time window(300 secs)
                #look at every time, calculate and check if within the window
                failed_attempts[ip] = [t for t in failed_attempts[ip] if timestamp - t < WINDOW]
                
                #keep track of failed attempts every time one occurs
                print(f"Detected SSH failure from {ip} ({len(failed_attempts[ip])}/{THRESHOLD})")
                
                #once attempts == 5, add to blacklist
                if len(failed_attempts[ip]) >= THRESHOLD:
                    blacklist_attacker(ip)

#ensure script is modular
if __name__ == "__main__":
    try:
        run_ssh_guard()
    #graceful exit(on ctrl c)
    except KeyboardInterrupt:
        print("\nSSH_Guard detaching from NIC and shutting down")

    finally:
    #graceful cleanup
    b.remove_xdp(INTERFACE, 0)
