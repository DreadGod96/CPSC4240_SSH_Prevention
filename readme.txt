Key Terms

eBPF - extended Berkley Packet Filter
-Tool designed to filter network traffic
-Acts as a universal VM built into the kernel. Allows c code to run inside the kernel and isolates it to protect the kernel.

XDP - Express Data Path
-Entry point to network driver. eBPF attaches to the hook and enables the SSH sentinel to be placed at the NIC.


1. Making the daemon:

    1.run sudo vim /etc/systemd/system/SSH_Guard.service
    2.Paste the below code:

[Unit]
Description=Sentinel-XDP Intrusion Prevention Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /home/emonro2/CPSC4240_SSH_Prevention/SSH_Guard.py
WorkingDirectory=/home/emonro2/CPSC4240_SSH_Prevention/
StandardOutput=journal
StandardError=journal
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target

2. Verify the Paths

Inside the file, look at the ExecStart and WorkingDirectory lines. They must point to where your script actually lives.

3. Reload systemd
    
    sudo systemctl daemon-reload

4. Enable
    
    sudo systemctl enable SSH_Guard

5. Start
    
    sudo systemctl start SSH_Guard


To verify it is working:

sudo systemctl status SSH_Guard

sudo journalctl -u SSH_Guard -f



Key commands:

verify NIC hook:
ip link show wlp2s0

confirm sentinel existence:
sudo bpftool prog show name xdp_sentinel

view blacklist:
sudo bpftool map dump name blacklist

check ban log file:
cat /var/log/NIC_Guard_Bans.log

check auth log:
tail -f /var/log/auth.log

Nuclear reset:
sudo systemctl restart SSH_Guard

Persistence test:
sudo pkill -f SSH_Guard.py

Check if it auto reboots:
sudo systemctl status SSH_Guard

Erase ban log:
sudo truncate -s 0 /var/log/NIC_Guard_Bans.log