# CS 4351 - Assignment 6: ARP Cache Poisoning and MITM Attack Scripts

This repository contains Python scripts developed for Assignment 6 of the CS 4351: Computer Security course. These scripts demonstrate various ARP cache poisoning techniques and their application in Man-in-the-Middle (MITM) attacks on Telnet and Netcat sessions. All scripts are designed to be used with the Scapy library.

## Lab Overview

The lab environment consists of three Docker containers on the same virtual network (10.9.0.0/24):
* **Host A (Victim Client):** IP `10.9.0.5`, MAC `02:42:0a:09:00:05`
* **Host B (Victim Server):** IP `10.9.0.6`, MAC `02:42:0a:09:00:06`
* **Host M (Attacker):** IP `10.9.0.105`, MAC `02:42:0a:09:00:69` (or as configured)

The objective is to use Host M to launch attacks, intercepting and modifying communication between Host A and Host B.

## Prerequisites

* **Docker and Docker Compose:** For setting up the lab environment as described in the assignment.
* **Scapy:** All Python scripts rely on the Scapy library for packet manipulation. This should be installed on the attacker machine (Host M).
    ```bash
    pip install scapy
    ```
* **Privileges:** Scripts that send raw packets or sniff network traffic typically require root privileges to run (e.g., using `sudo python3 script_name.py`).

## Scripts

The following scripts are included:

### Task 1: ARP Cache Poisoning

These scripts demonstrate different methods to poison the ARP cache of a target machine (Host A) to map Host B's IP address to Host M's MAC address. They are intended to be run on Host M.

1.  **`task1A_arp_request.py`**
    * **Description:** Sends a single crafted ARP *request* packet to Host A to poison its cache.
    * **Usage:** `sudo python3 task1A_arp_request.py`
    * **Objective:** To make Host A map Host B's IP (`10.9.0.6`) to an attacker-controlled MAC.

2.  **`task1B_arp_reply.py`**
    * **Description:** Sends a single crafted ARP *reply* packet to Host A to poison its cache.
    * **Usage:** `sudo python3 task1B_arp_reply.py`
    * **Objective:** To make Host A map Host B's IP (`10.9.0.6`) to Host M's MAC. This script is tested under scenarios where Host A's cache may or may not already contain an entry for Host B.

3.  **`task1C_gratuitous_arp.py`**
    * **Description:** Sends a single *gratuitous* ARP packet, appearing to originate from Host B's IP but with Host M's MAC, to update ARP caches on the network (targeting Host A).
    * **Usage:** `sudo python3 task1C_gratuitous_arp.py`
    * **Objective:** To make Host A map Host B's IP (`10.9.0.6`) to Host M's MAC. Tested under scenarios with and without a pre-existing cache entry on Host A.

### Task 2 & 3: Man-in-the-Middle (MITM) Attacks

These tasks involve setting up a continuous ARP poisoning attack to intercept traffic and then using specialized scripts to modify that traffic.

1.  **`combined_poison.py`**
    * **Description:** Performs continuous ARP poisoning against *both* Host A and Host B.
        * Tells Host A that Host B's IP is at Host M's MAC.
        * Tells Host B that Host A's IP is at Host M's MAC.
    * This script needs to be running in the background on Host M for the MITM attacks in Task 2 and Task 3 to work.
    * **Usage:** `sudo python3 combined_poison.py`
    * **Note:** Sends ARP packets periodically (e.g., every 5 seconds).

2.  **`telnet_mitm.py`** (For Task 2)
    * **Description:** Intercepts a Telnet session between Host A (client) and Host B (server). It modifies each character typed by Host A, replacing it with 'Z' before forwarding to Host B. Traffic from Host B to Host A is forwarded unmodified.
    * **Prerequisites:**
        * `combined_poison.py` must be running on Host M.
        * IP forwarding must be **OFF** on Host M (`sudo sysctl net.ipv4.ip_forward=0`).
    * **Usage:** `sudo python3 telnet_mitm.py`
    * **Telnet Credentials:** User `seed`, Password `dees` on Host B.

3.  **`netcat_mitm.py`** (For Task 3)
    * **Description:** Intercepts a Netcat session between Host A (client) and Host B (server listening on port 9090). It replaces every occurrence of a specified first name (e.g., "Jesus") in messages sent from Host A to Host B with a sequence of 'A's of the same length.
    * **Prerequisites:**
        * `combined_poison.py` must be running on Host M.
        * IP forwarding must be **OFF** on Host M (`sudo sysctl net.ipv4.ip_forward=0`).
        * **Important:** You **must** edit this script to set the `USER_FIRST_NAME` variable to your actual first name.
    * **Usage:** `sudo python3 netcat_mitm.py`

## General Instructions for Running MITM Attack Scripts (Tasks 2 & 3)

1.  **Setup Docker Environment:** Ensure Host A, Host B, and Host M containers are running.
2.  **Start Continuous ARP Poisoning:** On Host M, run `sudo python3 combined_poison.py`. Keep this running in one terminal.
3.  **Disable IP Forwarding on Host M:** In another terminal on Host M, run `sudo sysctl net.ipv4.ip_forward=0`.
4.  **Run the Specific MITM Script:** In a new terminal on Host M, run either `sudo python3 telnet_mitm.py` or `sudo python3 netcat_mitm.py`.
5.  **Initiate Communication:**
    * For Telnet: From Host A, `telnet 10.9.0.6`.
    * For Netcat: On Host B, `nc -lp 9090`. Then from Host A, `nc 10.9.0.6 9090`.
6.  **Observe:** Check the terminals of Host A, Host B, and Host M (script output) to see the effects of the MITM attack.

## Lab Environment Configuration (Key Parameters)

* **Host A IP:** `10.9.0.5`
* **Host A MAC:** `02:42:0a:09:00:05`
* **Host B IP:** `10.9.0.6`
* **Host B MAC:** `02:42:0a:09:00:06`
* **Host M IP (Attacker):** `10.9.0.105` (as per lab diagram, may vary based on actual container config, e.g., `10.9.0.7` if using `hostC` directly)
* **Host M MAC (Attacker):** `02:42:0a:09:00:69` (or the actual MAC of Host M's `eth0` interface in the `10.9.0.0/24` network)
* **Shared Volume:** Scripts are typically placed in `./volumes` on the host VM and accessed via `/volumes` inside the attacker container.

## Notes

* The MAC addresses and attacker IP mentioned are based on the lab description. Verify these with `ip addr show` on each container if you encounter issues.
* Always ensure the correct network interface (e.g., `eth0`) is specified in Scapy's `sendp()` function if it's not automatically detected correctly.
* These scripts are for educational purposes to understand network vulnerabilities. Unauthorized ARP poisoning or MITM attacks are illegal.
