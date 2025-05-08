#!/bin/bash

# Flush all existing rules
iptables -F
iptables -X

# Set default policies to DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback interface
iptables -A INPUT -i lo -j ACCEPT

# Allow already established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow DNS (UDP and TCP on port 53) from DNS Pi
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT

# Optional: Log dropped packets for debugging
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4

echo "[+] Firewall rules applied."
