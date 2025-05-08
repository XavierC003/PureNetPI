PureNet Pi – Unified DNS and Firewall Manager

Author: Xavier Christian 
Date: May 2025 
Project Type: Senior Capstone – CSCI 494

📌 Overview

PureNet Pi is a custom Python-based tool that provides DNS filtering and remote firewall management on Raspberry Pi devices. It allows users to block domains and IP addresses in real time using a command-line interface. This project combines DNS resolution, logging, SSH-based firewall control, and interactive user commands in a single portable script.

⚙️ Features

DNS server built using dnslib

Domain-level blocking using local site blocklist

IP-level blocking via SSH and iptables

Real-time command-line interface

DNS logging to local file

Persistent startup using systemd

🧰 Requirements

Python 3.x

dnslib (pip3 install dnslib)

Raspberry Pi OS (or any Linux distro)

SSH key authentication between DNS Pi and Firewall Pi

iptables installed and configured on Firewall Pi

🏗️ Installation

Clone or copy the project to your Raspberry Pi.

Install Python dependencies:

pip3 install dnslib

Configure SSH access from DNS Pi to Firewall Pi.

Ensure ip_blocklist.txt and site_blocklist.txt exist (can be empty).

Set Python script to bind to port 53:

sudo setcap 'cap_net_bind_service=+ep' $(which python3)

(Optional) Register the script as a systemd service for autostart.

🚀 Running the Program

sudo python3 Pi_Hole_Fire_Wall_Manager.py

You will see a CLI where you can run commands:

Example Commands

add-site example.com

remove-site example.com

add-ip 192.168.1.10

remove-ip 192.168.1.10

list-sites, list-ips, check-site, check-ip

exit

📡 Architecture

Client Device → DNS Pi (blocks domains) → Firewall Pi (blocks IPs) → Internet

🛡 Example Use Case

DNS Pi blocks ads.com so devices can't resolve the domain.

Firewall Pi blocks 192.168.1.20 so that device loses internet access.

All commands issued from one terminal CLI.

📁 Files

Pi_Hole_Fire_Wall_Manager.py: Main script

Firewall.sh: Firewall

📖 License

This project is for educational use as part of the senior capstone course. Open for extension and improvement.

🧠 Credits

Inspired by Pi-hole, iptables, dnslib, and open-source networking principles.

📬 Creators

Created by Xavier Christian and Chance Foster for CSCI 494 Senior Project.


