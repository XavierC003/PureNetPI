#!/usr/bin/env python3
"""
Unified Pi-Hole–style DNS blocker + firewall manager CLI
 
Features:
- Domain and IP blocklists stored in text files
- DNS server using dnslib for domain-level blocking
- IP blocking using remote firewall over SSH (iptables)
- CLI commands to add/remove/check/list domains and IPs
 
Usage:
chmod +x Pi_Hole_Fire_Wall_Manager.py
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
./Pi_Hole_Fire_Wall_Manager.py
"""
 
import sys, subprocess, threading, datetime, logging
from dnslib import DNSRecord, RR, A, QTYPE
from dnslib.server import DNSServer, BaseResolver, DNSHandler
 
# ==== Config ====
IP_BLOCKLIST_FILE = "ip_blocklist.txt"
SITE_BLOCKLIST_FILE = "site_blocklist.txt"
LOG_FILE = "dns_queries.log"
 
FW_HOST = "192.168.88.92"  # firewall Pi IP
FW_USER = "pi"
SSH_KEY = "/home/pi/.ssh/id_rsa"
UPSTREAM_DNS = ("8.8.8.8", 53)
 
# ==== Persistence ====
def load_blocklist(filename):
    try:
        with open(filename, "r") as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        return set()
 
def save_blocklist(filename, blocklist):
    with open(filename, "w") as f:
        for item in sorted(blocklist):
            f.write(item + "\n")
 
domain_blocklist = load_blocklist(SITE_BLOCKLIST_FILE)
ip_blocklist = load_blocklist(IP_BLOCKLIST_FILE)
 
# ==== Remote Firewall ====
def remote_exec(cmd: str):
    ssh_cmd = [
        "ssh", "-i", SSH_KEY,
        f"{FW_USER}@{FW_HOST}",
        "-o", "BatchMode=yes",
        cmd
    ]
    try:
        result = subprocess.run(ssh_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Remote command failed: {e.stderr.decode().strip()}")
 
def block_ip_remote(ip: str):
    remote_exec(f"sudo iptables -A INPUT -s {ip} -j DROP")
    remote_exec(f"sudo iptables -A FORWARD -s {ip} -j DROP")
 
def unblock_ip_remote(ip: str):
    remote_exec(f"sudo iptables -D INPUT -s {ip} -j DROP")
    remote_exec(f"sudo iptables -D FORWARD -s {ip} -j DROP")
 
# ==== DNS Resolver ====
class BlocklistResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = request.q.qname.idna().rstrip('.')
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]
        timestamp = datetime.datetime.now().isoformat()
 
        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} | {client_ip} | {qname} | {qtype}\n")
 
        # Block domain
        if qname in domain_blocklist:
            reply = request.reply()
            return reply
 
        # Forward upstream
        upstream_data = request.send(*UPSTREAM_DNS)
        upstream_reply = DNSRecord.parse(upstream_data)
 
        # Strip IPs that are blocked
        clean = request.reply()
        for rr in upstream_reply.rr:
            if rr.rtype == QTYPE.A and str(rr.rdata) in ip_blocklist:
                continue
            clean.add_answer(rr)
        return clean
 
def start_dns_server():
    resolver = BlocklistResolver()
    DNSHandler.log_request = lambda *args, **kwargs: None  # silence logs
    server = DNSServer(resolver, port=53, address="0.0.0.0")
    server.start_thread()
    print("[+] DNS server started on port 53")
 
# ==== CLI ====
def add_site(domain):
    d = domain.lower()
    if d in domain_blocklist:
        print(f"[!] {d} already blocked")
    else:
        domain_blocklist.add(d)
        save_blocklist(SITE_BLOCKLIST_FILE, domain_blocklist)
        print(f"[+] Domain {d} blocked (DNS)")
 
def remove_site(domain):
    d = domain.lower()
    if d in domain_blocklist:
        domain_blocklist.remove(d)
        save_blocklist(SITE_BLOCKLIST_FILE, domain_blocklist)
        print(f"[-] Domain {d} unblocked (DNS)")
    else:
        print(f"[!] {d} not in blocklist")
 
def list_sites():
    print("Blocked domains:" if domain_blocklist else "(No blocked domains)")
    for d in sorted(domain_blocklist): print(f"  {d}")
 
def check_site(domain):
    print("Blocked." if domain.lower() in domain_blocklist else "Allowed.")
 
def add_ip(ip):
    if ip in ip_blocklist:
        print(f"[!] {ip} already blocked")
    else:
        ip_blocklist.add(ip)
        save_blocklist(IP_BLOCKLIST_FILE, ip_blocklist)
        print(f"[+] Blocking IP {ip} remotely via firewall...")
        block_ip_remote(ip)
        print(f"[+] IP {ip} blocked (firewall)")
 
def remove_ip(ip):
    if ip in ip_blocklist:
        ip_blocklist.remove(ip)
        save_blocklist(IP_BLOCKLIST_FILE, ip_blocklist)
        unblock_ip_remote(ip)
        print(f"[-] IP {ip} unblocked (firewall)")
    else:
        print(f"[!] {ip} not in blocklist")
 
def list_ips():
    print("Blocked IPs:" if ip_blocklist else "(No blocked IPs)")
    for i in sorted(ip_blocklist): print(f"  {i}")
 
def check_ip(ip):
    print("Blocked." if ip in ip_blocklist else "Allowed.")
 
def help_text():
    print("""
Commands:
  add-site <DOMAIN>    – block a domain via DNS
  remove-site <DOMAIN> – unblock a domain
  check-site <DOMAIN>  – check domain status
  list-sites           – list blocked domains
 
  add-ip <IP>          – block an IP via firewall
  remove-ip <IP>       – unblock an IP
  check-ip <IP>        – check IP status
  list-ips             – list blocked IPs
 
  help                 – show this message
  exit | quit          – exit program
""")
 
def main():
    print("Unified Pi-hole + Firewall Manager CLI")
    help_text()
    while True:
        try:
            parts = input("> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            break
        if not parts:
            continue
        cmd, *args = parts
        if cmd in ('exit', 'quit'):
            break
        elif cmd == 'help':
            help_text()
        elif cmd == 'add-site' and args:
            add_site(args[0])
        elif cmd == 'remove-site' and args:
            remove_site(args[0])
        elif cmd == 'check-site' and args:
            check_site(args[0])
        elif cmd == 'list-sites':
            list_sites()
        elif cmd == 'add-ip' and args:
            add_ip(args[0])
        elif cmd == 'remove-ip' and args:
            remove_ip(args[0])
        elif cmd == 'check-ip' and args:
            check_ip(args[0])
        elif cmd == 'list-ips':
            list_ips()
        else:
            print("[!] Unknown command. Type 'help'.")
    print("Goodbye.")
 
if __name__ == '__main__':
    start_dns_server()
    main()