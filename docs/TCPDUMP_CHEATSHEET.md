# 📘 Packet Pushers Style Deep Dive: Interpreting `tcpdump` Output

Mastering packet analysis with `tcpdump` is an essential competency for Network Engineers, Threat Hunters, and Security Operations Center (SOC) Analysts. While graphical analyzers like Wireshark provide rich visual trees, `tcpdump` is fast, ubiquitous across every Unix-like server and network appliance, and scriptable via command-line pipelines.

This guide provides an end-to-end breakdown of how `tcpdump` formats packet headers, TCP flags, sequence numbers, and payload contents, modeled after the industry-standard **Packet Pushers** deep-dive methodology.

---

## 1. The Anatomy of a `tcpdump` Output Line

When analyzing a packet with `tcpdump -nn -r incident_traffic.pcap`, a standard TCP packet line appears as follows:

```text
09:53:20.035000 IP 192.168.1.105.49152 > 192.0.2.10.80: Flags [S], seq 1000, win 64240, length 0
│               │  │               │ │  │           │  │         │         │          │
│               │  │               │ │  │           │  │         │         │          └─ Payload byte length
│               │  │               │ │  │           │  │         │         └─ Window size (bytes)
│               │  │               │ │  │           │  │         └─ Sequence number
│               │  │               │ │  │           │  └─ TCP Control Flags
│               │  │               │ │  └─ Destination Port (80 = HTTP)
│               │  │               │ └─ Destination IP address
│               │  │               └─ Source Port (ephemeral client port)
│               │  └─ Source IP address
│               └─ Network Layer Protocol (IPv4)
└─ Timestamp (Hours:Minutes:Seconds.Microseconds)
```

### Key Field Breakdown:
1. **Timestamp**: High-precision packet arrival time (`09:53:20.035000`). Relative deltas between timestamps expose network latency, packet loss, or automated beaconing loops.
2. **Network Protocol**: `IP` indicates IPv4. `IP6` indicates IPv6.
3. **Source & Destination**: `IP.PORT > IP.PORT`. The `>` character denotes packet flow direction.
4. **Flags**: Enclosed in square brackets `[ ]`. Can represent one or more TCP control bits.
5. **Sequence Number (`seq`)**: The byte stream position sent by the source.
6. **Acknowledgment Number (`ack`)**: The next sequence number byte expected by the receiver.
7. **Window Size (`win`)**: Flow control receive buffer available at the sender of this packet.
8. **Length (`length`)**: Data payload length in bytes (excluding IP and TCP headers).

---

## 2. Deciphering TCP Flags in `tcpdump`

`tcpdump` uses a shorthand notation inside square brackets `[...]` to display which flags are set in the TCP header:

| Flag Symbol | TCP Flag Name | Meaning & Typical Context |
| :---: | :---: | :--- |
| **`[S]`** | **SYN** | **Synchronize**: Initiation of a new connection (Step 1 of 3-Way Handshake). |
| **`[S.]`** | **SYN-ACK** | **Synchronize + Acknowledgment**: Server acknowledges client SYN and proposes its own sequence number (Step 2 of Handshake). |
| **`[.]`** | **ACK** | **Acknowledgment**: Confirms receipt of previously transmitted data. In `tcpdump`, a single dot `.` represents the ACK bit. |
| **`[P]` / `[P.]`** | **PSH** / **PSH-ACK** | **Push**: Tells the receiving stack to push buffered data immediately to the application layer without waiting for a full segment. Typical in interactive HTTP requests, SSH keystrokes, and API calls. |
| **`[F]` / `[F.]`** | **FIN** / **FIN-ACK** | **Finish**: Graceful connection teardown. Sender has no more data to transmit. |
| **`[R]` / `[R.]`** | **RST** / **RST-ACK** | **Reset**: Abrupt termination. Indicates port closed, firewall reset, or invalid connection state. |
| **`[U]`** | **URG** | **Urgent**: Urgent pointer field is significant (rarely used in modern protocols). |
| **`[C]`** | **CWR** | **Congestion Window Reduced**: Sender responded to an ECN-Echo flag. |
| **`[E]`** | **ECE** | **ECN-Echo**: Explicit Congestion Notification to negotiate network bottleneck handling. |

> 💡 **Packet Pushers Pro-Tip**: When `tcpdump` prints `Flags [.]`, remember that almost all TCP segments after the initial `[S]` packet carry the ACK bit set! If there are other flags combined with ACK, `tcpdump` places a dot next to the flag letter (e.g., `[P.]` = PUSH + ACK, `[F.]` = FIN + ACK, `[R.]` = RST + ACK).

---

## 3. Dissecting the TCP 3-Way Handshake

In the lab capture (`incident_traffic.pcap`), observing the initial connection to the legitimate website reveals the canonical 3-way handshake:

```text
# Packet 3: SYN from Client
09:53:20.035000 IP 192.168.1.105.49152 > 192.0.2.10.80: Flags [S], seq 1000, win 64240, length 0

# Packet 4: SYN-ACK from Web Server
09:53:20.058000 IP 192.0.2.10.80 > 192.168.1.105.49152: Flags [S.], seq 50000, ack 1001, win 65535, length 0

# Packet 5: ACK from Client
09:53:20.060000 IP 192.168.1.105.49152 > 192.0.2.10.80: Flags [.], ack 1, win 64240, length 0
```

### What Happened Behind the Bytes?
1. **Client SYN**: Client selects Initial Sequence Number (ISN) `1000`. Requests connection to port 80.
2. **Server SYN-ACK**: Server acknowledges client's ISN (`ack 1001` = $1000 + 1$) and generates its own ISN `50000`.
3. **Client ACK**: Client acknowledges server's ISN. Note that `tcpdump` switches to relative sequence numbering by default on subsequent packets (`ack 1` relative to `50000`).

---

## 4. Sequence Numbers: Relative vs. Absolute

By default, `tcpdump` displays **relative sequence numbers** once a handshake is established to make packet offsets easier to read.
To view actual, un-normalized raw 32-bit sequence numbers (as seen by firewalls and raw sockets), use the `-S` flag:

```bash
# Relative numbering (default)
tcpdump -r incident_traffic.pcap -nn 'tcp port 80'

# Absolute 32-bit sequence numbers
tcpdump -r incident_traffic.pcap -nn -S 'tcp port 80'
```

Output comparison:
- Relative: `seq 1:229, ack 1` (Sent 228 bytes of data)
- Absolute: `seq 1001:1229, ack 50001`

The notation `seq 1001:1229` means:
- The segment begins at byte `1001`.
- The segment ends at byte `1229` (non-inclusive of 1229).
- Total data carried = $1229 - 1001 = 228\text{ bytes}$.

---

## 5. Inspecting Application Payloads with `-A` and `-X`

When investigating application-layer compromise (e.g. HTTP, DNS, SMTP, plain text C2 protocols), header-only inspection is insufficient.

- **`-A` (ASCII Output)**: Prints packet payload in readable ASCII text. Ideal for searching HTTP headers, HTML bodies, and SQL injection strings.
- **`-X` (Hex + ASCII Output)**: Prints both hexadecimal offsets and ASCII characters side-by-side. Essential for inspecting binary headers (like PE `MZ`, ELF executables, or packed shellcode).
- **`-s 0` (Snapshot Length)**: Sets snaplen to full packet size (0 means unclipped, up to 65535 bytes) so payloads are not truncated.

### Practical Example: Uncovering the Malicious Stager
```bash
tcpdump -r incident_traffic.pcap -A -s 0 'host 198.51.100.25 and port 80'
```
Excerpt:
```text
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: application/x-msdownload
Content-Disposition: attachment; filename="recipe_installer.exe"
Content-Length: 87

MZ..............This program cannot be run in DOS mode.
MALWARE_DROPPER_STAGER_ID_9921
```
The ASCII view immediately identifies:
1. File served: `recipe_installer.exe`.
2. Content-Type: `application/x-msdownload`.
3. Binary magic bytes: `MZ` ($0x4D5A$ DOS executable header).

---

## 6. Berkeley Packet Filters (BPF) Quick-Reference Table

BPF syntax allows kernel-level packet filtering, drastically reducing processing overhead when analyzing high-volume captures:

| Filter Expression | Analytical Purpose |
| :--- | :--- |
| `tcpdump -r file.pcap -nn` | Do not resolve DNS names or port names (speeds up rendering and prevents reverse-DNS leaks). |
| `tcpdump -r file.pcap 'port 53'` | Isolate DNS requests and responses. |
| `tcpdump -r file.pcap 'tcp[tcpflags] & tcp-syn != 0'` | Filter only SYN packets (detect scans or connection initiations). |
| `tcpdump -r file.pcap 'tcp[tcpflags] & tcp-rst != 0'` | Filter connection resets (detect blocked connections or closed ports). |
| `tcpdump -r file.pcap 'host 198.51.100.25'` | Filter bidirectional traffic involving specific threat actor IP. |
| `tcpdump -r file.pcap 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'` | Filter only TCP packets containing non-zero data payload (strips empty ACKs). |

---

## 7. Forensic Checklist for Incident Analysts

When assigned a suspected network breach capture:

1. **Top Talkers & Protocols**: Run initial pass with `-c 100` or pipe into `awk` / `sort` to identify high-volume IPs.
2. **DNS Resolution Audit**: Examine port 53 traffic for typosquatting, DGA domains, or suspicious redirects.
3. **Session Reassembly**: Trace TCP streams using client ephemeral ports (e.g. `tcp port 49152`) through handshake, push, and teardown.
4. **Payload Extraction**: Search for unencrypted credentials, redirect headers (`Location:`, `window.location.replace`), and downloaded binaries.
5. **IOC Cataloging**: Record every confirmed malicious domain, IPv4/IPv6, URL path, and file hash for SIEM ingestion and firewall blocking.
