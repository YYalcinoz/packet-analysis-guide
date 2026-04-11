# Wireshark Cheat Sheet

> Personal reference for packet analysis and network security work.

---

## Table of Contents

- [Display Filters](#display-filters)
- [Capture Filters](#capture-filters)
- [Useful Analysis Techniques](#useful-analysis-techniques)
- [Security-Focused Filters](#security-focused-filters)
- [tshark Quick Reference](#tshark-quick-reference)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Color Rules](#color-rules-default)
- [Common Port Numbers](#quick-reference-common-port-numbers)

---

## Display Filters

Display filters narrow down what you **see** in the packet list (applied after capture).

### Basic Protocol Filters

| Filter | Description |
|--------|-------------|
| `tcp` | Show only TCP traffic |
| `udp` | Show only UDP traffic |
| `icmp` | Show only ICMP (ping) traffic |
| `arp` | Show only ARP traffic |
| `dns` | Show only DNS traffic |
| `http` | Show only HTTP traffic |
| `tls` | Show only TLS/SSL traffic |
| `ftp` | Show only FTP traffic |
| `ssh` | Show only SSH traffic (port 22) |
| `dhcp` | Show DHCP traffic (IP assignment) |
| `smb` | Show SMB (Windows file sharing) traffic |

---

### IP & Address Filters

| Filter | Description |
|--------|-------------|
| `ip.addr == 192.168.1.1` | Traffic to OR from this IP |
| `ip.src == 192.168.1.1` | Traffic FROM this IP only |
| `ip.dst == 192.168.1.1` | Traffic TO this IP only |
| `ip.addr == 192.168.1.0/24` | Entire subnet |
| `eth.addr == aa:bb:cc:dd:ee:ff` | Filter by MAC address |
| `ipv6.addr == ::1` | IPv6 loopback |
| `ip.ttl < 10` | Low TTL — may indicate traceroute or routing issues |
| `ip.ttl == 64` | Common Linux TTL default |
| `ip.ttl == 128` | Common Windows TTL default |

> **TTL tip:** Operating systems use different default TTL values. This can help you fingerprint devices passively.

---

### Port Filters

| Filter | Description |
|--------|-------------|
| `tcp.port == 80` | TCP port 80 (either direction) |
| `tcp.srcport == 443` | Source port 443 |
| `tcp.dstport == 22` | Destination port 22 |
| `udp.port == 53` | UDP port 53 (DNS) |
| `tcp.port in {80 443 8080}` | Multiple ports at once |
| `tcp.dstport < 1024` | Connections to well-known ports |

---

### TCP Flag Filters

| Filter | Description |
|--------|-------------|
| `tcp.flags.syn == 1` | SYN packets (connection requests) |
| `tcp.flags.ack == 1` | ACK packets |
| `tcp.flags.fin == 1` | FIN packets (connection teardown) |
| `tcp.flags.reset == 1` | RST packets (connection reset) |
| `tcp.flags.push == 1` | PSH flag — data being pushed immediately |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | Only SYN (not SYN-ACK) — useful for SYN flood detection |
| `tcp.analysis.retransmission` | Retransmitted packets |
| `tcp.analysis.zero_window` | Zero window (receiver buffer full) |
| `tcp.analysis.duplicate_ack` | Duplicate ACKs — often signals packet loss |
| `tcp.analysis.fast_retransmission` | Fast retransmission events |

**TCP Handshake Reference:**
```
Client → Server   SYN                  (I want to connect)
Server → Client   SYN-ACK              (OK, let's connect)
Client → Server   ACK                  (Connected)

Client → Server   FIN                  (I want to close)
Server → Client   FIN-ACK              (OK, closing)
Client → Server   ACK                  (Closed)

Either side       RST                  (Abort immediately)
```

---

### HTTP Filters

| Filter | Description |
|--------|-------------|
| `http.request` | All HTTP requests |
| `http.response` | All HTTP responses |
| `http.request.method == "GET"` | Only GET requests |
| `http.request.method == "POST"` | Only POST requests |
| `http.response.code == 200` | HTTP 200 OK |
| `http.response.code == 301` | HTTP 301 Redirect |
| `http.response.code == 403` | HTTP 403 Forbidden |
| `http.response.code == 404` | HTTP 404 Not Found |
| `http.response.code == 500` | HTTP 500 Server Error |
| `http.host == "example.com"` | Requests to a specific host |
| `http.request.uri contains "login"` | URIs containing "login" |
| `http.request.uri contains "admin"` | URIs containing "admin" |
| `http.cookie` | Packets containing cookies |
| `http.authorization` | Packets with HTTP auth headers |

> **Note:** Wireshark only dissects HTTP on port 80 by default. For custom ports: right-click a packet → *Decode As → HTTP*.

---

### DNS Filters

| Filter | Description |
|--------|-------------|
| `dns` | All DNS traffic |
| `dns.qry.name == "example.com"` | DNS query for specific domain |
| `dns.qry.name contains "evil"` | Domain name contains string |
| `dns.flags.response == 0` | DNS queries only |
| `dns.flags.response == 1` | DNS responses only |
| `dns.resp.len > 512` | Large DNS responses (possible DNS tunneling) |
| `dns.qry.type == 1` | A record queries (IPv4) |
| `dns.qry.type == 28` | AAAA record queries (IPv6) |
| `dns.qry.type == 16` | TXT record queries |
| `dns.qry.type == 255` | ANY queries |
| `dns.flags.rcode != 0` | DNS errors (NXDOMAIN, SERVFAIL, etc.) |

**DNS Response Codes:**
| Code | Name | Meaning |
|------|------|---------|
| 0 | NOERROR | Success |
| 1 | FORMERR | Format error |
| 2 | SERVFAIL | Server failed |
| 3 | NXDOMAIN | Domain does not exist |
| 5 | REFUSED | Query refused |

---

### TLS / HTTPS Filters

| Filter | Description |
|--------|-------------|
| `tls` | All TLS traffic |
| `tls.handshake` | TLS handshake packets only |
| `tls.handshake.type == 1` | ClientHello (client initiates TLS) |
| `tls.handshake.type == 2` | ServerHello (server responds) |
| `tls.handshake.type == 11` | Certificate exchange |
| `ssl.alert_message` | TLS alerts (errors, warnings) |

> **Decrypting TLS:** Wireshark can decrypt TLS if you provide the server's private key or a session key log file. Go to *Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*.

---

### Logical Operators

| Operator | Symbol | Example |
|----------|--------|---------|
| AND | `&&` or `and` | `ip.src == 10.0.0.1 && tcp.port == 80` |
| OR | `\|\|` or `or` | `tcp.port == 80 \|\| tcp.port == 443` |
| NOT | `!` or `not` | `!arp` |
| Equals | `==` | `ip.ttl == 64` |
| Not equals | `!=` | `ip.addr != 192.168.1.1` |
| Greater than | `>` | `frame.len > 1000` |
| Less than | `<` | `frame.len < 100` |
| Contains | `contains` | `http.request.uri contains "admin"` |
| Matches (regex) | `matches` | `dns.qry.name matches ".*\.ru$"` |

---

## Capture Filters

Capture filters are applied **before/during** capture (BPF syntax). More efficient than display filters for large traffic volumes.

| Filter | Description |
|--------|-------------|
| `host 192.168.1.1` | Traffic to/from this host |
| `src host 192.168.1.1` | Traffic from this host |
| `dst host 192.168.1.1` | Traffic to this host |
| `net 192.168.1.0/24` | Entire subnet |
| `port 80` | Traffic on port 80 |
| `not port 22` | Exclude SSH |
| `tcp` | TCP traffic only |
| `udp port 53` | DNS over UDP |
| `port 80 or port 443` | HTTP and HTTPS |
| `host 10.0.0.1 and port 443` | Specific host + port combo |
| `icmp` | ICMP only |
| `not broadcast and not multicast` | Exclude broadcast/multicast noise |
| `greater 1000` | Packets larger than 1000 bytes |

> **Important:** Capture filters use **BPF syntax**, display filters use **Wireshark's own syntax** — they are not interchangeable.

---

## Useful Analysis Techniques

### Follow a Stream
Right-click a packet → **Follow → TCP Stream** (or UDP/HTTP/TLS)

Shows the full conversation in readable form. Useful for:
- Seeing plaintext HTTP credentials or form data
- Reconstructing file transfers
- Spotting command & control traffic patterns
- Reading cleartext protocol exchanges (FTP, Telnet, SMTP)

### Statistics Menu

| Menu Item | Use |
|-----------|-----|
| `Statistics → Protocol Hierarchy` | See breakdown of all protocols in the capture |
| `Statistics → Conversations` | Top talkers, bytes transferred per pair |
| `Statistics → Endpoints` | All unique IPs/MACs seen |
| `Statistics → IO Graph` | Traffic volume over time |
| `Statistics → DNS` | DNS query/response summary |
| `Statistics → HTTP → Requests` | All HTTP requests and their hosts |
| `Statistics → TCP Stream Graphs` | RTT, throughput, window scaling graphs |

### Export Objects
`File → Export Objects → HTTP` — Extract files transferred over HTTP (images, executables, documents, etc.)

Also available: `IMF`, `SMB`, `TFTP` object export.

### Packet Comments
Right-click any packet → **Packet Comment** — Add your own notes to a packet. Useful when documenting findings in a `.pcap` file you're sharing.

### Time Display
`View → Time Display Format` — Switch between:
- Seconds since capture start (default)
- UTC / local clock time
- Delta time between packets (useful for spotting delays)

---

## Security-Focused Filters

### Detect Port Scanning (Nmap-style)
```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```
Many SYN packets to **different ports** from one source = likely port scan.
Look for a single source IP with a high number of unique destination ports.

### Detect SYN Flood
```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```
Same filter — look for **high volume** targeting one destination IP on one port.

### Detect Nmap NULL / FIN / Xmas Scans
```
tcp.flags == 0x000
```
NULL scan — no flags set. Used to evade basic firewalls.
```
tcp.flags.fin == 1 and tcp.flags.syn == 0 and tcp.flags.ack == 0
```
FIN scan.
```
tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1
```
Xmas scan — FIN + PSH + URG set simultaneously.

### Detect ARP Spoofing
```
arp.duplicate-address-detected
```
Or manually:
```
arp
```
Look for multiple ARP replies mapping **different MACs to the same IP** — a classic sign of a man-in-the-middle attack.

Also useful:
```
arp.opcode == 2
```
Shows only ARP replies (gratuitous ARP abuse often appears here).

### Detect DNS Tunneling
```
dns.resp.len > 512
```
```
dns.qry.name matches ".*\.[a-z0-9]{20,}\."
```
Unusually long subdomains or oversized TXT records can indicate data being exfiltrated over DNS.

### Detect ICMP Tunneling
```
icmp and data.len > 64
```
Standard pings have small payloads. Large ICMP payloads may be used for covert data transfer.

### Cleartext Credentials
```
http.request.method == "POST" and http.request.uri contains "login"
```
Follow the TCP stream to see if credentials are visible in plaintext.

Also check FTP and Telnet streams — both transmit credentials in cleartext by design.

### Suspicious Outbound Connections
```
ip.dst != 192.168.1.0/24 and tcp.flags.syn == 1 and tcp.flags.ack == 0
```
New outbound SYN packets leaving your network. Adjust the subnet to match your environment.

### Beaconing / C2 Traffic Pattern
No single filter — look for:
- Regular intervals between SYN packets to the same external IP
- Constant packet sizes
- Connections to unusual ports (e.g. 4444, 1337, 8888)

```
tcp.dstport in {4444 1337 8888 6666 9999}
```

---

## tshark Quick Reference

`tshark` is the command-line version of Wireshark. Useful for scripting, remote servers, or quick terminal analysis.

### Basic Usage

```bash
# List available interfaces
tshark -D

# Capture on a specific interface
tshark -i eth0

# Capture and write to a file
tshark -i eth0 -w capture.pcap

# Read a pcap file
tshark -r capture.pcap

# Limit capture to N packets
tshark -i eth0 -c 100
```

### Filtering with tshark

```bash
# Apply a display filter while reading
tshark -r capture.pcap -Y "http.request"

# Apply a capture filter (BPF)
tshark -i eth0 -f "port 80"

# Combine both
tshark -i eth0 -f "tcp" -Y "tcp.flags.syn == 1"
```

### Extracting Specific Fields

```bash
# Print source IP, destination IP, and protocol
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e _ws.col.Protocol

# Print DNS query names
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name

# Print HTTP requested URIs
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```

### Statistics

```bash
# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# Top conversations
tshark -r capture.pcap -q -z conv,tcp

# DNS statistics
tshark -r capture.pcap -q -z dns,tree
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + E` | Start/Stop capture |
| `Ctrl + R` | Reload / restart capture |
| `Ctrl + F` | Find packet |
| `Ctrl + G` | Go to packet number |
| `Ctrl + Shift + E` | Export specified packets |
| `Ctrl + Alt + Shift + T` | Follow TCP stream |
| `Ctrl + Shift + X` | Follow HTTP stream |
| `Ctrl + M` | Mark/unmark packet |
| `Ctrl + Shift + N` | Next marked packet |
| `Ctrl + D` | Display filter expression builder |
| `F5` | Refresh |
| `Spacebar` | Scroll to next packet |
| `Tab` | Move between panels |
| `Alt + →` | Go forward in navigation history |
| `Alt + ←` | Go back in navigation history |

---

## Color Rules (Default)

| Color | Meaning |
|-------|---------|
| Green | TCP traffic |
| Light blue | UDP traffic |
| Black | TCP errors / bad packets |
| Red | Problems (RST, checksum errors) |
| Yellow | Routing issues |
| Purple | ICMP |
| Gray | Broadcast traffic |

> Customize via: `View → Coloring Rules`

---

## Quick Reference: Common Port Numbers

| Port | Protocol | Service | Notes |
|------|----------|---------|-------|
| 20/21 | TCP | FTP | Cleartext — credentials visible in capture |
| 22 | TCP | SSH | Encrypted |
| 23 | TCP | Telnet | Cleartext — avoid in production |
| 25 | TCP | SMTP | Email sending |
| 53 | TCP/UDP | DNS | Queries usually UDP; large responses use TCP |
| 67/68 | UDP | DHCP | IP assignment |
| 80 | TCP | HTTP | Cleartext web traffic |
| 110 | TCP | POP3 | Email retrieval (cleartext) |
| 143 | TCP | IMAP | Email retrieval |
| 443 | TCP | HTTPS | Encrypted web traffic (TLS) |
| 445 | TCP | SMB | Windows file sharing — common attack surface |
| 3306 | TCP | MySQL | Database — should not be exposed externally |
| 3389 | TCP | RDP | Windows Remote Desktop |
| 5432 | TCP | PostgreSQL | Database |
| 8080 | TCP | HTTP Alternate | Common for proxies and dev servers |
| 8443 | TCP | HTTPS Alternate | Alternative HTTPS port |
| 4444 | TCP | — | Common Metasploit reverse shell default |

---

*Last updated: April 2026*
