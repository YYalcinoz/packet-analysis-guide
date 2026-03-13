# Wireshark Cheat Sheet

> Personal reference for packet analysis and network security work.

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

---

### Port Filters

| Filter | Description |
|--------|-------------|
| `tcp.port == 80` | TCP port 80 (either direction) |
| `tcp.srcport == 443` | Source port 443 |
| `tcp.dstport == 22` | Destination port 22 |
| `udp.port == 53` | UDP port 53 (DNS) |
| `tcp.port in {80 443 8080}` | Multiple ports at once |

---

### TCP Flag Filters

| Filter | Description |
|--------|-------------|
| `tcp.flags.syn == 1` | SYN packets (connection requests) |
| `tcp.flags.ack == 1` | ACK packets |
| `tcp.flags.fin == 1` | FIN packets (connection teardown) |
| `tcp.flags.reset == 1` | RST packets (connection reset) |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | Only SYN (not SYN-ACK) — useful for SYN flood detection |
| `tcp.analysis.retransmission` | Retransmitted packets |
| `tcp.analysis.zero_window` | Zero window (receiver buffer full) |

---

### HTTP Filters

| Filter | Description |
|--------|-------------|
| `http.request` | All HTTP requests |
| `http.response` | All HTTP responses |
| `http.request.method == "GET"` | Only GET requests |
| `http.request.method == "POST"` | Only POST requests |
| `http.response.code == 200` | HTTP 200 OK |
| `http.response.code == 404` | HTTP 404 Not Found |
| `http.host == "example.com"` | Requests to a specific host |
| `http.request.uri contains "login"` | URIs containing "login" |

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

> **Note:** Capture filters use BPF syntax, display filters use Wireshark's own syntax — they are **not interchangeable**.

---

## Useful Analysis Techniques

### Follow a Stream
Right-click a packet → **Follow → TCP Stream** (or UDP/HTTP)  
Shows the full conversation in readable form. Great for:
- Seeing plaintext HTTP credentials
- Reconstructing file transfers
- Spotting command & control traffic

### Statistics Menu
| Menu Item | Use |
|-----------|-----|
| `Statistics → Protocol Hierarchy` | See breakdown of all protocols in the capture |
| `Statistics → Conversations` | Top talkers, bytes transferred per pair |
| `Statistics → Endpoints` | All unique IPs/MACs seen |
| `Statistics → IO Graph` | Traffic volume over time |
| `Statistics → DNS` | DNS query/response summary |

### Export Objects
`File → Export Objects → HTTP` — Extract files transferred over HTTP (images, executables, etc.)

---

## Security-Focused Filters

### Detect Port Scanning (Nmap-style)
```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```
Many SYN packets to different ports from one source = likely port scan.

### Detect SYN Flood
```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```
Same filter — look for **volume** targeting one destination.

### Detect ARP Spoofing
```
arp.duplicate-address-detected
```
Or manually check:
```
arp
```
Look for multiple ARP replies mapping different MACs to the same IP.

### Detect DNS Tunneling
```
dns.resp.len > 512
```
or
```
dns.qry.name matches ".*\.[a-z0-9]{20,}\."
```
Unusually long subdomains or large TXT records can indicate tunneling.

### Cleartext Credentials
```
http.request.method == "POST" and http.request.uri contains "login"
```
Follow the TCP stream to see if credentials are visible in plaintext.

### Suspicious Outbound Connections
```
ip.dst != 192.168.1.0/24 and tcp.flags.syn == 1 and tcp.flags.ack == 0
```
New outbound connections leaving your network — filter to your subnet.

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
| `F5` | Refresh |
| `Spacebar` | Scroll to next packet |
| `Tab` | Move between panels |

---

## Color Rules (Default)

| Color | Meaning |
|-------|---------|
| 🟢 Green | TCP traffic |
| 🔵 Light blue | UDP traffic |
| ⬛ Black | TCP errors / bad packets |
| 🔴 Red | Problems (RST, checksum errors) |
| 🟡 Yellow | Routing issues |
| 🟣 Purple | ICMP |

---

## Quick Reference: Common Port Numbers

| Port | Protocol | Service |
|------|----------|---------|
| 20/21 | TCP | FTP |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67/68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 |
| 143 | TCP | IMAP |
| 443 | TCP | HTTPS |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |
| 5432 | TCP | PostgreSQL |
| 8080 | TCP | HTTP Alternate |

---

*Last updated: March 2026*
