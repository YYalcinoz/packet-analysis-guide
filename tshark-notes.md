# tshark Notes

> tshark is the command-line version of Wireshark. Useful for capturing and analyzing traffic on remote servers, headless systems, or anywhere you need to script packet analysis.

---

## Table of Contents

- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [Capture Filters](#capture-filters)
- [Display Filters](#display-filters)
- [Reading pcap Files](#reading-pcap-files)
- [Extracting Specific Fields](#extracting-specific-fields)
- [Statistics](#statistics)
- [Output Formats](#output-formats)
- [Useful One-Liners](#useful-one-liners)
- [tshark vs Wireshark Filter Syntax](#tshark-vs-wireshark-filter-syntax)

---

## Installation

```bash
# Debian/Ubuntu
sudo apt install tshark

# RHEL/CentOS/Fedora
sudo dnf install wireshark-cli

# macOS (Homebrew)
brew install wireshark

# Verify installation
tshark --version
```

> **Permission note:** On Linux, tshark requires root or membership in the `wireshark` group to capture live traffic.
> ```bash
> sudo usermod -aG wireshark $USER
> # Log out and back in for the change to take effect
> ```

---

## Basic Usage

```bash
# List available network interfaces
tshark -D

# Capture on a specific interface (replace eth0 with your interface)
tshark -i eth0

# Capture on any interface
tshark -i any

# Capture and save to a file
tshark -i eth0 -w capture.pcap

# Capture only N packets then stop
tshark -i eth0 -c 100

# Capture for N seconds then stop
tshark -i eth0 -a duration:30

# Capture until file reaches N kilobytes
tshark -i eth0 -a filesize:1024 -w capture.pcap

# Capture with verbose packet details
tshark -i eth0 -V
```

---

## Capture Filters

Applied before capture — uses BPF syntax. Reduces the volume of traffic captured.

```bash
# Only TCP traffic
tshark -i eth0 -f "tcp"

# Only traffic on port 80
tshark -i eth0 -f "port 80"

# Traffic to/from a specific host
tshark -i eth0 -f "host 192.168.1.1"

# Traffic from a specific host
tshark -i eth0 -f "src host 192.168.1.1"

# Exclude SSH traffic
tshark -i eth0 -f "not port 22"

# DNS traffic only
tshark -i eth0 -f "udp port 53"

# HTTP and HTTPS combined
tshark -i eth0 -f "port 80 or port 443"

# Specific subnet
tshark -i eth0 -f "net 192.168.1.0/24"
```

---

## Display Filters

Applied after capture — uses Wireshark display filter syntax. Can be combined with capture filters.

```bash
# Filter by protocol
tshark -i eth0 -Y "dns"
tshark -i eth0 -Y "http"
tshark -i eth0 -Y "tls"

# Filter by IP
tshark -i eth0 -Y "ip.addr == 192.168.1.1"
tshark -i eth0 -Y "ip.src == 10.0.0.1"

# Filter by port
tshark -i eth0 -Y "tcp.port == 443"

# TCP flags
tshark -i eth0 -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0"

# HTTP POST requests only
tshark -i eth0 -Y "http.request.method == POST"

# DNS queries only (not responses)
tshark -i eth0 -Y "dns.flags.response == 0"

# Combine capture and display filter
tshark -i eth0 -f "tcp" -Y "tcp.flags.syn == 1"
```

---

## Reading pcap Files

```bash
# Read and print a pcap file
tshark -r capture.pcap

# Read with a display filter
tshark -r capture.pcap -Y "http.request"

# Read quietly (suppress packet count summary)
tshark -r capture.pcap -q

# Read only first N packets
tshark -r capture.pcap -c 50

# Read with full packet details
tshark -r capture.pcap -V

# Read and write filtered output to a new pcap
tshark -r capture.pcap -Y "dns" -w dns-only.pcap
```

---

## Extracting Specific Fields

Use `-T fields` with `-e` to extract specific fields. Great for scripting and piping into other tools.

```bash
# Source IP and destination IP
tshark -r capture.pcap -T fields -e ip.src -e ip.dst

# Add column separator (default is tab)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -E separator=,

# Source IP, destination IP, and protocol
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e _ws.col.Protocol

# DNS query names
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# HTTP hosts and URIs
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# HTTP response codes
tshark -r capture.pcap -Y "http.response" -T fields -e http.response.code -e http.response.phrase

# TLS SNI (Server Name Indication) — reveals destination hostname in encrypted traffic
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name

# TCP stream index — useful for grouping packets per connection
tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e tcp.stream

# Frame timestamp and length
tshark -r capture.pcap -T fields -e frame.time -e frame.len
```

> **Tip:** Run `tshark -G fields | grep "fieldname"` to search for available field names.

---

## Statistics

Run statistics on a capture without printing every packet. Use `-q` to suppress packet output.

```bash
# Protocol hierarchy — breakdown of all protocols seen
tshark -r capture.pcap -q -z io,phs

# Top conversations (TCP)
tshark -r capture.pcap -q -z conv,tcp

# Top conversations (UDP)
tshark -r capture.pcap -q -z conv,udp

# All endpoints (IP)
tshark -r capture.pcap -q -z endpoints,ip

# DNS query summary
tshark -r capture.pcap -q -z dns,tree

# HTTP request statistics
tshark -r capture.pcap -q -z http,tree

# HTTP request URIs
tshark -r capture.pcap -q -z http_req,tree

# IO graph — packets per second over time (text-based)
tshark -r capture.pcap -q -z io,stat,1

# Expert info — all warnings and errors detected
tshark -r capture.pcap -q -z expert
```

---

## Output Formats

```bash
# Default — human-readable summary (one line per packet)
tshark -r capture.pcap

# Verbose — full packet details
tshark -r capture.pcap -V

# JSON output
tshark -r capture.pcap -T json

# JSON, compact (ek fields only)
tshark -r capture.pcap -T jsonraw

# PDML — XML format, verbose
tshark -r capture.pcap -T pdml

# Fields — custom column extraction (see above)
tshark -r capture.pcap -T fields -e ip.src -e ip.dst

# One-liner output — useful for piping
tshark -r capture.pcap -T tabs
```

---

## Useful One-Liners

```bash
# Count packets by protocol
tshark -r capture.pcap -q -z io,phs | head -30

# List all unique destination IPs
tshark -r capture.pcap -T fields -e ip.dst | sort -u

# List all unique DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# Count DNS queries per domain
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# Find all HTTP POST requests and their destinations
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e ip.dst -e http.host -e http.request.uri

# Extract TLS SNI names — see where encrypted traffic is going
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u

# Find SYN packets — possible port scan
tshark -r capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e ip.dst -e tcp.dstport | sort -u

# Count SYN packets per source IP (detect port scanners)
tshark -r capture.pcap -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src | sort | uniq -c | sort -rn

# Live capture — print only DNS queries as they happen
tshark -i eth0 -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name

# Live capture — print HTTP requests in real time
tshark -i eth0 -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri
```

---

## tshark vs Wireshark Filter Syntax

Both tools use the same display filter syntax. The difference is where you apply them.

| | tshark | Wireshark |
|-|--------|-----------|
| Capture filter (BPF) | `-f "port 80"` | Capture Options → Enter capture filter |
| Display filter | `-Y "http.request"` | Filter bar at the top |
| Read file | `-r file.pcap` | File → Open |
| Write file | `-w file.pcap` | File → Save As |
| Statistics | `-z conv,tcp` | Statistics menu |
| Field extraction | `-T fields -e ip.src` | Not directly available in GUI |

> **Key difference:** tshark is scriptable and works over SSH on remote servers. Wireshark is better for interactive investigation of a capture.

---
