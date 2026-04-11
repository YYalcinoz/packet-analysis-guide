# Packet Analysis Guide

Personal notes, cheat sheets, and references built while learning **packet analysis**, **network fundamentals**, and **network security**.

> All techniques documented here are for **educational purposes only**. Only capture and analyze traffic on networks you own or have explicit permission to monitor. Unauthorized interception is illegal in most jurisdictions.

---

## Contents

| File | Description |
|------|-------------|
| [`wireshark-cheatsheet.md`](./wireshark-cheatsheet.md) | Display filters, capture filters, security-focused filters, analysis techniques, shortcuts |

**Coming soon:**
| File | Description |
|------|-------------|
| `tshark-notes.md` | Command-line packet analysis with tshark |
| `protocols/tcp-handshake.md` | TCP connection lifecycle deep dive |
| `protocols/dns-analysis.md` | DNS query/response structure and anomalies |
| `scenarios/port-scan-detection.md` | Walkthrough: identifying a port scan from a pcap |

---

## Topics Covered

- **Wireshark** — display & capture filters, stream following, statistics tools, color rules
- **Protocol analysis** — TCP/IP, DNS, HTTP/HTTPS, ARP, ICMP, FTP, SSH
- **Security patterns** — detecting port scans, SYN floods, ARP spoofing, DNS tunneling, cleartext credentials
- **tshark** *(planned)* — terminal-based capture and filtering

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [Wireshark](https://www.wireshark.org/) | GUI packet capture & analysis |
| [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) | CLI version of Wireshark |
| [Nmap](https://nmap.org/) | Network scanning & host discovery |
| [TryHackMe](https://tryhackme.com/) | Hands-on labs and exercises |

---

## Getting Started

If you're new to packet analysis:

1. **Install Wireshark** → [wireshark.org/download](https://www.wireshark.org/#download)
2. **Open a sample capture** — no live traffic needed to start learning
   - [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)
   - [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) — real-world pcap exercises
3. **Start with the cheatsheet** → [`wireshark-cheatsheet.md`](./wireshark-cheatsheet.md)

**Recommended learning path:**
```
Basic filters → Follow TCP streams → Statistics tools → Security-focused analysis
```

---

## Resources

**Documentation**
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [BPF Capture Filter Syntax](https://biot.com/capstats/bpf.html)

**Books**
- *The Practice of Network Security Monitoring* — Richard Bejtlich
- *Practical Packet Analysis* — Chris Sanders

**Practice Labs**
- [TryHackMe — Wireshark rooms](https://tryhackme.com/module/wireshark)
- [Blue Team Labs Online](https://blueteamlabs.online/)
- [PacketTotal](https://packettotal.com/) — upload and analyze pcap files online

---

## Roadmap

- [x] Wireshark display filter reference
- [x] Capture filter (BPF) reference
- [x] Security-focused filter patterns
- [x] Common port quick reference
- [ ] tshark command-line notes
- [ ] Protocol deep dives (TCP, DNS, TLS)
- [ ] Real scenario walkthroughs with sample pcaps
- [ ] ICMP analysis notes

---

*Work in progress — updated as I learn.*
*Last updated: April 2026*
