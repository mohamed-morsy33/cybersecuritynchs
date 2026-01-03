# Network Traffic Analysis with Wireshark

You've learned about networks, protocols, and security. Now it's time to see network traffic in action. **Wireshark** is the industry-standard tool for capturing and analyzing network packets. If you want to understand what's really happening on a network, you need to master Wireshark.

## What is Wireshark?

**Wireshark** is a free, open-source packet analyzer. It captures network traffic in real-time and displays it in human-readable format. Think of it as a microscope for networks—it lets you examine every single packet flowing across the wire.

Security professionals use Wireshark to:
- Troubleshoot network issues
- Detect malicious activity
- Reverse engineer protocols
- Analyze malware communication
- Investigate security incidents
- Learn how protocols actually work
- Capture credentials (in authorized testing)
- Verify encryption is working

Wireshark is so powerful and essential that it's installed by default on Kali Linux and used daily by security professionals worldwide.

## Understanding Packet Capture

Before we dive into Wireshark, let's understand what we're capturing.

### Promiscuous Mode

Normally, your network card only captures packets addressed to you. In **promiscuous mode**, your network card captures all packets on the network segment, regardless of destination. This is essential for security analysis but also why packet sniffing can be a privacy concern.

Note: On switched networks, you usually only see:
- Broadcast traffic
- Multicast traffic
- Traffic to/from your machine

To see other traffic, you'd need to be on a hub (rare today), use ARP poisoning to redirect traffic through your machine, or have access to network tap/SPAN port.

### Capture Filters vs. Display Filters

**Capture filters**: Applied during capture, determine what packets are saved. More efficient but can't be changed after capture.

**Display filters**: Applied after capture, determine what you see. Can be changed anytime without recapturing.

Both use different syntax—capture filters use BPF (Berkeley Packet Filter), display filters use Wireshark's own syntax.

## Getting Started with Wireshark

### The Interface

When you open Wireshark, you see:
- **Interface list**: Network interfaces you can capture from
- **Capture pane**: Real-time packet list during capture
- **Packet details pane**: Expanded view of selected packet
- **Packet bytes pane**: Raw hexadecimal and ASCII data

### Capturing Your First Packets

1. Select a network interface (usually your active connection)
2. Click the blue shark fin icon to start capture
3. Generate some traffic (visit a website)
4. Click the red square to stop capture
5. Examine the results

Each row represents one packet with columns:
- **No.**: Packet number
- **Time**: When packet was captured
- **Source**: Source IP address
- **Destination**: Destination IP address
- **Protocol**: Protocol used (TCP, UDP, HTTP, etc.)
- **Length**: Packet size in bytes
- **Info**: Summary of packet contents

### Understanding the Packet Details

Click on any packet to see three views:

**Packet List**: The summary row

**Packet Details**: Expandable tree showing each protocol layer:
- Frame: Physical layer info
- Ethernet II: Data link layer (MAC addresses)
- Internet Protocol: Network layer (IP addresses)
- TCP/UDP: Transport layer (ports, flags)
- Application data: Whatever protocol is inside (HTTP, DNS, etc.)

**Packet Bytes**: Raw data in hex and ASCII

This three-pane view is Wireshark's power—you can see the same packet at different levels of detail.

## Display Filters: Finding What Matters

With thousands or millions of packets, you need to filter. Display filters are Wireshark's query language.

### Basic Display Filter Syntax

**Filter by protocol:**
```
http
tcp
dns
icmp
```

**Filter by IP address:**
```
ip.addr == 192.168.1.1          # Any direction
ip.src == 192.168.1.1           # Source only
ip.dst == 192.168.1.1           # Destination only
```

**Filter by port:**
```
tcp.port == 80                   # Any direction
tcp.srcport == 443              # Source port
tcp.dstport == 22               # Destination port
```

**Combine filters:**
```
ip.addr == 192.168.1.1 && tcp.port == 80
http || dns
tcp.port == 443 && ip.src == 10.0.0.5
```

**Logical operators:**
- `&&` or `and`: Both conditions must be true
- `||` or `or`: Either condition true
- `!` or `not`: Negation

### Common Security Filters

**Find login credentials (if not encrypted):**
```
http.request.method == "POST"
ftp.request.command == "PASS"
```

**Find DNS queries:**
```
dns.qry.name contains "malicious"
```

**Find TCP connections:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Find specific HTTP methods:**
```
http.request.method == "POST"
http.request.uri contains "/admin"
```

**Find errors:**
```
http.response.code >= 400
tcp.analysis.retransmission
```

**Find large packets (potential data exfiltration):**
```
frame.len > 1000
```

**Find suspicious user agents:**
```
http.user_agent contains "sqlmap"
http.user_agent contains "nikto"
```

## Analyzing Common Protocols

### HTTP Traffic

HTTP is unencrypted and reveals everything. Let's analyze an HTTP request:

```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html
```

In Wireshark:
1. Filter for `http`
2. Find a GET request
3. Right-click → Follow → HTTP Stream
4. See the entire conversation in plain text

You can see:
- URLs visited
- Cookies
- Form data
- User agents
- Server responses

**Security note**: This is why HTTPS is crucial. HTTP traffic is completely visible to anyone on the network.

### HTTPS Traffic

HTTPS encrypts HTTP, so you'll see:
- TLS handshake (establishing encryption)
- Encrypted application data (unreadable)
- Certificate information (visible during handshake)

Filter: `tls` or `ssl`

You can see:
- Which sites are visited (from SNI in Client Hello)
- IP addresses
- Certificate validity
- TLS version
- Cipher suites

But you can't see:
- Specific URLs
- Transmitted data
- Cookies or credentials

### DNS Traffic

DNS queries reveal a lot about user activity:

Filter: `dns`

You can see:
- What domains are being resolved
- Response IP addresses
- Query types (A, AAAA, MX, TXT, etc.)

**Security uses:**
- Detect DNS tunneling (data exfiltration through DNS)
- Find connections to known malicious domains
- Identify command and control traffic
- Spot DGA (Domain Generation Algorithm) patterns

Example filter for DNS queries only:
```
dns.flags.response == 0
```

### TCP Three-Way Handshake

Understanding TCP handshakes is fundamental:

1. **SYN**: Client → Server (initiating connection)
2. **SYN-ACK**: Server → Client (acknowledging and returning SYN)
3. **ACK**: Client → Server (acknowledging server's SYN)

Filter to see only handshakes:
```
tcp.flags.syn == 1
```

**What this reveals:**
- Which services are being accessed
- Successful vs. failed connections
- Port scanning activity (many SYNs, few ACKs)

### FTP Traffic (Unencrypted File Transfer)

FTP sends credentials in plaintext:

Filter: `ftp`

You'll see:
- USER command (username)
- PASS command (password in plain text!)
- File transfers
- Directory listings

Right-click a packet → Follow → TCP Stream to see the entire session.

**Security lesson**: FTP is incredibly insecure. Use SFTP or FTPS instead.

## Detecting Attacks with Wireshark

### Port Scanning

**SYN Scan**: Many SYN packets to different ports, few responses
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

Look for:
- Single source IP
- Many different destination ports
- High packet rate
- Many RST responses (closed ports)

### ARP Spoofing

**ARP poisoning** redirects traffic by lying about MAC addresses.

Filter: `arp`

Look for:
- Duplicate IP addresses with different MACs
- Many ARP replies without corresponding requests
- Gratuitous ARP (announcements without requests)

Filter for duplicate IPs:
```
arp.duplicate-address-detected
```

### Malware Communication

**Indicators:**
- Unusual ports
- Suspicious domains in DNS queries
- Regular beacon intervals (malware checking in)
- Large uploads (data exfiltration)
- Connections to known malicious IPs

Filter for beaconing (regular intervals):
```
tcp && frame.time_delta > 60 && frame.time_delta < 61
```

### Password Sniffing

If credentials are sent unencrypted:

**HTTP authentication:**
```
http.authbasic
```

**FTP passwords:**
```
ftp.request.command == "PASS"
```

**Telnet login:**
```
telnet && tcp.port == 23
```

Right-click → Follow Stream to see full credential exchange.

## Advanced Wireshark Techniques

### Statistics and Analysis

**Protocol Hierarchy**: Statistics → Protocol Hierarchy
- Shows breakdown of all protocols in capture
- Identifies unusual traffic

**Conversations**: Statistics → Conversations
- Lists all pairs of communicating hosts
- Shows data transferred
- Identifies heavy users or data transfers

**I/O Graphs**: Statistics → I/O Graph
- Visualizes traffic over time
- Spots spikes or patterns
- Useful for DDoS analysis

### Following Streams

Right-click any packet → Follow → [protocol] Stream

Shows entire conversation in readable format. Works for:
- TCP Stream
- UDP Stream
- HTTP Stream
- TLS Stream (shows encrypted data)

### Exporting Objects

For HTTP/HTTPS captures: File → Export Objects → HTTP

Extracts all files transferred:
- Images
- JavaScript
- CSS
- Downloads
- Malware samples (be careful!)

### Time Display Formats

View → Time Display Format
- Seconds since beginning of capture
- Absolute time
- Delta time (since previous packet)

Useful for identifying timing patterns.

### Coloring Rules

View → Coloring Rules

Wireshark colors packets by default:
- Light blue: UDP
- Light purple: TCP
- Black: Errors
- Green: HTTP
- Light yellow: Windows-specific traffic

You can create custom rules:
```
tcp.analysis.retransmission → Red (possible network issues)
dns.qry.name contains "malware" → Red (suspicious DNS)
```

## Capturing Strategies

### Targeted Capture

Don't capture everything—be specific:

**Capture filter for HTTP only:**
```
port 80 or port 443
```

**Capture specific host:**
```
host 192.168.1.100
```

**Capture subnet:**
```
net 192.168.1.0/24
```

**Exclude broadcast noise:**
```
not broadcast and not multicast
```

### Ring Buffer for Long-Term Capture

For continuous monitoring:
1. Capture → Options
2. Enable "Use multiple files"
3. Set ring buffer (e.g., 100 files of 10 MB each)
4. Wireshark automatically rotates files

### Remote Capture

Capture on one machine, analyze on another:
1. Set up tcpdump on remote server
2. Pipe traffic to Wireshark on local machine

```bash
ssh user@remote "tcpdump -i eth0 -w -" | wireshark -k -i -
```

## Practical Scenarios

### Scenario 1: Investigating Slow Network

1. Start capture on affected user's system
2. Reproduce the problem
3. Statistics → Protocol Hierarchy
4. Look for unusual protocols or heavy usage
5. Check for retransmissions: `tcp.analysis.retransmission`
6. Examine high-traffic conversations

### Scenario 2: Suspected Data Exfiltration

1. Capture traffic from suspected system
2. Statistics → Conversations → sort by bytes
3. Look for large uploads to unusual destinations
4. Check DNS queries for suspicious domains
5. Follow streams to examine content
6. Export objects to find transferred files

### Scenario 3: Malware Analysis

1. Capture traffic in isolated VM
2. Execute malware sample
3. Stop capture after observable activity
4. Filter DNS queries: identify C2 domains
5. Filter HTTP/HTTPS: identify beacon patterns
6. Check for protocols on unusual ports
7. Export malware downloads

## Best Practices

1. **Capture with permission**: Only on networks you own or have authorization
2. **Secure captures**: Packet captures may contain sensitive data
3. **Use appropriate filters**: Don't capture more than needed
4. **Save important captures**: They're evidence
5. **Document findings**: Note unusual patterns
6. **Practice regularly**: Skills improve with use
7. **Stay updated**: New protocols and attacks emerge constantly

## Legal and Ethical Considerations

**Important**: Packet capture can reveal:
- Passwords and credentials
- Private communications
- Financial information
- Medical records
- Trade secrets

**Rules:**
- Only capture on networks you own or have written permission
- Don't capture in public Wi-Fi without authorization
- Treat captured data as highly sensitive
- Follow company security policies
- Understand local laws on network monitoring

In many jurisdictions, unauthorized packet capture is illegal wiretapping.

## Tools That Complement Wireshark

**tcpdump**: Command-line packet capture (often used on servers)
```bash
tcpdump -i eth0 -w capture.pcap port 80
```

**tshark**: Command-line version of Wireshark (great for scripting)
```bash
tshark -r capture.pcap -Y http.request -T fields -e http.host
```

**NetworkMiner**: Extracts artifacts from pcap files
**CapAnalysis**: Web-based pcap analyzer
**Zeek** (formerly Bro): Network security monitoring platform

## What's Next

Wireshark is a skill that develops over time. Start by:
1. Capturing your own web browsing
2. Analyzing different protocols
3. Practicing with public pcap files
4. Participating in CTF challenges
5. Contributing to investigations

In upcoming lessons, we'll use Wireshark to analyze specific attack scenarios and learn how to detect sophisticated threats. Every security professional needs packet analysis skills—it's the ground truth of what's really happening on a network.

Keep practicing, and you'll develop an intuition for what's normal vs. suspicious in network traffic. That intuition is invaluable in cybersecurity.
