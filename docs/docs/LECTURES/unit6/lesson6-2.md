# Advanced Wireshark Techniques and Protocol Analysis

You know the basics of Wireshark. Now let's explore advanced techniques that security professionals use to hunt threats, analyze complex protocols, and extract forensic evidence from network traffic.

## Advanced Display Filters

### Filter Operators

**Comparison operators:**
```
eq or ==    Equal
ne or !=    Not equal
gt or >     Greater than
lt or <     Less than
ge or >=    Greater than or equal
le or <=    Less than or equal
```

**Logical operators:**
```
and or &&   Logical AND
or  or ||   Logical OR
not or !    Logical NOT
```

**Membership operators:**
```
in          Value in set
contains    String contains substring
matches     Regex match
```

### Complex Filter Examples

**Find large HTTP responses:**
```
http.response && frame.len > 10000
```

**Detect potential data exfiltration:**
```
(http.request.method == "POST" || ftp-data) && frame.len > 50000
```

**Find failed authentication attempts:**
```
http.response.code == 401 || http.response.code == 403
```

**Detect potential C2 beaconing (regular intervals):**
```
tcp.flags.push == 1 && tcp.len < 100 && tcp.len > 0
```

**Find cleartext passwords:**
```
tcp contains "password=" || tcp contains "pwd=" || tcp contains "pass="
```

**Detect SQL injection attempts:**
```
http.request.uri contains "union select" || http.request.uri contains "' or 1=1"
```

**Find encrypted traffic without proper certificates:**
```
ssl.handshake.type == 11 && !ssl.handshake.certificate
```

### Filter Macros

**Create reusable filter expressions:**

```
# Define in profile
${web} = tcp.port == 80 || tcp.port == 443 || tcp.port == 8080

# Use in filters
${web} && ip.addr == 192.168.1.100
```

## Protocol Analysis

### HTTP/HTTPS Analysis

**Extract HTTP objects:**
1. File → Export Objects → HTTP
2. Filter by content type
3. Save files for analysis

**Analyze HTTP headers:**
```
http.request.method == "GET"
http.user_agent contains "curl"
http.cookie contains "session"
http.referer
```

**Detect suspicious user agents:**
```
http.user_agent contains "sqlmap" ||
http.user_agent contains "nikto" ||
http.user_agent contains "nmap" ||
http.user_agent contains "masscan"
```

**Find redirects:**
```
http.response.code == 301 || http.response.code == 302
```

### DNS Analysis

**Identify DNS tunneling:**
```
dns.qry.name.len > 50
```

**Find unusual query types:**
```
dns.qry.type != 1 && dns.qry.type != 28  # Not A or AAAA records
```

**Detect DGA (Domain Generation Algorithm):**
```
dns.qry.name matches "[a-z]{20,}\\."  # Long random-looking domains
```

**Extract all queried domains:**
```
dns.flags.response == 0
```

Statistics → DNS → Query/Response

### TLS/SSL Analysis

**Identify weak cipher suites:**
```
ssl.handshake.ciphersuite == 0x0005  # RSA_WITH_RC4_128_SHA (weak)
```

**Find expired certificates:**
```
x509ce.validity.notAfter < "2024-01-01"
```

**Detect SSL/TLS downgrade attacks:**
```
ssl.handshake.version < 0x0303  # TLS 1.2 is 0x0303
```

**Extract certificate details:**
```
x509ce.dNSName
x509af.utcTime
```

### SMB Analysis

**Detect lateral movement:**
```
smb2.cmd == 5  # Session Setup
```

**Find file access:**
```
smb2.filename
```

**Detect credential theft attempts:**
```
ntlmssp.auth.username
```

## TCP Stream Analysis

### Following Streams

**Right-click packet → Follow → TCP Stream**

**Use cases:**
- Reconstruct file transfers
- Read email content
- View HTTP requests/responses
- Analyze protocol handshakes

**Filter after following:**
```
tcp.stream eq 42
```

### Stream Index

**Show all streams:**
```
Statistics → Conversations → TCP
```

**Filter specific stream:**
```
tcp.stream == 5
```

**Find streams with errors:**
```
tcp.analysis.retransmission || tcp.analysis.lost_segment
```

## Advanced Statistical Analysis

### I/O Graphs

**Statistics → I/O Graph**

**Create multiple graphs:**
1. Total packets over time
2. HTTP traffic (port 80)
3. HTTPS traffic (port 443)
4. DNS queries

**Example filters:**
```
Graph 1: (no filter) - All traffic
Graph 2: tcp.port == 80 - HTTP
Graph 3: tcp.port == 443 - HTTPS
Graph 4: dns - DNS queries
```

**Identify anomalies:**
- Traffic spikes
- Regular beaconing patterns
- Unusual times (3 AM traffic)

### Protocol Hierarchy

**Statistics → Protocol Hierarchy**

**Shows:**
- Percentage of each protocol
- Packet count
- Byte count

**Identify unusual protocols:**
- High percentage of ICMP (C2 tunneling?)
- Unexpected protocols (IRC on corporate network?)
- Encrypted protocols on unusual ports

### Endpoints

**Statistics → Endpoints**

**View by:**
- Ethernet (MAC addresses)
- IPv4/IPv6 (IP addresses)
- TCP/UDP (ports)

**Identify:**
- Top talkers (most traffic)
- Unusual connections
- Port scanning (many ports from one IP)

### Conversations

**Statistics → Conversations**

**Shows:**
- Communication pairs
- Packets/bytes exchanged
- Duration

**Use to:**
- Find large data transfers
- Identify C2 communication
- Detect lateral movement
- Track specific connections

## Expert Information

**Analyze → Expert Information**

**Categories:**
- **Errors**: Malformed packets, checksums
- **Warnings**: Unusual events
- **Notes**: Standard protocol events
- **Chats**: Application messages

**Common indicators:**
- TCP retransmissions (network issues or attacks)
- TCP out-of-order (possible MITM)
- Checksum errors (corrupted or crafted packets)
- Connection resets (blocked connections)

## Decrypting Traffic

### Decrypting SSL/TLS

**Method 1: Using Server Private Key**

1. Edit → Preferences → Protocols → TLS
2. RSA keys list → Add
3. IP: server IP
4. Port: 443
5. Protocol: http
6. Key file: server.key

**Limitations:**
- Only works with RSA key exchange
- Doesn't work with forward secrecy (DHE/ECDHE)

**Method 2: Using Browser Session Keys**

Set environment variable:
```bash
export SSLKEYLOGFILE=/path/to/sslkeys.log
```

Launch browser, capture traffic:
1. Edit → Preferences → Protocols → TLS
2. (Pre)-Master-Secret log filename: /path/to/sslkeys.log

**This works with forward secrecy!**

### Decrypting WPA/WPA2

**Capture WPA handshake:**
1. Capture during client connection
2. Edit → Preferences → Protocols → IEEE 802.11
3. Enable decryption
4. Add key: wpa-pwd:password:SSID

**Requirements:**
- Captured 4-way handshake
- Know the password

## Packet Manipulation

### Editing Packets

**Method 1: Hex editing**

Right-click packet → Copy → Bytes as Hex Stream

Edit and inject using:
```bash
# Create raw packet file
xxd -r -p hex_data > packet.bin

# Inject with scapy
from scapy.all import *
packet = rdpcap("packet.bin")
send(packet)
```

**Method 2: Using tcprewrite**

```bash
# Change MAC addresses
tcprewrite --enet-smac=00:11:22:33:44:55 \
           --enet-dmac=aa:bb:cc:dd:ee:ff \
           --infile=input.pcap --outfile=output.pcap

# Change IP addresses
tcprewrite --srcipmap=0.0.0.0/0:10.0.0.0/24 \
           --dstipmap=0.0.0.0/0:192.168.1.0/24 \
           --infile=input.pcap --outfile=output.pcap
```

## Wireshark Profiles

### Creating Custom Profiles

**Edit → Configuration Profiles → New**

**Per-profile settings:**
- Custom coloring rules
- Display columns
- Filter expressions
- Preferences

**Example profiles:**
- Web traffic analysis
- Malware investigation
- Wireless analysis
- VoIP troubleshooting

### Custom Columns

**Edit → Preferences → Appearance → Columns**

**Useful custom columns:**
```
Type: Custom
Title: "HTTP Host"
Field: http.host

Type: Custom
Title: "DNS Query"
Field: dns.qry.name

Type: Custom  
Title: "TLS SNI"
Field: tls.handshake.extensions_server_name
```

## Advanced Coloring Rules

**View → Coloring Rules**

**Example rules:**

**Red - Retransmissions:**
```
tcp.analysis.retransmission
```

**Orange - HTTP errors:**
```
http.response.code >= 400
```

**Yellow - DNS queries:**
```
dns.flags.response == 0
```

**Green - Successful HTTP:**
```
http.response.code == 200
```

**Purple - Encrypted traffic:**
```
ssl || tls
```

## Command-Line Power: tshark

**tshark** is Wireshark's CLI version.

### Basic Usage

```bash
# Capture to file
tshark -i eth0 -w capture.pcap

# Capture with filter
tshark -i eth0 -f "port 80" -w http.pcap

# Read from file
tshark -r capture.pcap

# Apply display filter
tshark -r capture.pcap -Y "http.request"
```

### Field Extraction

```bash
# Extract HTTP hosts
tshark -r capture.pcap -Y "http.request" -T fields -e http.host

# Extract source IPs and ports
tshark -r capture.pcap -T fields -e ip.src -e tcp.srcport

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Extract TLS SNI
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name
```

### Statistics with tshark

```bash
# Protocol hierarchy
tshark -r capture.pcap -q -z io,phs

# Conversations
tshark -r capture.pcap -q -z conv,tcp

# HTTP requests
tshark -r capture.pcap -q -z http,tree

# DNS queries
tshark -r capture.pcap -q -z dns,tree
```

### Automation Scripts

**Extract all URLs:**
```bash
#!/bin/bash
tshark -r $1 -Y "http.request" -T fields \
    -e ip.src -e http.host -e http.request.uri | \
    awk '{print $1 " http://" $2 $3}' | \
    sort -u > urls.txt
```

**Find potential C2 beaconing:**
```bash
#!/bin/bash
tshark -r $1 -T fields -e ip.dst -e frame.time_relative | \
    awk '{print $1, $2-prev[$1]; prev[$1]=$2}' | \
    awk '$2 > 55 && $2 < 65 {count[$1]++} 
         END {for (ip in count) if (count[ip] > 10) print ip, count[ip]}'
```

## Detecting Common Attacks

### Port Scan Detection

**SYN scan:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Multiple destination ports from same source:**
```
Statistics → Conversations → TCP
Sort by "Packets A→B"
```

### ARP Spoofing Detection

```
arp.duplicate-address-detected
```

**Or look for:**
- Same IP with different MACs
- Gratuitous ARP from non-gateway

### DNS Tunneling Detection

```
dns.qry.name.len > 50 || dns.response.len > 512
```

### HTTP Tunneling

```
http.request.method == "CONNECT"
```

### Brute Force Detection

**HTTP:**
```
http.response.code == 401
```

Count 401s per source IP.

**SSH:**
```
tcp.port == 22 && tcp.flags.syn == 1
```

High volume of connections.

## Performance Optimization

### For Large Captures

**Use capture filters (not display filters):**
```bash
# Only HTTP/HTTPS
tcpdump -i eth0 -w capture.pcap "port 80 or port 443"
```

**Split large files:**
```bash
editcap -c 100000 large.pcap split.pcap
```

**Index files:**
Wireshark automatically creates .pcapng indexes for faster access.

**Use tshark for analysis:**
Faster than GUI for batch processing.

## Practical Scenarios

### Scenario 1: Investigating Data Exfiltration

**Steps:**
1. Filter large outbound transfers:
   ```
   tcp.port == 443 && tcp.len > 1000
   ```
2. Statistics → Conversations
3. Identify unusual destinations
4. Follow TCP streams
5. Export objects if HTTP
6. Check DNS queries for suspicious domains

### Scenario 2: Malware C2 Analysis

**Steps:**
1. Find beaconing patterns (I/O Graph)
2. Extract regular connections
3. Filter DNS queries:
   ```
   dns.flags.response == 0
   ```
4. Follow TCP streams for C2 traffic
5. Extract IOCs (IPs, domains, URIs)

### Scenario 3: Incident Response

**Steps:**
1. Timeline with I/O Graph
2. Identify initial compromise time
3. Track lateral movement:
   ```
   smb2 || rdp || winrm
   ```
4. Find data exfiltration
5. Extract IOCs
6. Document in timeline

## Key Takeaways

**Advanced Wireshark skills:**
- Complex display filters
- Protocol-specific analysis
- Stream reconstruction
- Statistical analysis
- Decryption techniques
- CLI automation with tshark

**Detection techniques:**
- Port scans
- ARP spoofing
- DNS tunneling
- C2 beaconing
- Data exfiltration

**Best practices:**
- Use appropriate filters
- Leverage statistics
- Automate with tshark
- Create custom profiles
- Document findings

**Remember:**
- Wireshark shows what happened
- Your job is interpreting it
- Context is everything
- Practice makes perfect

Mastering Wireshark takes time. Analyze real traffic, practice with CTF challenges, and review public PCAPs. The more you use it, the more patterns you'll recognize.

Next lesson, we'll explore network forensics—using captured traffic as evidence and reconstructing attack timelines.
