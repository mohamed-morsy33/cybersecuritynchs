# Network Forensics and Incident Investigation

Network forensics is the capture, recording, and analysis of network traffic to discover security incidents, understand attacks, and provide evidence. This lesson teaches you how to conduct thorough network investigations.

## Network Forensics Fundamentals

### What is Network Forensics?

**Network forensics involves:**
- Capturing network traffic
- Preserving evidence
- Analyzing packet data
- Reconstructing events
- Identifying attackers
- Supporting legal proceedings

**Different from network security monitoring:**
- Forensics looks backward (what happened?)
- Monitoring looks at present (what's happening now?)
- Both use similar tools but different approaches

### Legal Considerations

**Chain of custody:**
- Document who handled evidence
- When and where it was collected
- How it was stored
- Any modifications made

**Evidence admissibility:**
- Must be relevant
- Must be authentic
- Must be complete
- Must be reliable

**Best practices:**
- Hash all captures (MD5, SHA256)
- Write-protect original evidence
- Work on copies, not originals
- Document every step
- Timestamp everything

## Setting Up for Forensics

### Network Tap vs SPAN Port

**Network TAP (Test Access Point):**
- Physical device
- Passive (doesn't affect traffic)
- Sees all packets (no drops)
- Expensive but reliable
- Ideal for forensics

**SPAN Port (Switch Port Analyzer):**
- Switch feature (port mirroring)
- Free (uses existing hardware)
- Can drop packets under load
- Easier to deploy
- Good for most scenarios

**Placement considerations:**
- Internet connection (see all external traffic)
- DMZ (monitor public servers)
- Internal segments (detect lateral movement)
- Critical servers (protect high-value assets)

### Full Packet Capture Systems

**Tools:**
- **Security Onion**: Complete forensics platform
- **Moloch**: Large-scale packet capture
- **Stenographer**: Google's packet capture system
- **tcpdump/tshark**: Manual capture

**Storage requirements:**
```
1 Gbps link fully utilized:
- 450 GB per hour
- 10.8 TB per day
- 75.6 TB per week

Typical corporate network (20% utilization):
- 90 GB per hour
- 2.16 TB per day
- 15.12 TB per week
```

**Retention policies:**
- Keep everything: Weeks (expensive)
- Keep metadata: Months
- Keep full packets: Days to weeks
- Balance cost vs. investigation needs

## Investigation Methodology

### The OSCAR Process

**O - Obtain Information**
- When did incident occur?
- What systems affected?
- What type of incident?
- Who reported it?

**S - Strategize**
- Define investigation scope
- Identify data sources
- Determine timeline
- Allocate resources

**C - Collect Evidence**
- Capture network traffic
- Collect logs
- Preserve state
- Document everything

**A - Analyze**
- Process evidence
- Identify patterns
- Extract IOCs
- Reconstruct events

**R - Report**
- Document findings
- Create timeline
- Provide recommendations
- Prepare for legal proceedings

### Initial Triage

**Quick assessment questions:**

1. **What happened?**
   - Data breach?
   - Malware infection?
   - Unauthorized access?
   - DoS attack?

2. **When did it happen?**
   - Check logs for timeframe
   - Identify initial compromise
   - Determine duration

3. **What's the scope?**
   - Single system or multiple?
   - One network segment or multiple?
   - Internal or external attacker?

4. **What data is available?**
   - Full packet captures?
   - NetFlow data?
   - Firewall logs?
   - IDS alerts?

## Analysis Techniques

### Timeline Reconstruction

**Build chronological timeline:**

1. **Initial compromise:**
   - Phishing email timestamp
   - Malware execution time
   - First C2 connection

2. **Reconnaissance:**
   - Port scans
   - Network mapping
   - Service enumeration

3. **Lateral movement:**
   - SMB connections
   - RDP sessions
   - Pass-the-hash attacks

4. **Data exfiltration:**
   - Large uploads
   - Unusual protocols
   - Off-hours transfers

5. **Covering tracks:**
   - Log deletion
   - Tool removal
   - Backdoor installation

**Example timeline:**
```
2024-01-15 14:23:15 - User opens phishing email
2024-01-15 14:23:47 - Macro executes, downloads malware
2024-01-15 14:24:03 - First C2 connection to evil.com
2024-01-15 14:30:12 - Port scan of internal network
2024-01-15 15:45:33 - SMB connection to file server
2024-01-15 16:12:44 - Large file transfer begins
2024-01-15 18:34:22 - Backdoor installed for persistence
```

### Identifying the Attacker

**Attribution is difficult but look for:**

**Network indicators:**
- Source IP addresses (VPN/Tor?)
- Geolocation data
- ASN (Autonomous System Number)
- Infrastructure patterns

**Behavioral indicators:**
- Tools used (custom or public?)
- Techniques (match known groups?)
- Timing (time zone indicators?)
- Targets (specific or opportunistic?)

**Language indicators:**
- Error messages
- Comments in code
- Keyboard layouts
- Time formats

**Never assume attribution is certain** - VPNs, proxies, and compromised systems complicate this.

## Analyzing Specific Attack Types

### Data Exfiltration Investigation

**Look for:**

**Large outbound transfers:**
```
tcp.len > 1000 && ip.dst != <your_network>
```

**Unusual protocols:**
- FTP from non-FTP servers
- SSH from workstations
- DNS queries with large responses

**Off-hours activity:**
```
frame.time >= "2024-01-15 22:00:00" && 
frame.time <= "2024-01-16 06:00:00"
```

**Encrypted channels:**
```
ssl || ssh || tls
```

**DNS tunneling:**
```
dns.qry.name.len > 50
```

**Analysis steps:**
1. Identify unusual large transfers
2. Determine destination
3. Extract transferred files if possible
4. Identify compromised accounts
5. Trace back to initial compromise

### Malware C2 Investigation

**Beaconing detection:**

Look for regular intervals in I/O graphs:
```bash
tshark -r capture.pcap -T fields \
  -e frame.time_relative -e ip.dst | \
  awk '{diff=$1-prev[$2]; prev[$2]=$1; 
       if(diff>55 && diff<65) print $2, diff}'
```

**C2 characteristics:**
- Regular check-ins (every 60 seconds)
- Small packet sizes (commands)
- Specific user agents
- Base64 encoded data
- Specific URLs or URI patterns

**Extract C2 infrastructure:**
```bash
# Get all contacted IPs
tshark -r capture.pcap -Y "tcp.port == 443" \
  -T fields -e ip.dst | sort -u

# Get all DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort -u
```

### Lateral Movement Investigation

**Look for:**

**SMB connections:**
```
smb2.cmd == 5  # Session Setup
```

**RDP connections:**
```
tcp.port == 3389
```

**WMI/PowerShell remoting:**
```
tcp.port == 5985 || tcp.port == 5986
```

**PsExec:**
```
smb2.filename contains "psexecsvc"
```

**Pass-the-hash:**
```
ntlmssp.auth.ntlmv2response
```

**Create lateral movement map:**
```
Source → Destination → Method → Time
10.0.1.5 → 10.0.1.10 → RDP → 14:23:15
10.0.1.10 → 10.0.1.20 → SMB → 14:45:22
10.0.1.20 → 10.0.1.50 → WMI → 15:12:33
```

### Credential Theft Investigation

**Look for:**

**Kerberos tickets:**
```
kerberos.CNameString
```

**NTLM authentication:**
```
ntlmssp.auth.username
```

**LDAP queries:**
```
ldap.filter contains "samaccountname"
```

**Password guessing:**
```
http.response.code == 401
```

Multiple 401s from same source = brute force.

## Carving and Reconstruction

### File Carving from PCAPs

**Extract files from HTTP:**

Wireshark: File → Export Objects → HTTP

**Command line:**
```bash
# Using tcpflow
tcpflow -r capture.pcap -o output_dir

# Using binwalk
binwalk -e --dd='.*' capture.pcap
```

**Extract files from SMB:**

```bash
tshark -r capture.pcap -Y "smb2.filename" \
  --export-objects smb,output_dir
```

### Reconstructing Sessions

**Email reconstruction:**

```bash
# Extract SMTP traffic
tshark -r capture.pcap -Y "tcp.port == 25" \
  -z follow,tcp,ascii,0 > email.txt
```

**Web session reconstruction:**

```bash
# Extract HTTP session
tshark -r capture.pcap -Y "tcp.stream == 5" \
  -z follow,tcp,ascii,5 > session.txt
```

**FTP file transfer:**

```bash
# Find data channel
tshark -r capture.pcap -Y "ftp-data"

# Extract file
tshark -r capture.pcap -Y "tcp.stream == 42" \
  -T fields -e data.data | xxd -r -p > file.bin
```

## NetFlow Analysis

**NetFlow = flow records (not full packets)**

**What NetFlow captures:**
- Source/Destination IP
- Source/Destination Port
- Protocol
- Byte count
- Packet count
- Start/End time

**What it doesn't capture:**
- Packet contents
- Payloads
- Exact sequences

**Advantages:**
- Much smaller storage
- Longer retention possible
- Good for big picture analysis
- Privacy-friendly

**Tools:**
- nfdump
- SiLK
- Elastic Stack

**Example queries:**

```bash
# Top talkers
nfdump -R /data/flows -s ip/bytes

# Find port scans
nfdump -R /data/flows 'flags S and not flags A' \
  -o extended | awk '{print $6}' | sort | uniq -c | sort -rn

# Large transfers
nfdump -R /data/flows 'bytes > 100000000'
```

## Creating Investigation Reports

### Report Structure

**1. Executive Summary**
- What happened (non-technical)
- Impact
- Key findings
- Recommendations

**2. Incident Overview**
- Timeline
- Affected systems
- Incident type
- Attack vector

**3. Technical Analysis**
- Evidence sources
- Analysis methodology
- Detailed findings
- IOCs

**4. Timeline of Events**
- Chronological reconstruction
- Key events highlighted
- Evidence references

**5. Indicators of Compromise**
- File hashes
- IP addresses
- Domain names
- URLs
- Registry keys
- Filenames

**6. Attack Attribution**
- TTPs observed
- Tool identification
- Possible threat actors
- Confidence level

**7. Containment & Remediation**
- Actions taken
- Systems isolated
- Accounts disabled
- Patches applied

**8. Recommendations**
- Short-term fixes
- Long-term improvements
- Policy changes
- Training needs

**9. Appendices**
- Raw evidence
- Full packet captures
- Log excerpts
- Screenshots

### Visualization

**Create visual aids:**

**Network diagram:**
- Show attack path
- Indicate compromised systems
- Mark entry/exit points

**Timeline visualization:**
- Graphical timeline
- Major events marked
- Duration indicators

**Traffic graphs:**
- Volume over time
- Spikes during attack
- Normal vs. attack traffic

**Attack tree:**
- Initial access
- Privilege escalation
- Lateral movement
- Objectives achieved

## Automated Analysis

### RITA (Real Intelligence Threat Analytics)

**Detects:**
- Beaconing
- DNS tunneling
- Long connections
- Blacklisted IPs/domains

```bash
# Import data
rita import /path/to/zeek/logs dataset_name

# Show beacons
rita show-beacons dataset_name

# Show long connections
rita show-long-connections dataset_name

# HTML report
rita html-report dataset_name
```

### Zeek (formerly Bro)

**Network security monitor:**

```bash
# Analyze pcap
zeek -r capture.pcap

# Generated logs:
# conn.log - Connections
# http.log - HTTP requests
# dns.log - DNS queries
# ssl.log - SSL/TLS connections
# files.log - Files transferred
```

**Query logs:**

```bash
# Find large uploads
cat conn.log | zeek-cut id.orig_h id.resp_h \
  id.resp_p orig_bytes | awk '$4 > 1000000'

# Extract all DNS queries
cat dns.log | zeek-cut query | sort -u

# Find HTTP POST requests
cat http.log | zeek-cut method uri | grep POST
```

## Key Takeaways

**Network forensics skills:**
- Evidence collection and preservation
- Timeline reconstruction
- Attack pattern recognition
- Attribution analysis
- Report writing

**Investigation approach:**
- Methodical and documented
- Focus on answering key questions
- Build comprehensive timeline
- Extract actionable IOCs
- Provide clear recommendations

**Tools and techniques:**
- Wireshark for deep analysis
- tshark for automation
- NetFlow for big picture
- Zeek for security monitoring
- RITA for automated detection

**Remember:**
- Treat everything as evidence
- Document exhaustively
- Maintain chain of custody
- Work on copies, not originals
- Time is critical (data retention)

Network forensics is detective work. You're piecing together what happened from digital traces. Practice builds intuition—the more investigations you conduct, the faster you'll spot patterns and identify threats.

Next, we'll move into applied cryptography and how encryption is actually used to secure systems and communications.
