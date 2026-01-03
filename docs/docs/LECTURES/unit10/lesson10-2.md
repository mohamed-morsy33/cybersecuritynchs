# Incident Response and Digital Forensics

When prevention fails, incident response saves the day. This lesson covers how to detect, respond to, and recover from security incidents while preserving evidence for investigation and potential legal proceedings.

## Incident Response Framework

### NIST Incident Response Lifecycle

**4 phases:**

1. **Preparation** - Build capability before incident occurs
2. **Detection & Analysis** - Identify and understand incident
3. **Containment, Eradication & Recovery** - Stop damage and restore
4. **Post-Incident Activity** - Learn and improve

### SANS Incident Response Process

**6 steps:**

1. **Preparation** - Tools, training, policies
2. **Identification** - Detect and verify incident
3. **Containment** - Limit damage
4. **Eradication** - Remove threat
5. **Recovery** - Restore systems
6. **Lessons Learned** - Document and improve

## Preparation Phase

### Building an Incident Response Team

**Core roles:**

**Incident Response Manager**
- Coordinates response
- Makes critical decisions
- Communicates with stakeholders
- Manages resources

**Security Analyst**
- Analyzes alerts and logs
- Identifies indicators of compromise
- Performs triage
- Documents findings

**Forensic Investigator**
- Preserves evidence
- Analyzes systems
- Reconstructs events
- Prepares reports

**System Administrator**
- Provides technical access
- Implements containment
- Restores systems
- Maintains business operations

**Legal Counsel**
- Advises on legal obligations
- Manages law enforcement interaction
- Protects attorney-client privilege
- Handles disclosure requirements

**Communications Lead**
- Internal communications
- External communications
- Media relations
- Customer notifications

### Essential Tools

**Network monitoring:**
- Wireshark / tcpdump
- Zeek (Bro)
- Security Onion
- Suricata / Snort

**Endpoint detection:**
- OSSEC / Wazuh
- Sysmon
- osquery
- Velociraptor

**Memory analysis:**
- Volatility
- Rekall
- WinDbg

**Disk forensics:**
- Autopsy / Sleuth Kit
- FTK Imager
- EnCase
- X-Ways Forensics

**Log analysis:**
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- Graylog

**Malware analysis:**
- Cuckoo Sandbox
- REMnux
- FLARE VM
- IDA Pro / Ghidra

### Incident Response Plan

**Key components:**

```
1. Contact Information
   - Team members (phone, email, backup)
   - Vendors (IT, security, legal)
   - Law enforcement
   - Insurance
   
2. Roles and Responsibilities
   - Who does what
   - Decision authority
   - Escalation paths
   
3. Communication Plan
   - Internal notifications
   - External notifications
   - Media statements
   - Customer communications
   
4. Detection and Analysis
   - Alert sources
   - Triage procedures
   - Severity classification
   - Documentation requirements
   
5. Containment Strategies
   - Network isolation procedures
   - Account disabling
   - System shutdown criteria
   
6. Evidence Collection
   - Chain of custody forms
   - Collection procedures
   - Storage requirements
   
7. Eradication and Recovery
   - Malware removal
   - System rebuild
   - Verification procedures
   
8. Post-Incident
   - Lessons learned template
   - Improvement tracking
```

## Detection & Analysis

### Indicators of Compromise (IOCs)

**Network IOCs:**
- Suspicious IP addresses
- Unusual DNS queries
- C2 beacon patterns
- Large data transfers
- Connections to known bad domains

**Host IOCs:**
- Unexpected processes
- New user accounts
- Modified system files
- Suspicious registry keys
- Scheduled tasks
- Unknown services

**Application IOCs:**
- Failed login attempts
- Privilege escalation
- Unusual access patterns
- Error messages
- Configuration changes

### Alert Triage

**Priority classification:**

**Critical (P1):**
- Active data exfiltration
- Ransomware execution
- System compromise with admin access
- Critical infrastructure impact
- Response time: Immediate

**High (P2):**
- Malware detected
- Privilege escalation attempt
- Credential compromise
- Response time: < 1 hour

**Medium (P3):**
- Policy violation
- Suspicious activity
- Reconnaissance detected
- Response time: < 4 hours

**Low (P4):**
- Failed attack attempt
- Scanner activity
- False positive likely
- Response time: < 24 hours

### Initial Analysis

**Questions to answer:**

1. **What happened?**
   - Type of incident
   - Attack vector
   - Malware involved

2. **When did it start?**
   - First compromise
   - Detection time
   - Dwell time

3. **What systems affected?**
   - Compromised hosts
   - Accessed data
   - Network segments

4. **Who is the attacker?**
   - Internal/external
   - Sophistication level
   - Possible attribution

5. **What's the impact?**
   - Data loss
   - System availability
   - Business impact

## Containment

### Short-term Containment

**Immediate actions to limit damage:**

**Network isolation:**
```bash
# Isolate host using firewall
iptables -I INPUT 1 -s <attacker_ip> -j DROP
iptables -I OUTPUT 1 -d <attacker_ip> -j DROP

# Or disconnect network entirely
ifconfig eth0 down

# On Windows
netsh interface set interface "Ethernet" admin=disable
```

**Account suspension:**
```bash
# Disable compromised user (Linux)
passwd -l username
usermod -L username

# Disable AD account (Windows)
Disable-ADAccount -Identity username

# Force password reset
Set-ADAccountPassword -Identity username -Reset
```

**Block malicious IPs:**
```bash
# Firewall rules
ufw deny from <malicious_ip>

# At network level (contact network team)
# Block at firewall/IDS
```

### Long-term Containment

**Allows business to continue while preparing for eradication:**

**Segment network:**
- Move affected systems to isolated VLAN
- Restrict traffic flow
- Monitor for lateral movement

**Apply patches:**
- Patch exploited vulnerabilities
- Update signatures
- Harden configurations

**Strengthen authentication:**
- Force password resets
- Implement MFA
- Review permissions

## Evidence Collection

### Order of Volatility

**Collect most volatile data first:**

1. **Registers, cache** - Nanoseconds
2. **Memory (RAM)** - Seconds to minutes
3. **Network connections** - Seconds
4. **Running processes** - Seconds
5. **Open files** - Minutes
6. **Network configuration** - Minutes
7. **Disk contents** - Hours to days
8. **Logs** - Days to months
9. **Backups** - Months to years

### Memory Acquisition

**Linux:**
```bash
# Using LiME (Linux Memory Extractor)
sudo insmod lime.ko "path=/tmp/memory.dump format=lime"

# Or dump with dd (less reliable)
sudo dd if=/dev/mem of=/tmp/memory.dump bs=1M
```

**Windows:**
```powershell
# Using WinPMEM
winpmem.exe memory.dump

# Using DumpIt
DumpIt.exe

# Using FTK Imager
# GUI tool - select Capture Memory
```

**Memory analysis:**
```bash
# Volatility framework
volatility -f memory.dump imageinfo

# List processes
volatility -f memory.dump --profile=Win10x64 pslist

# Network connections
volatility -f memory.dump --profile=Win10x64 netscan

# List DLLs
volatility -f memory.dump --profile=Win10x64 dlllist

# Dump process
volatility -f memory.dump --profile=Win10x64 procdump -p 1234 -D output/

# Scan for malware
volatility -f memory.dump --profile=Win10x64 malfind
```

### Disk Acquisition

**Create forensic image:**

```bash
# Using dd (forensic copy)
sudo dd if=/dev/sda of=/mnt/evidence/disk.img bs=4M status=progress conv=noerror,sync

# Calculate hash
sha256sum /mnt/evidence/disk.img > /mnt/evidence/disk.img.sha256

# Using dcfldd (better for forensics)
sudo dcfldd if=/dev/sda of=/mnt/evidence/disk.img hash=sha256 hashlog=/mnt/evidence/hash.log

# Using FTK Imager (Windows GUI)
# File → Create Disk Image → Select source → Create image
```

**Mount as read-only:**
```bash
# Mount forensic image
sudo mount -o ro,loop disk.img /mnt/evidence

# Or use write blocker hardware
```

### Network Evidence

**Capture live traffic:**
```bash
# Full packet capture
sudo tcpdump -i eth0 -w incident.pcap

# Capture specific host
sudo tcpdump -i eth0 host 192.168.1.100 -w suspect.pcap

# Capture for specific time
timeout 3600 sudo tcpdump -i eth0 -w hourly.pcap
```

**Export NetFlow data:**
```bash
# Export flows from router/switch
# Query flow collector for incident timeframe
nfdump -R /data/flows -t 2024-01-15.14:00-2024-01-15.16:00 -o extended
```

### Log Collection

**Centralized logging:**
```bash
# Linux system logs
sudo cp -r /var/log /mnt/evidence/logs/

# Windows Event logs
wevtutil epl System C:\evidence\System.evtx
wevtutil epl Security C:\evidence\Security.evtx
wevtutil epl Application C:\evidence\Application.evtx

# Web server logs
sudo cp /var/log/apache2/access.log /mnt/evidence/
sudo cp /var/log/apache2/error.log /mnt/evidence/
```

**Timeline creation:**
```bash
# Create timeline with log2timeline/plaso
log2timeline.py timeline.plaso /mnt/evidence/

# Generate timeline
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# Filter timeline
psort.py -o l2tcsv timeline.plaso "date > '2024-01-15 14:00:00'"
```

### Chain of Custody

**Documentation required:**

```
Evidence Form

Case Number: IR-2024-001
Evidence Number: E-001
Date/Time Collected: 2024-01-15 14:23:15 UTC
Collected By: John Smith, Incident Responder
Location: Server Room, Building A, Floor 3
Description: Hard drive from compromised web server
Make/Model: Seagate ST2000DM008 2TB
Serial Number: ZDH12345
Hash (SHA-256): abc123def456...

Chain of Custody:
Date/Time | Transferred From | Transferred To | Purpose | Signature
----------------------------------------------------------------------
2024-01-15 14:23 | John Smith | Evidence locker | Storage | J. Smith
2024-01-15 16:45 | Evidence locker | Jane Doe | Analysis | J. Doe
2024-01-16 10:00 | Jane Doe | Evidence locker | Storage | J. Doe
```

## Analysis

### Timeline Reconstruction

**Build event timeline:**

```
2024-01-15 13:45:22 - Phishing email received by user@company.com
2024-01-15 13:47:15 - User clicks malicious link
2024-01-15 13:47:23 - Malware downloaded (invoice.pdf.exe)
2024-01-15 13:48:01 - Malware executed
2024-01-15 13:48:15 - First C2 beacon to evil.com
2024-01-15 14:15:33 - Credential dumping (mimikatz)
2024-01-15 14:45:22 - Lateral movement to file server
2024-01-15 15:23:11 - Large file transfer begins (data exfiltration)
2024-01-15 16:30:44 - Ransomware deployment
2024-01-15 16:31:00 - Files encrypted
2024-01-15 16:35:12 - Ransom note displayed
```

### Root Cause Analysis

**5 Whys technique:**

```
Problem: Ransomware encrypted critical files

Why? Ransomware was executed on the network
  Why? Attacker had access to deploy ransomware
    Why? Attacker moved laterally from initial compromise
      Why? User credentials were compromised
        Why? User clicked phishing link and ran malware
          Root cause: Insufficient user security awareness training
                     No email filtering for malicious links
```

### Indicators of Compromise Extraction

**Create IOC list:**

```python
#!/usr/bin/env python3
# extract_iocs.py

import re
import sys

def extract_iocs(logfile):
    """Extract IOCs from logs"""
    iocs = {
        'ips': set(),
        'domains': set(),
        'urls': set(),
        'hashes': set(),
        'emails': set()
    }
    
    # Regex patterns
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+' 
    hash_pattern = r'\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b'
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    with open(logfile, 'r', errors='ignore') as f:
        content = f.read()
        
        iocs['ips'].update(re.findall(ip_pattern, content))
        iocs['domains'].update(re.findall(domain_pattern, content))
        iocs['urls'].update(re.findall(url_pattern, content))
        iocs['hashes'].update(re.findall(hash_pattern, content))
        iocs['emails'].update(re.findall(email_pattern, content))
    
    # Remove private/internal IPs
    iocs['ips'] = {ip for ip in iocs['ips'] 
                   if not ip.startswith(('10.', '192.168.', '172.'))}
    
    return iocs

# Usage
if __name__ == '__main__':
    iocs = extract_iocs(sys.argv[1])
    
    print("=== Indicators of Compromise ===\n")
    print(f"IPs ({len(iocs['ips'])}):")
    for ip in sorted(iocs['ips']):
        print(f"  {ip}")
    
    print(f"\nDomains ({len(iocs['domains'])}):")
    for domain in sorted(iocs['domains']):
        print(f"  {domain}")
    
    print(f"\nFile Hashes ({len(iocs['hashes'])}):")
    for hash_val in sorted(iocs['hashes']):
        print(f"  {hash_val}")
```

## Eradication & Recovery

### Malware Removal

**Clean infected systems:**

```bash
# Identify malware
ps aux | grep suspicious_process
netstat -tulpn | grep suspicious_connection

# Kill malicious processes
sudo kill -9 <pid>

# Remove malicious files
sudo rm -f /tmp/malware.exe
sudo rm -f /var/tmp/.hidden_backdoor

# Remove persistence
sudo crontab -e  # Remove malicious cron jobs
sudo systemctl disable malicious.service
sudo rm /etc/systemd/system/malicious.service

# Check and remove from startup
sudo nano /etc/rc.local
```

**Or rebuild from scratch:**
- Faster and more reliable
- Ensures complete eradication
- Restore from clean backup
- Apply all patches before reconnecting

### System Hardening

**Before bringing systems back online:**

```bash
# Update all software
sudo apt update && sudo apt upgrade -y

# Remove unnecessary services
sudo systemctl disable <unused_service>

# Configure firewall
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh

# Harden SSH
sudo nano /etc/ssh/sshd_config
# PermitRootLogin no
# PasswordAuthentication no
# AllowUsers specific_user

# Enable logging
sudo systemctl enable rsyslog
sudo systemctl enable auditd
```

### Verification

**Confirm eradication:**

```bash
# Scan for malware
sudo clamscan -r /
sudo rkhunter --check

# Check for suspicious processes
ps aux | grep -E 'malware|suspicious'

# Check network connections
sudo netstat -tulpn | grep ESTABLISHED

# Review startup items
systemctl list-unit-files | grep enabled

# Check for new users
cat /etc/passwd | tail -10

# Monitor for 72 hours before declaring success
```

## Post-Incident Activities

### Lessons Learned Meeting

**Within 2 weeks of incident closure**

**Agenda:**
1. What happened? (timeline)
2. What went well?
3. What could be improved?
4. What will we do differently?
5. Action items with owners and dates

**Questions to answer:**

- How was the incident detected?
- Was detection timely?
- Were procedures followed?
- Were roles and responsibilities clear?
- Were tools adequate?
- Was communication effective?
- What's the estimated cost/impact?
- How can we prevent recurrence?

### Incident Report

**Executive summary:**
- What happened (non-technical)
- Impact on business
- Actions taken
- Current status
- Next steps

**Technical details:**
- Attack vector
- Timeline of events
- Systems affected
- Indicators of compromise
- Evidence collected
- Analysis findings

**Response effectiveness:**
- What worked well
- What needs improvement
- Resources used
- Costs incurred

**Recommendations:**
- Immediate actions
- Short-term improvements (30 days)
- Long-term improvements (90+ days)
- Budget requirements

## Key Takeaways

**Incident response success requires:**
- Preparation before incidents occur
- Clear roles and responsibilities
- Well-practiced procedures
- Proper tools and training
- Effective communication
- Thorough documentation

**Evidence handling:**
- Maintain chain of custody
- Preserve original evidence
- Work on copies
- Document everything
- Hash all evidence

**Critical skills:**
- Quick decision-making under pressure
- Technical analysis capability
- Clear communication
- Attention to detail
- Staying calm

**Remember:**
- Every incident is a learning opportunity
- Speed matters but accuracy matters more
- Documentation is crucial
- Team coordination is essential
- Practice makes perfect

Incident response is high-pressure work that requires both technical skill and cool judgment. Regular training, tabletop exercises, and continuous improvement will prepare you to handle real incidents effectively.
