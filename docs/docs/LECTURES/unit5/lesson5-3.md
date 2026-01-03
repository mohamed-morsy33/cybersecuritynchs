# Malware Analysis Fundamentals

Understanding malware is critical for defense. This lesson teaches you how to safely analyze malicious software to understand its behavior, capabilities, and how to detect it.

## Safety First

**NEVER analyze malware on your main system!**

### Safe Analysis Environment

**Requirements:**
1. **Isolated VM**: No network access to your main network
2. **Snapshots**: Take snapshot before analysis, revert after
3. **Network isolation**: Host-only or isolated network
4. **Monitoring tools**: Process monitor, network monitor, API monitor
5. **Backups**: Everything backed up before starting

**Recommended setup:**
```
Host Machine (Your computer)
    ↓
Virtual Machine (Isolated)
    ├─ No shared folders
    ├─ No clipboard sharing
    ├─ Host-only network (optional)
    └─ Snapshot before analysis
```

**Tools for analysis VM:**
- Windows 10 (most malware targets Windows)
- REMnux (Linux distro for malware analysis)
- FLARE VM (Windows malware analysis distribution)

## Types of Malware Analysis

### Static Analysis

**Examine without executing.**

**Basic static analysis:**
- File properties (size, type, creation date)
- Strings extraction
- PE header analysis
- Hash calculation
- VirusTotal lookup

**Advanced static analysis:**
- Disassembly
- Decompilation
- Code analysis
- Signature creation

### Dynamic Analysis

**Execute and observe behavior.**

**What to monitor:**
- File system changes
- Registry modifications
- Network connections
- Process creation
- API calls
- Memory modifications

### Hybrid Analysis

**Combination of static and dynamic.**
- Static analysis first (safer)
- Dynamic analysis to confirm findings
- Iterative process

## Static Analysis Tools and Techniques

### File Identification

```bash
# File type
file suspicious.exe

# Calculate hashes
md5sum suspicious.exe
sha1sum suspicious.exe
sha256sum suspicious.exe

# Detailed file info
exiftool suspicious.exe
```

### Strings Analysis

```bash
# Extract strings (minimum 8 characters)
strings -n 8 suspicious.exe > strings.txt

# Look for interesting strings
grep -i "http" strings.txt
grep -i "password" strings.txt
grep -i "\.exe" strings.txt
grep -i "cmd" strings.txt

# Unicode strings
strings -el suspicious.exe
```

**What to look for:**
- URLs and IP addresses
- File paths
- Registry keys
- Function names
- Error messages
- Embedded files
- Encryption keys

### PE Header Analysis

**Use PEview, PE-bear, or pestudio:**

**Important sections:**
- **Import table**: What DLLs/functions it uses
- **Export table**: Functions it provides
- **Resources**: Embedded files, icons
- **Sections**: Code, data, resources

**Suspicious indicators:**
- Unusual entry point
- Packed/compressed sections (high entropy)
- Suspicious imports (network, process manipulation)
- Modified timestamps
- Unusual section names

### Detecting Packers

**Packers compress/encrypt malware to evade detection.**

```bash
# Detect packer
upx -t suspicious.exe  # Check if UPX packed

# Entropy analysis (high entropy = packed/encrypted)
# Use pe-studio or similar tool
```

**Common packers:**
- UPX
- ASPack
- PECompact
- Themida
- VMProtect

**Unpacking:**
- Some packers can be reversed (UPX: `upx -d file.exe`)
- Others require manual unpacking or debugging

## Dynamic Analysis Tools

### Process Monitor (Procmon)

**Windows Sysinternals tool - essential for dynamic analysis.**

**Setup filters:**
```
Process Name is malware.exe
Operation begins with Write
Path contains HKCU\Software
```

**What to monitor:**
- File operations (Create, Write, Delete)
- Registry operations (RegSetValue, RegCreateKey)
- Network operations (TCP/UDP connects)
- Process operations (Process Create, Thread Create)

**Common malware behaviors:**
- Creating files in Temp or AppData
- Modifying Run keys (persistence)
- Modifying firewall settings
- Dropping additional files
- Injecting into other processes

### Process Explorer

**View running processes and their properties:**
- Memory usage
- Handles (files, registry keys open)
- DLLs loaded
- Network connections
- Strings in memory

**Suspicious indicators:**
- Unsigned executables
- Unusual parent-child relationships
- Process injection
- Hidden processes

### Wireshark / tcpdump

**Monitor network traffic:**

```bash
# Capture all traffic
sudo tcpdump -i any -w malware_traffic.pcap

# In Wireshark:
# - Filter by malware's IP
# - Look for DNS queries (C2 domains)
# - Extract objects (downloaded files)
# - Analyze HTTP/HTTPS connections
```

**What to look for:**
- Command and control (C2) servers
- Downloaded payloads
- Exfiltrated data
- Protocols used
- Beaconing intervals

### Regshot

**Registry comparison tool:**

1. Take snapshot before execution
2. Execute malware
3. Take snapshot after execution
4. Compare snapshots

**Reveals:**
- New/modified registry keys
- Persistence mechanisms
- Configuration changes

## Malware Behaviors to Identify

### Persistence Mechanisms

**How malware survives reboot:**

**Registry Run keys:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

**Scheduled tasks:**
```
C:\Windows\System32\Tasks\
```

**Services:**
```
HKLM\System\CurrentControlSet\Services\
```

**Startup folder:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```

**WMI Event Subscriptions:**
- Fileless persistence
- Hard to detect

### Network Communication

**Beaconing:**
- Regular intervals (heartbeat to C2)
- Indicates active C2 connection

**Data exfiltration:**
- Large outbound transfers
- Unusual protocols (DNS tunneling)
- Encrypted connections

**Domain Generation Algorithms (DGA):**
- Generates many domain names
- Tries them until one works
- Evades domain blacklisting

### Process Injection

**Running code in another process:**

**Techniques:**
- DLL injection
- Process hollowing
- APC injection
- Reflective DLL injection

**Why:**
- Hide malicious code
- Evade detection
- Elevate privileges
- Access process memory

### Credential Theft

**Common techniques:**
- Mimikatz (extract passwords from memory)
- Keylogging
- Form grabbing (browser)
- Credential dumping (SAM, LSASS)

## Dynamic Analysis in Practice

### Analysis Workflow

**1. Preparation:**
```bash
# Take VM snapshot
# Set up monitoring tools
# Start Procmon with filters
# Start Wireshark capture
# Open Process Explorer
```

**2. Execution:**
```bash
# Execute malware
# Observe immediate behavior
# Let it run for 5-10 minutes
# Interact with system (malware might wait)
```

**3. Observation:**
- What files created/modified?
- What registry keys changed?
- What network connections made?
- What processes spawned?
- Any anti-analysis techniques?

**4. Documentation:**
- Screenshot everything
- Save logs from all tools
- Document timeline of events
- Note any unusual behavior

**5. Cleanup:**
```bash
# Save artifacts
# Revert to clean snapshot
# Never boot infected VM again without snapshot
```

### Example Analysis

**Sample: TrojanDownloader.exe**

**Static analysis findings:**
```
File: TrojanDownloader.exe
MD5: 3bc69e6373cd1e36c6a3eef2b8b30c1e
Imports: URLDownloadToFileA, CreateProcessA, RegSetValueExA
Strings: http://evil.com/payload.exe, Software\Microsoft\Windows\CurrentVersion\Run
```

**Dynamic analysis findings:**
```
File created: C:\Users\User\AppData\Local\Temp\payload.exe
Registry modified: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update = "C:\Users\User\AppData\Local\Temp\payload.exe"
Network: Connected to evil.com:80
Process: Created payload.exe
```

**Conclusion:**
- Downloads additional payload from evil.com
- Achieves persistence via Run key
- Executes downloaded payload
- Classic trojan downloader behavior

## Anti-Analysis Techniques

Malware often detects analysis environments.

### VM Detection

**Checks for:**
- VMware artifacts (files, registry keys)
- VirtualBox guest additions
- Hypervisor instructions
- Hardware characteristics (unusual CPU, MAC addresses)

### Debugger Detection

**Techniques:**
- IsDebuggerPresent() API
- PEB flags
- Timing checks (debugger slower)
- Exception handling

### Sandbox Evasion

**Malware may:**
- Sleep for extended periods
- Check for mouse movement
- Require user interaction
- Check for internet connectivity
- Validate environment (specific files/registry keys)

### Obfuscation

**Code obfuscation:**
- String encryption
- Control flow obfuscation
- Dead code insertion
- Polymorphic code

## Creating Indicators of Compromise (IOCs)

**From analysis, extract IOCs:**

**File-based:**
- MD5/SHA256 hashes
- File names
- File sizes
- File paths

**Network-based:**
- IP addresses
- Domain names
- URLs
- User-agents

**Registry-based:**
- Registry keys created/modified
- Registry values

**Behavioral:**
- Process injection patterns
- Service creation
- Scheduled task names

### YARA Rules

**Create detection signatures:**

```yara
rule TrojanDownloader {
    meta:
        description = "Detects TrojanDownloader"
        author = "Security Team"
        date = "2024-01-01"
    
    strings:
        $url = "evil.com" ascii
        $registry = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $api1 = "URLDownloadToFileA" ascii
        $api2 = "CreateProcessA" ascii
    
    condition:
        all of ($api*) and ($url or $registry)
}
```

**Test YARA rule:**
```bash
yara my_rule.yar suspicious_file.exe
```

## Automated Analysis

### Cuckoo Sandbox

**Automated malware analysis system:**

**Features:**
- Automated VM execution
- Behavior analysis
- Network traffic capture
- Memory dumps
- Screenshots
- API call tracing

**Setup:**
```bash
# Install dependencies
sudo apt install python3 python3-pip mongodb postgresql

# Install Cuckoo
pip3 install cuckoo

# Initialize
cuckoo init

# Configure VMs in conf/virtualbox.conf
# Submit samples:
cuckoo submit malware.exe
```

### Online Sandboxes

**When you can't set up local analysis:**

**ANY.RUN:**
- Interactive analysis
- Public and private submissions
- Real-time interaction

**Joe Sandbox:**
- Comprehensive analysis
- Multiple OS support
- Detailed reports

**Hybrid Analysis:**
- Multiple engines
- IOC extraction
- MITRE ATT&CK mapping

**VirusTotal:**
- Multi-engine scanning
- Behavior analysis
- Community insights

**Caution:** Don't submit sensitive malware publicly!

## Reporting Findings

### Analysis Report Structure

**1. Executive Summary**
- Malware type
- Threat level
- Key findings

**2. Technical Details**
- File information (hashes, size, type)
- Static analysis findings
- Dynamic analysis findings
- Network indicators

**3. Indicators of Compromise**
- File hashes
- IPs/domains
- Registry keys
- Filenames

**4. Detection Rules**
- YARA rules
- Snort/Suricata rules
- Firewall rules

**5. Mitigation Recommendations**
- Block IOCs
- Patch vulnerabilities
- Update signatures

## Key Takeaways

**Malware analysis workflow:**
1. Safety first (isolated environment)
2. Static analysis (understand without executing)
3. Dynamic analysis (observe behavior)
4. Document findings
5. Create IOCs and rules
6. Share intelligence

**Essential skills:**
- Safe lab setup
- Tool proficiency
- Pattern recognition
- Documentation
- Patience and persistence

**Remember:**
- Always use isolated VMs
- Snapshot before analysis
- Never analyze on production systems
- Document everything
- Share findings responsibly

Malware analysis is part art, part science. The more samples you analyze, the better you'll become at spotting patterns and understanding malicious behavior.

Next, we'll explore more advanced topics in traffic analysis and network forensics.
