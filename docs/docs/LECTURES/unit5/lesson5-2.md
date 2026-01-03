# Advanced Scripting for Security

You've learned basic scripting. Now let's level up with advanced techniques that security professionals use daily. These scripts automate reconnaissance, testing, analysis, and response—saving hours of manual work.

## Python for Security - Advanced Techniques

### Working with APIs

Most security tools and services provide APIs. Learn to interact with them.

#### HTTP Requests with Authentication

```python
import requests

# Basic authentication
response = requests.get('https://api.example.com/data',
                       auth=('username', 'password'))

# Bearer token authentication
headers = {'Authorization': 'Bearer YOUR_TOKEN_HERE'}
response = requests.get('https://api.example.com/data', headers=headers)

# API key in header
headers = {'X-API-Key': 'your-api-key'}
response = requests.get('https://api.example.com/data', headers=headers)

print(response.json())
```

#### VirusTotal API Integration

```python
import requests
import hashlib

def check_file_virustotal(filepath, api_key):
    # Calculate file hash
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Check hash on VirusTotal
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': api_key}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"Malicious detections: {stats['malicious']}")
        print(f"Total engines: {sum(stats.values())}")
        return stats
    elif response.status_code == 404:
        print("File not found in VirusTotal database")
    else:
        print(f"Error: {response.status_code}")
    
    return None

# Usage
check_file_virustotal('suspicious.exe', 'YOUR_API_KEY')
```

### Multithreading for Speed

**Speed up network scanning:**

```python
import threading
import socket
from queue import Queue

# Thread-safe queue
queue = Queue()
open_ports = []

def port_scan(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            print(f"Port {port} is open")
        sock.close()
    except:
        pass

def worker(target):
    while not queue.empty():
        port = queue.get()
        port_scan(target, port)
        queue.task_done()

def threaded_port_scan(target, num_threads=100):
    # Fill queue with ports
    for port in range(1, 1025):
        queue.put(port)
    
    # Create threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # Wait for completion
    queue.join()
    
    return sorted(open_ports)

# Usage
target = "192.168.1.1"
print(f"Scanning {target}...")
ports = threaded_port_scan(target)
print(f"Open ports: {ports}")
```

### Subprocess Management

**Execute system commands safely:**

```python
import subprocess
import shlex

def run_command(command):
    """Safely execute shell command"""
    try:
        # Split command safely
        args = shlex.split(command)
        
        # Run command
        result = subprocess.run(args, 
                              capture_output=True, 
                              text=True, 
                              timeout=30)
        
        return {
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {'error': 'Command timed out'}
    except Exception as e:
        return {'error': str(e)}

# Usage
result = run_command('nmap -sV 192.168.1.1')
print(result['stdout'])
```

### Regular Expressions for Log Parsing

```python
import re
from collections import Counter

def parse_auth_log(logfile):
    """Parse authentication log for failed logins"""
    failed_ips = []
    
    # Pattern for failed SSH attempts
    pattern = r'Failed password for .+ from (\d+\.\d+\.\d+\.\d+)'
    
    with open(logfile, 'r') as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                failed_ips.append(match.group(1))
    
    # Count attempts per IP
    ip_counts = Counter(failed_ips)
    
    # IPs with more than 5 attempts
    suspicious = {ip: count for ip, count in ip_counts.items() if count > 5}
    
    return suspicious

# Usage
suspicious_ips = parse_auth_log('/var/log/auth.log')
for ip, count in suspicious_ips.items():
    print(f"{ip}: {count} failed attempts")
```

### Working with JSON and Databases

```python
import json
import sqlite3

def store_scan_results(results, db_path='scans.db'):
    """Store scan results in SQLite database"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            target TEXT,
            port INTEGER,
            service TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert results
    for result in results:
        cursor.execute('''
            INSERT INTO scans (target, port, service)
            VALUES (?, ?, ?)
        ''', (result['target'], result['port'], result['service']))
    
    conn.commit()
    conn.close()

def query_scans(target, db_path='scans.db'):
    """Query previous scans for a target"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT port, service, timestamp
        FROM scans
        WHERE target = ?
        ORDER BY timestamp DESC
    ''', (target,))
    
    results = cursor.fetchall()
    conn.close()
    
    return results

# Usage
results = [
    {'target': '192.168.1.1', 'port': 22, 'service': 'ssh'},
    {'target': '192.168.1.1', 'port': 80, 'service': 'http'}
]
store_scan_results(results)

previous_scans = query_scans('192.168.1.1')
for scan in previous_scans:
    print(f"Port {scan[0]}: {scan[1]} (scanned: {scan[2]})")
```

## Bash Scripting - Advanced

### Automated Vulnerability Scanner

```bash
#!/bin/bash
# vulnerability_scanner.sh

TARGET=$1
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

# Create output directory
mkdir -p $OUTPUT_DIR

echo "[*] Starting scan of $TARGET"
echo "[*] Results will be saved to $OUTPUT_DIR"

# Nmap scan
echo "[*] Running Nmap scan..."
nmap -sV -sC -oN $OUTPUT_DIR/nmap_scan.txt $TARGET
nmap -p- -oN $OUTPUT_DIR/nmap_full.txt $TARGET &

# Nikto web scan
echo "[*] Running Nikto web scan..."
nikto -h $TARGET -o $OUTPUT_DIR/nikto_scan.txt &

# SSL scan
echo "[*] Running SSL scan..."
sslscan $TARGET > $OUTPUT_DIR/ssl_scan.txt &

# DNS enumeration
echo "[*] Running DNS enumeration..."
dig any $TARGET > $OUTPUT_DIR/dns_records.txt
dnsrecon -d $TARGET -t std > $OUTPUT_DIR/dns_recon.txt &

# Wait for background jobs
wait

# Summary report
echo "[*] Generating summary report..."
cat > $OUTPUT_DIR/summary.txt << EOF
Vulnerability Scan Report
Target: $TARGET
Date: $(date)

Files generated:
- nmap_scan.txt: Service version detection
- nmap_full.txt: Full port scan
- nikto_scan.txt: Web vulnerabilities
- ssl_scan.txt: SSL/TLS configuration
- dns_records.txt: DNS records
- dns_recon.txt: DNS reconnaissance

Review each file for potential vulnerabilities.
EOF

echo "[*] Scan complete! Results in $OUTPUT_DIR/"
```

### Log Analysis Script

```bash
#!/bin/bash
# analyze_logs.sh

LOG_FILE="/var/log/auth.log"
ALERT_THRESHOLD=5

echo "=== Security Log Analysis ==="
echo

# Failed login attempts
echo "[*] Failed SSH Login Attempts:"
grep "Failed password" $LOG_FILE | \
    awk '{print $(NF-3)}' | \
    sort | uniq -c | sort -rn | \
    while read count ip; do
        if [ $count -gt $ALERT_THRESHOLD ]; then
            echo "  ALERT: $ip - $count attempts"
        else
            echo "  $ip - $count attempts"
        fi
    done
echo

# Successful logins
echo "[*] Successful SSH Logins:"
grep "Accepted password" $LOG_FILE | \
    awk '{print $(NF-3), $(NF-5)}' | \
    sort | uniq -c | sort -rn | head -10
echo

# New user accounts
echo "[*] New User Accounts Created:"
grep "new user" $LOG_FILE | tail -5
echo

# Sudo usage
echo "[*] Recent Sudo Commands:"
grep "sudo:" $LOG_FILE | tail -10
echo

# Port scans (from firewall logs)
if [ -f "/var/log/syslog" ]; then
    echo "[*] Possible Port Scans:"
    grep "IPTables-Dropped" /var/log/syslog | \
        awk '{print $(NF-2)}' | \
        grep -oP '\d+\.\d+\.\d+\.\d+' | \
        sort | uniq -c | sort -rn | head -10
fi
```

### Automated Backup Script

```bash
#!/bin/bash
# secure_backup.sh

BACKUP_SOURCE="/important/data"
BACKUP_DEST="/backup/location"
ENCRYPTION_KEY="/path/to/encryption.key"
RETENTION_DAYS=30

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_${DATE}.tar.gz.enc"

echo "[*] Starting backup at $(date)"

# Create compressed archive
echo "[*] Creating archive..."
tar -czf - $BACKUP_SOURCE | \
    openssl enc -aes-256-cbc -salt -pbkdf2 \
    -pass file:$ENCRYPTION_KEY > \
    $BACKUP_DEST/$BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "[+] Backup created: $BACKUP_FILE"
    
    # Calculate hash
    sha256sum $BACKUP_DEST/$BACKUP_FILE > \
        $BACKUP_DEST/${BACKUP_FILE}.sha256
    echo "[+] Hash generated"
    
    # Remove old backups
    echo "[*] Removing backups older than $RETENTION_DAYS days..."
    find $BACKUP_DEST -name "backup_*.tar.gz.enc" \
        -mtime +$RETENTION_DAYS -delete
    
    echo "[+] Backup complete!"
else
    echo "[!] Backup failed!"
    exit 1
fi

# Send notification
echo "Backup completed successfully" | \
    mail -s "Backup Report" admin@example.com
```

## Python Security Tools

### Password Strength Checker

```python
import re
import string

def check_password_strength(password):
    """Analyze password strength"""
    score = 0
    feedback = []
    
    # Length check
    if len(password) < 8:
        feedback.append("Password too short (minimum 8 characters)")
    elif len(password) >= 12:
        score += 2
        feedback.append("Good length")
    else:
        score += 1
    
    # Complexity checks
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 2
        feedback.append("Contains special characters")
    else:
        feedback.append("Add special characters")
    
    # Common patterns
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("Avoid repeated characters")
    
    if re.search(r'(123|abc|password|qwerty)', password.lower()):
        score -= 2
        feedback.append("Avoid common patterns")
    
    # Determine strength
    if score < 3:
        strength = "Weak"
    elif score < 5:
        strength = "Medium"
    elif score < 7:
        strength = "Strong"
    else:
        strength = "Very Strong"
    
    return {
        'strength': strength,
        'score': score,
        'feedback': feedback
    }

# Usage
password = input("Enter password to check: ")
result = check_password_strength(password)
print(f"Strength: {result['strength']} (Score: {result['score']})")
for item in result['feedback']:
    print(f"  - {item}")
```

### Network Traffic Monitor

```python
from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import time

class TrafficMonitor:
    def __init__(self):
        self.packets = []
        self.start_time = time.time()
        self.ip_counter = Counter()
        self.port_counter = Counter()
    
    def packet_callback(self, packet):
        """Process captured packet"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Count IPs
            self.ip_counter[src_ip] += 1
            self.ip_counter[dst_ip] += 1
            
            # Get ports
            if TCP in packet:
                self.port_counter[packet[TCP].dport] += 1
            elif UDP in packet:
                self.port_counter[packet[UDP].dport] += 1
            
            # Store packet info
            self.packets.append({
                'src': src_ip,
                'dst': dst_ip,
                'protocol': packet[IP].proto,
                'size': len(packet)
            })
    
    def start_capture(self, interface='eth0', duration=60):
        """Capture packets for specified duration"""
        print(f"Starting capture on {interface} for {duration} seconds...")
        sniff(iface=interface, prn=self.packet_callback, 
              timeout=duration, store=False)
    
    def analyze(self):
        """Analyze captured traffic"""
        print("\n=== Traffic Analysis ===")
        print(f"Total packets: {len(self.packets)}")
        print(f"Duration: {time.time() - self.start_time:.2f} seconds")
        
        print("\nTop 10 IPs by packet count:")
        for ip, count in self.ip_counter.most_common(10):
            print(f"  {ip}: {count} packets")
        
        print("\nTop 10 Destination Ports:")
        for port, count in self.port_counter.most_common(10):
            service = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH',
                53: 'DNS', 25: 'SMTP', 21: 'FTP'
            }.get(port, 'Unknown')
            print(f"  {port} ({service}): {count} packets")
        
        # Detect anomalies
        self.detect_anomalies()
    
    def detect_anomalies(self):
        """Detect suspicious patterns"""
        print("\n=== Anomaly Detection ===")
        
        # Port scan detection
        for ip, count in self.ip_counter.items():
            unique_ports = sum(1 for p in self.packets 
                             if p['src'] == ip)
            if unique_ports > 50:
                print(f"  ALERT: Possible port scan from {ip}")
        
        # High volume
        avg_packets = len(self.packets) / len(self.ip_counter)
        for ip, count in self.ip_counter.most_common(5):
            if count > avg_packets * 10:
                print(f"  ALERT: High traffic volume from {ip}")

# Usage (requires root)
# monitor = TrafficMonitor()
# monitor.start_capture(interface='eth0', duration=60)
# monitor.analyze()
```

### Automated Incident Response

```python
import subprocess
import datetime
import json

class IncidentResponse:
    def __init__(self):
        self.incident_log = []
    
    def log_action(self, action, details):
        """Log incident response action"""
        entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'action': action,
            'details': details
        }
        self.incident_log.append(entry)
        print(f"[{entry['timestamp']}] {action}: {details}")
    
    def block_ip(self, ip_address):
        """Block malicious IP with iptables"""
        try:
            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            subprocess.run(cmd.split(), check=True)
            self.log_action('BLOCK_IP', f"Blocked {ip_address}")
            return True
        except Exception as e:
            self.log_action('ERROR', f"Failed to block {ip_address}: {e}")
            return False
    
    def isolate_host(self, hostname):
        """Isolate compromised host"""
        # This would integrate with your network management system
        self.log_action('ISOLATE_HOST', f"Isolated {hostname}")
        # Actual implementation would vary by environment
    
    def collect_evidence(self, target):
        """Collect forensic evidence"""
        evidence_dir = f"evidence_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        subprocess.run(['mkdir', '-p', evidence_dir])
        
        # Memory dump (if installed)
        try:
            subprocess.run(['sudo', 'dd', 'if=/dev/mem', 
                          f'of={evidence_dir}/memory.img'], 
                          timeout=300)
            self.log_action('COLLECT_MEMORY', f"Memory dumped to {evidence_dir}")
        except:
            pass
        
        # Network connections
        result = subprocess.run(['ss', '-tunap'], capture_output=True, text=True)
        with open(f'{evidence_dir}/connections.txt', 'w') as f:
            f.write(result.stdout)
        
        # Process list
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        with open(f'{evidence_dir}/processes.txt', 'w') as f:
            f.write(result.stdout)
        
        self.log_action('COLLECT_EVIDENCE', f"Evidence saved to {evidence_dir}")
        return evidence_dir
    
    def notify_team(self, message):
        """Send notification to security team"""
        # This would integrate with your notification system
        # Email, Slack, PagerDuty, etc.
        self.log_action('NOTIFY', message)
    
    def save_incident_report(self, filename='incident_report.json'):
        """Save incident log to file"""
        with open(filename, 'w') as f:
            json.dump(self.incident_log, f, indent=2)
        print(f"Incident report saved to {filename}")

# Usage example
def respond_to_brute_force(attacking_ip):
    """Automated response to brute force attack"""
    ir = IncidentResponse()
    
    ir.log_action('DETECT', f"Brute force attack detected from {attacking_ip}")
    
    # Block the attacker
    ir.block_ip(attacking_ip)
    
    # Collect evidence
    evidence_dir = ir.collect_evidence(attacking_ip)
    
    # Notify team
    ir.notify_team(f"Brute force attack from {attacking_ip} blocked. "
                   f"Evidence: {evidence_dir}")
    
    # Save report
    ir.save_incident_report()

# respond_to_brute_force('192.168.1.100')
```

## Key Takeaways

**Advanced scripting enables:**
- Automation of repetitive tasks
- Faster reconnaissance and scanning
- Real-time monitoring and alerting
- Automated incident response
- Custom security tools

**Best practices:**
- Error handling (try/except, exit codes)
- Logging all actions
- Input validation
- Secure credential storage
- Code comments and documentation
- Testing before production use

**Remember:**
- Scripts are tools—use responsibly
- Always have permission before scanning
- Test in isolated environments first
- Keep scripts updated
- Share knowledge with team

These advanced scripting skills separate security professionals from beginners. Practice building your own tools, contribute to open-source projects, and continuously refine your automation skills.

Next lesson, we'll explore malware analysis techniques and how to reverse engineer malicious code.
