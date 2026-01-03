# Security Automation and SOAR

Security operations centers (SOCs) are overwhelmed with alerts. Automation is no longer optional—it's essential. This lesson covers security automation, orchestration, and SOAR (Security Orchestration, Automation, and Response) platforms.

## The Case for Automation

### The Alert Fatigue Problem

**Typical SOC challenges:**
- 10,000+ alerts per day
- 99% are false positives or low priority
- Analysts spend 80% of time on repetitive tasks
- Average time to investigate: 3-5 hours
- Critical threats get lost in noise
- Analyst burnout and turnover

**What automation solves:**
- Triage alerts automatically
- Enrich with threat intelligence
- Execute standard response actions
- Document everything
- Free analysts for complex investigations

### ROI of Automation

**Cost savings:**
```
Manual investigation: 3 hours × $50/hour = $150
Automated triage: 5 minutes × $50/hour = $4.17
Savings per alert: $145.83

With 1,000 alerts/day:
Annual savings: $145.83 × 1000 × 365 = $53+ million
```

**Efficiency gains:**
- Respond in seconds vs. hours
- Consistent response quality
- 24/7 operation
- Scale without hiring

## Security Automation Basics

### Types of Automation

**Alert enrichment:**
- IP reputation lookup
- Domain age check
- VirusTotal scan
- WHOIS lookup
- Geolocation
- Historical activity

**Containment actions:**
- Block IP at firewall
- Disable user account
- Isolate infected host
- Quarantine email
- Reset password

**Investigation automation:**
- Query logs automatically
- Correlate events
- Extract IOCs
- Search threat intel
- Generate timeline

**Response orchestration:**
- Create ticket
- Send notifications
- Execute playbooks
- Update case management
- Generate reports

### Automation Pyramid

```
Level 4: Full Automation (autonomous response)
         ↑
Level 3: Orchestration (multi-tool workflows)
         ↑
Level 2: Scripting (single-tool automation)
         ↑
Level 1: Manual (analyst does everything)
```

**Start at Level 2, progress to Level 4.**

## Scripting for Security

### Python Security Automation

**Example: Automated alert enrichment**

```python
#!/usr/bin/env python3
import requests
import json

class AlertEnricher:
    def __init__(self, vt_api_key):
        self.vt_api_key = vt_api_key
    
    def check_ip_reputation(self, ip):
        """Check IP against VirusTotal"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key}
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'total_engines': sum(stats.values()),
                'reputation': 'malicious' if stats.get('malicious', 0) > 0 else 'clean'
            }
        return None
    
    def get_domain_info(self, domain):
        """Get WHOIS and age info"""
        import whois
        
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'age_days': (datetime.now() - w.creation_date).days if w.creation_date else None
            }
        except:
            return None
    
    def enrich_alert(self, alert):
        """Enrich alert with contextual information"""
        enriched = alert.copy()
        
        # Check source IP
        if 'src_ip' in alert:
            enriched['src_ip_reputation'] = self.check_ip_reputation(alert['src_ip'])
        
        # Check destination IP
        if 'dst_ip' in alert:
            enriched['dst_ip_reputation'] = self.check_ip_reputation(alert['dst_ip'])
        
        # Check domain
        if 'domain' in alert:
            enriched['domain_info'] = self.get_domain_info(alert['domain'])
        
        # Calculate risk score
        enriched['risk_score'] = self.calculate_risk_score(enriched)
        
        return enriched
    
    def calculate_risk_score(self, alert):
        """Calculate risk score based on enrichment data"""
        score = 0
        
        # IP reputation
        if alert.get('src_ip_reputation', {}).get('malicious', 0) > 0:
            score += 50
        
        # New domain
        domain_age = alert.get('domain_info', {}).get('age_days')
        if domain_age and domain_age < 30:
            score += 30
        
        # Severity
        if alert.get('severity') == 'critical':
            score += 20
        
        return min(score, 100)  # Cap at 100

# Usage
enricher = AlertEnricher(vt_api_key='your_api_key')

alert = {
    'id': 'ALT-12345',
    'severity': 'high',
    'src_ip': '198.51.100.42',
    'dst_ip': '203.0.113.10',
    'domain': 'suspicious-domain.com'
}

enriched_alert = enricher.enrich_alert(alert)
print(json.dumps(enriched_alert, indent=2))
```

### Automated Response Actions

**Example: Auto-block malicious IPs**

```python
#!/usr/bin/env python3
import subprocess
import logging
from datetime import datetime

class AutoResponder:
    def __init__(self, log_file='auto_response.log'):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(message)s'
        )
        self.logger = logging
    
    def block_ip(self, ip, reason):
        """Block IP at firewall"""
        try:
            # Using iptables
            cmd = f"sudo iptables -I INPUT 1 -s {ip} -j DROP"
            subprocess.run(cmd.split(), check=True)
            
            self.logger.info(f"BLOCKED IP: {ip} - Reason: {reason}")
            
            # Add to blocklist file
            with open('/etc/security/blocklist.txt', 'a') as f:
                f.write(f"{ip}\t{datetime.now()}\t{reason}\n")
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to block {ip}: {e}")
            return False
    
    def disable_user_account(self, username, reason):
        """Disable compromised user account"""
        try:
            # Linux
            subprocess.run(['sudo', 'passwd', '-l', username], check=True)
            
            self.logger.info(f"DISABLED ACCOUNT: {username} - Reason: {reason}")
            
            # Send notification
            self.send_notification(
                f"User account {username} has been disabled due to: {reason}"
            )
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to disable {username}: {e}")
            return False
    
    def isolate_host(self, hostname, reason):
        """Isolate compromised host"""
        try:
            # This would integrate with your network management
            # Example: modify firewall rules, change VLAN, etc.
            
            self.logger.info(f"ISOLATED HOST: {hostname} - Reason: {reason}")
            
            # Create incident ticket
            self.create_ticket(
                title=f"Host Isolation: {hostname}",
                description=f"Automatically isolated due to: {reason}",
                priority='high'
            )
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to isolate {hostname}: {e}")
            return False
    
    def send_notification(self, message):
        """Send notification to security team"""
        # Integrate with Slack, email, SMS, etc.
        print(f"NOTIFICATION: {message}")
    
    def create_ticket(self, title, description, priority):
        """Create incident ticket"""
        # Integrate with JIRA, ServiceNow, etc.
        print(f"TICKET CREATED: {title} - {priority}")

# Usage
responder = AutoResponder()

# Automated response to brute force
if failed_login_count > 10:
    responder.block_ip(source_ip, "Brute force attempt")
    responder.create_ticket(
        title=f"Brute force from {source_ip}",
        description=f"Blocked after {failed_login_count} failed attempts",
        priority='medium'
    )
```

## SOAR Platforms

### What is SOAR?

**Security Orchestration, Automation, and Response**

**Components:**
1. **Orchestration** - Connect multiple tools
2. **Automation** - Execute actions automatically
3. **Response** - Standardized playbooks
4. **Case Management** - Track investigations
5. **Threat Intelligence** - Integrate feeds

**Popular SOAR platforms:**
- Splunk Phantom (now SOAR)
- IBM Resilient
- Palo Alto Cortex XSOAR
- Swimlane
- Demisto (acquired by Palo Alto)
- TheHive Project (open source)

### Playbooks

**Automated response workflows**

**Phishing investigation playbook:**

```
1. Receive phishing alert
   ↓
2. Extract email metadata
   - Sender, subject, attachments
   - URLs, headers
   ↓
3. Enrich indicators
   - Check URLs against threat intel
   - Scan attachments with sandbox
   - Look up sender reputation
   ↓
4. Assess risk
   If malicious:
     - Quarantine email across organization
     - Block sender
     - Add IOCs to blocklist
   If suspicious:
     - Flag for analyst review
     - Request user confirmation
   If benign:
     - Release from quarantine
     - Close case
   ↓
5. Document findings
   - Update case
   - Generate report
   - Close ticket
```

**Malware detection playbook:**

```
1. Malware detected on endpoint
   ↓
2. Gather context
   - Process tree
   - Network connections
   - File hashes
   ↓
3. Containment
   - Isolate host from network
   - Kill malicious process
   - Block C2 domain
   ↓
4. Analysis
   - Submit sample to sandbox
   - Check threat intelligence
   - Identify IOCs
   ↓
5. Hunt for additional infections
   - Search for IOCs across environment
   - Check other endpoints
   ↓
6. Remediation
   - Clean or reimage infected hosts
   - Block identified IOCs
   - Update signatures
   ↓
7. Recovery
   - Restore from backup if needed
   - Verify system clean
   - Return to production
```

### Integrations

**Common integrations:**

**SIEM:**
- Splunk
- Elastic
- QRadar
- ArcSight

**EDR:**
- CrowdStrike
- Carbon Black
- SentinelOne
- Microsoft Defender

**Firewall:**
- Palo Alto
- Fortinet
- Cisco
- pfSense

**Threat Intelligence:**
- VirusTotal
- AlienVault OTX
- MISP
- ThreatConnect

**Ticketing:**
- ServiceNow
- JIRA
- Remedy
- Zendesk

**Communication:**
- Slack
- Microsoft Teams
- Email
- SMS

## Building Custom Automation

### TheHive + Cortex Example

**Open-source SOAR platform**

**Architecture:**
```
TheHive (Case Management)
    ↕
Cortex (Analyzers & Responders)
    ↕
External Services (VirusTotal, MISP, etc.)
```

**Creating custom analyzer:**

```python
#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer

class CustomIPAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.api_key', None, 'API key is missing')
    
    def summary(self, raw):
        """Generate summary for TheHive"""
        taxonomies = []
        level = "info"
        namespace = "CustomAnalyzer"
        predicate = "Reputation"
        
        if raw['reputation'] == 'malicious':
            level = "malicious"
            value = "Malicious"
        else:
            value = "Clean"
        
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}
    
    def run(self):
        """Main analysis logic"""
        if self.data_type == 'ip':
            ip = self.get_data()
            
            # Your analysis logic here
            result = {
                'ip': ip,
                'reputation': self.check_reputation(ip),
                'threat_score': self.calculate_threat_score(ip),
                'sources': self.query_threat_feeds(ip)
            }
            
            self.report(result)
        else:
            self.error('Invalid data type')
    
    def check_reputation(self, ip):
        # Implementation
        pass
    
    def calculate_threat_score(self, ip):
        # Implementation
        pass
    
    def query_threat_feeds(self, ip):
        # Implementation
        pass

if __name__ == '__main__':
    CustomIPAnalyzer().run()
```

### Ansible for Security Automation

**Playbook for incident response:**

```yaml
---
- name: Incident Response Playbook
  hosts: affected_hosts
  become: yes
  
  tasks:
    - name: Isolate host from network
      command: ifconfig eth0 down
      register: isolation_result
    
    - name: Kill malicious process
      shell: pkill -9 -f "{{ malicious_process }}"
      ignore_errors: yes
    
    - name: Collect evidence
      block:
        - name: Dump memory
          command: lime-dump /tmp/memory.dump
        
        - name: Collect logs
          archive:
            path:
              - /var/log/syslog
              - /var/log/auth.log
            dest: /tmp/logs.tar.gz
        
        - name: List processes
          shell: ps aux > /tmp/processes.txt
        
        - name: List network connections
          shell: netstat -tulpn > /tmp/connections.txt
    
    - name: Transfer evidence
      fetch:
        src: "{{ item }}"
        dest: /evidence/{{ inventory_hostname }}/
        flat: yes
      with_items:
        - /tmp/memory.dump
        - /tmp/logs.tar.gz
        - /tmp/processes.txt
        - /tmp/connections.txt
    
    - name: Clean malware
      file:
        path: "{{ item }}"
        state: absent
      with_items:
        - /tmp/malware.exe
        - /etc/cron.d/malicious
    
    - name: Harden system
      include_tasks: hardening.yml
    
    - name: Send notification
      slack:
        token: "{{ slack_token }}"
        msg: "Host {{ inventory_hostname }} has been cleaned and hardened"
        channel: '#security-ops'

- name: Update firewall rules
  hosts: firewall
  tasks:
    - name: Block malicious IPs
      command: >
        iptables -I INPUT 1 -s {{ item }} -j DROP
      with_items: "{{ malicious_ips }}"
```

## Metrics and KPIs

### Key Metrics to Track

**Detection metrics:**
- Mean Time to Detect (MTTD)
- Alert volume
- False positive rate
- Detection accuracy

**Response metrics:**
- Mean Time to Respond (MTTR)
- Mean Time to Contain (MTTC)
- Mean Time to Recover
- Automation rate (% automated)

**Efficiency metrics:**
- Alerts triaged automatically
- Time saved per alert
- Cost per investigation
- Analyst productivity

**Example dashboard:**
```
Security Operations Dashboard

Alerts Today: 8,432
  Automated: 7,891 (94%)
  Analyst Review: 541 (6%)
  
Current Incidents: 12
  Critical: 2
  High: 5
  Medium: 5
  
MTTR: 45 minutes (target: < 60 min)
MTTD: 12 minutes (target: < 15 min)

Top Alert Sources:
  1. Failed Login Attempts (3,221)
  2. Malware Detection (2,104)
  3. Port Scans (1,876)
  4. Data Exfiltration (892)
  5. Privilege Escalation (339)
```

## Best Practices

### Automation Guidelines

**Start small:**
- Pick high-volume, low-complexity tasks
- Automate alert enrichment first
- Gradually increase automation

**Test thoroughly:**
- Test in lab environment
- Peer review automation logic
- Have rollback plan
- Document everything

**Human in the loop:**
- Require approval for critical actions
- Analyst can override automation
- Review automated decisions regularly

**Continuous improvement:**
- Track automation effectiveness
- Adjust based on feedback
- Update playbooks regularly
- Share lessons learned

### Common Pitfalls

**Over-automation:**
- Automating complex decisions too early
- No human oversight on critical actions
- Brittle automation that breaks often

**Under-documentation:**
- No runbooks for automation
- Undocumented integrations
- No change management

**Ignoring false positives:**
- Automation amplifies bad detection logic
- Creates alert fatigue
- Wastes resources

**Poor error handling:**
- Automation fails silently
- No alerts on automation failures
- No fallback to manual process

## Key Takeaways

**Automation benefits:**
- Faster response times
- Consistent quality
- Free analysts for complex work
- Scale without adding headcount
- Reduce human error

**Start with:**
- Alert enrichment
- Simple containment actions
- Reporting automation
- Progress to complex playbooks

**Success factors:**
- Executive support
- Cross-team collaboration
- Proper tooling
- Training and documentation
- Continuous improvement

**Remember:**
- Automation is journey, not destination
- Start small, grow gradually
- Measure everything
- Keep human in the loop
- Continuously improve

Security automation transforms SOC operations from reactive firefighting to proactive threat hunting. Done right, it makes teams more effective, analysts happier, and organizations more secure.
