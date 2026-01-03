# How Do We Protect Against This? (Protection & Prevention)

You've learned how attacks work. Now let's talk about defense. This is where theory meets practice—implementing security controls that actually protect systems and data. Defense is harder than offense, but with the right strategies and tools, it's achievable.

## Defense in Depth

The fundamental principle: **never rely on a single security control**. Layer multiple defenses so if one fails, others still protect you.

Think of a medieval castle:
- Moat (perimeter defense)
- Outer walls (firewall)
- Inner walls (network segmentation)
- Guards (monitoring)
- Vault (encryption)
- Drawbridge (access control)

Multiple obstacles make successful attack much harder.

**Apply to IT:**
- Network firewall
- IDS/IPS
- Endpoint protection
- Access controls
- Encryption
- Security monitoring
- User training
- Incident response plans

If attackers bypass the firewall, they still face IDS, endpoint protection, monitoring, etc.

## Security Frameworks

Organizations use **security frameworks** to structure their defense:

### NIST Cybersecurity Framework

Five core functions:

**1. Identify**
- Asset management (know what you have)
- Risk assessment
- Governance

**2. Protect**
- Access control
- Data security
- Security training
- Protective technology

**3. Detect**
- Monitoring
- Anomaly detection
- Security events

**4. Respond**
- Response planning
- Communication
- Analysis
- Mitigation
- Improvements

**5. Recover**
- Recovery planning
- Improvements
- Communication

### ISO 27001/27002

International standards for information security management.

**Domains:**
- Security policy
- Organization of information security
- Asset management
- Access control
- Cryptography
- Physical security
- Operations security
- Communications security
- System development security
- Supplier relationships
- Incident management
- Business continuity
- Compliance

### CIS Controls

**Center for Internet Security Critical Security Controls**—prioritized, actionable defenses:

**Basic Controls (do these first):**
1. Inventory and control of hardware assets
2. Inventory and control of software assets
3. Continuous vulnerability management
4. Controlled use of administrative privileges
5. Secure configuration for hardware and software
6. Maintenance, monitoring, and analysis of audit logs

**Foundational Controls:**
7-16 (email security, malware defenses, data recovery, etc.)

**Organizational Controls:**
17-20 (incident response, penetration testing, etc.)

## Network Security

### Firewalls (Revisited)

**Implementation best practices:**

**Default deny**: Block everything, explicitly allow only what's needed
```
# Bad: Allow everything except specific blocks
# Good: Block everything except specific allows
```

**Least privilege**: Only allow minimum necessary access

**Rule ordering matters**: More specific rules first
```
1. Allow 192.168.1.50:443 to any (specific)
2. Block 192.168.1.0/24 to any (general)
```

**Regular review**: Remove unused rules, ensure rules still needed

**Stateful inspection**: Track connection state, not just individual packets

**Application-level filtering**: Inspect actual content, not just headers

### Intrusion Detection/Prevention Systems

**Signature-based detection:**
- Matches known attack patterns
- Fast and accurate for known threats
- Can't detect new attacks

**Anomaly-based detection:**
- Establishes baseline of normal behavior
- Detects deviations
- Can find zero-day attacks
- Higher false positive rate

**Behavioral analysis:**
- Looks for suspicious behaviors (port scanning, failed logins)
- Useful for insider threats

**Deployment:**
- **Inline (IPS)**: Can block attacks, but adds latency
- **Out-of-band (IDS)**: Monitor-only, no impact on traffic flow

**Tuning is critical:**
- Too sensitive → false positives, alert fatigue
- Too permissive → miss real attacks
- Continuous tuning based on environment

### Network Segmentation

**Microsegmentation**: Divide network into small zones

**Implementation:**
- VLANs for logical separation
- Firewalls between segments
- Zero Trust principles

**Example segmentation:**
```
[Internet]
    ↓
[DMZ] - Public web servers
    ↓
[Firewall]
    ↓
[Internal Network]
    ├─ [Employee Network]
    ├─ [Server Network]
    ├─ [Development Network]
    └─ [IoT/Guest Network]
```

Each segment has appropriate controls and isolation.

### Network Access Control (NAC)

**Pre-connection checks:**
1. Device identification
2. Authentication
3. Compliance check (OS patches, antivirus updated)
4. Authorization (what can you access?)

**Enforcement:**
- Full access (compliant, authorized)
- Quarantine (needs updates)
- Guest access (untrusted devices)
- Denied (failed checks)

**802.1X**: Port-based network access control
- User/device authentication before network access
- RADIUS server validates credentials
- Switch grants or denies access

## Endpoint Security

Endpoints (desktops, laptops, servers, mobile devices) are common attack targets.

### Antivirus / Anti-Malware

**Traditional antivirus:**
- Signature-based detection
- Effective against known malware
- Signature database must be updated

**Next-gen antivirus (NGAV):**
- Machine learning
- Behavioral analysis
- Cloud-based threat intelligence
- Can detect unknown malware

**Endpoint Detection and Response (EDR):**
- Continuous monitoring
- Threat detection
- Investigation capabilities
- Automated response
- Forensics data

### Host-Based Firewall

Software firewall on individual systems.

**Benefits:**
- Controls traffic to/from specific applications
- Last line of defense
- Protects even on untrusted networks

**Configuration:**
```bash
# Linux (iptables example)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -j DROP  # Default deny

# Windows
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow
```

### Application Whitelisting

Only approved applications can run.

**Benefits:**
- Prevents unauthorized software execution
- Stops most malware
- Reduces attack surface

**Challenges:**
- Management overhead
- User resistance
- Needs accurate software inventory

**Tools:** Windows AppLocker, Carbon Black, bit9

### Patch Management

**Unpatched systems are low-hanging fruit for attackers.**

**Process:**
1. Inventory all systems and software
2. Monitor for new patches
3. Test patches in non-production
4. Deploy in stages
5. Verify successful installation
6. Document exceptions

**Prioritization:**
- Critical systems first
- Publicly known vulnerabilities
- Exploits in the wild
- CVSS severity scores

**Challenges:**
- Patch compatibility issues
- Downtime for patching
- Legacy systems that can't be patched

**Virtual patching**: IPS rules that protect unpatched systems

## Application Security

### Secure Development Lifecycle (SDL)

Security integrated into development process:

**Requirements phase:**
- Define security requirements
- Threat modeling

**Design phase:**
- Security architecture
- Review design for vulnerabilities

**Implementation phase:**
- Secure coding practices
- Code review
- Static analysis

**Testing phase:**
- Security testing
- Penetration testing
- Dynamic analysis

**Deployment phase:**
- Secure configuration
- Hardening

**Maintenance phase:**
- Patch management
- Monitoring
- Incident response

### Input Validation

**Never trust user input.**

**Whitelist validation** (preferred):
```python
# Good: Only allow expected characters
import re
if re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
    # Process username
else:
    # Reject
```

**Blacklist validation** (less secure):
```python
# Bad: Try to block malicious input
# Attackers find ways around blacklists
```

**Validation rules:**
- Type (string, integer, email)
- Length (min/max)
- Format (regex pattern)
- Range (numerical bounds)
- Charset (allowed characters)

**Sanitization:**
```python
import html
safe_output = html.escape(user_input)  # Prevents XSS
```

### Parameterized Queries

**Prevents SQL injection:**

**Vulnerable:**
```python
# BAD
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
```

**Secure:**
```python
# GOOD
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

The database properly handles user input, preventing injection.

### Output Encoding

**Prevents XSS:**

```python
# Encode for HTML context
safe_html = html.escape(user_data)

# Encode for JavaScript context
safe_js = json.dumps(user_data)

# Encode for URL context
safe_url = urllib.parse.quote(user_data)
```

Context-appropriate encoding is crucial.

### Web Application Firewall (WAF)

Filters HTTP/HTTPS traffic to web applications.

**Protection against:**
- SQL injection
- XSS
- CSRF
- File inclusion
- DDoS

**Modes:**
- **Blacklist** (negative security): Block known attacks
- **Whitelist** (positive security): Allow only known good traffic

**Popular WAFs:**
- ModSecurity (open-source)
- Cloudflare WAF
- AWS WAF
- Azure WAF
- Imperva

### Security Headers

HTTP response headers that enhance security:

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
X-XSS-Protection: 1; mode=block
Referrer-Policy: no-referrer
```

**Benefits:**
- Prevent clickjacking
- Enforce HTTPS
- Mitigate XSS
- Control resource loading

## Access Control

### Authentication

**Password security:**
- Minimum length (12+ characters)
- Complexity requirements
- Password history (prevent reuse)
- Expiration policies (controversial)
- Account lockout after failed attempts
- Password managers encouraged

**Multi-Factor Authentication (MFA):**
Require multiple factors:
```
Something you know (password)
+ Something you have (phone, token)
+ Something you are (biometric)
```

**MFA methods:**
- SMS codes (weak, vulnerable to SIM swapping)
- Authenticator apps (TOTP—Google Authenticator, Authy)
- Hardware tokens (YubiKey, U2F)
- Push notifications (Duo, Okta)
- Biometrics (as second factor)

**Passwordless authentication:**
- FIDO2/WebAuthn
- Magic links
- Biometrics alone (risky)

### Authorization

**Principle of Least Privilege:**
Give users minimum access needed for their job.

**Role-Based Access Control (RBAC):**
```
Roles:
- Admin: Full access
- Developer: Read/write code, read logs
- Analyst: Read-only access
- Guest: Limited access to specific resources
```

**Review access regularly:**
- Quarterly access reviews
- Remove access for departures
- Adjust for role changes
- Audit privileged accounts

### Privileged Access Management (PAM)

Special controls for admin accounts:

**Just-in-time access**: Temporary elevation when needed
**Session recording**: Record all admin actions
**MFA required**: Extra authentication for privilege
**Approval workflows**: Manager approval for sensitive access
**Credential vaulting**: Store admin passwords securely

## Data Protection

### Data Classification

**Categories:**
- **Public**: No harm if disclosed
- **Internal**: Some harm, limited to organization
- **Confidential**: Significant harm, limited to need-to-know
- **Restricted**: Severe harm, heavily protected (PII, financial, trade secrets)

**Different controls by classification:**
```
Public: Basic security
Internal: Access controls, encryption in transit
Confidential: Strong encryption, MFA, monitoring
Restricted: Strongest encryption, audit logging, DLP, isolated systems
```

### Encryption

**At rest**: Encrypt stored data
- Full disk encryption (BitLocker, FileVault, LUKS)
- Database encryption (TDE - Transparent Data Encryption)
- File/folder encryption

**In transit**: Encrypt data moving across networks
- TLS 1.3 for web traffic
- VPN for remote access
- SSH for remote administration
- Encrypted email (S/MIME, PGP)

**Key management:**
- Hardware Security Modules (HSM)
- Key Management Service (KMS)
- Regular key rotation
- Secure key storage

### Data Loss Prevention (DLP)

Prevent unauthorized data exfiltration.

**Techniques:**
- Content inspection (scan for credit cards, SSNs, etc.)
- Contextual analysis (who, what, where, when)
- Pattern matching (regex for sensitive data)
- Fingerprinting (track specific documents)

**Enforcement points:**
- Network DLP (monitor network traffic)
- Endpoint DLP (control USB, email, uploads)
- Cloud DLP (monitor cloud services)

**Actions:**
- Block: Prevent transfer
- Quarantine: Hold for review
- Alert: Notify security team
- Encrypt: Allow with encryption

### Backup and Recovery

**3-2-1 Rule:**
- 3 copies of data
- 2 different media types
- 1 offsite backup

**Testing backups:**
- Regular restore tests
- Verify data integrity
- Document restore procedures
- Time recovery objectives (RTO)

**Ransomware protection:**
- Immutable backups (can't be encrypted)
- Air-gapped backups (offline)
- Version history
- Rapid recovery capability

## Security Monitoring

### Logging

**What to log:**
- Authentication attempts (success and failure)
- Authorization changes
- System changes
- Network connections
- File access
- Application events
- Security alerts

**Log management:**
- Centralized collection (Syslog, SIEM)
- Adequate retention (comply with policies/regulations)
- Protection from tampering
- Regular review

### SIEM (Security Information and Event Management)

Centralized platform for security monitoring.

**Capabilities:**
- Log aggregation
- Correlation (connect related events)
- Alerting
- Dashboards
- Incident investigation
- Compliance reporting

**Popular SIEM solutions:**
- Splunk
- ELK Stack (Elasticsearch, Logstash, Kibana)
- QRadar
- ArcSight
- Sentinel

**Use cases:**
- Detect brute force attacks (multiple failed logins)
- Identify compromised accounts (unusual access patterns)
- Track lateral movement
- Detect data exfiltration
- Compliance monitoring

### Security Orchestration, Automation and Response (SOAR)

Automates security operations:

**Capabilities:**
- Automated threat intelligence gathering
- Automated response actions
- Workflow orchestration
- Case management
- Playbooks for common scenarios

**Example automated response:**
```
1. Alert: Multiple failed logins detected
2. SOAR enriches: Geolocate IP, check threat intel
3. SOAR decides: IP on blacklist → Block automatically
4. SOAR acts: Update firewall, disable account, create ticket
5. SOAR notifies: Alert analyst
```

## Incident Response

### Incident Response Plan

**Preparation:**
- Define roles and responsibilities
- Create playbooks for common incidents
- Establish communication channels
- Maintain contact lists
- Regular training and drills

**Detection and Analysis:**
- Monitor alerts
- Triage incidents
- Determine scope and severity
- Preserve evidence

**Containment:**
- Short-term: Isolate affected systems
- Long-term: Patch vulnerabilities, rebuild systems

**Eradication:**
- Remove malware
- Close attack vectors
- Patch vulnerabilities

**Recovery:**
- Restore systems from clean backups
- Verify systems are clean
- Monitor for reinfection

**Lessons Learned:**
- Post-incident review
- Document what happened
- Identify improvements
- Update procedures

### Forensics

**Evidence handling:**
- Chain of custody documentation
- Bit-for-bit disk imaging
- Write blockers (prevent evidence modification)
- Hash verification (prove integrity)

**Analysis:**
- File system analysis
- Memory analysis
- Network traffic analysis
- Log analysis
- Malware analysis

**Tools:**
- FTK (Forensic Toolkit)
- EnCase
- Autopsy
- Volatility (memory forensics)
- Wireshark (network forensics)

## Security Testing

### Vulnerability Assessment

Regular scanning for vulnerabilities:

**Tools:**
- Nessus
- OpenVAS
- Qualys
- Rapid7

**Process:**
1. Scan systems
2. Identify vulnerabilities
3. Assess risk
4. Prioritize remediation
5. Verify fixes

### Penetration Testing

Authorized simulated attacks to find weaknesses.

**Types:**
- **Black box**: No inside knowledge
- **White box**: Full knowledge of systems
- **Gray box**: Partial knowledge

**Methodology:**
1. Planning and reconnaissance
2. Scanning
3. Gaining access
4. Maintaining access
5. Analysis and reporting

**Important:**
- Written authorization (scope, timing, methods)
- Rules of engagement
- Non-disclosure agreements
- Clear reporting of findings

### Red Team / Blue Team Exercises

**Red Team**: Offensive security, simulates attackers
**Blue Team**: Defensive security, protects systems
**Purple Team**: Red and blue working together

**Benefits:**
- Test detection capabilities
- Validate response procedures
- Identify gaps
- Train staff

## User Security Awareness

**Humans are often the weakest link.**

### Training Topics

**Phishing recognition:**
- Suspicious sender addresses
- Urgent language
- Requests for credentials
- Unexpected attachments
- Hover before clicking links

**Password security:**
- Strong, unique passwords
- Password manager usage
- MFA enrollment
- Never share passwords

**Physical security:**
- Lock workstations
- Secure documents
- Visitor badges
- Clean desk policy

**Reporting:**
- How to report suspicious activity
- No punishment for good-faith reports
- Encourage security culture

### Simulated Phishing

Send fake phishing emails to test awareness:
- Track click rates
- Provide immediate training
- Improve over time
- No punishment, only education

## Vulnerability Management

### Process

**1. Discovery**: Identify all assets
**2. Prioritization**: Risk-based approach
- CVSS score (severity)
- Exploitability
- Asset criticality
- Threat intelligence

**3. Remediation**: Fix vulnerabilities
- Patching
- Configuration changes
- Compensating controls

**4. Verification**: Confirm fixes work

**5. Continuous monitoring**: Ongoing process

### Metrics

Track security posture:
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Number of vulnerabilities (by severity)
- Patch compliance rates
- Time to patch critical vulnerabilities

## Security Policies and Governance

### Key Policies

**Acceptable Use Policy**: What users can do with IT resources
**Data Classification Policy**: How to handle different data types
**Password Policy**: Password requirements
**Remote Access Policy**: VPN and remote work rules
**Incident Response Policy**: How to handle incidents
**Change Management Policy**: How changes are made

### Compliance

**Regulations vary by industry:**
- **GDPR**: EU data protection
- **HIPAA**: US healthcare data
- **PCI DSS**: Payment card data
- **SOX**: Financial reporting
- **FISMA**: US government systems

**Compliance requirements drive security controls.**

## Key Takeaways

Effective defense requires:
1. **Defense in depth**: Multiple layers
2. **Security frameworks**: Structured approach
3. **Continuous monitoring**: Detect threats
4. **Regular testing**: Find gaps before attackers do
5. **User training**: Address human element
6. **Incident response**: Prepare for breaches
7. **Continuous improvement**: Learn and adapt

**Remember**: Perfect security is impossible. The goal is:
- Make attacks difficult and expensive
- Detect attacks quickly
- Respond effectively
- Minimize damage
- Recover rapidly
- Learn from incidents

Security is a process, not a destination. Threats evolve, so defenses must evolve too.

In the final lesson, we'll explore encryption systems in depth, bringing together cryptographic concepts with practical implementation.
