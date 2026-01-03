# Legal Frameworks and Compliance

Ethics guide your choices, but laws and regulations enforce them. This lesson covers the legal landscape of cybersecurity—what you must know to stay on the right side of the law and help organizations remain compliant.

## Criminal Laws

### Computer Fraud and Abuse Act (CFAA) - United States

**The CFAA makes it illegal to:**
- Access a computer without authorization
- Exceed authorized access
- Cause damage to protected computers
- Obtain information through unauthorized access
- Traffic in passwords
- Threaten to cause damage

**Key provisions:**
```
18 U.S.C. § 1030(a)(1) - Accessing classified information
18 U.S.C. § 1030(a)(2) - Obtaining information from protected computers
18 U.S.C. § 1030(a)(3) - Accessing government computers
18 U.S.C. § 1030(a)(4) - Fraud via computer
18 U.S.C. § 1030(a)(5) - Damaging protected computers
18 U.S.C. § 1030(a)(6) - Trafficking in passwords
18 U.S.C. § 1030(a)(7) - Extortion via computer
```

**"Protected computer"** = any computer used in interstate commerce (basically all of them)

**Penalties:**
- First offense: Up to 5 years
- Second offense: Up to 10 years
- Causing damage: Up to 10 years
- With intent to extort: Up to 20 years

**Controversial aspects:**
- Broad interpretation of "unauthorized access"
- Terms of Service violations potentially criminal
- Aaron Swartz case highlighted problems
- Ongoing debates about reform

### Computer Misuse Act 1990 (CMA) - United Kingdom

**Three main offenses:**

**Section 1: Unauthorized access**
- Penalty: Up to 2 years imprisonment
- Covers: Accessing any computer without permission

**Section 2: Unauthorized access with intent**
- Penalty: Up to 5 years imprisonment
- Covers: Accessing to commit further crimes

**Section 3: Unauthorized modification**
- Penalty: Up to 10 years imprisonment
- Covers: Modifying computer material (malware, defacement)

**Section 3A: Making, supplying, or obtaining tools**
- Penalty: Up to 2 years (summary), 10 years (indictment)
- Covers: Hacking tools, exploits

### Other Criminal Laws

**Electronic Communications Privacy Act (ECPA)**
- Prohibits interception of electronic communications
- Covers email, phone calls, data transmissions
- Stored Communications Act (SCA) is part of ECPA

**Wire Fraud Statute (18 U.S.C. § 1343)**
- Using electronic communications for fraud
- Applies to many cybercrimes

**Identity Theft and Assumption Deterrence Act**
- Criminalizes identity theft
- Federal crime to use another's identity

**Economic Espionage Act**
- Protects trade secrets
- Criminal penalties for theft

## Data Protection and Privacy Laws

### General Data Protection Regulation (GDPR) - EU

**Scope:**
- Applies to EU residents' data
- Extraterritorial (applies to companies outside EU)
- Covers personal data processing

**Key principles:**
1. **Lawfulness, fairness, transparency**
2. **Purpose limitation** (collect for specific purposes)
3. **Data minimization** (only collect what's needed)
4. **Accuracy** (keep data accurate and up to date)
5. **Storage limitation** (don't keep longer than necessary)
6. **Integrity and confidentiality** (security)
7. **Accountability** (demonstrate compliance)

**Data subject rights:**
- Right to access
- Right to rectification
- Right to erasure ("right to be forgotten")
- Right to restrict processing
- Right to data portability
- Right to object
- Rights related to automated decision-making

**Security requirements:**
- Pseudonymization and encryption
- Ability to ensure confidentiality, integrity, availability
- Ability to restore availability after incident
- Regular testing and evaluation

**Breach notification:**
- Must notify supervisory authority within 72 hours
- Must notify affected individuals if high risk
- Document all breaches

**Penalties:**
- Up to €20 million OR 4% of global annual revenue
- Whichever is higher

**Data Protection Officer (DPO):**
- Required for public authorities
- Required for large-scale monitoring
- Required for large-scale processing of sensitive data

### California Consumer Privacy Act (CCPA) / CPRA

**Consumer rights:**
- Know what personal information is collected
- Know whether information is sold or disclosed
- Say no to sale of information
- Access personal information
- Request deletion
- Equal service and price

**Business obligations:**
- Provide privacy notice
- Respond to consumer requests
- Don't discriminate against consumers exercising rights
- Implement reasonable security

**Penalties:**
- Up to $7,500 per intentional violation
- Up to $2,500 per violation
- Private right of action for data breaches

### Health Insurance Portability and Accountability Act (HIPAA)

**Applies to:**
- Healthcare providers
- Health plans
- Healthcare clearinghouses
- Business associates

**Protected Health Information (PHI):**
- Any health information that can identify individual
- Includes medical records, payment information, etc.

**Privacy Rule:**
- Limits use and disclosure of PHI
- Gives patients rights over their information
- Requires written authorization for most uses

**Security Rule:**
- Administrative safeguards
- Physical safeguards
- Technical safeguards
- Requires risk assessments

**Breach Notification Rule:**
- Notify affected individuals
- Notify HHS (Department of Health and Human Services)
- Media notification if >500 people affected

**Penalties:**
- Tier 1: $100-$50,000 per violation (unknowing)
- Tier 2: $1,000-$50,000 (reasonable cause)
- Tier 3: $10,000-$50,000 (willful neglect, corrected)
- Tier 4: $50,000+ (willful neglect, not corrected)
- Criminal penalties possible

### Payment Card Industry Data Security Standard (PCI DSS)

**Not a law, but contractually required by card companies**

**12 requirements:**
1. Install and maintain firewall configuration
2. Don't use vendor-supplied defaults
3. Protect stored cardholder data
4. Encrypt transmission of cardholder data
5. Protect systems against malware
6. Develop and maintain secure systems
7. Restrict access to cardholder data
8. Identify and authenticate access
9. Restrict physical access to cardholder data
10. Track and monitor network access
11. Regularly test security systems
12. Maintain information security policy

**Compliance levels:**
- Level 1: 6+ million transactions/year (annual onsite audit)
- Level 2: 1-6 million transactions/year (annual self-assessment)
- Level 3: 20,000-1 million e-commerce (annual self-assessment)
- Level 4: <20,000 e-commerce or <1 million (annual self-assessment)

**Penalties:**
- Fines from card brands ($5,000-$100,000/month)
- Increased transaction fees
- Loss of ability to process cards

## Sector-Specific Regulations

### Financial Services

**Gramm-Leach-Bliley Act (GLBA)**
- Financial institutions must protect customer information
- Privacy notices required
- Opt-out for information sharing

**Sarbanes-Oxley Act (SOX)**
- Internal controls over financial reporting
- IT controls are part of this
- Criminal penalties for executives

**New York Department of Financial Services (NYDFS) Cybersecurity Regulation**
- Applies to financial institutions in NY
- Requires cybersecurity program
- Annual certification to superintendent
- Incident response plan required

### Critical Infrastructure

**NERC CIP (North American Electric Reliability Corporation Critical Infrastructure Protection)**
- Standards for electric grid security
- Mandatory for utilities
- Covers physical and cyber security

**Transportation Security Administration (TSA) Security Directives**
- Apply to pipelines, rail, aviation
- Cybersecurity requirements
- Incident reporting

## International Laws

### China Cybersecurity Law

**Key provisions:**
- Data localization (critical data must stay in China)
- Network security reviews
- Real-name registration
- Cooperation with authorities

### Australia Privacy Act

**Australian Privacy Principles (APPs)**
- 13 principles for handling personal information
- Covers collection, use, disclosure, security
- Notifiable Data Breaches scheme

### Brazil LGPD (Lei Geral de Proteção de Dados)

**Similar to GDPR:**
- Data subject rights
- Consent requirements
- Security requirements
- Breach notification

## Compliance Frameworks

### NIST Cybersecurity Framework

**Five functions:**
1. **Identify** - Asset management, risk assessment
2. **Protect** - Access control, training, data security
3. **Detect** - Monitoring, detection processes
4. **Respond** - Response planning, communications
5. **Recover** - Recovery planning, improvements

**Not mandatory but widely adopted**
- Referenced by regulations
- Used for assessments
- Industry standard

### ISO 27001/27002

**ISO 27001:** Information Security Management System (ISMS)
- Certification available
- Requires risk assessment
- Continuous improvement

**ISO 27002:** Code of practice
- Detailed controls
- Implementation guidance

**14 control domains:**
1. Information security policies
2. Organization of information security
3. Human resource security
4. Asset management
5. Access control
6. Cryptography
7. Physical and environmental security
8. Operations security
9. Communications security
10. System acquisition, development, maintenance
11. Supplier relationships
12. Incident management
13. Business continuity
14. Compliance

### SOC 2 (System and Organization Controls)

**Trust Services Criteria:**
- **Security** (required for all)
- Availability
- Processing integrity
- Confidentiality
- Privacy

**Two types:**
- **Type I:** Design of controls at point in time
- **Type II:** Operating effectiveness over period (6-12 months)

**Used for:** SaaS vendors, cloud providers, service organizations

## Compliance in Practice

### Risk Assessments

**Required by many regulations**

**Steps:**
1. Identify assets
2. Identify threats
3. Identify vulnerabilities
4. Determine likelihood
5. Determine impact
6. Calculate risk
7. Prioritize
8. Implement controls
9. Monitor and review

### Policies and Procedures

**Required documents:**
- Information security policy
- Acceptable use policy
- Incident response plan
- Business continuity plan
- Disaster recovery plan
- Data retention policy
- Vendor management policy
- Change management procedures

**Policy structure:**
```
1. Purpose
2. Scope
3. Definitions
4. Policy statements
5. Responsibilities
6. Enforcement
7. Review and updates
```

### Training and Awareness

**Required by most regulations**

**Topics:**
- Security basics
- Phishing awareness
- Password security
- Data handling
- Incident reporting
- Compliance requirements

**Frequency:**
- Annual training minimum
- New hire training
- Role-specific training
- Ad-hoc training for threats

### Audit and Assessment

**Internal audits:**
- Regular self-assessments
- Verify controls are working
- Identify gaps

**External audits:**
- Independent verification
- Required for some regulations
- Provides assurance to stakeholders

**Penetration testing:**
- Test security controls
- Identify vulnerabilities
- Often required annually

### Incident Response and Reporting

**Notification requirements vary:**

**GDPR:** 72 hours to authority
**HIPAA:** 60 days to individuals
**PCI DSS:** Immediately to acquiring bank
**State breach laws:** Varies (typically 30-90 days)

**What to report:**
- Nature of breach
- Data involved
- Number of affected individuals
- Remediation steps
- Contact information

### Documentation

**Critical for compliance:**
- Policies and procedures
- Risk assessments
- Training records
- Audit logs
- Incident reports
- Vendor assessments
- Business associate agreements
- Data processing agreements

**Retention requirements vary:**
- HIPAA: 6 years
- SOX: 7 years
- GDPR: As long as necessary
- PCI DSS: 1 year minimum

## Consequences of Non-Compliance

### Regulatory Fines

**Can be massive:**
- British Airways: £20 million (GDPR)
- Marriott: £18.4 million (GDPR)
- Equifax: $575 million (FTC settlement)
- Capital One: $80 million (OCC fine)

### Lawsuits

**Private right of action:**
- Data breach class actions
- Can be costly even if settled
- Reputation damage

### Business Impact

**Beyond fines:**
- Loss of customers
- Reputation damage
- Inability to process payments (PCI)
- Loss of contracts
- Stock price impact
- Executive turnover

### Criminal Charges

**Possible for:**
- Willful violations
- Obstruction
- False statements
- Executives can be personally liable

## Staying Compliant

### Continuous Monitoring

**Don't wait for audits:**
- Regular vulnerability scans
- Log monitoring
- Access reviews
- Configuration reviews
- Vendor assessments

### Change Management

**Updates can break compliance:**
- Document changes
- Assess impact on security
- Test before deploying
- Update documentation

### Vendor Management

**Third parties are your responsibility:**
- Due diligence before selection
- Contractual requirements
- Regular assessments
- Incident response coordination
- Right to audit

### Keep Current

**Laws and regulations change:**
- Subscribe to updates
- Attend conferences
- Professional associations
- Legal counsel
- Compliance consultants

## Practical Compliance Checklist

**GDPR Compliance:**
- [ ] Data inventory completed
- [ ] Lawful basis identified for processing
- [ ] Privacy notices updated
- [ ] Data subject request procedures
- [ ] Breach notification procedures
- [ ] DPO appointed (if required)
- [ ] Data protection impact assessments
- [ ] Vendor agreements updated
- [ ] Staff training completed
- [ ] Technical and organizational measures

**HIPAA Compliance:**
- [ ] Risk assessment completed
- [ ] Policies and procedures documented
- [ ] Business associate agreements
- [ ] Encryption implemented
- [ ] Access controls
- [ ] Audit logging
- [ ] Training completed
- [ ] Incident response plan
- [ ] Breach notification procedures
- [ ] Physical security measures

**PCI DSS Compliance:**
- [ ] Cardholder data inventory
- [ ] Network segmentation
- [ ] Firewall configuration
- [ ] No default passwords
- [ ] Data encryption
- [ ] Malware protection
- [ ] Secure systems and applications
- [ ] Access control
- [ ] Unique IDs
- [ ] Physical access restrictions
- [ ] Logging and monitoring
- [ ] Security testing
- [ ] Information security policy

## Key Takeaways

**Legal landscape:**
- Criminal laws punish unauthorized access
- Privacy laws protect personal data
- Sector regulations add requirements
- International laws create complexity
- Compliance frameworks provide structure

**Your responsibilities:**
- Know the laws that apply
- Implement required controls
- Document everything
- Train users
- Monitor continuously
- Report incidents properly

**Compliance is not security:**
- Meeting minimum requirements ≠ secure
- Security should exceed compliance
- But compliance is mandatory baseline

**Remember:**
- Ignorance is not a defense
- Personal liability is possible
- Non-compliance is expensive
- Compliance is ongoing, not one-time
- Get legal advice when uncertain

Understanding legal requirements is essential for security professionals. You need to protect your organization legally as well as technically. This knowledge helps you make informed decisions and avoid costly violations.
