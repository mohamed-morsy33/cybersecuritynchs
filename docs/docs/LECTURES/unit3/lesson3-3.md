# Network Design and Architecture

Understanding individual network components isn't enough. You need to know how they fit together to create secure, efficient networks. This lesson covers network design principles and common architectures you'll encounter.

## Network Design Principles

### Defense in Depth

**Multiple layers of security:**
```
Internet
  ↓
Border Firewall (Perimeter)
  ↓
DMZ (Public servers)
  ↓
Internal Firewall
  ↓
Core Network
  ├─ VLANs (Segmentation)
  ├─ IDS/IPS (Detection)
  ├─ Access Controls (Authorization)
  └─ Encryption (Confidentiality)
```

**No single point of failure** for security.

### Segmentation

**Divide network into zones based on:**
- Security requirements
- Function
- Data sensitivity
- Trust level

**Benefits:**
- Contain breaches
- Reduce attack surface
- Apply different security policies
- Improve performance

### Redundancy

**Eliminate single points of failure:**
- Multiple internet connections
- Redundant switches/routers
- Multiple power supplies
- Backup systems
- Geographic diversity

**High availability = uptime**

### Scalability

**Design for growth:**
- Add capacity without redesign
- Modular architecture
- Room for expansion
- Future-proof technology choices

## Common Network Architectures

### Three-Tier Architecture

**Traditional enterprise design:**

```
┌─────────────────┐
│   Core Layer    │  High-speed backbone
│   (Switches)    │  Connects distribution layers
└────────┬────────┘  No packet manipulation
         │
┌────────┴────────┐
│ Distribution    │  Policy enforcement
│    Layer        │  VLANs, ACLs, routing
└────────┬────────┘  Aggregation point
         │
┌────────┴────────┐
│  Access Layer   │  End-user connections
│   (Switches)    │  Port security
└─────────────────┘  PoE for phones, APs
```

**Core layer:**
- Purpose: Fast packet switching
- Devices: High-performance Layer 3 switches
- Features: Redundancy, high bandwidth
- Minimal processing (routing only)

**Distribution layer:**
- Purpose: Policy enforcement, routing
- Devices: Layer 3 switches, routers
- Features: VLANs, ACLs, firewalls
- Connect access to core

**Access layer:**
- Purpose: End-device connections
- Devices: Layer 2 switches
- Features: PoE, port security, VLANs
- Desktops, printers, phones, APs

**Advantages:**
- Clear hierarchy
- Scalable
- Maintainable
- Predictable performance

**Disadvantages:**
- Can be overbuilt for small networks
- More equipment = more cost
- Complexity

### Two-Tier (Collapsed Core)

**Simplified for smaller networks:**

```
┌─────────────────┐
│ Core/Distribution│ Combined layer
│     Layer       │ Routing + policy
└────────┬────────┘
         │
┌────────┴────────┐
│  Access Layer   │ End-user connections
└─────────────────┘
```

**When to use:**
- Smaller organizations
- Limited budget
- Fewer users (<500)
- Less complex requirements

### Spine-Leaf Architecture

**Modern data center design:**

```
      Spine1    Spine2    Spine3
        │         │         │
     ┌──┴────┬────┴────┬────┴───┐
     │       │         │        │
   Leaf1   Leaf2    Leaf3    Leaf4
     │       │         │        │
  Servers Servers  Servers  Servers
```

**Characteristics:**
- Every leaf connects to every spine
- Two hops between any servers
- Predictable latency
- Easy to scale (add leaf switches)
- No spanning tree needed

**Advantages:**
- Low latency
- High bandwidth
- Scalability
- Redundancy

**Use cases:**
- Data centers
- Cloud providers
- High-performance computing

### Hub and Spoke (Star)

**Central site with remote locations:**

```
      HQ (Hub)
     /  |  \
    /   |   \
Branch Branch Branch
 (Spoke)(Spoke)(Spoke)
```

**Characteristics:**
- All traffic goes through hub
- Spokes don't connect directly
- Centralized management/security
- VPN connections

**Advantages:**
- Centralized control
- Easier security management
- Simplified monitoring

**Disadvantages:**
- Hub is single point of failure
- Bandwidth bottleneck at hub
- Spoke-to-spoke requires two hops

### Full Mesh

**Every site connects to every other site:**

```
  Site A ─── Site B
   │  \      / │
   │   \    /  │
   │    \  /   │
  Site C ─── Site D
```

**Advantages:**
- No single point of failure
- Direct paths (low latency)
- Load distribution

**Disadvantages:**
- Expensive (many connections)
- Complex management
- Scales poorly (n×(n-1)/2 connections)

**Use cases:**
- Critical systems
- Financial trading
- When budget allows

### Partial Mesh

**Compromise between hub-spoke and full mesh:**
- Critical sites: full mesh
- Less critical: hub-and-spoke
- Best of both worlds

## Network Zones

### DMZ (Demilitarized Zone)

**Purpose:** Host public-facing services

**Design:**
```
Internet
   ↓
Firewall 1 (External)
   ↓
  DMZ
  ├─ Web servers
  ├─ Email servers
  ├─ DNS servers
  └─ FTP servers
   ↓
Firewall 2 (Internal)
   ↓
Internal Network
```

**Rules:**
- Internet → DMZ: Limited access (HTTP, HTTPS, SMTP)
- DMZ → Internal: Very restricted (database queries only)
- Internal → DMZ: Manage servers
- Internal → Internet: Through firewall

**Security benefits:**
- Public servers isolated
- Breach contained to DMZ
- Internal network protected
- Two firewalls provide defense in depth

### Internal Network

**Corporate network for employees:**

**Segmentation by:**
- Department (Sales, Engineering, HR)
- Function (User workstations, Printers, VoIP)
- Security level (Standard, Restricted, Confidential)

**Example VLANs:**
```
VLAN 10: Users (192.168.10.0/24)
VLAN 20: Servers (192.168.20.0/24)
VLAN 30: Management (192.168.30.0/24)
VLAN 40: Guest (192.168.40.0/24)
VLAN 50: VoIP (192.168.50.0/24)
```

### Management Network

**Separate network for device management:**

**Out-of-band management:**
- Dedicated network
- Physical separation
- Even if production network fails
- Accessible via console servers

**Devices managed:**
- Switches
- Routers
- Firewalls
- Servers (IPMI, iLO, iDRAC)

**Security:**
- Extremely restricted access
- VPN required
- MFA mandatory
- All actions logged

### Guest Network

**Visitors and untrusted devices:**

**Characteristics:**
- Isolated from internal network
- Internet access only
- Captive portal (login page)
- Bandwidth limits
- Time limits
- Content filtering

**Security:**
- No access to internal resources
- Separate VLAN
- Separate IP range
- Strict firewall rules

**Implementation:**
```
Guest VLAN 40
   ↓
Firewall rules:
  Allow: Internet (HTTP, HTTPS)
  Deny: Internal networks
  Deny: Private IP ranges
```

## Wireless Network Design

### Site Survey

**Before deploying wireless:**

**Physical survey:**
- Building layout
- Construction materials (affect signal)
- Sources of interference
- Coverage requirements
- Capacity requirements

**RF survey:**
- Measure signal strength
- Identify dead zones
- Find interference sources
- Optimize channel selection
- Determine AP placement

**Tools:**
- Ekahau
- NetSpot
- AirMagnet
- inSSIDer

### Controller vs. Autonomous APs

**Controller-based (Enterprise):**
- Central wireless controller
- Manages multiple APs
- Centralized configuration
- Roaming support
- Guest portal
- Scalable

**Autonomous APs (Standalone):**
- Each AP configured independently
- No controller needed
- Simpler (small deployments)
- Lower cost

### Wireless Security Architecture

**SSID strategy:**
```
Corporate SSID
  ├─ WPA2-Enterprise (802.1X)
  ├─ Corporate VLAN
  └─ Access to internal resources

Guest SSID
  ├─ WPA2-PSK or open with captive portal
  ├─ Guest VLAN
  └─ Internet only
```

**Best practices:**
- Separate SSIDs for different purposes
- Unique VLANs per SSID
- Enterprise authentication for employees
- Guest isolation
- Regular security audits

## Cloud Network Architecture

### Hybrid Cloud

**Combination of on-premises and cloud:**

```
On-Premises Data Center
        ↓
     VPN/Direct Connect
        ↓
   Cloud (AWS/Azure/GCP)
```

**Use cases:**
- Gradual migration
- Burst capacity
- Disaster recovery
- Data sovereignty requirements

### Multi-Cloud

**Multiple cloud providers:**
- Avoid vendor lock-in
- Leverage best features of each
- Geographic distribution
- Redundancy

**Challenges:**
- Complex management
- Security consistency
- Cost tracking
- Network connectivity

### Cloud Network Components

**VPC (Virtual Private Cloud):**
- Logically isolated network
- Define IP range
- Subnets (public/private)
- Route tables
- Internet/NAT gateways

**Security Groups:**
- Virtual firewalls
- Instance-level
- Stateful
- Allow rules only

**Network ACLs:**
- Subnet-level
- Stateless
- Allow and deny rules

**VPC Peering:**
- Connect VPCs
- Private connectivity
- No internet gateway

**Transit Gateway:**
- Central hub for VPC connectivity
- Simplify complex networks

## Zero Trust Architecture

**Never trust, always verify:**

### Traditional Perimeter Model

```
Internet (Untrusted)
      ↓
   Firewall
      ↓
Internal Network (Trusted)
```

**Problem:** Assumes internal = safe

### Zero Trust Model

```
   Every Request
        ↓
   Authenticate
        ↓
    Authorize
        ↓
    Encrypt
        ↓
   Continuous Verification
```

**Principles:**
1. **Verify explicitly:** Always authenticate and authorize
2. **Least privilege:** Minimum necessary access
3. **Assume breach:** Limit blast radius

### Implementation

**Micro-segmentation:**
- Granular network zones
- Per-application firewalls
- Workload-specific policies

**Identity-based access:**
- User and device identity
- Continuous authentication
- Context-aware (location, time, device posture)

**Software-defined perimeter:**
- Application-level access
- Hide infrastructure
- Only authorized users see resources

**Components:**
- Identity provider (Azure AD, Okta)
- Access proxy
- Policy engine
- Endpoint verification
- Encryption everywhere

## Network Documentation

**Critical for security and operations:**

### Physical Diagrams

**Rack layouts:**
- Equipment placement
- Cable management
- Power distribution
- Cooling

**Site diagrams:**
- Building locations
- Equipment rooms
- Cable paths
- Access points

### Logical Diagrams

**Network topology:**
- Devices and connections
- IP addressing
- VLANs
- Routing

**Security zones:**
- Trust boundaries
- Firewall placement
- DMZ layout
- Access controls

### Configuration Documentation

**IP addressing scheme:**
```
10.0.0.0/8 - Corporate
  10.1.0.0/16 - HQ
    10.1.10.0/24 - Servers
    10.1.20.0/24 - Users
    10.1.30.0/24 - Printers
  10.2.0.0/16 - Branch 1
  10.3.0.0/16 - Branch 2
```

**VLAN assignments:**
- VLAN numbers and names
- IP ranges
- Purpose
- Security requirements

**Firewall rules:**
- Rule number
- Source/destination
- Action
- Purpose
- Date created
- Owner

### Change Management

**Document all changes:**
- What changed
- Why it changed
- Who approved
- When it changed
- Rollback plan

**Version control:**
- Configuration backups
- Before/after states
- Change history

## Network Monitoring and Management

### SNMP (Simple Network Management Protocol)

**Monitor device health:**
- CPU usage
- Memory usage
- Interface statistics
- Temperature
- Fan status

**SNMP versions:**
- v1: Basic, no security
- v2c: Better but still no encryption
- v3: Encrypted, authenticated (use this!)

### NetFlow/sFlow

**Traffic analysis:**
- Who's talking to whom
- How much bandwidth used
- Application identification
- Anomaly detection

**Use cases:**
- Capacity planning
- Security monitoring
- Troubleshooting
- Billing

### Syslog

**Centralized logging:**
- Collect logs from all devices
- Correlation
- Long-term retention
- Compliance

**Syslog server:**
- Receive logs
- Parse and index
- Alert on patterns
- Reporting

**Log sources:**
- Routers, switches
- Firewalls
- Servers
- Applications
- Security devices

## Disaster Recovery and Business Continuity

### Redundant Connections

**Multiple internet providers:**
- Different providers
- Different paths
- Automatic failover
- BGP for redundancy

### Geographic Diversity

**Separate locations:**
- Data replication
- Disaster recovery site
- Different power grids
- Different network providers

### Recovery Time Objective (RTO)

**How long can you be down?**
- Critical systems: minutes
- Important systems: hours
- Non-critical: days

**Design accordingly:**
- Hot standby (instant failover)
- Warm standby (quick startup)
- Cold standby (restore from backup)

### Recovery Point Objective (RPO)

**How much data loss is acceptable?**
- Real-time replication (RPO = 0)
- Frequent backups (RPO = minutes/hours)
- Daily backups (RPO = 24 hours)

## Common Design Mistakes

**Flat networks:**
- No segmentation
- Broadcast storms
- Security nightmare

**Over-complexity:**
- Too many layers
- Difficult to troubleshoot
- Management overhead

**Under-provisioning:**
- Insufficient bandwidth
- No growth room
- Performance issues

**No redundancy:**
- Single points of failure
- Network goes down = business stops

**Poor documentation:**
- Can't troubleshoot effectively
- Dangerous changes
- Knowledge loss when people leave

**Ignoring security:**
- Security as afterthought
- No defense in depth
- Vulnerable to attacks

## Key Takeaways

**Good network design:**
- Segmentation for security
- Redundancy for availability
- Scalability for growth
- Documentation for management
- Monitoring for visibility

**Security integrated:**
- Multiple layers (defense in depth)
- Least privilege access
- Zero trust principles
- Continuous monitoring

**No one-size-fits-all:**
- Match design to requirements
- Consider budget
- Plan for growth
- Regular review and updates

Understanding network architecture helps you:
- Design secure networks
- Identify security gaps
- Plan defenses effectively
- Troubleshoot issues
- Communicate with network teams

In the next units, we'll apply these concepts to real-world security scenarios and see how attackers exploit architectural weaknesses.
