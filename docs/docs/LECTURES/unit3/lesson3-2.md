# Network Devices and Hardware

Networks aren't just cables and wireless signals. They're made up of specialized hardware devices, each with specific functions. Understanding these devices is crucial—they're both security tools and attack targets.

## Network Interface Cards (NICs)

**NICs connect computers to networks.**

### Physical Network Cards

**Wired NIC (Ethernet):**
- RJ-45 connector
- Speeds: 10/100/1000 Mbps (Gigabit), 10 Gbps, 40 Gbps
- Built into motherboard or expansion card
- MAC address burned into hardware

**Wireless NIC (Wi-Fi):**
- Antenna (internal or external)
- Standards: 802.11a/b/g/n/ac/ax (Wi-Fi 6)
- USB adapters, PCIe cards, built-in
- Can operate in monitor mode (packet sniffing)

### MAC Addresses

**MAC (Media Access Control) address:**
- 48-bit hardware address
- Format: `00:1A:2B:3C:4D:5E` (6 pairs of hex)
- First 3 bytes: OUI (Organizationally Unique Identifier) - identifies manufacturer
- Last 3 bytes: Device-specific

**Example:**
```
00:1A:2B → Cisco Systems
3C:4D:5E → Unique device ID
```

**View your MAC address:**
```bash
# Linux
ip link show
ifconfig

# Windows
ipconfig /all

# macOS
ifconfig
```

**Security note:**
- MAC addresses can be spoofed (changed in software)
- Used for tracking devices
- MAC filtering on networks (weak security)

## Hubs (Obsolete)

**Hubs:** Simple repeaters, rarely used today.

### How Hubs Work

1. Receives packet on one port
2. Broadcasts to ALL other ports
3. All devices see all traffic
4. Devices ignore packets not addressed to them

### Problems with Hubs

**Collisions:**
- Only one device can transmit at a time
- If two transmit simultaneously → collision
- Both must wait and retry
- Inefficient as network grows

**Security:**
- Every device sees all traffic
- Easy packet sniffing
- No segmentation

**Hubs are dead.** Replaced by switches.

## Switches

**Switches:** Intelligent devices that forward packets only to intended recipient.

### How Switches Work

**MAC address table (CAM table):**
```
Port  | MAC Address
------|------------------
1     | 00:1A:2B:3C:4D:5E
2     | 11:22:33:44:55:66
3     | AA:BB:CC:DD:EE:FF
```

**Learning process:**
1. Device sends packet
2. Switch sees source MAC and source port
3. Records in MAC table
4. Now knows which port leads to that MAC

**Forwarding:**
1. Packet arrives for destination MAC
2. Switch checks MAC table
3. Forwards only to port where MAC is located
4. Other ports don't see the traffic

**Unknown destinations:**
- If MAC not in table, switch floods (sends to all ports except source)
- Destination responds, switch learns

### Switch Types

**Unmanaged switches:**
- Plug and play
- No configuration
- Limited features
- Home/small office use

**Managed switches:**
- Configurable via CLI or web interface
- VLANs
- Port mirroring
- Quality of Service (QoS)
- Access control lists
- SNMP monitoring
- Enterprise use

**Layer 2 vs Layer 3 switches:**

**Layer 2:** Forward based on MAC addresses (traditional)
**Layer 3:** Also perform routing (IP-based forwarding)
- Combine switch and router functionality
- Faster than traditional routing
- Common in enterprise core networks

### VLANs (Virtual LANs)

**VLANs logically segment a network:**

**Without VLANs:**
- All devices on one switch in same broadcast domain
- Everyone sees broadcasts
- No logical separation

**With VLANs:**
```
Switch with 24 ports:
VLAN 10 (Sales):        Ports 1-8
VLAN 20 (Engineering):  Ports 9-16
VLAN 30 (Guest):        Ports 17-24
```

**Benefits:**
- Security isolation
- Broadcast control
- Logical organization
- Easier management

**Inter-VLAN routing:**
- VLANs can't talk to each other without routing
- Layer 3 switch or router required
- Apply firewall rules between VLANs

**VLAN tagging (802.1Q):**
- Adds VLAN ID to Ethernet frame
- Trunk ports carry multiple VLANs
- Access ports belong to single VLAN

### Switch Security Features

**Port security:**
- Limit which MAC addresses can use a port
- Prevent MAC flooding attacks
- Limit number of MACs per port

**DHCP snooping:**
- Prevents rogue DHCP servers
- Builds trusted database of IP-MAC bindings
- Prevents DHCP starvation attacks

**Dynamic ARP Inspection (DAI):**
- Uses DHCP snooping database
- Validates ARP packets
- Drops ARP packets with mismatched IP-MAC
- Prevents ARP spoofing

**Port mirroring (SPAN):**
- Copy traffic from one port to another
- Used for monitoring/analysis
- Connect IDS/packet analyzer
- Essential security tool

## Routers

**Routers:** Connect different networks, make forwarding decisions based on IP addresses.

### Router Functions

**Routing:**
- Examines destination IP
- Consults routing table
- Forwards to next hop

**NAT (Network Address Translation):**
- Translates private IPs to public IP
- Allows multiple devices to share one public IP
- Adds layer of security (hides internal network)

**Firewall:**
- Filter traffic based on rules
- Stateful packet inspection
- Access control lists (ACLs)

**DHCP:**
- Assigns IP addresses automatically
- Provides subnet mask, gateway, DNS servers

**VPN:**
- Encrypted tunnels
- Remote access
- Site-to-site connections

### Routing Tables

**View routing table:**
```bash
# Linux
ip route show
route -n

# Windows
route print

# Cisco router
show ip route
```

**Example routing table:**
```
Destination      Gateway         Interface
0.0.0.0/0        192.168.1.1     eth0      (default route)
192.168.1.0/24   0.0.0.0         eth0      (directly connected)
10.0.0.0/8       192.168.1.254   eth0      (static route)
```

**Route types:**
- **Connected:** Directly attached networks
- **Static:** Manually configured
- **Dynamic:** Learned via routing protocols (OSPF, BGP, EIGRP)

### Routing Protocols

**Interior Gateway Protocols (within an organization):**

**RIP (Routing Information Protocol):**
- Distance vector (hop count)
- Simple but limited
- Max 15 hops
- Legacy

**OSPF (Open Shortest Path First):**
- Link state protocol
- Considers bandwidth, not just hops
- Fast convergence
- Scalable
- Enterprise standard

**EIGRP (Enhanced Interior Gateway Routing Protocol):**
- Cisco proprietary (mostly)
- Hybrid protocol
- Fast convergence
- Efficient

**Exterior Gateway Protocols (between organizations):**

**BGP (Border Gateway Protocol):**
- How the internet works
- Path vector protocol
- Policy-based routing
- AS (Autonomous System) numbers
- Extremely complex
- Targeted by nation-state attackers

### Router Security

**Best practices:**
- Change default passwords
- Disable unnecessary services
- Keep firmware updated
- Use strong encryption (WPA3 for wireless)
- Enable logging
- Implement ACLs
- Disable remote management (or use VPN)

**Common vulnerabilities:**
- Default credentials
- Outdated firmware
- UPnP (Universal Plug and Play) exploits
- DNS hijacking
- Weak wireless encryption

## Firewalls

**Firewalls:** Specialized security devices that filter traffic based on rules.

### Firewall Types by Deployment

**Network firewalls:**
- Standalone hardware devices
- Protect entire networks
- High throughput
- Expensive

**Host-based firewalls:**
- Software on individual computers
- Windows Firewall, iptables, pf
- Last line of defense
- Per-system configuration

**Cloud firewalls:**
- Security groups (AWS, Azure, GCP)
- Virtual network appliances
- Software-defined

### Firewall Types by Capability

**Packet-filtering firewalls:**
- Layer 3 and 4 (IP, TCP/UDP)
- Simple rules based on:
  - Source/destination IP
  - Source/destination port
  - Protocol
- Fast but limited

**Stateful firewalls:**
- Track connection state
- Understand TCP handshakes
- Allow related traffic
- Prevent spoofed packets
- Industry standard

**Application-layer firewalls:**
- Layer 7 (application content)
- Deep packet inspection
- HTTP filtering (URLs, methods)
- Block specific applications
- More processing overhead

**Next-generation firewalls (NGFW):**
- Integrated IPS
- Application awareness
- SSL/TLS inspection
- Advanced threat protection
- User identity integration
- Cloud integration

### Firewall Rules

**Example ACL (Access Control List):**
```
Rule  Action  Source          Dest            Port    Protocol
1     Allow   192.168.1.0/24  Any             80      TCP
2     Allow   192.168.1.0/24  Any             443     TCP
3     Allow   Any             192.168.1.0/24  Any     TCP  (established)
4     Deny    Any             Any             Any     Any
```

**Rule order matters:** First match wins

**Best practices:**
- Default deny (explicit allow)
- Most specific rules first
- Log denied traffic
- Regular review and cleanup
- Document purpose of each rule

## Wireless Access Points (APs)

**Access Points:** Provide wireless network connectivity.

### AP Modes

**Access Point mode:**
- Bridges wireless and wired networks
- Most common mode
- Connects clients to network

**Repeater mode:**
- Extends wireless range
- Receives and retransmits
- Halves effective bandwidth

**Bridge mode:**
- Connects two wired networks wirelessly
- Point-to-point links
- Building-to-building connections

**Client mode:**
- AP acts as wireless client
- Connects to another AP
- Provides wired ports

### Wi-Fi Standards

**802.11 family:**
```
Standard  Year  Frequency      Max Speed
802.11a   1999  5 GHz         54 Mbps
802.11b   1999  2.4 GHz       11 Mbps
802.11g   2003  2.4 GHz       54 Mbps
802.11n   2009  2.4/5 GHz     600 Mbps
802.11ac  2014  5 GHz         6.9 Gbps (theoretical)
802.11ax  2019  2.4/5 GHz     9.6 Gbps (Wi-Fi 6)
```

**2.4 GHz vs 5 GHz:**
- 2.4 GHz: Longer range, more interference, slower
- 5 GHz: Shorter range, less interference, faster

**Channels:**
- 2.4 GHz: 14 channels (1, 6, 11 non-overlapping in US)
- 5 GHz: More channels, less congestion

### Wireless Security

**Encryption standards:**

**WEP (Wired Equivalent Privacy):**
- **BROKEN** - Do not use!
- Crackable in minutes
- RC4 cipher with weak implementation

**WPA (Wi-Fi Protected Access):**
- Better than WEP
- TKIP encryption
- Still vulnerable
- Legacy compatibility

**WPA2:**
- Current standard (until WPA3 adoption)
- AES encryption
- Much more secure
- KRACK vulnerability (patched)

**WPA3:**
- Latest standard (2018)
- Stronger encryption
- Forward secrecy
- Protection against brute force
- Still being adopted

**Enterprise vs Personal:**
- **Personal (PSK):** Shared password for everyone
- **Enterprise (802.1X):** Individual authentication via RADIUS server

**Hidden SSIDs:**
- SSID not broadcast
- Security through obscurity
- **Not effective security**
- Easily discovered

**MAC filtering:**
- Whitelist/blacklist MAC addresses
- **Weak security** (MACs easily spoofed)
- Management overhead

## Load Balancers

**Load balancers:** Distribute traffic across multiple servers.

### Why Load Balance?

**Benefits:**
- High availability (server failure tolerance)
- Scalability (add more servers)
- Performance (distribute load)
- Maintenance (take servers offline without downtime)

### Load Balancing Algorithms

**Round robin:**
- Server 1, Server 2, Server 3, Server 1, Server 2...
- Simple and fair
- Doesn't consider server load

**Least connections:**
- Send to server with fewest active connections
- Better for varied session lengths

**IP hash:**
- Hash client IP to determine server
- Same client always goes to same server
- Useful for session persistence

**Weighted:**
- Assign weights to servers
- More powerful servers get more traffic

### Layer 4 vs Layer 7 Load Balancing

**Layer 4 (Transport):**
- Decisions based on IP and port
- Fast (less inspection)
- No application awareness
- TCP/UDP load balancing

**Layer 7 (Application):**
- Decisions based on HTTP content
- URL-based routing
- Cookie-based persistence
- SSL termination
- More processing overhead
- Application-aware decisions

## Proxies

**Proxies:** Intermediary servers between clients and destinations.

### Forward Proxies

**Client → Proxy → Internet**

**Use cases:**
- Content filtering (block websites)
- Caching (speed up repeat requests)
- Anonymity (hide client IP)
- Bypass geo-restrictions

**Example: Squid proxy**
```bash
# Install
sudo apt install squid

# Configure
sudo nano /etc/squid/squid.conf

# Access control
acl localnet src 192.168.1.0/24
http_access allow localnet
```

### Reverse Proxies

**Internet → Proxy → Internal Servers**

**Use cases:**
- Load balancing
- SSL termination (decrypt at proxy)
- Caching
- Security (hide internal servers)
- WAF (Web Application Firewall)

**Example: Nginx as reverse proxy**
```nginx
server {
    listen 80;
    server_name example.com;
    
    location / {
        proxy_pass http://backend:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Transparent Proxies

**Client unaware of proxy:**
- Network device redirects traffic
- No client configuration
- Used for forced filtering
- Controversial (privacy concerns)

## Intrusion Detection/Prevention Systems

**IDS/IPS hardware appliances:**

**Network-based (NIDS/NIPS):**
- Monitor network traffic
- Detect/block attacks
- Signature and anomaly-based
- Tap into network (IDS) or inline (IPS)

**Popular solutions:**
- Snort (open source)
- Suricata (open source)
- Cisco Firepower
- Palo Alto Networks

**Placement:**
- Perimeter (internet connection)
- Between network segments
- DMZ monitoring
- Critical server protection

## Network Taps and SPAN Ports

### Network Taps

**Physical devices that copy traffic:**
- Passive (no impact on network)
- Copy all packets
- Used for monitoring/security analysis
- Expensive but reliable

**Types:**
- Copper taps (Ethernet)
- Fiber taps
- Aggregation taps (multiple links → one analyzer)

### SPAN Ports (Port Mirroring)

**Switch feature:**
- Copy traffic from one or more ports
- Send copies to monitoring port
- Free (switch feature)
- Can impact switch performance

**Configuration example (Cisco):**
```
monitor session 1 source interface Gi1/0/1
monitor session 1 destination interface Gi1/0/24
```

## Network Attached Storage (NAS)

**File-level storage over network:**

**Protocols:**
- NFS (Network File System) - Unix/Linux
- SMB/CIFS (Server Message Block) - Windows
- AFP (Apple Filing Protocol) - macOS

**Use cases:**
- Centralized file storage
- Backups
- Media storage
- Log aggregation

**Security concerns:**
- Network exposure
- Authentication
- Encryption (often lacking)
- Ransomware target

## Key Takeaways

**Switches:**
- Forward based on MAC addresses
- VLANs for segmentation
- Security features (port security, ARP inspection)

**Routers:**
- Connect networks
- Forward based on IP addresses
- NAT, DHCP, firewall functionality

**Firewalls:**
- Control traffic flow
- Stateful inspection
- NGFWs offer advanced features

**Wireless APs:**
- Extend network wirelessly
- Security crucial (WPA2/WPA3)
- Channel management important

**Load balancers:**
- Distribute traffic
- High availability
- Layer 4 or Layer 7

**Each device:**
- Security tool
- Potential attack target
- Requires hardening
- Needs monitoring

Understanding network hardware helps you:
- Design secure networks
- Identify attack vectors
- Troubleshoot issues
- Select appropriate tools

In the next lessons, we'll see how these devices work together in real network architectures and how attackers target them.
