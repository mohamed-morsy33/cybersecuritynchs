# Computer Networks: A Deep Dive

Now that you understand what the internet is at a high level, let's zoom in and examine how computer networks actually function. This is where things get technical, but also where you'll start to see how security vulnerabilities emerge.

## What is a Network?

A **computer network** is simply two or more devices connected together to share resources and communicate. That's it. Your home setup with a laptop, phone, and printer connected to a router? That's a network. A corporation with thousands of computers across multiple buildings? Also a network, just bigger and more complex.

Networks exist at different scales:
- **PAN (Personal Area Network)**: Your personal devices, like your phone and wireless earbuds
- **LAN (Local Area Network)**: Devices in a home, office, or building
- **MAN (Metropolitan Area Network)**: Networks spanning a city
- **WAN (Wide Area Network)**: Networks spanning large geographic areas (the internet is the largest WAN)

## Network Topologies

The **topology** of a network refers to how devices are arranged and connected. Each topology has different security implications:

### Bus Topology
All devices connect to a single cable (the "bus"). Data travels along the bus until it reaches its destination. This is rare today because:
- If the bus cable fails, the entire network goes down
- All traffic is visible to all devices (major security problem)
- Performance degrades as more devices connect

### Star Topology
All devices connect to a central hub or switch. This is the most common topology in modern networks. Your home router is the center of a star topology.
- If one connection fails, only that device is affected
- Easier to manage and troubleshoot
- The central device is a single point of failure
- Better security than bus because traffic can be isolated

### Ring Topology
Devices are connected in a circle. Data travels around the ring in one direction. Used in some specialized networks.
- If one device fails, it can break the whole network (unless it's a dual ring)
- Predictable performance
- Data passes through multiple devices (security concern)

### Mesh Topology
Every device connects to every other device. Highly redundant and reliable. Used in critical infrastructure and some wireless networks.
- Extremely reliable—multiple paths for data
- Expensive and complex to implement
- Common in military and critical systems
- Redundancy helps security, but more connections mean more potential vulnerabilities

In reality, most networks use **hybrid topologies**—combinations of these basic types depending on needs and scale.

## The OSI Model: The Foundation

The **OSI (Open Systems Interconnection) Model** is a conceptual framework that describes how data moves through a network. It has seven layers, each with specific responsibilities. Understanding this is crucial for cybersecurity because attacks can target any layer.

### Layer 7: Application Layer
This is what you interact with—web browsers, email clients, file transfer applications. 
- **Protocols**: HTTP, HTTPS, FTP, SMTP, DNS
- **Security concerns**: SQL injection, cross-site scripting (XSS), application-level attacks
- **Example**: When you visit a website, this layer handles the request

### Layer 6: Presentation Layer
Handles data formatting, encryption, and compression. It ensures data from one system can be read by another.
- **Protocols**: SSL/TLS, JPEG, GIF, MPEG
- **Security concerns**: Encryption weaknesses, data encoding attacks
- **Example**: When HTTPS encrypts your password before sending it

### Layer 5: Session Layer
Manages sessions between applications—establishing, maintaining, and terminating connections.
- **Protocols**: NetBIOS, RPC, PPTP
- **Security concerns**: Session hijacking, man-in-the-middle attacks
- **Example**: Keeping you logged into a website as you navigate between pages

### Layer 4: Transport Layer
Ensures complete data transfer with error checking and flow control. This is where TCP and UDP operate.
- **Protocols**: TCP, UDP
- **Security concerns**: Port scanning, TCP SYN floods, DoS attacks
- **Example**: Breaking your file download into packets and ensuring they all arrive

### Layer 3: Network Layer
Handles routing and forwarding of data packets between networks. This is where IP addressing happens.
- **Protocols**: IP, ICMP, IPsec
- **Security concerns**: IP spoofing, routing attacks, ICMP flooding
- **Example**: Determining the path your data takes from your house to a server across the country

### Layer 2: Data Link Layer
Handles communication between adjacent network nodes. Deals with MAC addresses and switches.
- **Protocols**: Ethernet, Wi-Fi (802.11), PPP
- **Security concerns**: MAC spoofing, ARP poisoning, VLAN hopping
- **Example**: Your computer communicating with your router

### Layer 1: Physical Layer
The actual physical medium—cables, radio waves, fiber optics. Raw transmission of bits.
- **Components**: Cables, hubs, repeaters, network adapters
- **Security concerns**: Physical tapping, electromagnetic interference, cable cutting
- **Example**: The actual electrical signals on an Ethernet cable

## Why the OSI Model Matters for Security

Here's the critical insight: **attacks can happen at any layer**, and defenses must exist at every layer. 

If you only secure Layer 7 (application) but ignore Layer 2 (data link), an attacker could compromise your network through ARP poisoning. If you secure everything but forget about Layer 1 (physical), someone could literally tap into your cables.

When analyzing security incidents, you'll often need to trace through these layers to find where the attack occurred and how it succeeded.

## TCP/IP Model: The Practical Version

While the OSI model is conceptual, the **TCP/IP model** is what actually runs the internet. It has four layers that map roughly to the OSI model:

1. **Application Layer** (combines OSI layers 5-7): HTTP, FTP, DNS, SMTP
2. **Transport Layer** (OSI layer 4): TCP, UDP
3. **Internet Layer** (OSI layer 3): IP, ICMP, ARP
4. **Network Access Layer** (combines OSI layers 1-2): Ethernet, Wi-Fi

You'll see both models referenced in cybersecurity. The OSI model is better for understanding and teaching, while TCP/IP is better for practical implementation.

## Switching vs. Routing

Two fundamental concepts in networking:

### Switching (Layer 2)
**Switches** connect devices within the same network. They use **MAC addresses** to forward data to the correct device. 
- MAC addresses are hardware addresses burned into network cards
- Switches learn which MAC addresses are on which ports
- Creates separate collision domains (better performance)
- All devices on a switch can potentially see each other's traffic (security concern)

### Routing (Layer 3)
**Routers** connect different networks together. They use **IP addresses** to forward packets between networks.
- Make decisions about the best path for data
- Connect your home network to your ISP and ultimately the internet
- Implement Network Address Translation (NAT)
- Can filter traffic based on rules (basic firewall functionality)

In cybersecurity, you need to understand both because attacks might exploit switching (like ARP poisoning) or routing (like BGP hijacking).

## Network Addressing

Let's talk more about how devices are identified on networks:

### MAC Addresses
- **Format**: `00:1A:2B:3C:4D:5E` (six pairs of hexadecimal digits)
- **Scope**: Only relevant on the local network
- **Purpose**: Hardware identification
- **Security note**: Can be spoofed (changed in software), used for tracking devices

### IP Addresses (IPv4)
- **Format**: `192.168.1.100` (four octets, 0-255)
- **Public vs. Private**: Some ranges are reserved for private networks
  - `10.0.0.0` to `10.255.255.255`
  - `172.16.0.0` to `172.31.255.255`
  - `192.168.0.0` to `192.168.255.255`
- **Purpose**: Identifying devices across networks
- **Security note**: Can be spoofed, reveal geographic location

### Ports
- **Range**: 0-65535
- **Purpose**: Identify specific services or applications on a device
- **Well-known ports**: 
  - 80: HTTP
  - 443: HTTPS
  - 22: SSH
  - 21: FTP
  - 25: SMTP
- **Security note**: Open ports are attack vectors; port scanning is a reconnaissance technique

## Subnetting: Dividing Networks

**Subnetting** is the practice of dividing a network into smaller sub-networks. This improves performance and security by isolating traffic.

A **subnet mask** determines which part of an IP address is the network portion and which is the host portion.
- Example: `255.255.255.0` means the first three octets identify the network, the last octet identifies individual hosts
- CIDR notation: `192.168.1.0/24` means the same thing (24 bits for network, 8 bits for hosts)

Why this matters for security:
- You can isolate sensitive systems on separate subnets
- Apply different security policies to different subnets
- Limit lateral movement in case of a breach
- Implement network segmentation

## Protocols in Detail

Let's examine some key protocols you'll encounter:

### TCP (Transmission Control Protocol)
- **Connection-oriented**: Establishes a connection before sending data
- **Reliable**: Ensures all packets arrive and are in order
- **Three-way handshake**: SYN → SYN-ACK → ACK
- **Use cases**: Web browsing, email, file transfers
- **Security implications**: Can be exploited (SYN floods), but reliability helps prevent data corruption

### UDP (User Datagram Protocol)
- **Connectionless**: Just sends data without establishing a connection
- **Unreliable**: No guarantee packets arrive or are in order
- **Faster**: Less overhead than TCP
- **Use cases**: Video streaming, online gaming, DNS queries
- **Security implications**: Can be used for amplification attacks, harder to filter

### ICMP (Internet Control Message Protocol)
- **Purpose**: Error messages and network diagnostics
- **Tools**: Ping and traceroute use ICMP
- **Security implications**: Can be used for reconnaissance, covert channels, DDoS attacks (ping floods)

### ARP (Address Resolution Protocol)
- **Purpose**: Maps IP addresses to MAC addresses on local networks
- **How it works**: Broadcasts "Who has IP 192.168.1.1?" and the device with that IP responds with its MAC address
- **Security implications**: Easily exploited for man-in-the-middle attacks (ARP spoofing/poisoning)

## Network Security Basics

Every network needs security controls:

### Firewalls
Filter traffic based on rules—which IPs, ports, and protocols are allowed or blocked. Can operate at different layers.

### VLANs (Virtual LANs)
Logically segment a network even if devices are physically on the same switch. Improves security and performance.

### NAT (Network Address Translation)
Allows multiple devices to share a single public IP address. Provides a basic security layer by hiding internal network structure.

### Access Control Lists (ACLs)
Rules that permit or deny traffic based on various criteria. Used in routers and firewalls.

## Wireless Networks

Wi-Fi adds another dimension to network security:
- **Broadcasting**: Wireless networks advertise their presence
- **Range**: Signals extend beyond physical buildings
- **Encryption**: WPA3 is current standard, older WEP and WPA are broken
- **Attacks**: Evil twin access points, packet sniffing, de-authentication attacks

We'll cover wireless security in much more depth later, but remember that anything transmitted over the air can potentially be intercepted.

## What's Next?

In the following units, we'll build on this foundation:
- Apply these concepts to real-world security scenarios
- Learn to analyze network traffic and identify anomalies
- Study specific attacks that exploit network protocols
- Implement defenses at different network layers

Understanding networks is fundamental to cybersecurity. Most attacks travel over networks, most data breaches involve network exploitation, and most defenses involve network controls.

The key insight: **networks are complex systems with many moving parts, and each part is a potential security concern**. But with understanding comes the ability to secure them effectively.
