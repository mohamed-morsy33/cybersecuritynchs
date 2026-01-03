# VPN Technologies and Implementation

Virtual Private Networks (VPNs) create secure tunnels over untrusted networks. This lesson covers VPN protocols, architectures, and practical implementation for both site-to-site and remote access scenarios.

## VPN Fundamentals

### What VPNs Provide

**Security services:**
- **Confidentiality** - Encryption protects data in transit
- **Integrity** - Detects tampering
- **Authentication** - Verifies identity of endpoints
- **Access Control** - Restricts who can connect

**Use cases:**
- Remote worker access
- Site-to-site connectivity
- Privacy protection
- Bypass geo-restrictions
- Secure public Wi-Fi usage

### VPN Types

**Remote Access VPN:**
- Individual user connects to corporate network
- Client software on user device
- Examples: OpenVPN, WireGuard, Cisco AnyConnect

**Site-to-Site VPN:**
- Connect entire networks together
- Router-to-router connection
- Transparent to end users
- Examples: IPsec tunnels

**SSL/TLS VPN:**
- Browser-based access
- No client software needed
- Limited functionality
- Examples: Cisco SSL VPN, Fortinet

## IPsec VPN

### IPsec Components

**Security Associations (SA):**
- Defines security parameters
- One-way (need two for bidirectional)
- Identified by SPI (Security Parameter Index)

**Protocols:**

**AH (Authentication Header):**
- Provides authentication and integrity
- No encryption
- Protects IP header
- Rarely used alone

**ESP (Encapsulating Security Payload):**
- Provides encryption, authentication, integrity
- Most common
- Doesn't protect outer IP header

**Modes:**

**Transport Mode:**
- Encrypts only payload
- Original IP header preserved
- Used for end-to-end communication
- More efficient

**Tunnel Mode:**
- Encrypts entire IP packet
- New IP header added
- Used for site-to-site VPNs
- More secure

### IPsec Configuration

**Phase 1 (IKE Phase 1) - ISAKMP SA:**

Establishes secure channel for negotiation.

**Main Mode (6 messages):**
```
Initiator → Responder: SA proposal
Responder → Initiator: SA acceptance
Initiator → Responder: Key exchange
Responder → Initiator: Key exchange
Initiator → Responder: Authentication
Responder → Initiator: Authentication
```

**Aggressive Mode (3 messages):**
- Faster but less secure
- Identity sent in clear
- Used when IP address changes

**Phase 1 parameters:**
- Encryption: AES-256, AES-128, 3DES
- Hash: SHA-256, SHA-1, MD5
- Authentication: Pre-shared key, certificates
- DH Group: 2, 5, 14, 15, 16, 19, 20
- Lifetime: 86400 seconds (24 hours)

**Phase 2 (IKE Phase 2) - IPsec SA:**

Negotiates parameters for actual data encryption.

**Quick Mode:**
- Uses Phase 1 channel
- Negotiates IPsec parameters
- Can create multiple Phase 2 SAs

**Phase 2 parameters:**
- Protocol: ESP or AH
- Encryption: AES-256, AES-128
- Authentication: SHA-256, SHA-1
- PFS (Perfect Forward Secrecy): DH group
- Lifetime: 3600 seconds (1 hour)

### StrongSwan IPsec Configuration

**Install StrongSwan:**
```bash
sudo apt update
sudo apt install strongswan strongswan-pki
```

**Generate certificates:**
```bash
# Generate CA key
ipsec pki --gen --type rsa --size 4096 --outform pem > ca.key.pem

# Generate CA certificate
ipsec pki --self --ca --lifetime 3650 \
  --in ca.key.pem --type rsa \
  --dn "CN=VPN CA" \
  --outform pem > ca.cert.pem

# Generate server key
ipsec pki --gen --type rsa --size 4096 --outform pem > server.key.pem

# Generate server certificate
ipsec pki --pub --in server.key.pem --type rsa | \
  ipsec pki --issue --lifetime 1825 \
  --cacert ca.cert.pem --cakey ca.key.pem \
  --dn "CN=vpn.example.com" --san vpn.example.com \
  --flag serverAuth --flag ikeIntermediate \
  --outform pem > server.cert.pem

# Copy to system
sudo cp ca.cert.pem /etc/ipsec.d/cacerts/
sudo cp server.cert.pem /etc/ipsec.d/certs/
sudo cp server.key.pem /etc/ipsec.d/private/
```

**Configure /etc/ipsec.conf:**
```
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    strictcrlpolicy=no
    uniqueids=yes

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    
    # IKE Phase 1
    ike=aes256-sha256-modp2048,aes256-sha1-modp2048!
    
    # IKE Phase 2
    esp=aes256-sha256,aes256-sha1!
    
    # Dead Peer Detection
    dpdaction=clear
    dpddelay=300s
    dpdtimeout=600s
    
    # Server side
    left=%any
    leftid=@vpn.example.com
    leftcert=server.cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    
    # Client side
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    
    # Automatic key renegotiation
    rekey=yes
    ikelifetime=24h
    lifetime=8h
```

**Configure /etc/ipsec.secrets:**
```
: RSA server.key.pem
username : EAP "password"
```

**Enable IP forwarding:**
```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Configure firewall:**
```bash
# Allow IPsec
sudo ufw allow 500/udp
sudo ufw allow 4500/udp

# NAT for VPN clients
sudo iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT
```

**Start service:**
```bash
sudo systemctl restart strongswan-starter
sudo systemctl enable strongswan-starter
```

## OpenVPN

### OpenVPN Architecture

**Advantages:**
- Works over TCP or UDP
- Highly configurable
- Strong encryption
- Cross-platform
- Can traverse NAT easily

**Disadvantages:**
- Slower than WireGuard
- More complex configuration
- Larger codebase

### OpenVPN Server Setup

**Install OpenVPN:**
```bash
sudo apt update
sudo apt install openvpn easy-rsa
```

**Set up PKI:**
```bash
# Copy easy-rsa
make-cadir ~/openvpn-ca
cd ~/openvpn-ca

# Edit vars file
nano vars
# Set KEY_COUNTRY, KEY_PROVINCE, KEY_CITY, KEY_ORG, KEY_EMAIL

# Source vars
source vars

# Clean and build CA
./clean-all
./build-ca

# Generate server certificate
./build-key-server server

# Generate Diffie-Hellman parameters
./build-dh

# Generate HMAC signature
openvpn --genkey --secret keys/ta.key

# Copy keys to OpenVPN directory
sudo cp keys/{ca.crt,server.crt,server.key,dh2048.pem,ta.key} /etc/openvpn/
```

**Configure /etc/openvpn/server.conf:**
```
# Network settings
port 1194
proto udp
dev tun

# Certificates and keys
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem

# Network topology
server 10.8.0.0 255.255.255.0
topology subnet

# Push routes to clients
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

# Client configuration
client-to-client
keepalive 10 120
cipher AES-256-GCM
auth SHA256

# TLS security
tls-auth ta.key 0
tls-version-min 1.2

# Privileges
user nobody
group nogroup

# Persistence
persist-key
persist-tun

# Logging
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3

# Optional: compression
comp-lzo
```

**Enable IP forwarding and NAT:**
```bash
# Enable forwarding
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sudo sysctl -p

# Configure firewall
sudo ufw allow 1194/udp
sudo ufw allow OpenSSH

# NAT for VPN clients
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
```

**Start OpenVPN:**
```bash
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server
```

### OpenVPN Client Configuration

**Generate client certificate:**
```bash
cd ~/openvpn-ca
source vars
./build-key client1
```

**Create client config file (client1.ovpn):**
```
client
dev tun
proto udp
remote vpn.example.com 1194

resolv-retry infinite
nobind

user nobody
group nogroup

persist-key
persist-tun

remote-cert-tls server
cipher AES-256-GCM
auth SHA256

comp-lzo

verb 3

# Inline certificates
<ca>
[paste contents of ca.crt]
</ca>

<cert>
[paste contents of client1.crt]
</cert>

<key>
[paste contents of client1.key]
</key>

<tls-auth>
[paste contents of ta.key]
</tls-auth>
key-direction 1
```

**Connect client:**
```bash
sudo openvpn --config client1.ovpn
```

## WireGuard

### WireGuard Advantages

**Why WireGuard is gaining popularity:**
- Extremely fast (faster than IPsec and OpenVPN)
- Simple configuration
- Modern cryptography (no cipher negotiation)
- Small codebase (~4,000 lines vs OpenVPN's 100,000+)
- Built into Linux kernel (5.6+)
- Cross-platform

**Cryptography:**
- ChaCha20 for encryption
- Poly1305 for authentication
- Curve25519 for key exchange
- BLAKE2s for hashing
- No cipher negotiation - uses best practices only

### WireGuard Server Setup

**Install WireGuard:**
```bash
sudo apt update
sudo apt install wireguard
```

**Generate keys:**
```bash
# Generate server keys
wg genkey | sudo tee /etc/wireguard/server_private.key
sudo chmod 600 /etc/wireguard/server_private.key
sudo cat /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key

# Generate client keys
wg genkey | tee client_private.key
cat client_private.key | wg pubkey > client_public.key
```

**Configure /etc/wireguard/wg0.conf:**
```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = [server_private_key]

# IP forwarding
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client 1
[Peer]
PublicKey = [client1_public_key]
AllowedIPs = 10.0.0.2/32

# Client 2
[Peer]
PublicKey = [client2_public_key]
AllowedIPs = 10.0.0.3/32
```

**Enable IP forwarding:**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

**Open firewall:**
```bash
sudo ufw allow 51820/udp
```

**Start WireGuard:**
```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

### WireGuard Client Configuration

**Client config file (wg0-client.conf):**
```ini
[Interface]
Address = 10.0.0.2/24
PrivateKey = [client_private_key]
DNS = 8.8.8.8

[Peer]
PublicKey = [server_public_key]
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**Connect:**
```bash
sudo wg-quick up wg0-client
```

**Check status:**
```bash
sudo wg show
```

## VPN Performance Optimization

### WireGuard Performance

**Typical throughput:**
- WireGuard: 1000+ Mbps
- OpenVPN: 100-300 Mbps  
- IPsec: 400-600 Mbps

**Optimization tips:**
- Use UDP (not TCP)
- Enable MTU optimization
- Use modern hardware with AES-NI
- Minimize latency to VPN server

### OpenVPN Optimization

**Optimize /etc/openvpn/server.conf:**
```
# Use UDP
proto udp

# Optimize buffer sizes
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"

# Use faster cipher
cipher AES-128-GCM

# Compression (can help or hurt depending on data)
comp-lzo adaptive

# Faster TLS
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256

# Optimize TCP settings
tcp-nodelay
```

## VPN Security Best Practices

### Authentication

**Use strong authentication:**
- Certificate-based (best)
- Multi-factor authentication
- Avoid pre-shared keys for remote access
- Rotate credentials regularly

### Encryption

**Use modern ciphers:**
- AES-256-GCM
- ChaCha20-Poly1305
- Avoid: DES, 3DES, MD5, SHA1

### Access Control

**Implement least privilege:**
- Limit which networks clients can access
- Use split-tunnel when appropriate
- Implement network segmentation
- Log all connections

### Monitoring

**Monitor VPN usage:**
```bash
# OpenVPN status
sudo systemctl status openvpn@server
cat /var/log/openvpn-status.log

# WireGuard status
sudo wg show

# Check connected clients
sudo wg show wg0 peers
```

## Troubleshooting VPNs

### Common Issues

**Cannot connect:**
```bash
# Check service running
sudo systemctl status openvpn@server
sudo systemctl status wg-quick@wg0

# Check firewall
sudo ufw status
sudo iptables -L -n

# Check ports
sudo netstat -tulpn | grep -E '1194|51820'

# Check logs
sudo tail -f /var/log/openvpn.log
sudo journalctl -u wg-quick@wg0 -f
```

**Connected but no internet:**
```bash
# Check IP forwarding
sysctl net.ipv4.ip_forward

# Check NAT rules
sudo iptables -t nat -L -n

# Test DNS
dig @8.8.8.8 google.com

# Check routing
ip route
```

**Slow performance:**
```bash
# Test bandwidth
iperf3 -s  # On server
iperf3 -c vpn_server_ip  # On client

# Check MTU
ping -M do -s 1472 vpn_server_ip  # Find optimal MTU

# Monitor connections
sudo tcpdump -i wg0
```

## Key Takeaways

**VPN protocols:**
- IPsec: Industry standard, complex, good performance
- OpenVPN: Flexible, widely supported, moderate performance
- WireGuard: Modern, simple, best performance

**Implementation:**
- Plan architecture (site-to-site vs remote access)
- Generate proper certificates
- Configure encryption properly
- Enable IP forwarding and NAT
- Test thoroughly

**Security:**
- Use certificate-based authentication
- Modern encryption algorithms
- Implement access controls
- Monitor and log connections
- Regular updates and patches

**Remember:**
- VPNs protect data in transit only
- Still need endpoint security
- Performance varies by protocol
- Proper configuration is critical
- Test failover scenarios

VPNs are fundamental to modern network security. Whether connecting remote workers or linking office locations, understanding VPN technologies lets you implement secure, reliable connectivity for your organization.
