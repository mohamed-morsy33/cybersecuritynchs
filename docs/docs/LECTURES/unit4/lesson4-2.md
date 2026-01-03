# Implementing Network Security Controls

Theory is one thing—implementation is another. This lesson focuses on actually setting up and configuring security controls. These are hands-on skills you'll use daily as a security professional.

## Configuring Firewalls

### Linux iptables

**iptables** is the traditional Linux firewall.

#### Basic Concepts

**Tables:**
- **filter**: Default, for packet filtering
- **nat**: Network address translation
- **mangle**: Packet alteration
- **raw**: Connection tracking exemptions

**Chains:**
- **INPUT**: Packets destined for this system
- **OUTPUT**: Packets originating from this system
- **FORWARD**: Packets passing through this system

**Targets:**
- **ACCEPT**: Allow the packet
- **DROP**: Silently discard
- **REJECT**: Discard and send error
- **LOG**: Log the packet

#### Common iptables Commands

```bash
# View current rules
sudo iptables -L -v -n

# View with line numbers
sudo iptables -L --line-numbers

# Flush all rules (dangerous!)
sudo iptables -F

# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT
```

#### Building a Basic Firewall

```bash
# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP and HTTPS
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow ping
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# Log and drop everything else
sudo iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "
sudo iptables -A INPUT -j DROP
```

#### Rate Limiting (Anti-DDoS)

```bash
# Limit SSH connections
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP

# Limit ping
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
```

#### Port Knocking

**Hidden SSH access:**

```bash
# Close SSH by default
sudo iptables -A INPUT -p tcp --dport 22 -j DROP

# Knock sequence: 7000, 8000, 9000
sudo iptables -A INPUT -p tcp --dport 7000 -m recent --name SSH0 --set -j DROP
sudo iptables -A INPUT -p tcp --dport 8000 -m recent --name SSH0 --rcheck -m recent --name SSH1 --set -j DROP
sudo iptables -A INPUT -p tcp --dport 9000 -m recent --name SSH1 --rcheck -m recent --name SSH2 --set -j DROP
sudo iptables -A INPUT -p tcp --dport 22 -m recent --name SSH2 --rcheck -j ACCEPT
```

#### Saving Rules

```bash
# Debian/Ubuntu
sudo iptables-save > /etc/iptables/rules.v4
sudo ip6tables-save > /etc/iptables/rules.v6

# Or use iptables-persistent
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### UFW (Uncomplicated Firewall)

**Easier iptables frontend:**

#### Basic UFW Usage

```bash
# Enable UFW
sudo ufw enable

# Check status
sudo ufw status verbose

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow services
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow from specific IP
sudo ufw allow from 192.168.1.100

# Allow specific IP to specific port
sudo ufw allow from 192.168.1.100 to any port 22

# Deny port
sudo ufw deny 23

# Delete rule
sudo ufw delete allow 80

# Reset all rules
sudo ufw reset
```

#### Application Profiles

```bash
# List application profiles
sudo ufw app list

# Allow application
sudo ufw allow 'Apache Full'
sudo ufw allow 'OpenSSH'

# View application info
sudo ufw app info 'Apache Full'
```

#### Rate Limiting

```bash
# Limit SSH connections (6 connections in 30 seconds)
sudo ufw limit ssh
```

## Setting Up VPNs

### OpenVPN Server

#### Installation

```bash
# Install OpenVPN and Easy-RSA
sudo apt install openvpn easy-rsa

# Set up CA directory
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
```

#### Configure PKI

```bash
# Edit vars file
nano vars

# Set these:
export KEY_COUNTRY="US"
export KEY_PROVINCE="CA"
export KEY_CITY="SanFrancisco"
export KEY_ORG="MyOrg"
export KEY_EMAIL="admin@myorg.com"
export KEY_OU="MyOrgUnit"

# Source vars
source vars

# Clean and build CA
./clean-all
./build-ca
```

#### Generate Certificates

```bash
# Server certificate
./build-key-server server

# Client certificate
./build-key client1

# Diffie-Hellman parameters
./build-dh

# HMAC signature
openvpn --genkey --secret keys/ta.key
```

#### Server Configuration

```bash
# Create server config
sudo nano /etc/openvpn/server.conf
```

```
port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
tls-auth ta.key 0

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

keepalive 10 120
cipher AES-256-CBC
auth SHA256
user nobody
group nogroup
persist-key
persist-tun

status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
```

#### Enable IP Forwarding

```bash
# Temporarily
sudo sysctl -w net.ipv4.ip_forward=1

# Permanently
sudo nano /etc/sysctl.conf
# Uncomment: net.ipv4.ip_forward=1
sudo sysctl -p
```

#### NAT for VPN Clients

```bash
# Add iptables NAT rule
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

# Save rule
sudo netfilter-persistent save
```

#### Start OpenVPN

```bash
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server
```

#### Client Configuration

```
client
dev tun
proto udp
remote vpn-server.com 1194

resolv-retry infinite
nobind
persist-key
persist-tun

ca ca.crt
cert client1.crt
key client1.key
tls-auth ta.key 1

cipher AES-256-CBC
auth SHA256

verb 3
```

### WireGuard (Modern Alternative)

#### Installation

```bash
sudo apt install wireguard
```

#### Generate Keys

```bash
# Server keys
wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey

# Client keys (do this on client)
wg genkey | tee privatekey | wg pubkey > publickey
```

#### Server Configuration

```bash
sudo nano /etc/wireguard/wg0.conf
```

```
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <server-private-key>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
```

#### Start WireGuard

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

#### Client Configuration

```
[Interface]
PrivateKey = <client-private-key>
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn-server.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

## Intrusion Detection Systems

### Snort Installation and Configuration

#### Install Snort

```bash
sudo apt install snort
```

#### Configuration

```bash
sudo nano /etc/snort/snort.conf
```

```
# Set home network
var HOME_NET 192.168.1.0/24
var EXTERNAL_NET !$HOME_NET

# Set rule paths
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

# Output
output alert_fast: alert
output log_tcpdump: tcpdump.log
```

#### Writing Snort Rules

**Rule structure:**
```
action protocol src_ip src_port direction dest_ip dest_port (options)
```

**Examples:**

```
# Alert on ICMP ping
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; sid:1000001;)

# Alert on SSH brute force
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force"; flags: S; threshold: type both, track by_src, count 5, seconds 60; sid:1000002;)

# Alert on SQL injection attempt
alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1"; nocase; sid:1000003;)

# Alert on nmap scan
alert tcp any any -> $HOME_NET any (msg:"Nmap Scan Detected"; flags:S; detection_filter: track by_src, count 20, seconds 60; sid:1000004;)
```

**Rule options:**
- **msg**: Alert message
- **sid**: Signature ID (unique)
- **content**: Look for specific content
- **nocase**: Case-insensitive
- **flags**: TCP flags (S=SYN, A=ACK, F=FIN, R=RST)
- **threshold**: Rate limiting
- **detection_filter**: Advanced rate limiting

#### Running Snort

```bash
# Test configuration
sudo snort -T -c /etc/snort/snort.conf

# Run in IDS mode
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

# Run in IPS mode (inline)
sudo snort -Q --daq afpacket -i eth0:eth1 -c /etc/snort/snort.conf
```

### Suricata (Modern Alternative)

```bash
# Install
sudo apt install suricata

# Update rules
sudo suricata-update

# Run Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# View alerts
tail -f /var/log/suricata/fast.log
```

## Network Access Control (NAC)

### PacketFence Setup

**Open-source NAC solution:**

#### Installation

```bash
# Add repository
echo "deb http://inverse.ca/downloads/PacketFence/debian/ buster buster" | sudo tee /etc/apt/sources.list.d/packetfence.list
wget -O - https://inverse.ca/downloads/GPG_PUBLIC_KEY | sudo apt-key add -

# Install
sudo apt update
sudo apt install packetfence
```

#### Configuration

**Web interface:** http://server-ip:1443

**Configure:**
1. Network interfaces (management, registration, isolation)
2. Switch configuration
3. Authentication sources (AD, RADIUS, LDAP)
4. Violation policies
5. Provisioners (MDM integration)

#### 802.1X Configuration

**On switch (Cisco example):**
```
aaa new-model
aaa authentication dot1x default group radius
aaa authorization network default group radius

dot1x system-auth-control

interface GigabitEthernet1/0/1
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
```

**RADIUS server (FreeRADIUS):**
```bash
# Install
sudo apt install freeradius

# Configure client (switch)
sudo nano /etc/freeradius/3.0/clients.conf
```

```
client switch1 {
    ipaddr = 192.168.1.10
    secret = shared-secret
    shortname = switch1
}
```

## Web Application Firewall (WAF)

### ModSecurity with Apache

#### Installation

```bash
sudo apt install libapache2-mod-security2

# Enable
sudo a2enmod security2
sudo systemctl restart apache2
```

#### Configuration

```bash
# Copy recommended config
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Edit config
sudo nano /etc/modsecurity/modsecurity.conf
```

```
# Enable ModSecurity
SecRuleEngine On

# Set detection only (for testing)
# SecRuleEngine DetectionOnly

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLog /var/log/apache2/modsec_audit.log
```

#### OWASP Core Rule Set

```bash
# Install CRS
cd /etc/modsecurity
sudo git clone https://github.com/coreruleset/coreruleset.git
cd coreruleset
sudo mv crs-setup.conf.example crs-setup.conf

# Include in Apache
sudo nano /etc/apache2/mods-enabled/security2.conf
```

```
IncludeOptional /etc/modsecurity/*.conf
IncludeOptional /etc/modsecurity/coreruleset/crs-setup.conf
IncludeOptional /etc/modsecurity/coreruleset/rules/*.conf
```

```bash
sudo systemctl restart apache2
```

#### Custom Rules

```bash
sudo nano /etc/modsecurity/modsecurity_custom.conf
```

```
# Block SQL injection
SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,msg:'SQL Injection Attempt'"

# Block XSS
SecRule ARGS "@detectXSS" "id:1002,phase:2,deny,status:403,msg:'XSS Attempt'"

# Block directory traversal
SecRule ARGS "@contains ../" "id:1003,phase:2,deny,status:403,msg:'Directory Traversal Attempt'"

# Rate limiting
SecAction "id:1004,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"
SecRule IP:REQUEST_COUNT "@gt 100" "id:1005,phase:2,deny,status:429,msg:'Rate Limit Exceeded',setvar:ip.request_count=+1"
```

## Security Monitoring

### Centralized Logging with ELK Stack

#### Elasticsearch Installation

```bash
# Add repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Install
sudo apt update
sudo apt install elasticsearch

# Configure
sudo nano /etc/elasticsearch/elasticsearch.yml
```

```
network.host: localhost
http.port: 9200
```

```bash
# Start
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch
```

#### Logstash Installation

```bash
sudo apt install logstash

# Create configuration
sudo nano /etc/logstash/conf.d/syslog.conf
```

```
input {
  syslog {
    port => 5514
  }
}

filter {
  if [program] == "sshd" {
    grok {
      match => { "message" => "%{DATA:auth_method} %{DATA:auth_result} for %{DATA:user} from %{IP:src_ip}" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
}
```

```bash
# Start
sudo systemctl start logstash
sudo systemctl enable logstash
```

#### Kibana Installation

```bash
sudo apt install kibana

# Configure
sudo nano /etc/kibana/kibana.yml
```

```
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

```bash
# Start
sudo systemctl start kibana
sudo systemctl enable kibana
```

**Access Kibana:** http://localhost:5601

### SIEM Rules

**Failed login detection:**
```
# In Kibana, create alert:
Index: syslog-*
Query: program:"sshd" AND message:"Failed password"
Threshold: > 5 in 5 minutes
Action: Email alert
```

## Key Takeaways

**Hands-on skills covered:**
- Firewall configuration (iptables, UFW)
- VPN setup (OpenVPN, WireGuard)
- IDS implementation (Snort, Suricata)
- NAC deployment (802.1X)
- WAF configuration (ModSecurity)
- Centralized logging (ELK Stack)

**Best practices:**
- Test in lab before production
- Document all configurations
- Monitor logs for alerts
- Regular rule updates
- Performance testing
- Backup configurations

**Remember:**
- Security controls must be maintained
- Rules need constant tuning
- False positives are normal (at first)
- Defense in depth—use multiple controls

These are real-world skills. Practice them in virtual machines, build a home lab, and experiment. Reading about security is good; doing security is better.
