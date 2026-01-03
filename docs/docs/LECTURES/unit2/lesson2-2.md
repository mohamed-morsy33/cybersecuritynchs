# Internet Protocols Deep Dive

You know what the internet is and how it works at a high level. Now let's dive deeper into the protocols that make communication possible. Understanding these protocols is essential for security—many attacks exploit protocol weaknesses or misconfigurations.

## The Protocol Stack

Think of network communication as layers, each handling specific tasks. We'll examine the key protocols at each layer.

## Application Layer Protocols

These are the protocols you interact with directly.

### HTTP (HyperText Transfer Protocol)

**HTTP** is how web browsers communicate with web servers.

#### HTTP Request Structure
```http
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept: text/html
Accept-Language: en-US
Connection: keep-alive
```

**Components:**
- **Method**: GET, POST, PUT, DELETE, etc.
- **Path**: Resource being requested
- **Version**: HTTP/1.1, HTTP/2, HTTP/3
- **Headers**: Metadata about the request

#### HTTP Methods

**GET**: Retrieve data
```http
GET /users/123 HTTP/1.1
```

**POST**: Submit data
```http
POST /users HTTP/1.1
Content-Type: application/json

{"name": "John", "email": "john@example.com"}
```

**PUT**: Update/replace resource
```http
PUT /users/123 HTTP/1.1
Content-Type: application/json

{"name": "John Updated"}
```

**DELETE**: Remove resource
```http
DELETE /users/123 HTTP/1.1
```

**HEAD**: Like GET but only returns headers
**OPTIONS**: Describe communication options
**PATCH**: Partial update

#### HTTP Response Structure
```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1234
Server: Apache/2.4.41
Set-Cookie: sessionid=abc123

<!DOCTYPE html>
<html>
...
```

**Status codes:**
- **1xx**: Informational
- **2xx**: Success
  - 200: OK
  - 201: Created
  - 204: No Content
- **3xx**: Redirection
  - 301: Moved Permanently
  - 302: Found (temporary redirect)
  - 304: Not Modified
- **4xx**: Client errors
  - 400: Bad Request
  - 401: Unauthorized
  - 403: Forbidden
  - 404: Not Found
- **5xx**: Server errors
  - 500: Internal Server Error
  - 502: Bad Gateway
  - 503: Service Unavailable

#### HTTP Security Issues

**Unencrypted**: All data visible to anyone monitoring network
**Session hijacking**: Steal cookies to impersonate users
**Man-in-the-middle**: Intercept and modify traffic
**Replay attacks**: Capture and replay requests

**This is why HTTPS exists.**

### HTTPS (HTTP Secure)

HTTPS = HTTP + TLS encryption

**What it protects:**
- Confidentiality: Data encrypted
- Integrity: Detect if data modified
- Authentication: Verify you're talking to the right server

**What it doesn't protect:**
- Endpoint security: If server is compromised, HTTPS can't help
- Metadata: Can still see which sites you visit (not content)
- User actions: If user clicks malicious link, HTTPS doesn't stop it

**Key concepts:**
- Requires valid SSL/TLS certificate
- Browser verifies certificate before trusting connection
- All traffic encrypted after handshake
- Uses port 443 (HTTP uses port 80)

### DNS (Domain Name System)

**DNS** translates domain names to IP addresses.

#### DNS Record Types

**A record**: IPv4 address
```
example.com.  IN  A  93.184.216.34
```

**AAAA record**: IPv6 address
```
example.com.  IN  AAAA  2606:2800:220:1:248:1893:25c8:1946
```

**CNAME record**: Alias to another domain
```
www.example.com.  IN  CNAME  example.com.
```

**MX record**: Mail servers
```
example.com.  IN  MX  10 mail.example.com.
```

**NS record**: Name servers
```
example.com.  IN  NS  ns1.example.com.
```

**TXT record**: Arbitrary text (used for SPF, DKIM, verification)
```
example.com.  IN  TXT  "v=spf1 mx ~all"
```

**PTR record**: Reverse DNS (IP to domain)

#### DNS Query Process

1. User types `www.example.com` in browser
2. Computer checks local DNS cache
3. If not cached, queries configured DNS server (usually ISP's)
4. DNS server checks its cache
5. If not cached, queries root DNS servers
6. Root server responds with TLD (Top-Level Domain) server for `.com`
7. TLD server responds with authoritative name server for `example.com`
8. Authoritative server responds with IP address
9. Response cached at each level
10. Browser connects to IP address

#### DNS Security Issues

**DNS Spoofing/Poisoning**: Provide false DNS responses
- Attacker redirects traffic to malicious server
- User thinks they're on legitimate site

**DNS Cache Poisoning**: Corrupt DNS cache with false entries

**DNS Tunneling**: Exfiltrate data through DNS queries
- Encode data in subdomain names
- Bypasses many security controls

**DDoS via DNS Amplification**: Small queries → large responses
- Attacker spoofs victim's IP
- Sends queries to many DNS servers
- Servers send large responses to victim

**DNSSEC**: Digital signatures to verify DNS responses
- Prevents spoofing
- Not widely adopted yet

### FTP (File Transfer Protocol)

**FTP** transfers files between client and server.

#### How FTP Works

**Two channels:**
1. **Control channel** (port 21): Commands and responses
2. **Data channel** (port 20 or random): Actual file transfer

**Active vs. Passive mode:**
- **Active**: Server initiates data connection to client (firewall issues)
- **Passive**: Client initiates both connections (firewall-friendly)

#### FTP Commands
```
USER username        # Provide username
PASS password        # Provide password
LIST                 # List files
RETR filename        # Download file
STOR filename        # Upload file
DELE filename        # Delete file
MKD directory        # Create directory
CWD directory        # Change directory
QUIT                 # Disconnect
```

#### FTP Security Issues

**Major problem: Everything in plaintext**
- Username and password visible
- File contents visible
- Commands visible

**Solutions:**
- **FTPS**: FTP over TLS (explicit or implicit)
- **SFTP**: SSH File Transfer Protocol (different protocol, runs over SSH)

**Example SFTP:**
```bash
sftp user@server
sftp> ls
sftp> get file.txt
sftp> put local.txt
sftp> quit
```

### SMTP (Simple Mail Transfer Protocol)

**SMTP** sends email between servers.

#### Email Sending Process

1. User composes email in client (Gmail, Outlook)
2. Client sends to SMTP server (port 25, 587, or 465)
3. SMTP server looks up recipient's mail server (MX record)
4. Sends email to recipient's SMTP server
5. Recipient's server stores email
6. Recipient downloads via POP3/IMAP

#### SMTP Commands
```
HELO/EHLO            # Identify sender
MAIL FROM:           # Sender address
RCPT TO:             # Recipient address
DATA                 # Start message content
.                    # End message
QUIT                 # Disconnect
```

#### Email Security Issues

**SPF (Sender Policy Framework)**: TXT record lists authorized sending servers
```
v=spf1 mx ip4:192.0.2.0/24 ~all
```

**DKIM (DomainKeys Identified Mail)**: Digital signature
- Signs outgoing emails
- Recipients verify signature

**DMARC (Domain-based Message Authentication)**: Policy for SPF/DKIM failures
```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

**Phishing**: Spoofed sender addresses
**Spam**: Unsolicited email
**Email harvesting**: Collecting addresses for spam
**Malware attachments**: Malicious files

## Transport Layer Protocols

### TCP (Transmission Control Protocol)

**TCP** provides reliable, ordered delivery.

#### Three-Way Handshake

**Connection establishment:**
```
1. Client → Server: SYN (sequence = 1000)
2. Server → Client: SYN-ACK (sequence = 5000, ack = 1001)
3. Client → Server: ACK (sequence = 1001, ack = 5001)

Connection established!
```

#### TCP Header

Key fields:
- **Source port** (16 bits)
- **Destination port** (16 bits)
- **Sequence number** (32 bits): Track bytes sent
- **Acknowledgment number** (32 bits): Track bytes received
- **Flags**: SYN, ACK, FIN, RST, PSH, URG
- **Window size**: Flow control
- **Checksum**: Error detection

#### TCP Flags

**SYN**: Synchronize, start connection
**ACK**: Acknowledge received data
**FIN**: Finish, close connection gracefully
**RST**: Reset, abrupt close (error)
**PSH**: Push, send data immediately
**URG**: Urgent, prioritize this data

#### Connection Termination

Four-way handshake:
```
1. Client → Server: FIN
2. Server → Client: ACK
3. Server → Client: FIN
4. Client → Server: ACK

Connection closed!
```

#### TCP Security

**SYN Flood attack**: Send many SYN packets, never complete handshake
- Exhausts server's connection table
- Prevention: SYN cookies, rate limiting

**TCP hijacking**: Inject packets with correct sequence numbers
- Man-in-the-middle attack
- Prevention: Encryption (TLS)

**Reset attacks**: Send RST packets to terminate connections
- Prevention: Encryption

### UDP (User Datagram Protocol)

**UDP** is connectionless and unreliable (by design).

#### UDP Header

Simpler than TCP:
- Source port (16 bits)
- Destination port (16 bits)
- Length (16 bits)
- Checksum (16 bits)

**No sequence numbers, acknowledgments, or retransmissions.**

#### When to Use UDP

**Use cases:**
- DNS queries (single packet request/response)
- Video streaming (dropped frames tolerable)
- Online gaming (low latency critical)
- VoIP (voice calls, some packet loss acceptable)
- DHCP (network configuration)
- SNMP (network monitoring)

**Advantages:**
- Lower overhead
- Faster (no handshake)
- Better for real-time applications

**Disadvantages:**
- No reliability guarantee
- No flow control
- No congestion control

#### UDP Security

**UDP Flood**: Send massive amounts of UDP packets
- DDoS attack
- Prevention: Rate limiting, firewall rules

**Amplification attacks**: Small UDP query → large response
- DNS amplification (50x)
- NTP amplification (200x)
- Prevention: Configure servers to not respond to spoofed sources

## Network Layer Protocols

### IP (Internet Protocol)

**IP** handles addressing and routing.

#### IPv4 Packet Structure

**Header fields:**
- **Version**: 4 for IPv4
- **Header length**: Usually 20 bytes
- **TTL** (Time To Live): Decrements at each hop, prevents loops
- **Protocol**: TCP (6), UDP (17), ICMP (1)
- **Source IP**: 32-bit address
- **Destination IP**: 32-bit address
- **Checksum**: Header integrity

#### IPv4 Address Classes (Historical)

**Class A**: 0.0.0.0 to 127.255.255.255 (large networks)
**Class B**: 128.0.0.0 to 191.255.255.255 (medium networks)
**Class C**: 192.0.0.0 to 223.255.255.255 (small networks)

**Private ranges:**
- 10.0.0.0/8 (Class A)
- 172.16.0.0/12 (Class B)
- 192.168.0.0/16 (Class C)

**Special addresses:**
- 127.0.0.1: Loopback (localhost)
- 0.0.0.0: Default route
- 255.255.255.255: Broadcast

#### IPv6

**Address format**: Eight groups of four hexadecimal digits
```
2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

**Abbreviation rules:**
- Leading zeros can be omitted: `2001:db8:85a3:0:0:8a2e:370:7334`
- Consecutive zeros can be replaced with `::` (once only): `2001:db8:85a3::8a2e:370:7334`

**Special addresses:**
- `::1` - Loopback
- `::` - Unspecified
- `fe80::/10` - Link-local
- `ff00::/8` - Multicast

**Why IPv6?**
- IPv4 exhaustion (4.3 billion addresses not enough)
- IPv6 provides 340 undecillion addresses
- Better security (IPsec built-in)
- Simplified header
- No NAT needed

### ICMP (Internet Control Message Protocol)

**ICMP** sends error messages and diagnostic information.

#### Common ICMP Types

**Echo Request (Type 8)**: Ping request
**Echo Reply (Type 0)**: Ping response
**Destination Unreachable (Type 3)**: Can't reach destination
**Time Exceeded (Type 11)**: TTL expired (used by traceroute)
**Redirect (Type 5)**: Better route available

#### Ping

```bash
ping example.com

# Sends Echo Request
# Receives Echo Reply
# Shows round-trip time (RTT)
```

**Security implications:**
- Network reconnaissance
- ICMP tunneling (covert channel)
- ICMP flooding (DoS)
- Some networks block ICMP

#### Traceroute

```bash
traceroute example.com

# Sends packets with increasing TTL
# Each router decrements TTL
# When TTL=0, router sends ICMP Time Exceeded
# Shows path to destination
```

### ARP (Address Resolution Protocol)

**ARP** maps IP addresses to MAC addresses on local network.

#### How ARP Works

1. Computer wants to send packet to 192.168.1.100
2. Checks ARP cache (known IP→MAC mappings)
3. If not cached, broadcasts ARP request:
   ```
   "Who has 192.168.1.100? Tell 192.168.1.50"
   ```
4. Device with 192.168.1.100 responds:
   ```
   "192.168.1.100 is at MAC aa:bb:cc:dd:ee:ff"
   ```
5. Requester caches this mapping
6. Uses MAC address for actual communication

#### ARP Commands

```bash
# Show ARP cache
arp -a
ip neigh show

# Delete ARP entry
sudo arp -d 192.168.1.100

# Add static ARP entry
sudo arp -s 192.168.1.100 aa:bb:cc:dd:ee:ff
```

#### ARP Spoofing/Poisoning

**Attack:**
1. Attacker sends fake ARP responses
2. Claims attacker's MAC is gateway's IP
3. Victim sends traffic to attacker instead of gateway
4. Attacker forwards traffic (man-in-the-middle)

**Detection:**
- Duplicate IP addresses
- Unexpected ARP replies
- Changing MAC addresses for same IP

**Prevention:**
- Static ARP entries (impractical)
- ARP inspection on switches
- Network monitoring

## Putting It All Together

### Example: Loading a Web Page

Let's trace what happens when you visit `https://example.com`:

1. **DNS Resolution**
   - Query DNS server: "What's the IP for example.com?"
   - Response: "93.184.216.34"

2. **ARP** (if needed)
   - "What's the MAC address of my gateway?"
   - Gateway responds with its MAC

3. **TCP Handshake**
   - SYN to 93.184.216.34:443
   - SYN-ACK from server
   - ACK from client

4. **TLS Handshake**
   - Client Hello (supported ciphers)
   - Server Hello (chosen cipher, certificate)
   - Key exchange
   - Encrypted connection established

5. **HTTP Request**
   - GET / HTTP/1.1
   - Host: example.com

6. **HTTP Response**
   - 200 OK
   - Content-Type: text/html
   - HTML content

7. **Additional Resources**
   - Browser parses HTML
   - Requests CSS, JavaScript, images
   - Each resource: separate TCP connection (HTTP/1.1) or multiplexed (HTTP/2)

8. **Connection Close**
   - FIN/ACK exchange
   - Or keep-alive for reuse

### Security at Each Layer

**Application Layer:**
- Input validation
- Authentication
- Encryption (HTTPS)

**Transport Layer:**
- Port filtering
- SYN cookies
- Rate limiting

**Network Layer:**
- IP filtering
- Route filtering
- Spoofing prevention

**Link Layer:**
- MAC filtering
- ARP inspection
- VLAN segmentation

**Defense in depth: Protect at multiple layers.**

## Protocol Analysis Practice

To understand protocols deeply:
1. Capture traffic with Wireshark
2. Examine packet structure
3. Follow protocol flows
4. Identify anomalies

**Suggested exercises:**
- Capture and analyze HTTP traffic
- Observe TCP three-way handshake
- Watch DNS resolution
- Monitor ARP requests
- Trace full web page load

Understanding protocols is fundamental to:
- Detecting attacks
- Analyzing malware communication
- Troubleshooting network issues
- Designing secure systems

In the next lessons, we'll apply this knowledge to identify and exploit protocol weaknesses, and then learn how to defend against those attacks.
