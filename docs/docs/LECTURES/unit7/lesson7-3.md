# PKI and Certificate Management

Public Key Infrastructure (PKI) is the framework that enables secure communication across untrusted networks. Understanding PKI is essential for implementing HTTPS, email security, code signing, and authentication systems.

## Understanding PKI Components

### Core Components

**Certificate Authority (CA):**
- Issues and signs digital certificates
- Verifies identity before issuing
- Maintains certificate revocation lists
- Root of trust in PKI hierarchy

**Registration Authority (RA):**
- Verifies certificate requests
- Intermediary between users and CA
- Performs identity verification
- Approves or rejects requests

**Certificate:**
- Digital document binding public key to identity
- Signed by CA
- Contains subject information, validity period, public key

**Certificate Revocation List (CRL):**
- List of revoked certificates
- Published by CA
- Checked during certificate validation

**OCSP (Online Certificate Status Protocol):**
- Real-time certificate status checking
- Alternative to CRL
- More efficient for validation

## X.509 Certificates

### Certificate Structure

**Standard fields:**
```
Version: v3
Serial Number: unique identifier
Signature Algorithm: RSA-SHA256
Issuer: CN=Example CA
Validity:
    Not Before: 2024-01-01
    Not After: 2025-01-01
Subject: CN=example.com
Subject Public Key Info:
    Algorithm: RSA 2048 bit
    Public Key: ...
Extensions:
    Subject Alternative Name: DNS:www.example.com
    Key Usage: Digital Signature, Key Encipherment
    Extended Key Usage: TLS Web Server Authentication
Signature: ...
```

**Important fields:**

**Common Name (CN):** Primary identifier (domain name)
**Subject Alternative Names (SANs):** Additional identifiers
**Key Usage:** What the key can be used for
**Extended Key Usage:** Specific purposes (web server, code signing)
**Authority Key Identifier:** Links to issuing CA
**Subject Key Identifier:** Unique key identifier

### Reading Certificates

```bash
# View certificate details
openssl x509 -in certificate.crt -text -noout

# Check certificate dates
openssl x509 -in certificate.crt -dates -noout

# View certificate subject
openssl x509 -in certificate.crt -subject -noout

# View certificate issuer
openssl x509 -in certificate.crt -issuer -noout

# Check certificate fingerprint
openssl x509 -in certificate.crt -fingerprint -noout
```

## Creating a Certificate Authority

### Root CA Setup

```bash
# Create directory structure
mkdir -p ca/{root-ca,intermediate-ca}/{private,certs,newcerts,crl,csr}
cd ca/root-ca

# Generate root CA private key
openssl genrsa -aes256 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem

# Create root CA certificate
openssl req -config openssl.cnf \
    -key private/ca.key.pem \
    -new -x509 -days 7300 -sha256 -extensions v3_ca \
    -out certs/ca.cert.pem

# Verify root certificate
openssl x509 -noout -text -in certs/ca.cert.pem
```

### Root CA OpenSSL Configuration

```ini
# /root-ca/openssl.cnf
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /path/to/ca/root-ca
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand

private_key       = $dir/private/ca.key.pem
certificate       = $dir/certs/ca.cert.pem

crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

### Intermediate CA Setup

```bash
cd /path/to/ca/intermediate-ca

# Generate intermediate key
openssl genrsa -aes256 -out private/intermediate.key.pem 4096
chmod 400 private/intermediate.key.pem

# Create intermediate CSR
openssl req -config openssl.cnf -new -sha256 \
    -key private/intermediate.key.pem \
    -out csr/intermediate.csr.pem

# Sign intermediate certificate with root CA
cd ../root-ca
openssl ca -config openssl.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha256 \
    -in ../intermediate-ca/csr/intermediate.csr.pem \
    -out ../intermediate-ca/certs/intermediate.cert.pem

# Verify intermediate certificate
openssl verify -CAfile certs/ca.cert.pem \
    ../intermediate-ca/certs/intermediate.cert.pem

# Create certificate chain file
cat ../intermediate-ca/certs/intermediate.cert.pem \
    certs/ca.cert.pem > ../intermediate-ca/certs/ca-chain.cert.pem
```

## Issuing Server Certificates

### Generate Server Certificate

```bash
cd /path/to/ca/intermediate-ca

# Generate server private key
openssl genrsa -out private/server.key.pem 2048
chmod 400 private/server.key.pem

# Create certificate signing request
openssl req -config openssl.cnf \
    -key private/server.key.pem \
    -new -sha256 -out csr/server.csr.pem

# Sign server certificate
openssl ca -config openssl.cnf \
    -extensions server_cert -days 375 -notext -md sha256 \
    -in csr/server.csr.pem \
    -out certs/server.cert.pem

# Verify server certificate
openssl verify -CAfile certs/ca-chain.cert.pem \
    certs/server.cert.pem
```

### Server Certificate with SAN

```bash
# Create config with Subject Alternative Names
cat > server.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
CN = example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = example.com
DNS.2 = www.example.com
DNS.3 = api.example.com
IP.1 = 192.168.1.100
EOF

# Generate CSR with SANs
openssl req -new -key server.key.pem \
    -out server.csr.pem \
    -config server.cnf

# Sign with SANs
openssl x509 -req -in server.csr.pem \
    -CA ca-chain.cert.pem -CAkey ca.key.pem \
    -CAcreateserial -out server.cert.pem \
    -days 365 -sha256 \
    -extfile server.cnf -extensions v3_req
```

## Client Certificates

### Generate Client Certificate

```bash
# Generate client private key
openssl genrsa -out client.key.pem 2048

# Create client CSR
openssl req -new -key client.key.pem \
    -out client.csr.pem \
    -subj "/C=US/ST=State/O=Org/CN=user@example.com"

# Sign client certificate
openssl ca -config openssl.cnf \
    -extensions usr_cert -days 375 -notext -md sha256 \
    -in client.csr.pem \
    -out client.cert.pem

# Create PKCS12 file for client
openssl pkcs12 -export \
    -out client.p12 \
    -inkey client.key.pem \
    -in client.cert.pem \
    -certfile ca-chain.cert.pem
```

### Using Client Certificates

**Apache configuration:**
```apache
SSLVerifyClient require
SSLVerifyDepth 2
SSLCACertificateFile /path/to/ca-chain.cert.pem
```

**Nginx configuration:**
```nginx
ssl_client_certificate /path/to/ca-chain.cert.pem;
ssl_verify_client on;
ssl_verify_depth 2;
```

**Python requests:**
```python
import requests

response = requests.get(
    'https://example.com',
    cert=('client.cert.pem', 'client.key.pem'),
    verify='ca-chain.cert.pem'
)
```

## Certificate Revocation

### Creating CRL

```bash
# Revoke certificate
openssl ca -config openssl.cnf \
    -revoke certs/server.cert.pem

# Generate CRL
openssl ca -config openssl.cnf \
    -gencrl -out crl/ca.crl.pem

# View CRL
openssl crl -in crl/ca.crl.pem -noout -text
```

### OCSP Responder

```bash
# Start OCSP responder
openssl ocsp -port 8080 \
    -index index.txt \
    -CA certs/ca-chain.cert.pem \
    -rkey private/ca.key.pem \
    -rsigner certs/ca.cert.pem

# Check certificate status
openssl ocsp -CAfile certs/ca-chain.cert.pem \
    -url http://localhost:8080 \
    -resp_text \
    -issuer certs/intermediate.cert.pem \
    -cert certs/server.cert.pem
```

## Let's Encrypt (Free Certificates)

### Certbot Installation

```bash
# Install certbot
sudo apt install certbot python3-certbot-apache

# Or for nginx
sudo apt install certbot python3-certbot-nginx
```

### Obtaining Certificates

```bash
# Apache
sudo certbot --apache -d example.com -d www.example.com

# Nginx
sudo certbot --nginx -d example.com -d www.example.com

# Standalone (no web server)
sudo certbot certonly --standalone -d example.com

# DNS challenge (for wildcard)
sudo certbot certonly --manual --preferred-challenges dns \
    -d example.com -d *.example.com

# Webroot
sudo certbot certonly --webroot -w /var/www/html \
    -d example.com
```

### Automatic Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Setup automatic renewal (cron)
echo "0 3 * * * /usr/bin/certbot renew --quiet" | sudo crontab -

# Or use systemd timer (already configured)
sudo systemctl status certbot.timer
```

## Certificate Formats

### PEM (Privacy Enhanced Mail)

```
-----BEGIN CERTIFICATE-----
Base64 encoded certificate
-----END CERTIFICATE-----
```

Most common format, text-based.

### DER (Distinguished Encoding Rules)

Binary format, compact.

```bash
# PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem
```

### PKCS#12 / PFX

Container format, includes certificate and private key.

```bash
# Create PKCS12
openssl pkcs12 -export \
    -out certificate.p12 \
    -inkey private.key \
    -in certificate.crt \
    -certfile ca-chain.crt

# Extract certificate
openssl pkcs12 -in certificate.p12 \
    -nokeys -out certificate.crt

# Extract private key
openssl pkcs12 -in certificate.p12 \
    -nocerts -nodes -out private.key
```

### PKCS#7

Certificate chain format.

```bash
# Create PKCS7
openssl crl2pkcs7 -nocrl \
    -certfile certificate.crt \
    -certfile ca-chain.crt \
    -out certificate.p7b

# View PKCS7
openssl pkcs7 -print_certs -in certificate.p7b
```

## Certificate Validation

### Programmatic Validation

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
import datetime

def validate_certificate(cert_path, ca_path):
    """Validate certificate"""
    # Load certificate
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Load CA certificate
    with open(ca_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Check validity period
    now = datetime.datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        print("Certificate expired or not yet valid")
        return False
    
    # Verify signature
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            # padding and algorithm depend on cert
        )
        print("Signature valid")
    except:
        print("Invalid signature")
        return False
    
    # Check key usage
    try:
        key_usage = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
        
        if key_usage.digital_signature and key_usage.key_encipherment:
            print("Key usage appropriate for TLS")
    except:
        pass
    
    return True
```

### Common Validation Errors

**Expired certificate:**
```
Error: certificate has expired
Fix: Renew certificate
```

**Wrong hostname:**
```
Error: certificate is not valid for example.com
Fix: Add SAN for all domain names
```

**Self-signed certificate:**
```
Error: self signed certificate in certificate chain
Fix: Add CA certificate to trust store
```

**Incomplete chain:**
```
Error: unable to get local issuer certificate
Fix: Include intermediate certificates
```

## Certificate Pinning

### Why Pin Certificates?

**Certificate pinning** ensures your application only trusts specific certificates, preventing MitM even with compromised CAs.

### Pin Public Keys

```python
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl
import hashlib

class PinnedHTTPAdapter(HTTPAdapter):
    def __init__(self, pin, *args, **kwargs):
        self.pin = pin
        super().__init__(*args, **kwargs)
    
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

# Calculate pin
def get_certificate_pin(hostname):
    import ssl
    cert = ssl.get_server_certificate((hostname, 443))
    # Extract public key and hash
    # This is simplified - actual implementation more complex
    return hashlib.sha256(cert.encode()).hexdigest()

# Use pinned connection
session = requests.Session()
pin = "expected_certificate_hash"
session.mount('https://', PinnedHTTPAdapter(pin))
response = session.get('https://example.com')
```

## Best Practices

**Certificate management:**
- Use strong key sizes (2048+ bit RSA, 256+ bit ECC)
- Short validity periods (90 days recommended)
- Automate renewal
- Monitor expiration dates
- Test revocation procedures

**Key storage:**
- Protect private keys (chmod 400)
- Use HSMs for root CA keys
- Never transmit private keys unencrypted
- Backup keys securely

**Operational:**
- Maintain certificate inventory
- Set up expiration alerts
- Document procedures
- Test disaster recovery
- Regular security audits

## Troubleshooting

### Common Issues

**Certificate chain order:**
```bash
# Correct order:
# 1. Server certificate
# 2. Intermediate certificate(s)
# 3. Root certificate (optional)

cat server.crt intermediate.crt > server-chain.crt
```

**Private key mismatch:**
```bash
# Check if certificate and key match
openssl x509 -noout -modulus -in server.crt | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# Hashes should match
```

**Testing certificates:**
```bash
# Test with openssl
openssl s_client -connect example.com:443 -showcerts

# Check specific protocol
openssl s_client -connect example.com:443 -tls1_2

# Verify chain
openssl s_client -connect example.com:443 -CAfile ca-bundle.crt
```

## Key Takeaways

**PKI components:**
- Certificate Authorities issue and manage certificates
- Certificates bind public keys to identities
- Trust chains from root CAs to end entities
- Revocation mechanisms (CRL, OCSP)

**Certificate lifecycle:**
1. Key generation
2. CSR creation
3. CA signing
4. Deployment
5. Monitoring
6. Renewal
7. Revocation (if needed)

**Security considerations:**
- Protect private keys above all else
- Validate certificates properly
- Use short validity periods
- Automate renewal processes
- Monitor and alert on expiration

**Remember:**
- PKI is complex but essential
- Automation reduces errors
- Regular audits prevent issues
- Documentation is critical
- Test procedures regularly

Understanding PKI is crucial for implementing secure systems. Whether you're setting up HTTPS, authenticating users, or signing code, PKI provides the trust framework that makes it all work.
