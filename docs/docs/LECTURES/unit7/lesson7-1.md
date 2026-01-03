# Cryptography and Access Control

You've seen how easily data can be intercepted on networks. Now let's talk about how to protect it. **Cryptography** is the practice of securing information by transforming it into an unreadable format. It's the foundation of digital security—from HTTPS to messaging apps to cryptocurrency.

## What is Cryptography?

**Cryptography** comes from Greek words meaning "hidden writing." It's the science of using mathematical algorithms to:
- **Confidentiality**: Keep data secret
- **Integrity**: Ensure data hasn't been modified
- **Authentication**: Verify identity
- **Non-repudiation**: Prove actions can't be denied

Without cryptography, the internet as we know it couldn't exist. Every secure transaction, every private message, every protected password relies on cryptographic principles.

## The Basics: Plaintext and Ciphertext

**Plaintext**: The original, readable data
**Ciphertext**: The encrypted, unreadable data
**Encryption**: Converting plaintext to ciphertext
**Decryption**: Converting ciphertext back to plaintext
**Key**: Secret value used in encryption/decryption
**Algorithm (Cipher)**: The mathematical process for encryption

The goal: without the key, ciphertext should be computationally infeasible to decrypt, even if you know the algorithm.

## Symmetric Encryption

**Symmetric encryption** uses the same key for both encryption and decryption. It's like a locked box—the same key locks and unlocks it.

### How It Works

```
Plaintext → [Encryption Algorithm + Key] → Ciphertext
Ciphertext → [Decryption Algorithm + Same Key] → Plaintext
```

**Advantages:**
- Fast and efficient
- Simple to implement
- Good for encrypting large amounts of data

**Disadvantage:**
- Key distribution problem: how do you securely share the key?

### Common Symmetric Algorithms

**AES (Advanced Encryption Standard):**
- Current industry standard
- Key sizes: 128, 192, or 256 bits
- Used everywhere: HTTPS, VPNs, disk encryption, file encryption
- Extremely secure when properly implemented
- Fast in both hardware and software

**DES (Data Encryption Standard):**
- Old standard from 1970s
- 56-bit key (too small—can be brute forced)
- Deprecated, no longer secure
- Historic importance only

**3DES (Triple DES):**
- Applies DES three times with different keys
- More secure than DES but slower
- Being phased out in favor of AES

**ChaCha20:**
- Modern stream cipher
- Alternative to AES
- Fast on devices without AES hardware acceleration
- Used in TLS, SSH, VPNs

### Block vs. Stream Ciphers

**Block ciphers** (like AES):
- Encrypt fixed-size blocks of data (128 bits for AES)
- Need padding if data isn't a multiple of block size
- Require modes of operation (ECB, CBC, CTR, GCM)

**Stream ciphers** (like ChaCha20):
- Encrypt data bit by bit or byte by byte
- No padding needed
- Often faster for streaming data

### Modes of Operation

Block ciphers need a mode to handle multiple blocks:

**ECB (Electronic Codebook)** - DON'T USE:
- Each block encrypted independently
- Same plaintext block = same ciphertext block
- Patterns visible in encrypted data
- Insecure for most purposes

**CBC (Cipher Block Chaining)**:
- Each block XORed with previous ciphertext
- Requires initialization vector (IV)
- Sequential processing
- Common but being replaced

**CTR (Counter)**:
- Turns block cipher into stream cipher
- Can be parallelized (faster)
- Used in modern protocols

**GCM (Galois/Counter Mode)**:
- Provides encryption + authentication
- Current best practice
- Used in TLS 1.3, WPA3
- Fast and secure

## Asymmetric Encryption (Public Key Cryptography)

**Asymmetric encryption** uses two different keys: a public key (shared openly) and a private key (kept secret).

### How It Works

```
Plaintext → [Encryption + Public Key] → Ciphertext
Ciphertext → [Decryption + Private Key] → Plaintext
```

Anyone can encrypt with your public key, but only you can decrypt with your private key.

**Advantages:**
- Solves key distribution problem
- Enables digital signatures
- Foundation of secure communications

**Disadvantages:**
- Slower than symmetric encryption
- More computationally intensive
- Larger key sizes needed

### Common Asymmetric Algorithms

**RSA (Rivest-Shamir-Adleman):**
- Most widely used
- Key sizes: 2048, 3072, 4096 bits (2048 minimum today)
- Based on difficulty of factoring large numbers
- Used for key exchange, digital signatures
- Quantum computers threaten RSA's future

**ECC (Elliptic Curve Cryptography):**
- Smaller keys, same security as RSA
- 256-bit ECC ≈ 3072-bit RSA
- Faster and more efficient
- Growing in popularity
- Examples: ECDSA (signatures), ECDH (key exchange)

**Diffie-Hellman:**
- Key exchange protocol
- Allows two parties to agree on shared secret over insecure channel
- Doesn't encrypt data directly
- Foundation of forward secrecy

**ElGamal:**
- Alternative to RSA
- Used in PGP/GPG
- Based on discrete logarithm problem

### Hybrid Cryptography

In practice, we use both symmetric and asymmetric:

1. Use asymmetric encryption to exchange a symmetric key
2. Use symmetric encryption for actual data (faster)
3. This is how HTTPS, VPNs, and encrypted messaging work

Example TLS handshake:
1. Client and server use RSA or ECDH to agree on a symmetric key
2. All subsequent traffic encrypted with AES using that key
3. Best of both worlds: secure key exchange + fast encryption

## Hash Functions

**Hash functions** are one-way cryptographic operations that produce a fixed-size output (hash/digest) from any input.

### Properties of Cryptographic Hashes

1. **Deterministic**: Same input always produces same output
2. **Fast**: Quick to compute
3. **One-way**: Computationally infeasible to reverse
4. **Avalanche effect**: Small input change drastically changes output
5. **Collision resistant**: Hard to find two inputs with same hash

### Common Hash Functions

**MD5 (Message Digest 5):**
- 128-bit hash
- **BROKEN** - collision attacks practical
- Still seen but DO NOT USE for security
- OK for checksums only

**SHA-1 (Secure Hash Algorithm 1):**
- 160-bit hash
- **BROKEN** - collision attacks demonstrated (2017)
- Being phased out everywhere
- Don't use for new projects

**SHA-2 Family** (SHA-224, SHA-256, SHA-384, SHA-512):
- Current standard
- SHA-256 most common (256-bit hash)
- Very secure
- Used in TLS, Bitcoin, code signing

**SHA-3:**
- Latest standard
- Different algorithm than SHA-2
- Not widely adopted yet but available
- Insurance against SHA-2 vulnerabilities

**BLAKE2:**
- Fast alternative to SHA-2
- As secure as SHA-3
- Used in some modern systems

### Uses of Hash Functions

**Password Storage:**
Never store passwords in plaintext. Hash them:
```python
import hashlib

password = "user_password123"
hash_obj = hashlib.sha256(password.encode())
stored_hash = hash_obj.hexdigest()
# Store: stored_hash in database
```

To verify login:
```python
login_attempt = "user_password123"
attempt_hash = hashlib.sha256(login_attempt.encode()).hexdigest()
if attempt_hash == stored_hash:
    print("Login successful")
```

**But simple hashing isn't enough!** Attackers use rainbow tables (precomputed hashes).

**Salt**: Random data added to password before hashing:
```python
import os
import hashlib

salt = os.urandom(32)  # Random 32 bytes
password = "user_password123"
hash_input = salt + password.encode()
password_hash = hashlib.sha256(hash_input).hexdigest()

# Store both salt and hash
# Each user gets unique salt, so same password → different hashes
```

**Even better**: Use specialized password hashing algorithms:
- **bcrypt**: Deliberately slow, has built-in salt
- **scrypt**: Memory-hard (resists specialized hardware)
- **Argon2**: Winner of password hashing competition, current best practice

**File Integrity:**
Hash files to detect tampering:
```bash
sha256sum file.txt
# Output: hash value that uniquely identifies file contents
```

**Digital Signatures:**
Hash the message, encrypt hash with private key = signature

**Blockchain/Cryptocurrency:**
Each block contains hash of previous block, creating immutable chain

## Digital Signatures

**Digital signatures** prove authenticity and integrity using asymmetric cryptography.

### How They Work

**Signing:**
1. Hash the document
2. Encrypt hash with sender's private key
3. This encrypted hash is the signature

**Verifying:**
1. Hash the received document
2. Decrypt signature with sender's public key
3. Compare: if hashes match, signature valid

**What this proves:**
- **Authenticity**: Only holder of private key could create this signature
- **Integrity**: If document changed, hash won't match
- **Non-repudiation**: Signer can't deny signing

### Uses

- Code signing (verify software hasn't been tampered)
- Email signatures (PGP/GPG)
- Legal documents
- Cryptocurrency transactions
- SSL/TLS certificates
- Software updates

## Certificates and PKI

**Public Key Infrastructure (PKI)** is the framework for managing public keys and digital certificates.

### Digital Certificates

A **certificate** binds a public key to an identity. It contains:
- Subject (who the certificate is for)
- Public key
- Issuer (who vouches for this)
- Validity period
- Digital signature from issuer

### Certificate Authority (CA)

A **CA** is a trusted entity that issues certificates. Your browser trusts certain root CAs.

**Certificate chain:**
1. Root CA (trusted by OS/browser)
2. Intermediate CA (issued by Root CA)
3. End entity certificate (issued by Intermediate CA)

When you visit an HTTPS site:
1. Server sends its certificate
2. Browser checks if certificate is signed by trusted CA
3. Browser verifies certificate is valid (not expired, not revoked)
4. Browser uses public key from certificate to establish encrypted connection

**Security issues:**
- CAs have been compromised before
- Malicious certificates can be issued
- Certificate pinning helps (app only trusts specific certificates)

## Access Control

Now let's talk about controlling who can access what. **Access control** is about authentication (who are you?) and authorization (what can you do?).

### Authentication Factors

**Something you know:** Password, PIN, security question
**Something you have:** Phone, hardware token, smart card
**Something you are:** Biometrics (fingerprint, face, iris)
**Somewhere you are:** Geolocation
**Something you do:** Behavioral patterns (typing rhythm)

**Multi-Factor Authentication (MFA)**: Requires multiple factors. Much more secure than passwords alone.

Example: Password (know) + Text code (have) + Fingerprint (are)

### Authentication Methods

**Password-Based:**
- Most common
- Weakest when alone
- Vulnerable to: brute force, dictionary attacks, phishing, keyloggers
- Improvements: password managers, strong password policies, MFA

**Certificate-Based:**
- Uses digital certificates
- Common in enterprise (smart cards)
- SSH keys are similar concept
- More secure than passwords

**Biometric:**
- Convenient but has issues
- Can't change if compromised
- False positives/negatives
- Privacy concerns
- Best as second factor, not only factor

**Token-Based:**
- Hardware tokens (YubiKey, RSA SecurID)
- Software tokens (Google Authenticator, Authy)
- One-time passwords (OTP)
- Time-based OTP (TOTP) - code changes every 30 seconds

**SSO (Single Sign-On):**
- Authenticate once, access multiple services
- Reduces password fatigue
- Protocols: SAML, OAuth, OpenID Connect
- Risk: compromise of SSO = compromise of everything

### Authorization Models

**DAC (Discretionary Access Control):**
- Owner controls access to their resources
- Common in operating systems (file permissions)
- Flexible but hard to manage at scale

**MAC (Mandatory Access Control):**
- System-enforced rules
- Users can't change permissions
- Used in high-security environments (military, classified systems)
- Example: SELinux

**RBAC (Role-Based Access Control):**
- Permissions assigned to roles, users assigned to roles
- Easier to manage
- Common in enterprises
- Example: "Admin" role has all permissions, "User" role has read-only

**ABAC (Attribute-Based Access Control):**
- Access based on attributes (user attributes, resource attributes, environment)
- Most flexible
- Example: "Allow access if user.department = 'Finance' AND time < 5PM AND location = 'Office'"

### Principle of Least Privilege

Give users only the minimum access needed to do their job. This limits damage from:
- Compromised accounts
- Insider threats
- Accidents

Implement through:
- Proper RBAC
- Regular access reviews
- Just-in-time access (temporary elevation)
- Separation of duties

## Key Management

The security of encrypted data depends entirely on keeping keys secure.

### Key Generation

- Use cryptographically secure random number generators
- Never use weak or predictable keys
- Proper entropy (randomness) is critical

**Bad:**
```python
import random
key = random.randint(0, 1000000)  # NOT SECURE!
```

**Good:**
```python
import secrets
key = secrets.token_bytes(32)  # 256-bit secure random key
```

### Key Storage

**Never store keys in:**
- Source code
- Configuration files (plain text)
- Databases (unencrypted)
- Environment variables (if avoidable)

**Better options:**
- Hardware Security Modules (HSM)
- Key Management Services (KMS) - AWS KMS, Azure Key Vault
- Operating system keystores (Windows DPAPI, macOS Keychain)
- Encrypted key files with strong passphrases

### Key Rotation

- Regularly change encryption keys
- Limits damage if key is compromised
- Balance security vs. operational complexity

### Key Escrow and Recovery

- What if key is lost?
- Escrow: trusted third party holds backup key
- Recovery: mechanisms to regain access
- Trade-off: convenience vs. security vs. privacy

## Real-World Applications

### HTTPS/TLS

What happens when you visit https://example.com:

1. **Client Hello**: Browser sends supported cipher suites
2. **Server Hello**: Server picks cipher suite, sends certificate
3. **Certificate Verification**: Browser checks if certificate is valid
4. **Key Exchange**: Browser and server agree on symmetric key (using RSA or ECDH)
5. **Encrypted Communication**: All traffic encrypted with AES using agreed key

This combines:
- Asymmetric encryption (key exchange)
- Symmetric encryption (data)
- Hashing (integrity)
- Digital signatures (authentication)

### VPN

**VPN** creates encrypted tunnel through public networks:

1. Client authenticates to VPN server (password, certificate)
2. Key exchange establishes encryption keys
3. All traffic encrypted and sent through tunnel
4. VPN server decrypts and forwards to destination
5. Response encrypted and sent back

Protocols: OpenVPN, WireGuard, IPsec, SSTP

### End-to-End Encryption (E2EE)

Messages encrypted on sender's device, decrypted only on recipient's device. Provider can't read messages.

**Signal Protocol** (used by Signal, WhatsApp, etc.):
- Each user has identity key pair (long-term)
- Ephemeral keys for each conversation
- Perfect forward secrecy (old messages safe even if keys compromised)
- Ratcheting (keys constantly change)

### Disk Encryption

Full-disk encryption protects data at rest:
- **BitLocker** (Windows)
- **FileVault** (macOS)  
- **LUKS** (Linux)

Transparent to user, encryption happens automatically. Decryption key derived from password or TPM chip.

## Attacks on Cryptography

### Brute Force

Try every possible key. Effectiveness depends on key length:
- 56-bit DES: Breakable in hours
- 128-bit AES: Impossible with current technology
- 256-bit AES: Will remain secure for foreseeable future

### Dictionary Attacks

Try common passwords/keys. Why password hashing should be slow and salted.

### Rainbow Tables

Precomputed hashes for common passwords. Defeated by salting.

### Side-Channel Attacks

Attack the implementation, not the algorithm:
- **Timing attacks**: Measure how long operations take
- **Power analysis**: Monitor power consumption during crypto operations
- **Acoustic cryptanalysis**: Listen to sounds devices make
- **Cold boot attack**: Read RAM after system powered off

### Cryptanalysis

Mathematically analyzing algorithms for weaknesses. This is how MD5 and SHA-1 were broken.

### Social Engineering

Why attack encryption when you can trick someone into giving you the key? Often the weakest link.

## Best Practices

1. **Use established algorithms**: Don't create your own crypto
2. **Keep software updated**: Vulnerabilities get patched
3. **Use appropriate key sizes**: 2048-bit RSA minimum, 256-bit AES
4. **Implement properly**: Easier said than done, use crypto libraries
5. **Protect keys**: They're more important than encrypted data
6. **Use authenticated encryption**: GCM mode, not ECB
7. **Salt and hash passwords**: Use bcrypt, scrypt, or Argon2
8. **Enable HTTPS**: Everywhere, always
9. **Implement MFA**: Passwords alone aren't enough
10. **Principle of least privilege**: Minimize access

## The Future: Quantum Cryptography

**Quantum computers** threaten current cryptography:
- Can break RSA and ECC
- Symmetric encryption requires larger keys but remains secure

**Post-quantum cryptography**: Algorithms resistant to quantum computers
- Lattice-based
- Hash-based
- Code-based
- Multivariate

NIST standardizing post-quantum algorithms now. Migration will take years.

**Quantum key distribution (QKD)**: Uses quantum mechanics to detect eavesdropping. Theoretically unbreakable but limited by distance and cost.

## Conclusion

Cryptography is the foundation of digital security. Everything we do online—banking, shopping, communicating—relies on cryptographic protections. Understanding these principles is essential for any security professional.

The key insights:
- Encryption transforms readable data into unreadable form
- Symmetric encryption is fast but has key distribution challenges
- Asymmetric encryption solves distribution but is slower
- Hashing provides integrity and is used for passwords
- Digital signatures provide authentication
- Access control determines who can access what
- Key management is critical—keys are more valuable than data

In the next lessons, we'll explore the ethical frameworks that guide how we use these powerful tools, and then dive into specific attack techniques and defenses.

Remember: cryptography is a tool. Like any tool, it can be used for good or harm. The responsibility lies with those who wield it.
