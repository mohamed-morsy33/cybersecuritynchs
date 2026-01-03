# Secure Communication Protocols and End-to-End Encryption

Beyond VPNs and TLS, modern applications need end-to-end encryption, secure messaging, and privacy-preserving technologies. This lesson covers Signal Protocol, encrypted email, secure file transfer, and emerging privacy technologies.

## End-to-End Encryption (E2EE)

### What is E2EE?

**End-to-end encryption ensures only sender and recipient can read messages.**

**Traditional encryption:**
```
Alice → [Encrypted] → Server [Decrypts, Re-encrypts] → Bob
         Server can read messages
```

**End-to-end encryption:**
```
Alice → [Encrypted] ────────────────────→ Bob
         Server cannot read messages
```

**Properties:**
- Only endpoints have keys
- Server can't decrypt
- Protects against compromised servers
- Protects against government surveillance

### Perfect Forward Secrecy (PFS)

**Ensures past messages stay secure even if long-term keys compromised.**

**How it works:**
- Generate new ephemeral keys for each session
- Delete keys after use
- Compromise of current key doesn't affect past messages

**Without PFS:**
```
If attacker gets private key + has recorded traffic
  → Can decrypt all past communications
```

**With PFS:**
```
If attacker gets private key + has recorded traffic
  → Can only decrypt current session
  → Past sessions remain secure
```

## Signal Protocol

### The Gold Standard of E2EE

**Used by:**
- Signal Messenger
- WhatsApp
- Facebook Messenger (Secret Conversations)
- Google Messages (RCS)
- Skype (Private Conversations)

**Security properties:**
- End-to-end encryption
- Perfect forward secrecy
- Post-compromise security (future secrecy)
- Deniability
- Asynchronous messaging

### Double Ratchet Algorithm

**Core of Signal Protocol**

**Two ratchets:**

**1. Diffie-Hellman Ratchet:**
- New key agreement with each message
- Provides forward secrecy
- Updates shared secrets

**2. Symmetric Key Ratchet:**
- Derives new keys from previous keys
- Used between DH ratchet updates
- Fast and efficient

**Key hierarchy:**
```
Root Key
   ↓
Chain Keys (sending and receiving)
   ↓
Message Keys (one per message)
```

**How it works:**

```
Alice                           Bob
------                          -----
Generate DH keypair
Send DH public key  ────────→
                              Receive Alice's DH public key
                              Perform DH key agreement
                              Derive chain keys
                    ←────────  Send encrypted message
Receive message
Derive message key
Decrypt message
Generate new DH keypair
Send encrypted message ─────→
                              Perform new DH key agreement
                              Derive new chain keys
                              ...
```

**Each message:**
1. Derives unique message key
2. Deletes key after encryption/decryption
3. Can't be decrypted again

### X3DH (Extended Triple Diffie-Hellman)

**Initial key agreement for asynchronous messaging**

**Allows:**
- Encrypted messages to offline recipients
- No real-time interaction needed
- Immediate forward secrecy

**Keys involved:**
- Identity key (long-term)
- Signed prekey (medium-term)
- One-time prekeys (single-use)
- Ephemeral key (session-specific)

**Process:**

```
Bob (offline) publishes to server:
  - Identity public key (IKb)
  - Signed prekey (SPKb)
  - Multiple one-time prekeys (OPKb)

Alice wants to message Bob:
  1. Fetch Bob's keys from server
  2. Generate ephemeral key (EKa)
  3. Perform 3 or 4 DH operations:
     - DH(IKa, SPKb)
     - DH(EKa, IKb)
     - DH(EKa, SPKb)
     - DH(EKa, OPKb)  [if one-time prekey available]
  4. Combine DH results into shared secret
  5. Send initial message with EKa

Bob comes online:
  1. Receives message with Alice's EKa
  2. Performs same DH operations
  3. Derives same shared secret
  4. Decrypts message
  5. Deletes one-time prekey
```

### Implementing Signal-like Encryption

**Simple example (not production-ready):**

```python
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class SignalLikeEncryption:
    def __init__(self):
        # Long-term identity key
        self.identity_private = x25519.X25519PrivateKey.generate()
        self.identity_public = self.identity_private.public_key()
        
        # Current ratchet keys
        self.ratchet_private = None
        self.ratchet_public = None
        
        # Chain keys
        self.sending_chain_key = None
        self.receiving_chain_key = None
        
    def kdf(self, input_key_material, salt=None):
        """Key derivation function"""
        if salt is None:
            salt = b'\x00' * 32
        
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'Signal Protocol'
        )
        return kdf.derive(input_key_material)
    
    def dh(self, private_key, public_key):
        """Diffie-Hellman exchange"""
        return private_key.exchange(public_key)
    
    def ratchet_step(self, their_public_key):
        """Perform DH ratchet step"""
        # Generate new ratchet keypair
        self.ratchet_private = x25519.X25519PrivateKey.generate()
        self.ratchet_public = self.ratchet_private.public_key()
        
        # Perform DH
        dh_output = self.dh(self.ratchet_private, their_public_key)
        
        # Derive new chain keys
        root_key = self.kdf(dh_output)
        self.sending_chain_key = self.kdf(root_key, b'sending')
        self.receiving_chain_key = self.kdf(root_key, b'receiving')
        
        return self.ratchet_public
    
    def encrypt_message(self, plaintext):
        """Encrypt a message"""
        # Derive message key from chain key
        message_key = self.kdf(self.sending_chain_key)
        
        # Update chain key for next message
        self.sending_chain_key = self.kdf(self.sending_chain_key)
        
        # Encrypt
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.CTR(iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        return iv + ciphertext
    
    def decrypt_message(self, encrypted_data):
        """Decrypt a message"""
        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Derive message key from chain key
        message_key = self.kdf(self.receiving_chain_key)
        
        # Update chain key for next message
        self.receiving_chain_key = self.kdf(self.receiving_chain_key)
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(message_key),
            modes.CTR(iv)
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode()

# Usage (simplified)
alice = SignalLikeEncryption()
bob = SignalLikeEncryption()

# Initial key exchange
bob_ratchet_public = bob.ratchet_step(alice.identity_public)
alice.ratchet_step(bob_ratchet_public)

# Alice sends message
encrypted = alice.encrypt_message("Hello Bob!")
print(f"Encrypted: {encrypted.hex()}")

# Bob receives and decrypts
decrypted = bob.decrypt_message(encrypted)
print(f"Decrypted: {decrypted}")
```

## Encrypted Email

### PGP/GPG

**Pretty Good Privacy - Email encryption standard**

**Key management:**
```bash
# Generate key
gpg --full-generate-key

# List keys
gpg --list-keys
gpg --list-secret-keys

# Export public key
gpg --armor --export your@email.com > public_key.asc

# Import someone's public key
gpg --import their_public_key.asc

# Sign someone's key (trust)
gpg --sign-key their@email.com
```

**Encrypt email:**
```bash
# Encrypt message
gpg --encrypt --armor --recipient recipient@email.com message.txt

# Encrypt and sign
gpg --encrypt --sign --armor --recipient recipient@email.com message.txt

# Decrypt
gpg --decrypt encrypted_message.txt.asc
```

**Using with email client:**

**Thunderbird + Enigmail:**
- Install Enigmail addon
- Generate or import key
- Compose → Encrypt message
- Automatic encryption when recipient's key available

**Web of Trust:**
```
You sign Alice's key (you trust Alice is Alice)
Alice signs Bob's key (Alice trusts Bob is Bob)
You can trust Bob's key through Alice (transitive trust)
```

### S/MIME

**Secure/Multipurpose Internet Mail Extensions**

**Differences from PGP:**
- Uses X.509 certificates
- Requires Certificate Authority
- Better enterprise support
- Native support in email clients
- Hierarchical trust model

**Get certificate:**
1. Purchase from CA (or use free from organizations)
2. Generate CSR
3. Submit to CA
4. Receive certificate
5. Install in email client

**Outlook S/MIME:**
- File → Options → Trust Center → Email Security
- Import certificate
- "Encrypt contents and attachments"
- "Add digital signature"

## Secure File Transfer

### SCP (Secure Copy Protocol)

**Copy files over SSH:**

```bash
# Upload file
scp local_file.txt user@remote:/path/

# Download file
scp user@remote:/path/file.txt local_directory/

# Copy directory
scp -r local_directory/ user@remote:/path/

# Specify port
scp -P 2222 file.txt user@remote:/path/

# Preserve file attributes
scp -p file.txt user@remote:/path/
```

### SFTP (SSH File Transfer Protocol)

**Interactive file transfer:**

```bash
# Connect
sftp user@remote

# Navigate
pwd                 # Print working directory
lpwd                # Print local working directory
ls                  # List remote files
lls                 # List local files
cd directory        # Change remote directory
lcd directory       # Change local directory

# Transfer
put local_file.txt  # Upload
get remote_file.txt # Download
put -r directory/   # Upload directory
get -r directory/   # Download directory

# Exit
exit
```

### rsync over SSH

**Efficient file synchronization:**

```bash
# Sync directory
rsync -avz -e ssh local_dir/ user@remote:/path/

# Options explained:
# -a: archive mode (preserve permissions, timestamps)
# -v: verbose
# -z: compress during transfer
# -e ssh: use SSH

# Sync with delete (mirror)
rsync -avz --delete -e ssh local_dir/ user@remote:/path/

# Dry run (test without changes)
rsync -avzn -e ssh local_dir/ user@remote:/path/

# Show progress
rsync -avz --progress -e ssh local_dir/ user@remote:/path/

# Exclude files
rsync -avz --exclude='*.log' -e ssh local_dir/ user@remote:/path/
```

### Magic Wormhole

**Simple encrypted file transfer:**

```bash
# Install
pip install magic-wormhole

# Send file
wormhole send file.txt
# Outputs code: 7-crossword-ventilate

# Receive (on other machine)
wormhole receive 7-crossword-ventilate

# Send directory
wormhole send --code 5-example-code directory/

# The code is used for key exchange
# End-to-end encrypted
# Works through NAT/firewalls
```

## Encrypted Messaging Applications

### Signal

**Architecture:**
- Open source
- Centralized servers (but can't read messages)
- Phone number as identifier
- Desktop and mobile apps
- Voice and video calls

**Security features:**
- End-to-end encryption (Signal Protocol)
- Perfect forward secrecy
- Sealed sender (hide metadata)
- Disappearing messages
- Screen security (screenshot protection)
- Registration lock
- Safety numbers (verify identity)

### Matrix/Element

**Architecture:**
- Open source
- Decentralized (federated servers)
- Self-hostable
- Username as identifier
- Voice and video calls

**Security features:**
- End-to-end encryption (Olm/Megolm)
- Device verification
- Cross-signing
- Encrypted attachments
- Federated identity

### Wire

**Architecture:**
- Open source
- End-to-end encrypted
- Supports teams/business
- No phone number required

**Security features:**
- Signal Protocol
- Encrypted audio/video
- Encrypted file sharing
- External audit

## Privacy-Enhancing Technologies

### Tor (The Onion Router)

**Anonymous communication:**

```bash
# Install Tor
sudo apt install tor

# Configure as SOCKS proxy
# In /etc/tor/torrc:
SocksPort 9050

# Start Tor
sudo systemctl start tor

# Use with applications
curl --socks5-hostname localhost:9050 https://check.torproject.org/

# Use Tor Browser (recommended)
# Download from torproject.org
```

**How Tor works:**
```
You → Entry node → Middle node → Exit node → Destination

Each hop only knows previous and next hop
Destination doesn't know your IP
You don't know full path
Encrypted in layers (like onion)
```

### I2P (Invisible Internet Project)

**Anonymous network layer:**

```bash
# Install I2P
sudo apt install i2p

# Access web interface
# http://127.0.0.1:7657

# I2P provides:
# - Anonymous hosting
# - Encrypted communication
# - Distributed network
# - Hidden services
```

### Mixnets

**Anonymize metadata through mixing:**

**Examples:**
- Nym Network
- Katzenpost
- Loopix

**How it works:**
```
1. Batch messages from multiple senders
2. Mix (reorder) messages
3. Add delays
4. Forward to next mix node
5. Repeat multiple hops
6. Deliver to recipients

Result: Hard to trace which output came from which input
```

## Zero-Knowledge Proofs

**Prove you know something without revealing it**

**Example: Proving age without revealing birthdate**

```python
# Simplified concept (not real ZKP)
def prove_over_18(birthdate, current_date):
    """Prove age > 18 without revealing exact age"""
    age = current_date.year - birthdate.year
    
    # Create commitment
    commitment = hash(birthdate + random_salt)
    
    # Prove age > 18 without revealing birthdate
    proof = {
        'commitment': commitment,
        'is_over_18': age >= 18,
        'verification_data': generate_zkp(age >= 18)
    }
    
    return proof

# Verifier can confirm age > 18
# But learns nothing else about birthdate
```

**Real-world applications:**
- Anonymous credentials
- Private voting
- Blockchain privacy (Zcash)
- Private authentication

## Secure Communication Best Practices

### Operational Security

**Communication security:**
- Use E2EE for sensitive conversations
- Verify contacts (safety numbers)
- Enable disappearing messages for sensitive topics
- Be aware of metadata leakage
- Use secure devices

**Key management:**
- Generate strong keys
- Backup keys securely
- Rotate keys regularly
- Revoke compromised keys
- Verify key fingerprints

**Platform selection:**
- Open source preferred
- Audited by security researchers
- Active maintenance
- Clear threat model
- Strong encryption defaults

### Threat Modeling

**Ask yourself:**

**What are you protecting?**
- Messages
- Metadata (who talks to whom)
- Files
- Identity

**Who are you protecting against?**
- Casual snoopers
- Criminals
- Corporations
- Governments
- Nation states

**Choose tools accordingly:**
- Casual privacy: Signal, Wire
- High anonymity: Tor, I2P
- Maximum security: Air-gapped systems

## Key Takeaways

**End-to-end encryption:**
- Only sender and recipient can read
- Server compromise doesn't expose messages
- Signal Protocol is gold standard
- Requires proper key management

**Email security:**
- PGP/GPG for decentralized encryption
- S/MIME for enterprise
- Both require key/certificate management
- Metadata still exposed

**File transfer:**
- SCP/SFTP for regular use
- rsync for synchronization
- Magic Wormhole for simplicity
- Always verify recipients

**Privacy technologies:**
- Tor for anonymity
- I2P for hidden services
- Mixnets for metadata protection
- Zero-knowledge proofs for selective disclosure

**Remember:**
- Encryption protects content, not metadata
- Perfect forward secrecy is important
- Verify keys/identities
- Choose tools for your threat model
- Security vs. convenience tradeoff

Secure communication is more than just encryption—it's about protecting privacy, ensuring authenticity, and defending against diverse threats. Understanding these technologies helps you choose the right tools and use them correctly.
