# Applied Cryptography and Real-World Implementations

Cryptography theory is one thing—implementing it correctly is another. This lesson covers how to actually use cryptography in real applications, common pitfalls, and best practices for secure implementation.

## Implementing Encryption in Applications

### Python Cryptography

**Use the `cryptography` library—don't roll your own crypto!**

#### Symmetric Encryption (AES)

```python
from cryptography.fernet import Fernet

# Generate key
key = Fernet.generate_key()
print(f"Key (save this securely): {key.decode()}")

# Create cipher object
cipher = Fernet(key)

# Encrypt
plaintext = b"Secret message"
ciphertext = cipher.encrypt(plaintext)
print(f"Encrypted: {ciphertext}")

# Decrypt
decrypted = cipher.decrypt(ciphertext)
print(f"Decrypted: {decrypted.decode()}")
```

**Fernet provides:**
- AES-128 encryption in CBC mode
- HMAC for authentication
- Timestamp for freshness
- All-in-one authenticated encryption

#### File Encryption

```python
from cryptography.fernet import Fernet
import os

def encrypt_file(filename, key):
    """Encrypt a file"""
    cipher = Fernet(key)
    
    # Read file
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Encrypt
    encrypted = cipher.encrypt(data)
    
    # Write encrypted file
    with open(filename + '.enc', 'wb') as f:
        f.write(encrypted)
    
    print(f"Encrypted {filename} -> {filename}.enc")

def decrypt_file(filename, key):
    """Decrypt a file"""
    cipher = Fernet(key)
    
    # Read encrypted file
    with open(filename, 'rb') as f:
        encrypted = f.read()
    
    # Decrypt
    try:
        decrypted = cipher.decrypt(encrypted)
    except:
        print("Decryption failed - wrong key or corrupted file")
        return
    
    # Write decrypted file
    output = filename.replace('.enc', '.dec')
    with open(output, 'wb') as f:
        f.write(decrypted)
    
    print(f"Decrypted {filename} -> {output}")

# Usage
key = Fernet.generate_key()
encrypt_file('secret.txt', key)
decrypt_file('secret.txt.enc', key)
```

#### Password-Based Encryption

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.fernet import Fernet
import base64
import os

def derive_key_from_password(password, salt=None):
    """Derive encryption key from password"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_with_password(data, password):
    """Encrypt data with password"""
    key, salt = derive_key_from_password(password)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(data.encode())
    
    # Return salt + encrypted data
    return salt + encrypted

def decrypt_with_password(encrypted_data, password):
    """Decrypt data with password"""
    # Extract salt and encrypted data
    salt = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    
    # Derive key from password and salt
    key, _ = derive_key_from_password(password, salt)
    cipher = Fernet(key)
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

# Usage
password = "my_secure_password"
data = "Secret information"

encrypted = encrypt_with_password(data, password)
print(f"Encrypted: {encrypted.hex()}")

decrypted = decrypt_with_password(encrypted, password)
print(f"Decrypted: {decrypted}")
```

### Asymmetric Encryption (RSA)

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Save private key
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b'password')
)
with open('private_key.pem', 'wb') as f:
    f.write(pem_private)

# Save public key
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as f:
    f.write(pem_public)

# Encrypt with public key
message = b"Secret message"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt with private key
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Decrypted: {plaintext.decode()}")
```

**Note:** RSA encryption is limited by key size:
- 2048-bit key can encrypt ~245 bytes
- For larger data, encrypt a symmetric key with RSA
- Then encrypt data with symmetric key (hybrid encryption)

### Digital Signatures

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Sign a message
message = b"I agree to the terms"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(f"Signature: {signature.hex()}")

# Verify signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature valid!")
except:
    print("Signature invalid!")
```

## Password Storage

**NEVER store passwords in plaintext!**

### Hashing Passwords

```python
import bcrypt

def hash_password(password):
    """Hash password with bcrypt"""
    # Generate salt and hash
    salt = bcrypt.gensalt(rounds=12)  # Work factor: 2^12 iterations
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode(), hashed)

# Registration
password = "user_password123"
stored_hash = hash_password(password)
print(f"Stored hash: {stored_hash}")

# Login
login_password = "user_password123"
if verify_password(login_password, stored_hash):
    print("Login successful!")
else:
    print("Invalid password")
```

### Using Argon2 (More Secure)

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_password_argon2(password):
    """Hash password with Argon2"""
    return ph.hash(password)

def verify_password_argon2(password, hashed):
    """Verify password against Argon2 hash"""
    try:
        ph.verify(hashed, password)
        return True
    except:
        return False

# Usage
password = "secure_password"
hashed = hash_password_argon2(password)
print(f"Argon2 hash: {hashed}")

# Verification
if verify_password_argon2("secure_password", hashed):
    print("Password correct!")
```

## Secure Communication

### Creating a Secure Messaging System

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet

class SecureMessaging:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key(self):
        """Export public key for sharing"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def send_message(self, message, recipient_public_key_pem):
        """Encrypt message for recipient"""
        # Generate random symmetric key
        symmetric_key = Fernet.generate_key()
        cipher = Fernet(symmetric_key)
        
        # Encrypt message with symmetric key
        encrypted_message = cipher.encrypt(message.encode())
        
        # Load recipient's public key
        recipient_public_key = serialization.load_pem_public_key(
            recipient_public_key_pem
        )
        
        # Encrypt symmetric key with recipient's public key
        encrypted_key = recipient_public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Sign message
        signature = self.private_key.sign(
            encrypted_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            'encrypted_key': encrypted_key,
            'encrypted_message': encrypted_message,
            'signature': signature
        }
    
    def receive_message(self, package, sender_public_key_pem):
        """Decrypt and verify message"""
        # Load sender's public key
        sender_public_key = serialization.load_pem_public_key(
            sender_public_key_pem
        )
        
        # Verify signature
        try:
            sender_public_key.verify(
                package['signature'],
                package['encrypted_message'],
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified!")
        except:
            print("Invalid signature!")
            return None
        
        # Decrypt symmetric key
        symmetric_key = self.private_key.decrypt(
            package['encrypted_key'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message
        cipher = Fernet(symmetric_key)
        message = cipher.decrypt(package['encrypted_message'])
        
        return message.decode()

# Usage
alice = SecureMessaging()
bob = SecureMessaging()

# Alice sends message to Bob
message = "Hello Bob, this is secret!"
package = alice.send_message(message, bob.get_public_key())

# Bob receives message from Alice
received = bob.receive_message(package, alice.get_public_key())
print(f"Bob received: {received}")
```

## SSL/TLS in Applications

### Secure HTTPS Client

```python
import requests

# Verify SSL certificate (default)
response = requests.get('https://example.com')

# Custom certificate verification
response = requests.get(
    'https://example.com',
    verify='/path/to/ca-bundle.crt'
)

# Disable verification (NOT RECOMMENDED in production)
# response = requests.get('https://example.com', verify=False)

# Client certificate authentication
response = requests.get(
    'https://example.com',
    cert=('/path/to/client.crt', '/path/to/client.key')
)
```

### Secure Websocket Server

```python
import ssl
import asyncio
import websockets

async def secure_handler(websocket, path):
    """Handle secure websocket connections"""
    try:
        async for message in websocket:
            response = f"Echo: {message}"
            await websocket.send(response)
    except websockets.exceptions.ConnectionClosed:
        pass

# SSL context
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(
    certfile='/path/to/server.crt',
    keyfile='/path/to/server.key'
)

# Start secure server
start_server = websockets.serve(
    secure_handler,
    'localhost',
    8765,
    ssl=ssl_context
)

asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
```

## Common Cryptography Mistakes

### ❌ Mistake 1: Using ECB Mode

```python
# BAD - ECB mode reveals patterns
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)
```

```python
# GOOD - Use GCM or CBC
cipher = AES.new(key, AES.MODE_GCM)
```

### ❌ Mistake 2: Not Using IV/Nonce

```python
# BAD - Reusing same IV
iv = b'1234567890123456'
cipher = AES.new(key, AES.MODE_CBC, iv)
```

```python
# GOOD - Random IV each time
import os
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
```

### ❌ Mistake 3: Weak Random Numbers

```python
# BAD - Not cryptographically secure
import random
key = random.randint(0, 2**256)
```

```python
# GOOD - Cryptographically secure
import secrets
key = secrets.token_bytes(32)
```

### ❌ Mistake 4: Storing Keys in Code

```python
# BAD - Hardcoded key
key = b'my_secret_key_123'
```

```python
# GOOD - Key from environment or key store
import os
key = os.environ.get('ENCRYPTION_KEY').encode()

# Or from key management service
# key = get_key_from_kms()
```

### ❌ Mistake 5: No Authentication

```python
# BAD - Encryption without authentication
encrypted = cipher.encrypt(data)
```

```python
# GOOD - Authenticated encryption (GCM)
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(data)
```

### ❌ Mistake 6: Weak Hashing for Passwords

```python
# BAD - MD5 or SHA256 for passwords
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
```

```python
# GOOD - bcrypt, scrypt, or Argon2
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

## Key Storage and Management

### Environment Variables

```python
import os

# Load key from environment
encryption_key = os.environ.get('ENCRYPTION_KEY')

if not encryption_key:
    raise ValueError("ENCRYPTION_KEY not set!")
```

```bash
# Set in shell
export ENCRYPTION_KEY="your-key-here"

# Or in .env file (use python-dotenv)
echo "ENCRYPTION_KEY=your-key-here" > .env
```

### Configuration Files

```python
import json

def load_key_from_config():
    """Load key from encrypted config file"""
    with open('config.json.enc', 'rb') as f:
        encrypted_config = f.read()
    
    # Decrypt config with master key
    master_key = os.environ.get('MASTER_KEY')
    cipher = Fernet(master_key.encode())
    decrypted = cipher.decrypt(encrypted_config)
    
    config = json.loads(decrypted)
    return config['encryption_key']
```

### Hardware Security Modules (HSM)

```python
# Example using cloud HSM (AWS KMS)
import boto3

def encrypt_with_kms(data, key_id):
    """Encrypt data using AWS KMS"""
    kms = boto3.client('kms')
    
    response = kms.encrypt(
        KeyId=key_id,
        Plaintext=data
    )
    
    return response['CiphertextBlob']

def decrypt_with_kms(ciphertext, key_id):
    """Decrypt data using AWS KMS"""
    kms = boto3.client('kms')
    
    response = kms.decrypt(
        CiphertextBlob=ciphertext
    )
    
    return response['Plaintext']
```

## Practical Security Applications

### Encrypted Backup Script

```python
from cryptography.fernet import Fernet
import os
import tarfile
from datetime import datetime

def encrypted_backup(source_dir, backup_dir, key):
    """Create encrypted backup of directory"""
    # Create tarball
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    tarball_name = f'backup_{timestamp}.tar.gz'
    tarball_path = os.path.join('/tmp', tarball_name)
    
    with tarfile.open(tarball_path, 'w:gz') as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))
    
    # Encrypt tarball
    cipher = Fernet(key)
    with open(tarball_path, 'rb') as f:
        data = f.read()
    
    encrypted = cipher.encrypt(data)
    
    # Save encrypted backup
    encrypted_path = os.path.join(backup_dir, f'{tarball_name}.enc')
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted)
    
    # Clean up unencrypted tarball
    os.remove(tarball_path)
    
    print(f"Encrypted backup created: {encrypted_path}")
    return encrypted_path

# Usage
key = Fernet.generate_key()
encrypted_backup('/home/user/documents', '/backups', key)
```

### Secure Configuration Management

```python
import json
from cryptography.fernet import Fernet

class SecureConfig:
    def __init__(self, key):
        self.cipher = Fernet(key)
        self.config = {}
    
    def set(self, key, value):
        """Set configuration value"""
        self.config[key] = value
    
    def get(self, key):
        """Get configuration value"""
        return self.config.get(key)
    
    def save(self, filename):
        """Save encrypted configuration"""
        json_data = json.dumps(self.config)
        encrypted = self.cipher.encrypt(json_data.encode())
        
        with open(filename, 'wb') as f:
            f.write(encrypted)
    
    def load(self, filename):
        """Load encrypted configuration"""
        with open(filename, 'rb') as f:
            encrypted = f.read()
        
        decrypted = self.cipher.decrypt(encrypted)
        self.config = json.loads(decrypted.decode())

# Usage
key = Fernet.generate_key()
config = SecureConfig(key)

config.set('database_password', 'secret123')
config.set('api_key', 'key_abc123')
config.save('config.enc')

# Load later
new_config = SecureConfig(key)
new_config.load('config.enc')
print(new_config.get('database_password'))
```

## Key Takeaways

**Applied cryptography principles:**
- Use established libraries, not custom implementations
- Always use authenticated encryption (GCM mode)
- Generate keys securely (secrets module)
- Store keys safely (environment variables, KMS)
- Hash passwords with specialized algorithms (bcrypt, Argon2)

**Common patterns:**
- Hybrid encryption (RSA + AES) for large data
- Digital signatures for authenticity
- Key derivation from passwords (PBKDF2)
- Perfect forward secrecy (ephemeral keys)

**Security checklist:**
- ✓ Using secure random number generation
- ✓ Not hardcoding keys
- ✓ Using authenticated encryption
- ✓ Proper key management
- ✓ Regular key rotation
- ✓ Secure key transmission
- ✓ Protecting keys at rest

**Remember:**
- Cryptography is hard to get right
- Use well-tested libraries
- Don't roll your own crypto
- Security through obscurity doesn't work
- Always assume attackers know your algorithm

Next, we'll explore PKI (Public Key Infrastructure) and certificate management in detail.
