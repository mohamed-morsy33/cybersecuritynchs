# Basic Linux Commands

Now that you understand why Linux matters for cybersecurity, it's time to actually use it. The command line interface (CLI) is where you'll spend most of your time, so getting comfortable with basic commands is essential.

## The Terminal

The **terminal** (also called shell or command line) is your interface to Linux. Unlike graphical interfaces where you click icons, here you type commands. It might feel awkward at first, but it's far more powerful and precise.

When you open a terminal, you'll see a **prompt** that looks something like:
```
user@hostname:~$
```

Breaking this down:
- `user`: Your username
- `hostname`: The computer's name
- `~`: Current directory (~ means home directory)
- `$`: Regular user (if you see `#`, you're root)

## Navigation Commands

### pwd - Print Working Directory
Shows where you currently are in the file system.
```bash
pwd
# Output: /home/user
```

### ls - List Directory Contents
Shows files and folders in current directory.
```bash
# Basic listing
ls

# Long format (detailed)
ls -l

# Show hidden files (start with .)
ls -a

# Combine flags
ls -la

# Human-readable file sizes
ls -lh

# Sort by modification time
ls -lt
```

### cd - Change Directory
Move between directories.
```bash
# Go to home directory
cd
cd ~

# Go to specific directory
cd /etc

# Go up one level
cd ..

# Go up two levels
cd ../..

# Go to previous directory
cd -

# Relative path (from current location)
cd Documents

# Absolute path (from root)
cd /var/log
```

**Pro tip**: Use Tab for autocomplete. Start typing a directory name and hit Tab.

## File Manipulation

### cat - Concatenate and Display Files
Display file contents.
```bash
cat file.txt

# Display multiple files
cat file1.txt file2.txt

# Number lines
cat -n file.txt
```

### less - View Files Page by Page
Better for large files.
```bash
less largefile.txt
# Use arrow keys to scroll
# Press 'q' to quit
# Press '/' to search
# Press 'n' for next search result
```

### head and tail - View File Beginnings/Ends
```bash
# First 10 lines
head file.txt

# First 20 lines
head -n 20 file.txt

# Last 10 lines
tail file.txt

# Last 20 lines
tail -n 20 file.txt

# Follow file (watch new lines appear)
tail -f /var/log/syslog
```

### touch - Create Empty Files
```bash
touch newfile.txt

# Create multiple files
touch file1.txt file2.txt file3.txt

# Update timestamp of existing file
touch existingfile.txt
```

### mkdir - Make Directory
```bash
mkdir newfolder

# Create nested directories
mkdir -p parent/child/grandchild

# Create multiple directories
mkdir dir1 dir2 dir3
```

### cp - Copy Files/Directories
```bash
# Copy file
cp source.txt destination.txt

# Copy to directory
cp file.txt /home/user/Documents/

# Copy directory recursively
cp -r sourcedir/ destdir/

# Copy with verbose output
cp -v file.txt copy.txt

# Preserve permissions and timestamps
cp -p file.txt copy.txt
```

### mv - Move/Rename Files
```bash
# Rename file
mv oldname.txt newname.txt

# Move file to directory
mv file.txt /home/user/Documents/

# Move multiple files
mv file1.txt file2.txt /home/user/Documents/

# Move directory
mv olddir/ newdir/
```

### rm - Remove Files/Directories
**WARNING: No recycle bin in Linux! Deleted = gone forever.**

```bash
# Remove file
rm file.txt

# Remove multiple files
rm file1.txt file2.txt

# Remove directory and contents
rm -r directory/

# Force removal (no confirmation)
rm -f file.txt

# Interactive (ask before each deletion)
rm -i file.txt

# Remove directory (force and recursive)
rm -rf directory/
```

**NEVER run**: `rm -rf /` or `rm -rf /*` - this deletes everything!

## Viewing and Searching

### grep - Search Text
Find lines containing specific text.
```bash
# Search for word in file
grep "password" file.txt

# Case-insensitive search
grep -i "password" file.txt

# Show line numbers
grep -n "error" logfile.txt

# Recursive search in directory
grep -r "TODO" /home/user/code/

# Invert match (show lines NOT containing text)
grep -v "success" logfile.txt

# Count matches
grep -c "error" logfile.txt
```

### find - Find Files and Directories
```bash
# Find files by name
find /home -name "*.txt"

# Find directories
find /home -type d -name "Documents"

# Find files modified in last 7 days
find /home -mtime -7

# Find files larger than 100MB
find /home -size +100M

# Find and delete
find /tmp -name "*.tmp" -delete

# Find with specific permissions
find /home -perm 777
```

### locate - Quick File Search
Uses database, faster than find but less current.
```bash
# Update database first
sudo updatedb

# Find files
locate password.txt

# Case-insensitive
locate -i PASSWORD.TXT
```

## File Permissions

Every file has permissions for owner, group, and others.

### Understanding Permissions
```bash
ls -l file.txt
# Output: -rw-r--r-- 1 user group 1234 Jan 1 12:00 file.txt
```

Breaking down `-rw-r--r--`:
- First character: File type (`-` = file, `d` = directory, `l` = link)
- Next 3: Owner permissions (`rw-` = read, write, no execute)
- Next 3: Group permissions (`r--` = read only)
- Last 3: Other permissions (`r--` = read only)

Permissions in numeric form:
- `r` (read) = 4
- `w` (write) = 2
- `x` (execute) = 1

So `rwx` = 4+2+1 = 7, `rw-` = 4+2 = 6, `r--` = 4

### chmod - Change Permissions
```bash
# Give owner execute permission
chmod u+x script.sh

# Remove write permission from group
chmod g-w file.txt

# Set specific permissions (numeric)
chmod 755 script.sh  # rwxr-xr-x
chmod 644 file.txt   # rw-r--r--

# Recursive
chmod -R 755 directory/
```

Common permission sets:
- `777`: Everyone can do everything (usually bad idea)
- `755`: Owner full access, others read/execute (typical for directories)
- `644`: Owner read/write, others read (typical for files)
- `600`: Owner read/write only (private files)

### chown - Change Owner
```bash
# Change owner
sudo chown newowner file.txt

# Change owner and group
sudo chown newowner:newgroup file.txt

# Recursive
sudo chown -R newowner directory/
```

## System Information

### whoami - Current User
```bash
whoami
# Output: user
```

### hostname - Computer Name
```bash
hostname
# Output: kali-linux
```

### uname - System Information
```bash
# Basic info
uname

# All information
uname -a

# Kernel version
uname -r
```

### df - Disk Space
```bash
# Show disk usage
df

# Human-readable
df -h

# Specific filesystem
df -h /home
```

### du - Directory Size
```bash
# Size of directory
du -sh /home/user

# Size of all items in directory
du -h /home/user

# Show total only
du -s /home/user
```

### free - Memory Usage
```bash
# Show memory
free

# Human-readable
free -h
```

### top - Process Monitor
Real-time view of running processes.
```bash
top
# Press 'q' to quit
# Press 'k' to kill a process
# Press 'M' to sort by memory
# Press 'P' to sort by CPU
```

Better alternative: `htop` (if installed)
```bash
htop
```

### ps - Process Status
```bash
# Current user's processes
ps

# All processes
ps aux

# Search for specific process
ps aux | grep firefox
```

## Process Management

### Running Commands in Background
```bash
# Run in background
command &

# Example
python3 script.py &
```

### jobs - List Background Jobs
```bash
jobs
```

### fg - Bring to Foreground
```bash
# Bring last job to foreground
fg

# Bring specific job
fg %1
```

### kill - Terminate Process
```bash
# Kill by PID
kill 1234

# Force kill
kill -9 1234

# Kill by name
killall firefox
```

## Redirection and Pipes

### Output Redirection
```bash
# Write to file (overwrite)
echo "Hello" > file.txt

# Append to file
echo "World" >> file.txt

# Redirect errors
command 2> error.log

# Redirect both output and errors
command > output.log 2>&1
```

### Pipes
Send output of one command as input to another.
```bash
# Count lines
cat file.txt | wc -l

# Search in output
ps aux | grep python

# Chain multiple commands
cat file.txt | grep "error" | wc -l

# Sort and unique
cat file.txt | sort | uniq
```

## Text Processing

### wc - Word Count
```bash
# Count lines, words, characters
wc file.txt

# Just lines
wc -l file.txt

# Just words
wc -w file.txt
```

### sort - Sort Lines
```bash
# Sort alphabetically
sort file.txt

# Sort numerically
sort -n numbers.txt

# Reverse sort
sort -r file.txt

# Sort and remove duplicates
sort -u file.txt
```

### uniq - Remove Duplicates
Must be sorted first!
```bash
# Remove adjacent duplicates
sort file.txt | uniq

# Count occurrences
sort file.txt | uniq -c

# Show only duplicates
sort file.txt | uniq -d
```

## Archives and Compression

### tar - Archive Files
```bash
# Create archive
tar -cvf archive.tar directory/

# Extract archive
tar -xvf archive.tar

# Create compressed archive (gzip)
tar -czvf archive.tar.gz directory/

# Extract compressed archive
tar -xzvf archive.tar.gz

# List contents without extracting
tar -tvf archive.tar
```

Flags explained:
- `c`: create
- `x`: extract
- `v`: verbose
- `f`: file
- `z`: gzip compression
- `j`: bzip2 compression

### zip/unzip - Zip Archives
```bash
# Create zip
zip archive.zip file1 file2

# Create zip of directory
zip -r archive.zip directory/

# Extract zip
unzip archive.zip

# List contents
unzip -l archive.zip
```

## Network Commands

### ping - Test Connectivity
```bash
# Ping host
ping google.com

# Ping 4 times only
ping -c 4 google.com
```

### wget - Download Files
```bash
# Download file
wget https://example.com/file.txt

# Download with different name
wget -O newname.txt https://example.com/file.txt

# Download in background
wget -b https://example.com/largefile.zip
```

### curl - Transfer Data
```bash
# Download file
curl -O https://example.com/file.txt

# Save with different name
curl -o newname.txt https://example.com/file.txt

# Follow redirects
curl -L https://example.com

# Show headers only
curl -I https://example.com
```

### ifconfig / ip - Network Configuration
```bash
# Show network interfaces (older)
ifconfig

# Show network interfaces (modern)
ip addr show

# Show routing table
ip route show
```

## Command Tips and Tricks

### Command History
```bash
# Show history
history

# Run previous command
!!

# Run command from history
!123

# Search history
Ctrl+R (then start typing)

# Clear history
history -c
```

### Tab Completion
- Press Tab once: Complete if unique
- Press Tab twice: Show all possibilities

### Keyboard Shortcuts
- `Ctrl+C`: Cancel current command
- `Ctrl+Z`: Suspend current command
- `Ctrl+D`: Exit terminal / End of input
- `Ctrl+L`: Clear screen (same as `clear`)
- `Ctrl+A`: Move to beginning of line
- `Ctrl+E`: Move to end of line
- `Ctrl+U`: Delete from cursor to beginning
- `Ctrl+K`: Delete from cursor to end

### Getting Help
```bash
# Manual pages
man command

# Example
man ls

# Quick help
command --help

# Example
ls --help
```

## Practical Examples

### Find all .txt files in home directory
```bash
find ~ -name "*.txt"
```

### Search for "password" in all files
```bash
grep -r "password" /home/user/
```

### Find largest files in directory
```bash
du -ah /home/user | sort -rh | head -10
```

### Count how many times IP appears in log
```bash
grep "192.168.1.100" /var/log/apache2/access.log | wc -l
```

### Find all running Python processes
```bash
ps aux | grep python
```

### Monitor log file in real-time
```bash
tail -f /var/log/syslog
```

### Create directory structure
```bash
mkdir -p project/{src,docs,tests}
```

## Next Steps

Practice these commands! The only way to get comfortable is repetition. Try:
1. Navigate your file system using only terminal
2. Create, move, and delete files
3. Search for specific content in files
4. Monitor system processes
5. Combine commands with pipes

In the next lesson, we'll cover more advanced Linux topics including package management, user administration, and system services.

Remember: Google is your friend. If you forget a command or need to know options, search for it or use `man`. Every security professional regularly looks up commands—it's not about memorization, it's about knowing what's possible and where to find information.
