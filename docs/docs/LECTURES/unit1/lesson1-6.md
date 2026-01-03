# Package Management and System Administration

Linux systems need software installation, updates, and maintenance. As a security professional, you'll constantly be installing tools, updating systems, and managing services. This lesson covers the essential system administration tasks.

## Package Management

**Package managers** handle software installation, updates, and removal. Different Linux distributions use different package managers.

### APT (Debian/Ubuntu/Kali)

**APT** (Advanced Package Tool) is used on Debian-based systems like Ubuntu and Kali Linux.

#### Updating Package Lists
```bash
# Update package index
sudo apt update

# Always do this before installing new software!
```

#### Upgrading Packages
```bash
# Upgrade all installed packages
sudo apt upgrade

# Upgrade with automatic handling of dependencies
sudo apt full-upgrade

# Upgrade specific package
sudo apt upgrade package-name
```

#### Installing Packages
```bash
# Install package
sudo apt install nmap

# Install multiple packages
sudo apt install nmap wireshark metasploit-framework

# Install without confirmation
sudo apt install -y nmap

# Reinstall package
sudo apt install --reinstall nmap
```

#### Removing Packages
```bash
# Remove package (keep configuration files)
sudo apt remove nmap

# Remove package and configuration files
sudo apt purge nmap

# Remove unused dependencies
sudo apt autoremove

# Clean up downloaded package files
sudo apt clean
```

#### Searching for Packages
```bash
# Search for package
apt search nmap

# Show package information
apt show nmap

# List installed packages
apt list --installed

# List upgradeable packages
apt list --upgradeable
```

### YUM/DNF (Red Hat/Fedora/CentOS)

Used on Red Hat-based systems.

```bash
# Update package lists
sudo yum update  # or sudo dnf update

# Install package
sudo yum install nmap

# Remove package
sudo yum remove nmap

# Search for package
yum search nmap

# Show package info
yum info nmap
```

### Installing from Source

Sometimes you need to compile software from source code.

```bash
# 1. Download source code
wget https://example.com/software.tar.gz

# 2. Extract
tar -xzvf software.tar.gz
cd software/

# 3. Configure
./configure

# 4. Compile
make

# 5. Install
sudo make install

# 6. Uninstall (if needed)
sudo make uninstall
```

**Common compilation dependencies:**
```bash
sudo apt install build-essential
sudo apt install gcc g++ make
```

## User Management

### Creating Users
```bash
# Create new user
sudo useradd john

# Create user with home directory
sudo useradd -m john

# Create user with specific shell
sudo useradd -m -s /bin/bash john

# Set password
sudo passwd john
```

### Modifying Users
```bash
# Change user's shell
sudo usermod -s /bin/zsh john

# Add user to group
sudo usermod -aG sudo john    # Add to sudo group
sudo usermod -aG docker john  # Add to docker group

# Change home directory
sudo usermod -d /home/newjohn john

# Lock user account
sudo usermod -L john

# Unlock user account
sudo usermod -U john
```

### Deleting Users
```bash
# Delete user (keep home directory)
sudo userdel john

# Delete user and home directory
sudo userdel -r john
```

### User Information
```bash
# Show current user
whoami

# Show all users
cat /etc/passwd

# Show logged in users
who

# Show what users are doing
w

# Last logins
last

# Show user's groups
groups username

# Show user ID and group ID
id username
```

### Switching Users
```bash
# Switch to another user
su - john

# Switch to root
su -

# Run command as another user
sudo -u john command

# Open shell as root
sudo -i

# Run command as root
sudo command
```

## Group Management

### Creating Groups
```bash
# Create group
sudo groupadd developers

# Create group with specific GID
sudo groupadd -g 1001 developers
```

### Managing Groups
```bash
# Add user to group
sudo usermod -aG developers john

# Remove user from group
sudo gpasswd -d john developers

# Delete group
sudo groupdel developers

# Show all groups
cat /etc/group
```

## File System Management

### Mounting and Unmounting

```bash
# Mount a device
sudo mount /dev/sdb1 /mnt/usb

# Unmount
sudo umount /mnt/usb

# Mount with specific filesystem type
sudo mount -t ntfs /dev/sdb1 /mnt/windows

# Show mounted filesystems
mount

# Show disk usage
df -h
```

### /etc/fstab - Automatic Mounting

Edit `/etc/fstab` to automatically mount filesystems at boot:
```bash
sudo nano /etc/fstab
```

Example entry:
```
/dev/sdb1  /mnt/data  ext4  defaults  0  2
```

### Checking Disk Health
```bash
# Check filesystem
sudo fsck /dev/sdb1

# Check and repair
sudo fsck -y /dev/sdb1

# SMART status (if installed)
sudo smartctl -a /dev/sda
```

## Service Management (systemd)

Modern Linux uses **systemd** to manage services.

### Managing Services
```bash
# Start service
sudo systemctl start apache2

# Stop service
sudo systemctl stop apache2

# Restart service
sudo systemctl restart apache2

# Reload configuration
sudo systemctl reload apache2

# Enable service (start at boot)
sudo systemctl enable apache2

# Disable service (don't start at boot)
sudo systemctl disable apache2

# Check service status
sudo systemctl status apache2

# Show if service is active
systemctl is-active apache2

# Show if service is enabled
systemctl is-enabled apache2
```

### Viewing Services
```bash
# List all services
systemctl list-units --type=service

# List enabled services
systemctl list-unit-files --type=service --state=enabled

# List failed services
systemctl --failed
```

### Viewing Logs
```bash
# View service logs
sudo journalctl -u apache2

# Follow logs (real-time)
sudo journalctl -u apache2 -f

# View logs since boot
sudo journalctl -b

# View recent logs
sudo journalctl -n 50

# View logs for specific time
sudo journalctl --since "2024-01-01" --until "2024-01-02"
```

## System Logs

### Log Locations
```bash
/var/log/syslog        # General system log
/var/log/auth.log      # Authentication log
/var/log/kern.log      # Kernel log
/var/log/apache2/      # Apache logs
/var/log/mysql/        # MySQL logs
```

### Viewing Logs
```bash
# View recent system log
tail -f /var/log/syslog

# View authentication attempts
sudo tail -f /var/log/auth.log

# Search for failed logins
sudo grep "Failed password" /var/log/auth.log

# Count failed login attempts
sudo grep "Failed password" /var/log/auth.log | wc -l
```

## Scheduled Tasks (Cron)

**Cron** runs commands on a schedule.

### Crontab Syntax
```
* * * * * command
│ │ │ │ │
│ │ │ │ └─── Day of week (0-7, Sunday = 0 or 7)
│ │ │ └───── Month (1-12)
│ │ └─────── Day of month (1-31)
│ └───────── Hour (0-23)
└─────────── Minute (0-59)
```

### Managing Crontab
```bash
# Edit current user's crontab
crontab -e

# List crontab
crontab -l

# Remove crontab
crontab -r

# Edit another user's crontab
sudo crontab -u john -e
```

### Examples
```bash
# Run every day at 2 AM
0 2 * * * /path/to/backup.sh

# Run every hour
0 * * * * /path/to/check.sh

# Run every 15 minutes
*/15 * * * * /path/to/script.sh

# Run every Monday at 3 PM
0 15 * * 1 /path/to/weekly.sh

# Run at reboot
@reboot /path/to/startup.sh

# Run daily
@daily /path/to/daily.sh
```

### System-wide Cron
```bash
# Edit system crontabs
sudo vim /etc/crontab

# Or place scripts in:
/etc/cron.daily/      # Runs daily
/etc/cron.hourly/     # Runs hourly
/etc/cron.weekly/     # Runs weekly
/etc/cron.monthly/    # Runs monthly
```

## System Monitoring

### Resource Monitoring
```bash
# Real-time process monitor
top

# Better alternative (if installed)
htop

# Disk I/O statistics
iostat

# Virtual memory statistics
vmstat

# Network statistics
netstat -tuln    # Listening ports
netstat -plant   # All connections

# Modern alternative to netstat
ss -tuln         # Listening ports
ss -plant        # All connections
```

### System Information
```bash
# CPU information
lscpu
cat /proc/cpuinfo

# Memory information
free -h
cat /proc/meminfo

# Disk information
lsblk
fdisk -l

# PCI devices
lspci

# USB devices
lsusb

# Kernel version
uname -r

# Distribution information
cat /etc/os-release
lsb_release -a
```

## Network Configuration

### Network Interfaces
```bash
# Show interfaces (old)
ifconfig

# Show interfaces (modern)
ip addr show
ip a

# Bring interface up
sudo ip link set eth0 up

# Bring interface down
sudo ip link set eth0 down

# Set IP address
sudo ip addr add 192.168.1.100/24 dev eth0

# Delete IP address
sudo ip addr del 192.168.1.100/24 dev eth0
```

### Network Configuration Files

#### /etc/network/interfaces (Debian)
```bash
sudo nano /etc/network/interfaces
```

Static IP example:
```
auto eth0
iface eth0 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
```

DHCP example:
```
auto eth0
iface eth0 inet dhcp
```

#### netplan (Ubuntu 18.04+)
```bash
sudo nano /etc/netplan/01-netcfg.yaml
```

Example:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: false
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

Apply changes:
```bash
sudo netplan apply
```

### DNS Configuration
```bash
# Edit DNS servers
sudo nano /etc/resolv.conf
```

Example:
```
nameserver 8.8.8.8
nameserver 8.8.4.4
```

### Hostname
```bash
# Show hostname
hostname

# Change hostname temporarily
sudo hostname newhostname

# Change hostname permanently
sudo hostnamectl set-hostname newhostname

# Edit hosts file
sudo nano /etc/hosts
```

## Firewall (iptables/ufw)

### UFW (Uncomplicated Firewall)

Easier to use than raw iptables.

```bash
# Enable firewall
sudo ufw enable

# Disable firewall
sudo ufw disable

# Show status
sudo ufw status

# Verbose status
sudo ufw status verbose

# Allow port
sudo ufw allow 22
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

# Reset firewall (remove all rules)
sudo ufw reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing
```

### iptables (Advanced)

Lower-level firewall control.

```bash
# List rules
sudo iptables -L

# List with line numbers
sudo iptables -L --line-numbers

# Allow incoming SSH
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Drop all other incoming
sudo iptables -A INPUT -j DROP

# Save rules (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4

# Restore rules
sudo iptables-restore < /etc/iptables/rules.v4

# Flush all rules
sudo iptables -F
```

## System Updates and Security

### Keeping System Updated
```bash
# Update and upgrade (Debian/Ubuntu)
sudo apt update && sudo apt upgrade -y

# Security updates only
sudo apt update && sudo apt upgrade -y --only-upgrade

# Automatic updates (install package)
sudo apt install unattended-upgrades

# Configure automatic updates
sudo dpkg-reconfigure unattended-upgrades
```

### Security Hardening Basics

```bash
# Disable root login via SSH
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
sudo systemctl restart sshd

# Change SSH port (security through obscurity)
# In /etc/ssh/sshd_config: Port 2222

# Disable password authentication (use keys only)
# In /etc/ssh/sshd_config: PasswordAuthentication no

# Install fail2ban (blocks repeated failed logins)
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## Backups

### Using tar for Backups
```bash
# Backup home directory
sudo tar -czvf /backup/home-$(date +%Y%m%d).tar.gz /home

# Restore from backup
sudo tar -xzvf /backup/home-20240101.tar.gz -C /
```

### Using rsync for Backups
```bash
# Backup to another location
sudo rsync -avz /home /backup/

# Backup over network
sudo rsync -avz /home user@remote:/backup/

# Exclude certain files
sudo rsync -avz --exclude='*.tmp' /home /backup/
```

## Practical Security Examples

### Check for Failed Login Attempts
```bash
sudo grep "Failed password" /var/log/auth.log | tail -20
```

### Find Recently Modified Files
```bash
find /etc -mtime -1  # Modified in last 24 hours
```

### Check Listening Ports
```bash
sudo ss -tuln
sudo netstat -tuln
```

### See Active Connections
```bash
sudo ss -plant
sudo netstat -plant
```

### Check for Unusual Processes
```bash
ps aux | grep -v "\[" | grep -v "root" | sort -k 3 -r | head
```

### Monitor System Logs in Real-Time
```bash
sudo tail -f /var/log/syslog | grep -i error
```

## Key Takeaways

System administration skills you now have:
- Package management (installing/removing software)
- User and group management
- Service management (starting/stopping/enabling services)
- Log viewing and monitoring
- Scheduled tasks (cron)
- Network configuration
- Basic firewall rules
- System security hardening

These are fundamental skills every security professional needs. You'll use these daily whether you're:
- Setting up security tools
- Investigating incidents
- Hardening systems
- Monitoring for threats
- Analyzing logs

Practice these commands regularly. Set up a virtual machine and experiment. Break things (in your VM!) and fix them. That's how you truly learn system administration.

In the next lessons, we'll move beyond Linux basics and start applying these skills to security-specific scenarios.
