#!/bin/bash

# Comprehensive Security Scanning Script for Ubuntu 24
# Dynamically optimized for available CPU threads

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Define log file
LOG_DIR="$HOME/security_scans"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="$LOG_DIR/security_scan_$TIMESTAMP.log"
REPORT_FILE="$LOG_DIR/security_report_$TIMESTAMP.html"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Function to display section headers
section() {
    echo -e "\n${BLUE}==============================================================${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}==============================================================${NC}\n"
    echo -e "==============================================================" >> "$LOG_FILE"
    echo -e "   $1" >> "$LOG_FILE"
    echo -e "==============================================================" >> "$LOG_FILE"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to install packages if they don't exist
install_if_not_exists() {
    for pkg in "$@"; do
        if ! dpkg -l | grep -q "ii  $pkg"; then
            echo -e "${YELLOW}Installing $pkg...${NC}"
            sudo apt install -y "$pkg" >> "$LOG_FILE" 2>&1
        fi
    done
}

# Start HTML report
start_html_report() {
    cat > "$REPORT_FILE" << EOL
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - $(hostname) - $TIMESTAMP</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 30px; border-left: 5px solid #3498db; padding-left: 10px; }
        .warning { background-color: #fcf8e3; padding: 10px; border-left: 5px solid #f39c12; margin: 15px 0; }
        .danger { background-color: #f2dede; padding: 10px; border-left: 5px solid #c0392b; margin: 15px 0; }
        .success { background-color: #dff0d8; padding: 10px; border-left: 5px solid #27ae60; margin: 15px 0; }
        .info { background-color: #d9edf7; padding: 10px; border-left: 5px solid #3498db; margin: 15px 0; }
        pre { background-color: #f5f5f5; padding: 10px; border: 1px solid #ddd; overflow: auto; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <h1>Security Scan Report for $(hostname)</h1>
    <p><strong>Date:</strong> $(date)</p>
    <p><strong>System:</strong> $(lsb_release -ds)</p>
    <p><strong>Kernel:</strong> $(uname -r)</p>
    <div class="info">
        <p>This report contains the results of a comprehensive security scan. Please review all findings and take appropriate actions to address any vulnerabilities.</p>
    </div>
EOL
}

# Add section to HTML report
add_html_section() {
    local title="$1"
    local content="$2"
    local type="${3:-info}"
    
    cat >> "$REPORT_FILE" << EOL
    <h2>$title</h2>
    <div class="$type">
        <pre>$content</pre>
    </div>
EOL
}

# Finalize HTML report
end_html_report() {
    cat >> "$REPORT_FILE" << EOL
    <h2>Scan Summary</h2>
    <div class="info">
        <p>Scan completed at $(date)</p>
        <p>Full log file available at: $LOG_FILE</p>
    </div>
</body>
</html>
EOL
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo -e "${YELLOW}Please run with: sudo $0${NC}"
   exit 1
fi

# Start HTML report
start_html_report

# Record system information
section "System Information"
echo -e "${GREEN}Gathering system information...${NC}"

# Detect number of available CPU threads
CPU_THREADS=$(grep -c processor /proc/cpuinfo)
echo -e "${YELLOW}Detected $CPU_THREADS CPU threads. Optimizing scan parameters...${NC}"

# Calculate optimal thread usage
# Use different percentages of available threads for different types of tools
HIGH_THREADS=$CPU_THREADS
MEDIUM_THREADS=$(($CPU_THREADS * 3 / 4))
LOW_THREADS=$(($CPU_THREADS / 2))

# Ensure minimum thread count (no maximum cap)
if [ $MEDIUM_THREADS -lt 2 ]; then MEDIUM_THREADS=2; fi
if [ $LOW_THREADS -lt 2 ]; then LOW_THREADS=2; fi

SYS_INFO=$(cat << EOF
Hostname: $(hostname)
Operating System: $(lsb_release -ds)
Kernel Version: $(uname -r)
CPU Information: $(grep "model name" /proc/cpuinfo | head -1 | cut -d ":" -f2 | sed 's/^[ \t]*//')
Number of CPU Cores/Threads: $CPU_THREADS
Using for scans: Up to $HIGH_THREADS threads
System Uptime: $(uptime -p)
Last Boot: $(who -b | awk '{print $3" "$4}')
EOF
)

echo "$SYS_INFO" | tee -a "$LOG_FILE"
add_html_section "System Information" "$SYS_INFO"

# Update system first
section "System Updates"
echo -e "${GREEN}Updating package lists...${NC}"
apt update -qq >> "$LOG_FILE" 2>&1
echo -e "${GREEN}Checking for upgradable packages...${NC}"
UPGRADABLE=$(apt list --upgradable 2>/dev/null)
echo "$UPGRADABLE" >> "$LOG_FILE"
UPGRADE_COUNT=$(echo "$UPGRADABLE" | grep -c "upgradable")
echo -e "Found ${YELLOW}$UPGRADE_COUNT${NC} upgradable packages."
add_html_section "System Updates" "$UPGRADABLE\n\nTotal upgradable packages: $UPGRADE_COUNT" "warning"

# Install required tools
section "Installing Required Tools"
echo -e "${GREEN}Installing security tools...${NC}"
install_if_not_exists nmap lynis rkhunter chkrootkit aide clamav ufw fail2ban logwatch debsums nload iptraf-ng htop auditd portsentry tiger nikto binwalk foremost testdisk glances sysstat

# Wait for apt locks to be released
for i in {1..12}; do
    if sudo lsof /var/lib/dpkg/lock-frontend > /dev/null 2>&1; then
        echo -e "${YELLOW}Waiting for apt locks to be released... ($i/12)${NC}"
        sleep 10
    else
        break
    fi
done

# Update ClamAV signatures
section "Updating Antivirus Signatures"
echo -e "${GREEN}Updating ClamAV signatures...${NC}"
systemctl stop clamav-freshclam.service >> "$LOG_FILE" 2>&1
freshclam >> "$LOG_FILE" 2>&1
systemctl start clamav-freshclam.service >> "$LOG_FILE" 2>&1

# Port scanning with Nmap (utilizing multiple threads)
section "Network Port Scanning"
echo -e "${GREEN}Performing local port scan...${NC}"
LOCAL_IP=$(hostname -I | awk '{print $1}')
NETWORK=$(echo $LOCAL_IP | cut -d. -f1-3).0/24

# Get open ports on local machine
echo -e "${YELLOW}Scanning localhost for open ports...${NC}"
LOCALHOST_SCAN=$(nmap -T4 -sS -sV -p- --min-parallelism=$HIGH_THREADS localhost)
echo "$LOCALHOST_SCAN" >> "$LOG_FILE"
add_html_section "Open Ports on Localhost" "$LOCALHOST_SCAN"

# Scan the network (parallelized)
echo -e "${YELLOW}Scanning entire network $NETWORK...${NC}"
NETWORK_SCAN=$(nmap -T4 -sn --min-parallelism=$HIGH_THREADS $NETWORK)
echo "$NETWORK_SCAN" >> "$LOG_FILE"
add_html_section "Network Device Scan" "$NETWORK_SCAN"

# Enhanced Security Checks with Nmap Scripts
echo -e "${YELLOW}Performing vulnerability scan on localhost...${NC}"
VULN_SCAN=$(nmap -T4 -sV --script vuln --min-parallelism=$MEDIUM_THREADS localhost)
echo "$VULN_SCAN" >> "$LOG_FILE"
add_html_section "Vulnerability Scan Results" "$VULN_SCAN" "warning"

# Lynis security audit (leverage multiple threads where possible)
section "Lynis Security Audit"
echo -e "${GREEN}Running Lynis security audit...${NC}"
LYNIS_AUDIT=$(lynis audit system --quick)
echo "$LYNIS_AUDIT" >> "$LOG_FILE"
LYNIS_SCORE=$(echo "$LYNIS_AUDIT" | grep "Hardening index" | awk '{print $4}')
add_html_section "Lynis Security Audit" "$LYNIS_AUDIT\n\nHardening Index: $LYNIS_SCORE"

# Rootkit detection (running in parallel)
section "Rootkit Detection"
echo -e "${GREEN}Running rootkit detection scans...${NC}"

# Start rkhunter and chkrootkit in parallel
echo -e "${YELLOW}Running rkhunter scan...${NC}"
# Update rkhunter database first
rkhunter --update >> "$LOG_FILE" 2>&1
rkhunter --propupd >> "$LOG_FILE" 2>&1
rkhunter --check --skip-keypress >> "$LOG_FILE" 2>&1 &
RKHUNTER_PID=$!

echo -e "${YELLOW}Running chkrootkit scan...${NC}"
chkrootkit > "$LOG_DIR/chkrootkit_$TIMESTAMP.log" 2>&1 &
CHKROOTKIT_PID=$!

# Wait for both to complete
wait $RKHUNTER_PID
echo -e "${GREEN}RKHunter scan completed.${NC}"
RKHUNTER_RESULT=$(grep -A 5 "System checks summary" "$LOG_FILE" | tail -6)
add_html_section "RKHunter Results" "$RKHUNTER_RESULT"

wait $CHKROOTKIT_PID
echo -e "${GREEN}Chkrootkit scan completed.${NC}"
CHKROOTKIT_RESULT=$(grep -i "infected" "$LOG_DIR/chkrootkit_$TIMESTAMP.log" || echo "No infections found")
echo "$CHKROOTKIT_RESULT" >> "$LOG_FILE"
add_html_section "Chkrootkit Results" "$CHKROOTKIT_RESULT"

# Virus scanning - use multiple threads
section "Virus Scanning"
echo -e "${GREEN}Running virus scan on critical directories...${NC}"
# Run ClamAV with multithreading
CLAMSCAN_RESULT=$(clamscan -r -i -z --max-threads=$HIGH_THREADS --exclude-dir="^/sys|^/proc|^/dev" --max-filesize=4000M --max-scansize=4000M /bin /sbin /usr /etc /var/www 2>/dev/null)
echo "$CLAMSCAN_RESULT" >> "$LOG_FILE"
VIRUS_COUNT=$(echo "$CLAMSCAN_RESULT" | grep "Infected files" | awk '{print $3}')
add_html_section "ClamAV Virus Scan" "$CLAMSCAN_RESULT" "$([ $VIRUS_COUNT -gt 0 ] && echo 'danger' || echo 'success')"

# Firewall status check
section "Firewall Status"
echo -e "${GREEN}Checking firewall status...${NC}"
UFW_STATUS=$(ufw status verbose)
echo "$UFW_STATUS" >> "$LOG_FILE"
add_html_section "UFW Firewall Status" "$UFW_STATUS"

IPTABLES_RULES=$(iptables -L -v)
echo "$IPTABLES_RULES" >> "$LOG_FILE"
add_html_section "IPTables Rules" "$IPTABLES_RULES"

# Service and process monitoring
section "Running Services"
echo -e "${GREEN}Checking running services...${NC}"
RUNNING_SERVICES=$(systemctl list-units --type=service --state=running | grep ".service")
echo "$RUNNING_SERVICES" >> "$LOG_FILE"
add_html_section "Running Services" "$RUNNING_SERVICES"

section "Listening Ports"
echo -e "${GREEN}Checking listening ports...${NC}"
LISTENING_PORTS=$(ss -tulpn)
echo "$LISTENING_PORTS" >> "$LOG_FILE"
add_html_section "Listening Ports" "$LISTENING_PORTS"

# File integrity check
section "File Integrity Check"
echo -e "${GREEN}Checking file integrity...${NC}"

# Check if AIDE database exists, if not create it
if [ ! -f /var/lib/aide/aide.db ]; then
    echo -e "${YELLOW}Initializing AIDE database (this may take some time)...${NC}"
    aideinit >> "$LOG_FILE" 2>&1
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db >> "$LOG_FILE" 2>&1
    echo -e "${GREEN}AIDE database initialized. Future scans will compare against this baseline.${NC}"
    AIDE_RESULT="AIDE database initialized. No comparison available yet."
else
    echo -e "${YELLOW}Running AIDE file integrity check...${NC}"
    AIDE_RESULT=$(aide --check)
    echo "$AIDE_RESULT" >> "$LOG_FILE"
fi
add_html_section "AIDE File Integrity" "$AIDE_RESULT" "warning"

# Check system files against package database
section "Package Integrity Check"
echo -e "${GREEN}Verifying integrity of installed packages...${NC}"
# Split work across multiple parallel jobs
PACKAGE_CHECK=$(debsums -c 2>&1 | grep -v "OK$")
echo "$PACKAGE_CHECK" >> "$LOG_FILE"

if [ -z "$PACKAGE_CHECK" ]; then
    PACKAGE_CHECK="All checked packages passed verification."
fi
add_html_section "Package Integrity" "$PACKAGE_CHECK"

# Check for suspicious cron jobs
section "Cron Jobs Check"
echo -e "${GREEN}Checking for suspicious cron jobs...${NC}"
CRON_CHECK=$(for user in $(cut -f1 -d: /etc/passwd); do echo "Cron jobs for $user:"; crontab -u $user -l 2>/dev/null | grep -v "^#" || echo "None"; done)
echo "$CRON_CHECK" >> "$LOG_FILE"
add_html_section "Cron Jobs" "$CRON_CHECK"

# Check user accounts with shell access
section "User Accounts"
echo -e "${GREEN}Checking user accounts with shell access...${NC}"
SHELL_USERS=$(grep -v "nologin\|false" /etc/passwd)
echo "$SHELL_USERS" >> "$LOG_FILE"
add_html_section "Users with Shell Access" "$SHELL_USERS"

# Check for users with sudo/admin privileges
section "Admin Users"
echo -e "${GREEN}Checking admin users...${NC}"
ADMIN_USERS=$(grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' '\n')
echo "Users with sudo privileges:" >> "$LOG_FILE"
echo "$ADMIN_USERS" >> "$LOG_FILE"
add_html_section "Admin Users" "Users with sudo privileges:\n$ADMIN_USERS"

# Check SSH configuration
section "SSH Configuration"
echo -e "${GREEN}Checking SSH configuration...${NC}"
if [ -f /etc/ssh/sshd_config ]; then
    SSH_CONFIG=$(grep -v "^#" /etc/ssh/sshd_config | grep -v "^$")
    echo "$SSH_CONFIG" >> "$LOG_FILE"
    
    # Check for potential SSH security issues
    SSH_ISSUES=""
    if grep -q "PermitRootLogin yes" /etc/ssh/sshd_config; then
        SSH_ISSUES="${SSH_ISSUES}\n- WARNING: Root login is allowed."
    fi
    if grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
        SSH_ISSUES="${SSH_ISSUES}\n- WARNING: Password authentication is allowed."
    fi
    if ! grep -q "Protocol 2" /etc/ssh/sshd_config; then
        SSH_ISSUES="${SSH_ISSUES}\n- WARNING: Protocol 2 not explicitly set."
    fi
    
    if [ -n "$SSH_ISSUES" ]; then
        add_html_section "SSH Configuration" "$SSH_CONFIG\n\nPotential Security Issues:$SSH_ISSUES" "warning"
    else
        add_html_section "SSH Configuration" "$SSH_CONFIG"
    fi
else
    echo "SSH server not installed." >> "$LOG_FILE"
    add_html_section "SSH Configuration" "SSH server not installed."
fi

# Check CPU usage
section "System Resource Usage"
echo -e "${GREEN}Checking system resources...${NC}"
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
MEMORY_USAGE=$(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}')
DISK_USAGE=$(df -h / | awk 'NR==2{print $5}')

RESOURCE_INFO=$(cat << EOF
CPU Usage: $CPU_USAGE%
Memory Usage: $MEMORY_USAGE
Disk Usage: $DISK_USAGE
EOF
)

echo "$RESOURCE_INFO" >> "$LOG_FILE"
add_html_section "System Resource Usage" "$RESOURCE_INFO"

# Check for DMZ-specific issues
section "DMZ Security Check"
echo -e "${GREEN}Performing DMZ-specific security checks...${NC}"

# Determine if IP forwarding is enabled (important for DMZ)
IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [ "$IP_FORWARD" -eq 1 ]; then
    echo "WARNING: IP forwarding is enabled. This is only necessary if this system is acting as a router/firewall." >> "$LOG_FILE"
    DMZ_NOTES="- WARNING: IP forwarding is enabled ($IP_FORWARD)."
else
    echo "IP forwarding is disabled. This is good for DMZ servers that should not route traffic." >> "$LOG_FILE"
    DMZ_NOTES="- IP forwarding is properly disabled ($IP_FORWARD)."
fi

# Check for common DMZ misconfigurations
DMZ_CHECK=$(cat << EOF
IP Forwarding Status: $IP_FORWARD
$DMZ_NOTES

Network Interface Information:
$(ip -c addr)

Routing Table:
$(ip route)

NAT Table:
$(iptables -t nat -L -v)
EOF
)

echo "$DMZ_CHECK" >> "$LOG_FILE"
add_html_section "DMZ Configuration Check" "$DMZ_CHECK" "warning"

# Generate final report
section "Scan Complete"
echo -e "${GREEN}Security scan completed.${NC}"
echo -e "${GREEN}Log file saved to:${NC} $LOG_FILE"
echo -e "${GREEN}HTML report saved to:${NC} $REPORT_FILE"

# Finalize HTML report
end_html_report

# Recommend next steps
cat << EOF

${BLUE}==============================================================${NC}
${BLUE}                  SECURITY SCAN SUMMARY                       ${NC}
${BLUE}==============================================================${NC}

${GREEN}The security scan has completed successfully.${NC}

${YELLOW}Review the detailed report at:${NC} 
  $REPORT_FILE

${YELLOW}For a more detailed log, see:${NC}
  $LOG_FILE

${YELLOW}Recommended next steps:${NC}
1. Address any vulnerabilities or warnings found in the report
2. Apply system updates if needed (apt upgrade)
3. Review firewall rules to ensure they align with your DMZ design
4. Set up regular automated scanning using this script

For DMZ setup, ensure:
- Proper network segmentation
- Minimal services running on DMZ hosts
- Restrictive firewall rules between zones
- Regular security updates

Run this script regularly to maintain security posture.
EOF
