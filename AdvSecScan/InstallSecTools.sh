#!/bin/bash

# Security Software Installer Script
# This script installs all security tools needed for the comprehensive security scan

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo -e "${YELLOW}Please run with: sudo $0${NC}"
   exit 1
fi

# Function to display section headers
section() {
    echo -e "\n${BLUE}==============================================================${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}==============================================================${NC}\n"
}

# Update package lists
section "Updating Package Lists"
echo -e "${GREEN}Updating package lists...${NC}"
apt update

# Install packages in separate groups to avoid dependency issues
section "Installing Core Security Tools"
echo -e "${GREEN}Installing core security utilities...${NC}"
apt install -y nmap ufw fail2ban logwatch htop sysstat glances

section "Installing Network Analysis Tools"
echo -e "${GREEN}Installing network analysis tools...${NC}"
apt install -y iptraf-ng nload tcpdump wireshark

section "Installing Anti-Malware Tools"
echo -e "${GREEN}Installing anti-malware tools...${NC}"
apt install -y clamav clamav-daemon

section "Installing Rootkit Detection Tools"
echo -e "${YELLOW}Installing RKHunter separately...${NC}"
# Install rkhunter separately with more verbose output
apt install -y rkhunter
echo -e "${YELLOW}RKHunter installation complete. Checking status...${NC}"
if command -v rkhunter &> /dev/null; then
    echo -e "${GREEN}RKHunter installed successfully!${NC}"
else
    echo -e "${RED}RKHunter installation may have failed. Please check the output.${NC}"
fi

echo -e "${YELLOW}Installing chkrootkit...${NC}"
apt install -y chkrootkit

section "Installing File Integrity Tools"
echo -e "${GREEN}Installing file integrity checkers...${NC}"
apt install -y aide debsums

section "Installing System Auditing Tools"
echo -e "${GREEN}Installing system auditing tools...${NC}"
apt install -y auditd lynis tiger

section "Installing Additional Security Tools"
echo -e "${GREEN}Installing additional security utilities...${NC}"
apt install -y nikto binwalk foremost testdisk portsentry

# Update ClamAV signatures
section "Updating Antivirus Signatures"
echo -e "${GREEN}Updating ClamAV signatures...${NC}"
systemctl stop clamav-freshclam.service 2>/dev/null
freshclam
systemctl start clamav-freshclam.service 2>/dev/null

# Initialize AIDE database if needed
section "Setting Up AIDE"
echo -e "${YELLOW}Checking AIDE setup...${NC}"
if [ ! -f /var/lib/aide/aide.db ]; then
    echo -e "${YELLOW}Initializing AIDE database (this may take some time)...${NC}"
    aideinit
    if [ -f /var/lib/aide/aide.db.new ]; then
        cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        echo -e "${GREEN}AIDE database initialized successfully.${NC}"
    fi
else
    echo -e "${GREEN}AIDE database already exists.${NC}"
fi

# Summary
section "Installation Complete"
echo -e "${GREEN}All security tools have been installed.${NC}"
echo -e "\n${YELLOW}Installed Tools:${NC}"
echo -e "  ${GREEN}• Network scanning:${NC} nmap, tcpdump, wireshark"
echo -e "  ${GREEN}• Firewall/IDS:${NC} ufw, fail2ban, portsentry"
echo -e "  ${GREEN}• Rootkit detection:${NC} rkhunter, chkrootkit"
echo -e "  ${GREEN}• Antivirus:${NC} clamav"
echo -e "  ${GREEN}• File integrity:${NC} aide, debsums"
echo -e "  ${GREEN}• System auditing:${NC} lynis, tiger, auditd"
echo -e "  ${GREEN}• Monitoring:${NC} htop, glances, nload, iptraf-ng, sysstat"
echo -e "  ${GREEN}• Additional tools:${NC} nikto, binwalk, foremost, testdisk"

echo -e "\n${YELLOW}You can now run the main security scanning script:${NC}"
echo -e "  ${GREEN}sudo ./AdvSecScan.sh${NC}"
